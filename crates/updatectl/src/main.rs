//! `updatectl` — the CI-facing publisher for `updated`.
//!
//! Two subcommands, no `kubectl` and no secret-management code of its own:
//!
//! * `trust-root` mints a fresh TUF trust root — a one-time bootstrap. It generates the
//!   four ed25519 role keys into a directory (which the operator loads into Vault),
//!   initializes the empty release repository in S3, and prints the `root.json` that every
//!   group pins in its `release_repository.root_json`. It needs no Kubernetes access at all.
//!
//! * `deploy` is the per-release command. It reads the role keys from a directory — in
//!   production a Vault-backed Secret projected into the pod as a read-only file mount —
//!   builds the canonical deterministic `tar.zst` bundle, signs and publishes it as a TUF
//!   target into the S3 repository, then patches the named `UpdateGroup` to reference the
//!   new target. It touches Kubernetes only to patch that one resource.
//!
//! Keys are always just a directory of `root.pk8`, `targets.pk8`, `snapshot.pk8`, and
//! `timestamp.pk8`. Delivery (Vault → Secret → mount) is the platform's job; `updatectl`
//! stays out of the secret business. It only ever *mints and signs* — it never verifies;
//! signature verification is entirely the node's job, gated by the group's configuration.
//!
//! Everything reuses the operator's own libraries (`updated::bundle`, `updated_tuf::repo`,
//! `updatec`), so a CI publish and an operator republish agree on one bundle format, one
//! TUF layout, and one S3 object layout — there is no second code path to drift.
//!
//! Linux only: bundles carry Unix executable bits and the default platform is the host's
//! `linux-<arch>`. Every flag also reads a `UPDATECTL_*` environment variable, and AWS
//! credentials come from the standard environment, so a pipeline can inject everything
//! without assembling a command line.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Args, Parser, Subcommand, ValueEnum};
use futures::StreamExt;
use kube::api::{Api, Patch, PatchParams};
use kube::Client;
use object_store::path::Path as ObjectPath;
use object_store::ObjectStore;
use updatec::{S3Destination, UpdateGroup};
use updated_tuf::repo::{self, PublishTarget};

mod keygen;

type Error = Box<dyn std::error::Error>;

/// The online role keys a release publish signs with. Root keys are not among them.
const ONLINE_KEYS: [&str; 3] = ["targets.pk8", "snapshot.pk8", "timestamp.pk8"];

/// Mint trust roots and publish signed releases from CI, without kubectl.
#[derive(Parser, Debug)]
#[command(name = "updatectl", about, long_about = None, disable_version_flag = true)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate the ed25519 role keys into a directory, offline. No S3 or Kubernetes — mint
    /// on a trusted machine and load them into Vault.
    Keygen(keygen::KeygenArgs),
    /// Mint a fresh TUF trust root: generate role keys into a directory, initialize the
    /// empty release repository in S3, and print root.json. Needs no Kubernetes access.
    TrustRoot(TrustRootArgs),
    /// Rotate the trust root: activate the standby key, mint a new successor, and publish a
    /// co-signed new root version. Existing devices follow the chain automatically.
    RotateRoot(RotateRootArgs),
    /// Build, sign, and publish an application bundle, then roll a named UpdateGroup onto it.
    Deploy(DeployArgs),
    /// Build, sign, and publish a lifecycle-provider artifact bundle as
    /// a signed target. Like `deploy` but publishes only the target — no group is rolled. A
    /// provider set then references the resulting `path`+`sha256`.
    PublishProviderArtifact(ProviderArtifactArgs),
    /// Sign and publish an immutable provider set (`provider-sets/<id>.json`) as a target,
    /// binding the required lifecycle provider artifact by path+sha256. This is the
    /// S3-native counterpart of `server publish-provider-set`.
    PublishProviderSet(ProviderSetArgs),
}

/// The release repository backend, shared by both subcommands. AWS credentials come from
/// the standard `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` environment.
#[derive(Args, Debug)]
struct Backend {
    /// Directory of ed25519 role keys. `deploy` needs only the online keys (`targets.pk8`,
    /// `snapshot.pk8`, `timestamp.pk8`) — in production a Vault-backed Secret mounted
    /// read-only. `trust-root`/`rotate-root` also use the root keys (`root.pk8` active plus
    /// `root.next.pk8` standby). `trust-root` writes freshly minted keys here.
    #[arg(long, env = "UPDATECTL_KEYS_DIR")]
    keys_dir: PathBuf,

    /// Release-repository S3 bucket.
    #[arg(long, env = "UPDATECTL_BUCKET")]
    bucket: String,

    /// Release-repository S3 region.
    #[arg(long, env = "UPDATECTL_REGION")]
    region: String,

    /// Key prefix within the bucket. Empty means the bucket root.
    #[arg(long, env = "UPDATECTL_PREFIX", default_value = "")]
    prefix: String,

    /// Optional S3 endpoint override (e.g. MinIO). Omit for real AWS.
    #[arg(long, env = "UPDATECTL_ENDPOINT")]
    endpoint: Option<String>,
}

#[derive(Args, Debug)]
struct TrustRootArgs {
    #[command(flatten)]
    backend: Backend,

    /// Days until the freshly signed root/targets/snapshot/timestamp metadata expires.
    #[arg(long, env = "UPDATECTL_EXPIRY_DAYS", default_value_t = 365)]
    expiry_days: i64,

    /// Write root.json here instead of stdout. Either way it is the value to paste into a
    /// group's `release_repository.root_json`.
    #[arg(long, env = "UPDATECTL_ROOT_OUT")]
    root_out: Option<PathBuf>,

    /// Re-initialize an already-initialized repository. This invalidates everything signed
    /// under the old root — used deliberately.
    #[arg(long)]
    force: bool,

    #[arg(long, value_enum, env = "UPDATECTL_OUTPUT", default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(Args, Debug)]
struct RotateRootArgs {
    #[command(flatten)]
    backend: Backend,

    /// Where to write the freshly minted successor root key (mode 0600). Load it into Vault
    /// as the new standby after rotation. Must not already exist.
    #[arg(long, env = "UPDATECTL_NEW_KEY_OUT")]
    new_key_out: PathBuf,

    /// Days until the new root metadata expires.
    #[arg(long, env = "UPDATECTL_EXPIRY_DAYS", default_value_t = 365)]
    expiry_days: i64,

    /// Write the new root.json here instead of stdout (the anchor for new enrollments).
    #[arg(long, env = "UPDATECTL_ROOT_OUT")]
    root_out: Option<PathBuf>,

    #[arg(long, value_enum, env = "UPDATECTL_OUTPUT", default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(Args, Debug)]
struct DeployArgs {
    #[command(flatten)]
    backend: Backend,

    /// Namespace holding the UpdateGroup.
    #[arg(long, env = "UPDATECTL_NAMESPACE", default_value = "updated-system")]
    namespace: String,

    /// UpdateGroup to roll onto the new bundle (its `spec.deployment.application`).
    #[arg(long, env = "UPDATECTL_GROUP")]
    group: String,

    /// Product name; also the bundle target's component segment.
    #[arg(long, env = "UPDATECTL_PRODUCT")]
    product: String,

    /// Release channel.
    #[arg(long, env = "UPDATECTL_CHANNEL", default_value = "stable")]
    channel: String,

    /// Semantic version of this release.
    #[arg(long, env = "UPDATECTL_VERSION")]
    version: String,

    /// Bundle-relative path of the launched executable (e.g. `bin/app`).
    #[arg(long, env = "UPDATECTL_ENTRYPOINT")]
    entrypoint: String,

    /// Source to publish: a prepared directory tree, or a single executable file that is
    /// wrapped into a one-file bundle at `--entrypoint`.
    #[arg(long, env = "UPDATECTL_SOURCE")]
    source: PathBuf,

    /// Target platform `<os>-<arch>`. Defaults to the host's `linux-<arch>`.
    #[arg(long, env = "UPDATECTL_PLATFORM")]
    platform: Option<String>,

    /// Target path of the provider set this release ships with. When set (together with
    /// `--provider-set-sha256`), it is signed into the app target's custom metadata, so an
    /// ordered-fallback descent to this version re-selects exactly these providers — app and
    /// providers roll back as one unit. Omit to leave provider selection to the assignment head.
    #[arg(
        long,
        env = "UPDATECTL_PROVIDER_SET_PATH",
        requires = "provider_set_sha256"
    )]
    provider_set_path: Option<String>,

    /// sha256 of the provider set named by `--provider-set-path`.
    #[arg(
        long,
        env = "UPDATECTL_PROVIDER_SET_SHA256",
        requires = "provider_set_path"
    )]
    provider_set_sha256: Option<String>,

    /// Days until the re-signed TUF metadata expires.
    #[arg(long, env = "UPDATECTL_EXPIRY_DAYS", default_value_t = 365)]
    expiry_days: i64,

    /// Declare this publish an EMERGENCY CORRECTION: the operator admits it immediately, without
    /// waiting for the governing `UpdateGroupSet`'s rollout schedule. Nothing else is bypassed —
    /// concurrency slots, `maxUnavailable` staging, inputs, and prerequisites all still apply.
    ///
    /// Use it to escape a release the fleet cannot report on at all (one that bricks the agent),
    /// which is precisely the case no health signal could ever detect. The flag is written into
    /// `spec.emergencyCorrection` on every deploy, set or cleared, so an ordinary deploy of this
    /// group afterwards turns it back off — an override can never be silently permanent.
    #[arg(long, env = "UPDATECTL_EMERGENCY")]
    emergency: bool,

    /// Result format written to stdout. Diagnostics always go to stderr, so `json` yields a
    /// single clean object a pipeline can capture and parse.
    #[arg(long, value_enum, env = "UPDATECTL_OUTPUT", default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(Args, Debug)]
struct ProviderArtifactArgs {
    #[command(flatten)]
    backend: Backend,

    /// Product name; also the bundle target's component segment. The published target is
    /// `products/<product>/<channel>/<version>/<platform>/<product>`.
    #[arg(long, env = "UPDATECTL_PRODUCT")]
    product: String,

    /// Release channel.
    #[arg(long, env = "UPDATECTL_CHANNEL", default_value = "stable")]
    channel: String,

    /// Semantic version of this provider artifact.
    #[arg(long, env = "UPDATECTL_VERSION")]
    version: String,

    /// Bundle-relative path of the provider executable (e.g. `bin/lifecycle`).
    #[arg(long, env = "UPDATECTL_ENTRYPOINT")]
    entrypoint: String,

    /// Source to publish: a prepared directory tree, or a single executable file that is
    /// wrapped into a one-file bundle at `--entrypoint`.
    #[arg(long, env = "UPDATECTL_SOURCE")]
    source: PathBuf,

    /// Target platform `<os>-<arch>`. Defaults to the host's `linux-<arch>`.
    #[arg(long, env = "UPDATECTL_PLATFORM")]
    platform: Option<String>,

    /// Days until the re-signed TUF metadata expires.
    #[arg(long, env = "UPDATECTL_EXPIRY_DAYS", default_value_t = 365)]
    expiry_days: i64,
}

#[derive(Args, Debug)]
struct ProviderSetArgs {
    #[command(flatten)]
    backend: Backend,

    /// Provider set id; the published target is `provider-sets/<id>.json`.
    #[arg(long, env = "UPDATECTL_PROVIDER_SET_ID")]
    id: String,

    /// Lifecycle provider artifact target path (from `publish-provider-artifact`).
    #[arg(long)]
    provider_path: String,

    /// sha256 of the lifecycle provider artifact.
    #[arg(long)]
    provider_sha256: String,

    /// Extra argument passed to the lifecycle provider (repeatable).
    #[arg(long)]
    provider_arg: Vec<String>,

    /// Lifecycle provider timeout, milliseconds.
    #[arg(long, default_value_t = 300_000)]
    provider_timeout_ms: u64,

    /// Days until the re-signed TUF metadata expires.
    #[arg(long, env = "UPDATECTL_EXPIRY_DAYS", default_value_t = 365)]
    expiry_days: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    // The kube client and S3 store both drive rustls; install the workspace's one provider.
    updated::tls::install_crypto_provider();
    let result = match Cli::parse().command {
        Command::Keygen(args) => keygen::run(args).await,
        Command::TrustRoot(args) => trust_root(args).await,
        Command::RotateRoot(args) => rotate_root(args).await,
        Command::Deploy(args) => deploy(args).await,
        Command::PublishProviderArtifact(args) => publish_provider_artifact(args).await,
        Command::PublishProviderSet(args) => publish_provider_set(args).await,
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("updatectl: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

/// Wire up the S3 object store for the release repository. Credentials come from the
/// standard AWS environment (empty for anonymous/dev stores such as public MinIO).
fn build_store(backend: &Backend) -> Result<(S3Destination, Arc<dyn ObjectStore>), Error> {
    let destination = S3Destination {
        bucket: backend.bucket.clone(),
        prefix: backend.prefix.clone(),
        region: backend.region.clone(),
        credentials_secret_ref: None,
        endpoint: backend.endpoint.clone(),
    };
    let access = std::env::var("AWS_ACCESS_KEY_ID").ok();
    let secret = std::env::var("AWS_SECRET_ACCESS_KEY").ok();
    // Temporary credentials (STS AssumeRole, SSO, IRSA) are only valid with their session token.
    let token = std::env::var("AWS_SESSION_TOKEN").ok();
    let store = updatec::runtime::s3_store(
        &destination,
        updatec::runtime::S3Credentials {
            access_key: access.as_deref(),
            secret_key: secret.as_deref(),
            session_token: token.as_deref(),
        },
    )?;
    Ok((destination, store))
}

async fn trust_root(args: TrustRootArgs) -> Result<(), Error> {
    let backend = &args.backend;
    let (destination, store) = build_store(backend)?;

    // Refuse to silently invalidate an already-published repository.
    let initialized = repo_initialized(store.as_ref(), &destination).await?;
    if !args.force && initialized {
        return Err(format!(
            "release repository at s3://{}/{} is already initialized; pass --force to replace \
             it (this invalidates everything signed under the old root)",
            backend.bucket, backend.prefix
        )
        .into());
    }
    // A replacement must start ABOVE the versions the live repository has already published.
    // TUF clients remember the highest version they accepted and refuse anything lower, so a
    // replacement republished at version 1 is silently rejected by every node that ever saw the
    // old repository — no error at the publisher, and every agent stalled indefinitely.
    let start_version = if initialized {
        let next = live_metadata_version(store.as_ref(), &destination).await? + 1;
        eprintln!(
            "replacing a live repository: starting its metadata at version {next} so clients \
             past the old versions still accept it (nodes must still be re-pinned to the new root)"
        );
        next
    } else {
        1
    };

    // Mint the role keys into the target directory (the operator loads these into Vault),
    // then build an empty signed repository in a throwaway temp dir.
    let keys = repo::generate_keys(&backend.keys_dir).await?;
    eprintln!("wrote role keys to {}", backend.keys_dir.display());
    let repo_dir = tempfile::tempdir()?;
    repo::init_from_version(repo_dir.path(), &keys, args.expiry_days, start_version).await?;
    let root_json = tokio::fs::read(repo_dir.path().join("metadata/root.json")).await?;

    updatec::runtime::publish_repository(store.as_ref(), &destination, repo_dir.path()).await?;
    eprintln!(
        "initialized release repository at s3://{}/{}",
        backend.bucket, backend.prefix
    );

    // The root.json is the artifact the operator embeds in the group.
    match &args.root_out {
        Some(path) => {
            tokio::fs::write(path, &root_json).await?;
            eprintln!("wrote root.json to {}", path.display());
        }
        None if args.output == OutputFormat::Text => {
            use std::io::Write;
            std::io::stdout().write_all(&root_json)?;
        }
        None => {}
    }
    if args.output == OutputFormat::Json {
        let document = serde_json::json!({
            "bucket": backend.bucket,
            "prefix": backend.prefix,
            "keysDir": backend.keys_dir,
            "root": String::from_utf8_lossy(&root_json),
        });
        println!("{}", serde_json::to_string(&document)?);
    }
    Ok(())
}

async fn rotate_root(args: RotateRootArgs) -> Result<(), Error> {
    let backend = &args.backend;
    let (destination, store) = build_store(backend)?;

    // The current root must carry two keys (active + standby) so one can sign the transition.
    let keys = repo::Keys::in_dir(&backend.keys_dir);
    if keys.roots.len() < 2 {
        return Err(format!(
            "--keys-dir {} does not hold a standby root key (root.next.pk8); the root was \
             minted single-key and cannot be rotated in place — re-mint with `trust-root`",
            backend.keys_dir.display()
        )
        .into());
    }

    // Pull the current metadata so the new root version bumps from it.
    let repo_dir = checkout_metadata(store.as_ref(), &destination, backend).await?;

    // Mint the successor, then publish a new root version co-signed by the retained standby
    // (which retires the old active key) and the successor.
    repo::generate_root_key(&args.new_key_out).await?;
    let retained = &keys.roots[1..];
    repo::rotate_root(
        repo_dir.path(),
        retained,
        &args.new_key_out,
        args.expiry_days,
    )
    .await?;
    let root_json = tokio::fs::read(repo_dir.path().join("metadata").join("root.json")).await?;
    updatec::runtime::publish_repository(store.as_ref(), &destination, repo_dir.path()).await?;

    eprintln!(
        "rotated root at s3://{}/{}; minted successor key at {}",
        backend.bucket,
        backend.prefix,
        args.new_key_out.display()
    );
    eprintln!(
        "in Vault: promote the standby (root.next.pk8) to active (root.pk8), then install {} \
         as the new root.next.pk8",
        args.new_key_out.display()
    );
    eprintln!("existing devices follow the new root automatically; no group changes needed");

    match &args.root_out {
        Some(path) => {
            tokio::fs::write(path, &root_json).await?;
            eprintln!("wrote new root.json to {}", path.display());
        }
        None if args.output == OutputFormat::Text => {
            use std::io::Write;
            std::io::stdout().write_all(&root_json)?;
        }
        None => {}
    }
    if args.output == OutputFormat::Json {
        let document = serde_json::json!({
            "bucket": backend.bucket,
            "prefix": backend.prefix,
            "newKeyOut": args.new_key_out,
            "root": String::from_utf8_lossy(&root_json),
        });
        println!("{}", serde_json::to_string(&document)?);
    }
    Ok(())
}

async fn deploy(args: DeployArgs) -> Result<(), Error> {
    let backend = &args.backend;
    semver::Version::parse(&args.version)
        .map_err(|error| format!("--version {:?} is not valid semver: {error}", args.version))?;
    let platform = args
        .platform
        .clone()
        .unwrap_or_else(|| format!("linux-{}", std::env::consts::ARCH));
    let (os, arch) = platform
        .split_once('-')
        .ok_or_else(|| format!("--platform must be <os>-<arch>, got {platform:?}"))?;

    let (destination, store) = build_store(backend)?;
    let store = store.as_ref();
    let keys = open_keys(&backend.keys_dir)?;

    // Confirm the group exists before doing any signing work.
    let client = Client::try_default().await?;
    let groups: Api<UpdateGroup> = Api::namespaced(client, &args.namespace);
    groups.get(&args.group).await.map_err(|error| {
        format!(
            "UpdateGroup {} not found in {}: {error}",
            args.group, args.namespace
        )
    })?;

    // Work in a throwaway temp dir: the repository checkout never outlives the process.
    let repo_dir = checkout_metadata(store, &destination, backend).await?;

    // Build the bundle into a scratch dir, then register it as a signed target.
    let build_dir = tempfile::tempdir()?;
    let archive = build_dir.path().join("bundle.tar.zst");
    build_bundle(
        &args.source,
        &archive,
        build_dir.path(),
        &args.product,
        &args.version,
        &platform,
        &args.entrypoint,
    )?;

    let mut target = PublishTarget::application(
        &args.product,
        &args.channel,
        &args.version,
        os,
        arch,
        &args.product,
        archive,
    );
    // Bind the provider set into this app version's signed metadata (clap guarantees both flags
    // are present together), so a later ordered-fallback descent rolls providers back with it.
    if let (Some(path), Some(sha256)) = (&args.provider_set_path, &args.provider_set_sha256) {
        // Validate the digest here, at publish time. It is signed into the app target's metadata
        // and only read much later, by an ordered-fallback descent on a node — where a typo'd or
        // truncated digest surfaces as "provider set unresolvable" during a recovery, the worst
        // moment to discover a publishing mistake.
        if !updated_contracts::is_sha256_hex(sha256) {
            return Err(format!(
                "--provider-set-sha256 {sha256:?} is not a 64-character hex SHA-256"
            )
            .into());
        }
        target = target.with_provider_set(path, sha256);
    }
    let target_name = target.name.clone();
    repo::add_release(repo_dir.path(), &keys, vec![target], args.expiry_days).await?;
    let sha256 = repo::target_sha256(repo_dir.path(), &target_name).await?;

    // Upload immutable target bytes first and re-signed metadata last (timestamp is the
    // commit point) — the operator's exact publication order.
    updatec::runtime::publish_repository(store, &destination, repo_dir.path()).await?;
    eprintln!("published signed target {target_name} (sha256 {sha256})");

    // Roll the group. A JSON merge patch touches only the application reference, leaving
    // the rest of the deployment spec intact; the operator republishes assignments.
    //
    // `emergencyCorrection` is written on EVERY deploy, true or false. A merge patch that omitted
    // it would leave a previous `true` in place, so a one-off emergency would silently keep every
    // later release of this group exempt from its set's rollout schedule.
    let patch = group_patch(&target_name, &sha256, args.emergency);
    groups
        .patch(&args.group, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;
    eprintln!(
        "rolled UpdateGroup {} in {} to {} {}",
        args.group, args.namespace, args.product, args.version
    );
    if args.emergency {
        eprintln!(
            "declared an emergency correction: this deployment is admitted without waiting for \
             the governing UpdateGroupSet's rollout schedule"
        );
    }

    report_deploy(&args, &platform, &target_name, &sha256)
}

/// The merge patch that rolls an `UpdateGroup` onto a freshly published target.
///
/// `emergencyCorrection` is always written, true or false. A merge patch that omitted it would
/// leave a previous `true` in place, so a one-off emergency would silently keep every later release
/// of this group exempt from its `UpdateGroupSet`'s rollout schedule.
fn group_patch(target: &str, sha256: &str, emergency: bool) -> serde_json::Value {
    serde_json::json!({
        "spec": {
            "deployment": { "application": { "path": target, "sha256": sha256 } },
            "emergencyCorrection": emergency,
        }
    })
}

/// Check out the release repository's current signed metadata into a throwaway temp dir, ready
/// for a new target to be added and republished. Shared by the provider publish commands.
async fn checkout_repository(
    backend: &Backend,
) -> Result<
    (
        S3Destination,
        Arc<dyn ObjectStore>,
        repo::Keys,
        tempfile::TempDir,
    ),
    Error,
> {
    let (destination, store) = build_store(backend)?;
    let keys = open_keys(&backend.keys_dir)?;
    let repo_dir = checkout_metadata(store.as_ref(), &destination, backend).await?;
    Ok((destination, store, keys, repo_dir))
}

/// Check out a repository's current TUF metadata into a throwaway temp dir: create `metadata/` and
/// `targets/`, download the metadata, and confirm the repository is initialized (has
/// `metadata/root.json`). The single definition of that checkout preamble — deploy, root rotation,
/// and the provider-publish path all go through it, so they cannot drift on the directory layout or
/// the uninitialized-repository guard.
async fn checkout_metadata(
    store: &dyn ObjectStore,
    destination: &S3Destination,
    backend: &Backend,
) -> Result<tempfile::TempDir, Error> {
    let repo_dir = tempfile::tempdir()?;
    let metadata_dir = repo_dir.path().join("metadata");
    tokio::fs::create_dir_all(&metadata_dir).await?;
    tokio::fs::create_dir_all(repo_dir.path().join("targets")).await?;
    download_metadata(store, destination, &metadata_dir).await?;
    if !metadata_dir.join("root.json").exists() {
        return Err(format!(
            "release repository at s3://{}/{} is not initialized (no metadata/root.json); run \
             `updatectl trust-root` first",
            backend.bucket, backend.prefix
        )
        .into());
    }
    Ok(repo_dir)
}

/// Publish a provider artifact bundle as a signed target, without rolling any group.
async fn publish_provider_artifact(args: ProviderArtifactArgs) -> Result<(), Error> {
    let backend = &args.backend;
    semver::Version::parse(&args.version)
        .map_err(|error| format!("--version {:?} is not valid semver: {error}", args.version))?;
    let platform = args
        .platform
        .clone()
        .unwrap_or_else(|| format!("linux-{}", std::env::consts::ARCH));
    let (os, arch) = platform
        .split_once('-')
        .ok_or_else(|| format!("--platform must be <os>-<arch>, got {platform:?}"))?;

    let (destination, store, keys, repo_dir) = checkout_repository(backend).await?;

    let build_dir = tempfile::tempdir()?;
    let archive = build_dir.path().join("bundle.tar.zst");
    build_bundle(
        &args.source,
        &archive,
        build_dir.path(),
        &args.product,
        &args.version,
        &platform,
        &args.entrypoint,
    )?;

    let target = PublishTarget::application(
        &args.product,
        &args.channel,
        &args.version,
        os,
        arch,
        &args.product,
        archive,
    );
    let target_name = target.name.clone();
    repo::add_release(repo_dir.path(), &keys, vec![target], args.expiry_days).await?;
    let sha256 = repo::target_sha256(repo_dir.path(), &target_name).await?;
    updatec::runtime::publish_repository(store.as_ref(), &destination, repo_dir.path()).await?;
    // stdout carries the machine-readable `path sha256` for the caller to reference; diagnostics
    // go to stderr.
    println!("{target_name} {sha256}");
    eprintln!("published provider artifact {target_name} (sha256 {sha256})");
    Ok(())
}

/// Publish an immutable provider set (`provider-sets/<id>.json`) as a signed target.
async fn publish_provider_set(args: ProviderSetArgs) -> Result<(), Error> {
    let backend = &args.backend;
    let reconciler = reconciler(
        &args.provider_path,
        &args.provider_sha256,
        &args.provider_arg,
        args.provider_timeout_ms,
    )?;
    let set = updated_contracts::artifact::ProviderSet {
        schema: 1,
        id: args.id.clone(),
        reconciler,
    };

    let (destination, store, keys, repo_dir) = checkout_repository(backend).await?;

    let build_dir = tempfile::tempdir()?;
    let source = build_dir.path().join("provider-set.json");
    tokio::fs::write(&source, serde_json::to_vec(&set)?).await?;
    let target_name = format!("provider-sets/{}.json", args.id);
    let target = PublishTarget {
        name: target_name.clone(),
        source,
        custom: Default::default(),
    };
    repo::add_release(repo_dir.path(), &keys, vec![target], args.expiry_days).await?;
    let sha256 = repo::target_sha256(repo_dir.path(), &target_name).await?;
    updatec::runtime::publish_repository(store.as_ref(), &destination, repo_dir.path()).await?;
    println!("{target_name} {sha256}");
    eprintln!("published provider set {target_name} (sha256 {sha256})");
    Ok(())
}

/// Build a signed node reconciler from a validated artifact reference.
fn reconciler(
    path: &str,
    sha256: &str,
    args: &[String],
    timeout_millis: u64,
) -> Result<updated_contracts::artifact::Reconciler, Error> {
    if !updated_contracts::is_sha256_hex(sha256) {
        return Err(format!("provider sha256 {sha256:?} must be 64 hexadecimal characters").into());
    }
    Ok(updated_contracts::artifact::Reconciler {
        artifact: updated_contracts::artifact::TargetReference {
            path: path.to_owned(),
            sha256: sha256.to_ascii_lowercase(),
        },
        args: args.to_vec(),
        timeout_millis,
    })
}

/// Emit the machine-readable deploy result: a clean stdout payload (text or JSON) plus,
/// under GitHub Actions, `target`/`sha256`/`version` step outputs for later steps.
fn report_deploy(
    args: &DeployArgs,
    platform: &str,
    target: &str,
    sha256: &str,
) -> Result<(), Error> {
    match args.output {
        OutputFormat::Text => {
            println!("target={target}");
            println!("sha256={sha256}");
        }
        OutputFormat::Json => {
            let document = serde_json::json!({
                "namespace": args.namespace,
                "group": args.group,
                "product": args.product,
                "channel": args.channel,
                "version": args.version,
                "platform": platform,
                "target": target,
                "sha256": sha256,
                "emergency": args.emergency,
            });
            println!("{}", serde_json::to_string(&document)?);
        }
    }
    emit_github_outputs(&[
        ("target", target),
        ("sha256", sha256),
        ("version", &args.version),
    ])
}

/// Append `key=value` lines to the file named by `$GITHUB_OUTPUT`, the idiomatic way a
/// GitHub Actions step exposes outputs. A no-op elsewhere. Values here are single-line.
fn emit_github_outputs(pairs: &[(&str, &str)]) -> Result<(), Error> {
    let Some(path) = std::env::var_os("GITHUB_OUTPUT") else {
        return Ok(());
    };
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    for (key, value) in pairs {
        writeln!(file, "{key}={value}")?;
    }
    Ok(())
}

/// Resolve the signing keys from a mounted directory. `deploy` signs only the online roles
/// (targets/snapshot/timestamp), so the root keys are deliberately **not** required here —
/// a release pipeline never needs the root private keys, only `trust-root`/`rotate-root` do.
fn open_keys(dir: &Path) -> Result<repo::Keys, Error> {
    for key in ONLINE_KEYS {
        let path = dir.join(key);
        if !path.exists() {
            return Err(format!("--keys-dir {} is missing {key}", dir.display()).into());
        }
    }
    Ok(repo::Keys::in_dir(dir))
}

/// Whether the release repository has already been initialized (its `metadata/root.json`
/// exists in S3).
/// The highest metadata version the live repository has published, across root, timestamp,
/// snapshot, and targets. Missing or unreadable documents count as zero: the point is a floor to
/// start above, and every document that IS present raises it.
async fn live_metadata_version(
    store: &dyn ObjectStore,
    destination: &S3Destination,
) -> Result<u64, Error> {
    let mut highest = 0;
    for name in [
        "root.json",
        "timestamp.json",
        "snapshot.json",
        "targets.json",
    ] {
        let key = ObjectPath::from(object_key(&destination.prefix, &format!("metadata/{name}")));
        let bytes = match store.get(&key).await {
            Ok(result) => result.bytes().await?,
            Err(object_store::Error::NotFound { .. }) => continue,
            Err(error) => return Err(error.into()),
        };
        let version = serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .and_then(|document| document.pointer("/signed/version")?.as_u64())
            .unwrap_or(0);
        highest = highest.max(version);
    }
    Ok(highest)
}

async fn repo_initialized(
    store: &dyn ObjectStore,
    destination: &S3Destination,
) -> Result<bool, Error> {
    let root = ObjectPath::from(object_key(&destination.prefix, "metadata/root.json"));
    match store.head(&root).await {
        Ok(_) => Ok(true),
        Err(object_store::Error::NotFound { .. }) => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Mirror every metadata object under `<prefix>/metadata/` into `metadata_dir` so the TUF
/// editor can load the current generation and bump from it.
async fn download_metadata(
    store: &dyn ObjectStore,
    destination: &S3Destination,
    metadata_dir: &Path,
) -> Result<(), Error> {
    let prefix = ObjectPath::from(object_key(&destination.prefix, "metadata"));
    let mut listing = store.list(Some(&prefix));
    while let Some(entry) = listing.next().await {
        let meta = entry?;
        let filename = meta
            .location
            .filename()
            .ok_or_else(|| format!("release metadata object {} has no name", meta.location))?;
        let payload = store.get(&meta.location).await?.bytes().await?;
        tokio::fs::write(metadata_dir.join(filename), &payload).await?;
    }
    Ok(())
}

/// Join a repository prefix and a sub-path into a normalized S3 key, dropping empties so a
/// bucket-root prefix does not produce a leading slash.
fn object_key(prefix: &str, rest: &str) -> String {
    [prefix.trim_matches('/'), rest]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

/// Build the deterministic application archive. A directory is bundled as-is; a single file
/// is wrapped into a fresh tree at `--entrypoint` (matching `server publish-app`). Both the
/// wrapping shorthand and the archive format live in `updated::bundle` so every publish front end
/// emits byte-identical trees.
#[allow(clippy::too_many_arguments)]
fn build_bundle(
    source: &Path,
    archive: &Path,
    scratch: &Path,
    product: &str,
    version: &str,
    platform: &str,
    entrypoint: &str,
) -> Result<(), Error> {
    let entrypoints = updated::bundle::Entrypoints { entrypoint };
    updated::bundle::create_bundle_from_source(
        source,
        archive,
        &scratch.join("tree"),
        product,
        version,
        platform,
        &entrypoints,
    )
    .map_err(|error| format!("building bundle: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;
    use updated_tuf::repo;

    fn scratch(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "updatectl-{label}-{}-{}",
            std::process::id(),
            updated::rand::token().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn destination(prefix: &str) -> S3Destination {
        S3Destination {
            bucket: "releases".into(),
            prefix: prefix.into(),
            region: "us-east-1".into(),
            credentials_secret_ref: None,
            endpoint: None,
        }
    }

    #[test]
    fn object_key_normalizes_prefix_and_drops_empties() {
        // Only prefixes `s3_store` actually accepts: it requires an already-normalized, non-empty,
        // confined prefix, so a `/p/` case here proved nothing about any reachable input — the
        // store rejects that shape long before a key is ever joined.
        assert_eq!(object_key("routing", "metadata"), "routing/metadata");
        assert_eq!(
            object_key("a/b", "metadata/root.json"),
            "a/b/metadata/root.json"
        );
        // An empty sub-path must not leave a trailing slash.
        assert_eq!(object_key("a/b", ""), "a/b");
    }

    /// An emergency override must be self-clearing. The deploy patch therefore states
    /// `emergencyCorrection` on every publish rather than only when it is set — a merge patch that
    /// omitted the field would leave a previous `true` in place, exempting every later release of
    /// the group from its set's rollout schedule forever.
    #[test]
    fn the_deploy_patch_always_states_whether_this_is_an_emergency_correction() {
        let ordinary = group_patch("products/app/stable/1.0.0/linux-x86_64/app", "ab", false);
        assert_eq!(
            ordinary["spec"]["emergencyCorrection"],
            serde_json::json!(false)
        );
        assert_eq!(
            ordinary["spec"]["deployment"]["application"]["path"],
            "products/app/stable/1.0.0/linux-x86_64/app"
        );
        let emergency = group_patch("products/app/stable/0.9.0/linux-x86_64/app", "cd", true);
        assert_eq!(
            emergency["spec"]["emergencyCorrection"],
            serde_json::json!(true)
        );
        // Nothing else in the deployment spec is touched by either patch.
        assert_eq!(
            ordinary["spec"]["deployment"].as_object().unwrap().len(),
            1,
            "the patch names only the application reference"
        );
    }

    #[tokio::test]
    async fn deploy_requires_the_online_keys_but_not_the_root_keys() {
        let dir = scratch("keys");
        for key in ["targets.pk8", "snapshot.pk8", "timestamp.pk8"] {
            std::fs::write(dir.join(key), b"x").unwrap();
        }
        // No root.pk8 present: deploy's key resolution must still succeed.
        assert!(open_keys(&dir).is_ok());
        std::fs::remove_file(dir.join("targets.pk8")).unwrap();
        assert!(open_keys(&dir).is_err(), "a missing online key is rejected");
    }

    /// Author a repo, publish it to an in-memory store, then run the CLI's own
    /// download → rotate → re-publish cycle and prove a client pinned to the original root
    /// follows the rotation — exercising `repo_initialized`, `download_metadata`, prefix
    /// handling, and `publish_repository` exactly as the binary uses them.
    #[tokio::test]
    async fn s3_round_trip_publishes_downloads_and_rotates() {
        let root = scratch("s3");
        let keys = repo::generate_keys(&root.join("keys")).await.unwrap();
        let origin = root.join("origin");
        repo::init(&origin, &keys, 365).await.unwrap();

        let store = InMemory::new();
        let dest = destination("releases/app");

        assert!(
            !repo_initialized(&store, &dest).await.unwrap(),
            "an empty store is not initialized"
        );
        updatec::runtime::publish_repository(&store, &dest, &origin)
            .await
            .unwrap();
        assert!(
            repo_initialized(&store, &dest).await.unwrap(),
            "publishing makes the store report initialized"
        );

        // Pull the metadata back down, as `rotate_root`/`deploy` do.
        let work = root.join("work");
        let work_metadata = work.join("metadata");
        tokio::fs::create_dir_all(&work_metadata).await.unwrap();
        tokio::fs::create_dir_all(work.join("targets"))
            .await
            .unwrap();
        download_metadata(&store, &dest, &work_metadata)
            .await
            .unwrap();
        let pinned = tokio::fs::read(work_metadata.join("1.root.json"))
            .await
            .unwrap();

        // Rotate against the downloaded copy, then re-publish it.
        let successor = root.join("successor.pk8");
        repo::generate_root_key(&successor).await.unwrap();
        repo::rotate_root(&work, &keys.roots[1..], &successor, 365)
            .await
            .unwrap();
        updatec::runtime::publish_repository(&store, &dest, &work)
            .await
            .unwrap();

        // Download once more into a clean dir and verify through the real client.
        let mirror = root.join("mirror");
        let mirror_metadata = mirror.join("metadata");
        tokio::fs::create_dir_all(&mirror_metadata).await.unwrap();
        tokio::fs::create_dir_all(mirror.join("targets"))
            .await
            .unwrap();
        download_metadata(&store, &dest, &mirror_metadata)
            .await
            .unwrap();

        let metadata_url =
            url::Url::from_directory_path(std::fs::canonicalize(&mirror_metadata).unwrap())
                .unwrap();
        let targets_url =
            url::Url::from_directory_path(std::fs::canonicalize(mirror.join("targets")).unwrap())
                .unwrap();
        let repo = tough::RepositoryLoader::new(&pinned, metadata_url, targets_url)
            .transport(tough::FilesystemTransport)
            .expiration_enforcement(tough::ExpirationEnforcement::Safe)
            .load()
            .await
            .expect("client pinned to the original root loads the round-tripped repository");
        assert_eq!(
            repo.root().signed.version.get(),
            2,
            "the rotation survived the S3 publish/download round-trip"
        );
    }
}
