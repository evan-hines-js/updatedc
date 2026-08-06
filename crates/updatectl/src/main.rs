//! `updatectl` — the CI-facing publisher for `updated`.
//!
//! Two subcommands, no `kubectl` and no secret-management code of its own:
//!
//! * `trust-root` mints a fresh TUF trust root — a one-time bootstrap. It generates the
//!   ed25519 role keys into an empty directory (which the operator loads into Vault) and
//!   refuses one that already holds a role key, so a new root never inherits an old key,
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

/// Every role key a trust root is built from: the active root, its standby successor, and the
/// three online roles. `trust-root` mints all five and must find none of them already present.
const ROLE_KEYS: [&str; 5] = [
    "root.pk8",
    "root.next.pk8",
    "targets.pk8",
    "snapshot.pk8",
    "timestamp.pk8",
];

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
    /// `root.next.pk8` standby). `trust-root` mints freshly generated keys here and refuses a
    /// directory that already holds any role key — a fresh trust root never reuses one.
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

    /// Where the freshly minted successor root key is written (mode 0600), once the rotation has
    /// published. Load it into Vault as the new standby after rotation. Must not already exist —
    /// an attempt whose publish does not land writes nothing here, so retrying the ceremony is
    /// the identical re-run.
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
    // Before anything is minted, signed, or uploaded: a fresh trust root is only fresh if every
    // one of its keys is. `repo::generate_keys` is idempotent, so a directory that still holds an
    // old key silently pins that key into the new root.
    ensure_keys_dir_is_empty(&backend.keys_dir)?;
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
        let next = RoleVersions::live(store.as_ref(), &destination)
            .await?
            .highest()
            + 1;
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
    eprintln!("minted fresh role keys in {}", backend.keys_dir.display());
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

    // Nothing is minted, signed or uploaded until the destination for the successor key is known
    // to be free: the key that ends up at --new-key-out must be one this ceremony minted.
    ensure_new_key_out_is_free(&args.new_key_out)?;
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
    let checkout = checkout_metadata(store.as_ref(), &destination, backend).await?;

    // Mint the successor into a private staging file, then publish a new root version co-signed by
    // the retained standby (which retires the old active key) and the successor. The staged key
    // only moves to --new-key-out after the publish lands; an attempt that fails removes it, so
    // the retry is a plain re-run that mints again.
    let pending = PendingRootKey::mint(&args.new_key_out).await?;
    let retained = &keys.roots[1..];
    repo::rotate_root(checkout.path(), retained, pending.path(), args.expiry_days).await?;
    let root_json = tokio::fs::read(checkout.path().join("metadata").join("root.json")).await?;
    checkout.publish(store.as_ref(), &destination).await?;
    pending.commit()?;

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
    let checkout = checkout_metadata(store, &destination, backend).await?;

    // Resolve the provider set against the metadata in hand, before any bundle is built.
    let provider_set = resolve_provider_set(
        &checkout,
        args.provider_set_path.as_deref(),
        args.provider_set_sha256.as_deref(),
    )
    .await?;

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
    // Bind the resolved provider set into this app version's signed metadata, so a later
    // ordered-fallback descent rolls providers back with it.
    if let Some((path, sha256)) = &provider_set {
        target = target.with_provider_set(path, sha256);
    }
    let target_name = target.name.clone();
    repo::add_release(checkout.path(), &keys, vec![target], args.expiry_days).await?;
    let sha256 = repo::target_sha256(checkout.path(), &target_name).await?;

    // Upload immutable target bytes first and re-signed metadata last (timestamp is the
    // commit point) — the operator's exact publication order. The group patch below references
    // this generation, so a concurrent publisher must abort the upload rather than drop it.
    checkout.publish(store, &destination).await?;
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

/// Resolve `--provider-set-path`/`--provider-set-sha256` against the signed metadata this publish
/// already holds, returning the normalized reference to sign into the app target.
///
/// The reference is signed into the app version's custom metadata and then read exactly once,
/// much later: when an ordered-fallback descent picks this version on a node, `stage_providers`
/// calls `exact_target` on it. A well-formed but unresolvable reference — a stale copy-paste of a
/// previous set's path against the new set's digest, or a set published under a different prefix —
/// is accepted by every syntactic check and only fails there, leaving the node unable to complete
/// the rollback it is in the middle of. The checkout in hand is the same signed targets metadata
/// the node will verify against, so resolving it here turns that into a publish-time refusal with
/// nothing signed or uploaded. Digest comparison is case-insensitive and the lowercase form is
/// what gets signed, matching the hex every agent compares against.
async fn resolve_provider_set(
    checkout: &Checkout,
    path: Option<&str>,
    sha256: Option<&str>,
) -> Result<Option<(String, String)>, Error> {
    // clap's `requires` makes the flags all-or-nothing.
    let (Some(path), Some(sha256)) = (path, sha256) else {
        return Ok(None);
    };
    if !updated_contracts::is_sha256_hex(sha256) {
        return Err(
            format!("--provider-set-sha256 {sha256:?} is not a 64-character hex SHA-256").into(),
        );
    }
    let sha256 = sha256.to_ascii_lowercase();
    let signed = repo::target_sha256(checkout.path(), path)
        .await
        .map_err(|error| {
            format!(
            "--provider-set-path {path:?} does not resolve in this repository's signed metadata: \
             {error}. Publish the provider set with `publish-provider-set` against this same \
             bucket and prefix first, and pass the path it prints. Nothing was signed or uploaded."
        )
        })?;
    if signed != sha256 {
        return Err(format!(
            "--provider-set-sha256 {sha256} does not match the signed digest of \
             --provider-set-path {path:?}, which is {signed}: the two flags name different \
             provider sets. Nothing was signed or uploaded."
        )
        .into());
    }
    Ok(Some((path.to_string(), sha256)))
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
) -> Result<(S3Destination, Arc<dyn ObjectStore>, repo::Keys, Checkout), Error> {
    let (destination, store) = build_store(backend)?;
    let keys = open_keys(&backend.keys_dir)?;
    let checkout = checkout_metadata(store.as_ref(), &destination, backend).await?;
    Ok((destination, store, keys, checkout))
}

/// One checked-out generation of a release repository's signed metadata, plus the per-role
/// versions it was taken at.
///
/// Publishing is read-modify-write over shared S3 metadata: the checkout carries generation N,
/// `repo::add_release` signs N+1 locally, and the upload overwrites `N+1.targets.json`,
/// `N+1.snapshot.json`, and `timestamp.json` unconditionally. Two publishers against one prefix
/// therefore each sign an N+1 that omits the other's targets, and the loser's freshly patched
/// UpdateGroup points at a target that is no longer in verified metadata — every node in that
/// group stalls on "desired target absent from verified metadata" until someone republishes.
/// A single publisher per lineage is the documented model, so the recorded generation is not a
/// lock; it is the check that makes the unsupported case abort loudly with nothing uploaded
/// instead of silently dropping another publisher's signed targets.
struct Checkout {
    dir: tempfile::TempDir,
    generation: RoleVersions,
}

impl Checkout {
    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Publish the edited checkout, refusing to overwrite a generation this process never saw.
    async fn publish(
        &self,
        store: &dyn ObjectStore,
        destination: &S3Destination,
    ) -> Result<(), Error> {
        let live = RoleVersions::live(store, destination).await?;
        if let Some(moved) = live.moved_since(&self.generation) {
            return Err(format!(
                "release repository at s3://{}/{} moved {moved} while this publish was building \
                 and signing: another publisher is writing the same prefix. Nothing was uploaded \
                 — re-run this command once that publish has settled, and publish one release \
                 lineage from one place.",
                destination.bucket, destination.prefix
            )
            .into());
        }
        updatec::runtime::publish_repository(store, destination, self.path()).await?;
        Ok(())
    }
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
) -> Result<Checkout, Error> {
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
    // Record the generation these bytes are, not the one the store holds a moment later: the
    // republish compares against exactly what this checkout was built from.
    let generation = RoleVersions::checkout(&metadata_dir).await?;
    Ok(Checkout {
        dir: repo_dir,
        generation,
    })
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

    let (destination, store, keys, checkout) = checkout_repository(backend).await?;

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
    repo::add_release(checkout.path(), &keys, vec![target], args.expiry_days).await?;
    let sha256 = repo::target_sha256(checkout.path(), &target_name).await?;
    checkout.publish(store.as_ref(), &destination).await?;
    // stdout carries the machine-readable `path sha256` for the caller to reference; diagnostics
    // go to stderr.
    println!("{target_name} {sha256}");
    eprintln!("published provider artifact {target_name} (sha256 {sha256})");
    Ok(())
}

/// Publish an immutable provider set (`provider-sets/<id>.json`) as a signed target.
async fn publish_provider_set(args: ProviderSetArgs) -> Result<(), Error> {
    let backend = &args.backend;
    let set = provider_set(&args)?;

    let (destination, store, keys, checkout) = checkout_repository(backend).await?;

    let build_dir = tempfile::tempdir()?;
    let source = build_dir.path().join("provider-set.json");
    tokio::fs::write(&source, serde_json::to_vec(&set)?).await?;
    let target_name = format!("provider-sets/{}.json", set.id);
    let target = PublishTarget {
        name: target_name.clone(),
        source,
        custom: Default::default(),
    };
    repo::add_release(checkout.path(), &keys, vec![target], args.expiry_days).await?;
    let sha256 = repo::target_sha256(checkout.path(), &target_name).await?;
    checkout.publish(store.as_ref(), &destination).await?;
    println!("{target_name} {sha256}");
    eprintln!("published provider set {target_name} (sha256 {sha256})");
    Ok(())
}

/// Build the provider-set document this command will sign, and hold it to exactly the rule every
/// agent applies.
///
/// A published set is an immutable signed target: a document that fails `ProviderSet::validate`
/// (a zero or over-long timeout, an id the grammar rejects, an unconfined provider path, too many
/// arguments) is accepted by no node in the fleet, and the only remedy is publishing a corrected
/// id. So the same `validate` the agent runs at staging time runs here, before any signing or
/// upload, rather than a weaker digest-only approximation of it.
fn provider_set(args: &ProviderSetArgs) -> Result<updated_contracts::artifact::ProviderSet, Error> {
    let set = updated_contracts::artifact::ProviderSet {
        schema: updated_contracts::artifact::ProviderSet::SCHEMA,
        id: args.id.clone(),
        reconciler: updated_contracts::artifact::Reconciler {
            artifact: updated_contracts::artifact::TargetReference {
                path: args.provider_path.clone(),
                sha256: args.provider_sha256.to_ascii_lowercase(),
            },
            args: args.provider_arg.clone(),
            timeout_millis: args.provider_timeout_ms,
        },
    };
    set.validate().map_err(|error| {
        format!(
            "refusing to publish provider set {:?}: {error} (nothing was signed or uploaded)",
            args.id
        )
    })?;
    Ok(set)
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

/// Refuse a `--keys-dir` that already holds any role key.
///
/// `repo::generate_keys` mints only what is missing — deliberately, so `keygen` can top up a
/// directory. `trust-root` is the opposite promise: it mints a *fresh* trust root, and the
/// operator who runs it after a key disclosure is running it precisely to retire the exposed key.
/// Reusing a leftover file there would pin the compromised key into the new root and report
/// success, so the reuse is refused outright rather than made a flag: minting into a clean
/// directory is the only way to get a root whose keys are all new, and `--force` is about
/// replacing the published *repository*, never about overwriting private keys in place.
fn ensure_keys_dir_is_empty(dir: &Path) -> Result<(), Error> {
    let present: Vec<&str> = ROLE_KEYS
        .into_iter()
        .filter(|key| dir.join(key).exists())
        .collect();
    if present.is_empty() {
        return Ok(());
    }
    Err(format!(
        "--keys-dir {} already holds role keys ({}); `trust-root` mints a fresh trust root and \
         will not reuse an existing key — a root minted over a disclosed key would still be \
         signed by it. Point --keys-dir at an empty directory (move the old keys aside if they \
         are still needed to serve the current repository). Nothing was minted, signed, or \
         uploaded.",
        dir.display(),
        present.join(", ")
    )
    .into())
}

/// `--new-key-out` must name a path that does not exist. Whatever ends up there becomes a root
/// key at threshold 1 for the whole fleet, so it has to be a key this ceremony minted — a file
/// found at the path is of unknown provenance (planted by another local principal on a shared
/// runner, or a stale copy of an online role key) and is never adopted, whatever its mode.
fn ensure_new_key_out_is_free(path: &Path) -> Result<(), Error> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!("inspecting --new-key-out {}: {error}", path.display()).into()),
        Ok(_) => Err(format!(
            "--new-key-out {} already exists; `rotate-root` signs the key at this path into the \
             new root at threshold 1 and will only ever do that for a key it minted itself, so a \
             pre-existing file is refused rather than adopted. A rotation whose publish did not \
             land writes nothing here — retry the identical command. If this is a successor key \
             from a completed rotation, point --new-key-out at a fresh path. Nothing was minted, \
             signed, or uploaded.",
            path.display()
        )
        .into()),
    }
}

/// The successor root key, minted into a private staging file next to `--new-key-out` and moved
/// there only once the rotated root has been published.
///
/// This is what makes the ceremony — the one that answers a suspected root-key disclosure —
/// retryable without trusting a file on disk. The rotation is mint-then-publish and the publish
/// is allowed to fail for routine reasons (the generation guard aborts when another publisher
/// moved the prefix; S3 has transients). Such a failure uploads nothing, so the root is *not*
/// rotated, and dropping this guard removes the staged key: `--new-key-out` is still free and the
/// identical re-run mints a fresh successor and completes the ceremony. The operator never has to
/// hand-delete private key material, and no path exists by which a key the ceremony did not mint
/// reaches the new root.
struct PendingRootKey {
    staged: PathBuf,
    destination: PathBuf,
    committed: bool,
}

impl PendingRootKey {
    /// Mint a fresh ed25519 key into a staging file. `repo::generate_root_key` creates it
    /// exclusively at mode 0600, so a name another principal pre-planted is a hard error here
    /// rather than an adoption.
    async fn mint(destination: &Path) -> Result<Self, Error> {
        let stem = destination
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| "root-successor".to_string());
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_nanos())
            .unwrap_or_default();
        let staged =
            destination.with_file_name(format!(".{stem}.pending.{}.{nonce}", std::process::id()));
        repo::generate_root_key(&staged).await?;
        Ok(Self {
            staged,
            destination: destination.to_path_buf(),
            committed: false,
        })
    }

    fn path(&self) -> &Path {
        &self.staged
    }

    /// Move the staged key to `--new-key-out`. Called only after the rotated root is published,
    /// at which point the key must be delivered to the operator: if the destination was taken
    /// since the pre-flight check, the staged file is kept and named rather than clobbered or
    /// deleted.
    fn commit(mut self) -> Result<(), Error> {
        self.committed = true;
        ensure_new_key_out_is_free(&self.destination).map_err(|error| {
            format!(
                "{error}\nThe root WAS rotated and published. The successor key is at {} — move \
                 it somewhere safe and load it into Vault as the new standby.",
                self.staged.display()
            )
        })?;
        std::fs::rename(&self.staged, &self.destination).map_err(|error| {
            format!(
                "the root was rotated and published, but moving the successor key to {}: {error}. \
                 The key is at {} — move it somewhere safe and load it into Vault as the new \
                 standby.",
                self.destination.display(),
                self.staged.display()
            )
        })?;
        Ok(())
    }
}

impl Drop for PendingRootKey {
    fn drop(&mut self) {
        if !self.committed {
            let _ = std::fs::remove_file(&self.staged);
        }
    }
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

/// The four top-level TUF roles, the documents whose versions a publish bumps.
const TOP_LEVEL_METADATA: [&str; 4] = [
    "root.json",
    "timestamp.json",
    "snapshot.json",
    "targets.json",
];

/// The version each top-level TUF role currently declares, held per role rather than collapsed
/// into one number.
///
/// A single maximum cannot serve as the concurrent-publish measure: the roles advance
/// independently. `repo::publish_release` bumps targets/snapshot/timestamp and leaves root alone,
/// while `repo::rotate_root` and `repo::renew_root` bump only root — and under
/// `consistent_snapshot` (what `repo::init_from_version` writes) only `root.json` and
/// `timestamp.json` exist at unversioned names, so a maximum reduces to `max(root, timestamp)`.
/// One root rotation therefore parks the maximum above the timestamp and masks the next
/// publisher's commit entirely. Comparing role by role means every publish path advances a role
/// the guard is watching.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct RoleVersions([u64; TOP_LEVEL_METADATA.len()]);

impl RoleVersions {
    /// Read the live repository's role versions from S3. Missing or unreadable documents count
    /// as zero — the guard only cares that a role's version is the one this process saw.
    async fn live(store: &dyn ObjectStore, destination: &S3Destination) -> Result<Self, Error> {
        let mut versions = Self::default();
        for (slot, name) in TOP_LEVEL_METADATA.iter().enumerate() {
            let key =
                ObjectPath::from(object_key(&destination.prefix, &format!("metadata/{name}")));
            let bytes = match store.get(&key).await {
                Ok(result) => result.bytes().await?,
                Err(object_store::Error::NotFound { .. }) => continue,
                Err(error) => return Err(error.into()),
            };
            versions.0[slot] = document_version(&bytes);
        }
        Ok(versions)
    }

    /// The same measure taken over a local checkout's downloaded copies, so a checkout is
    /// compared against exactly the bytes it was built from.
    async fn checkout(metadata_dir: &Path) -> Result<Self, Error> {
        let mut versions = Self::default();
        for (slot, name) in TOP_LEVEL_METADATA.iter().enumerate() {
            match tokio::fs::read(metadata_dir.join(name)).await {
                Ok(bytes) => versions.0[slot] = document_version(&bytes),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Ok(versions)
    }

    /// The highest version any role has published — the floor a replacement repository must
    /// start above, because a TUF client refuses any role document below the version it last
    /// accepted for that role.
    fn highest(&self) -> u64 {
        self.0.iter().copied().max().unwrap_or(0)
    }

    /// The first role whose version differs from `base`, described for an operator, or `None`
    /// when every role still stands where `base` saw it.
    fn moved_since(&self, base: &Self) -> Option<String> {
        TOP_LEVEL_METADATA
            .iter()
            .enumerate()
            .find(|(slot, _)| self.0[*slot] != base.0[*slot])
            .map(|(slot, name)| format!("{name} from version {} to {}", base.0[slot], self.0[slot]))
    }
}

/// The version a signed TUF document declares; zero when it is unreadable.
fn document_version(bytes: &[u8]) -> u64 {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()
        .and_then(|document| document.pointer("/signed/version")?.as_u64())
        .unwrap_or(0)
}

/// Whether the release repository has already been initialized (its `metadata/root.json`
/// exists in S3).
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

    /// The same backend the CLI flags produce. `checkout_metadata` reads it only to name the
    /// repository in its diagnostics.
    fn backend(prefix: &str) -> Backend {
        Backend {
            keys_dir: PathBuf::new(),
            bucket: "releases".into(),
            region: "us-east-1".into(),
            prefix: prefix.into(),
            endpoint: None,
        }
    }

    fn provider_set_args() -> ProviderSetArgs {
        ProviderSetArgs {
            backend: backend("releases/app"),
            id: "web-linux-v4".into(),
            provider_path: "providers/lifecycle/1.0.0/linux-x86_64/lifecycle".into(),
            provider_sha256: "A".repeat(64),
            provider_arg: Vec::new(),
            provider_timeout_ms: 300_000,
            expiry_days: 365,
        }
    }

    /// A published provider set is an immutable signed target. Every flag combination the agent's
    /// own `validate` rejects must be refused here, before signing — a set that no node can accept
    /// cannot be repaired, only superseded under a new id.
    #[test]
    fn a_provider_set_is_held_to_the_agents_validation_before_it_is_signed() {
        let set = provider_set(&provider_set_args()).unwrap();
        assert_eq!(
            set.reconciler.artifact.sha256,
            "a".repeat(64),
            "the digest is normalized to the lowercase hex every agent compares against"
        );

        let cases = [
            ("timeout", {
                let mut args = provider_set_args();
                args.provider_timeout_ms = 0;
                args
            }),
            ("id", {
                let mut args = provider_set_args();
                args.id = "web linux".into();
                args
            }),
            ("artifact reference", {
                let mut args = provider_set_args();
                args.provider_path = "../escape".into();
                args
            }),
            ("artifact reference", {
                let mut args = provider_set_args();
                args.provider_sha256 = "not-a-digest".into();
                args
            }),
            ("arguments", {
                let mut args = provider_set_args();
                args.provider_arg = vec!["--flag".into(); 257];
                args
            }),
        ];
        for (expected, args) in cases {
            let error = provider_set(&args)
                .err()
                .unwrap_or_else(|| panic!("{expected}: expected a rejection"))
                .to_string();
            assert!(error.contains(expected), "{error}");
            assert!(
                error.contains("nothing was signed"),
                "the operator is told the repository is untouched: {error}"
            );
        }
    }

    /// Publishing is read-modify-write over shared signed metadata: two publishers against one
    /// prefix each sign a generation N+1 that omits the other's targets, and the last upload wins
    /// — silently erasing a target that a freshly patched UpdateGroup already points at. A
    /// checkout must refuse to publish over a generation it never saw, uploading nothing.
    #[tokio::test]
    async fn a_republish_refuses_a_generation_it_did_not_check_out() {
        let root = scratch("concurrent");
        let keys = repo::generate_keys(&root.join("keys")).await.unwrap();
        let origin = root.join("origin");
        repo::init(&origin, &keys, 365).await.unwrap();

        let store = InMemory::new();
        let dest = destination("releases/app");
        let backend = backend("releases/app");
        updatec::runtime::publish_repository(&store, &dest, &origin)
            .await
            .unwrap();

        // Both publishers check out the same generation, as two CI jobs would.
        let ours = checkout_metadata(&store, &dest, &backend).await.unwrap();
        let theirs = checkout_metadata(&store, &dest, &backend).await.unwrap();
        assert_eq!(
            ours.generation,
            RoleVersions::live(&store, &dest).await.unwrap()
        );

        // The other publisher commits while we are still building and signing.
        let file = root.join("theirs.json");
        tokio::fs::write(&file, b"{}").await.unwrap();
        repo::add_release(
            theirs.path(),
            &keys,
            vec![PublishTarget {
                name: "provider-sets/theirs.json".into(),
                source: file,
                custom: Default::default(),
            }],
            365,
        )
        .await
        .unwrap();
        theirs.publish(&store, &dest).await.unwrap();
        let published = RoleVersions::live(&store, &dest).await.unwrap();
        assert_ne!(published, ours.generation);
        let published = published.highest();

        let error = ours
            .publish(&store, &dest)
            .await
            .expect_err("a stale checkout must not overwrite the live generation")
            .to_string();
        assert!(error.contains("another publisher"), "{error}");

        // The other publisher's generation is intact: nothing was uploaded over it.
        assert_eq!(
            RoleVersions::live(&store, &dest).await.unwrap().highest(),
            published
        );
        let mirror = root.join("mirror");
        tokio::fs::create_dir_all(&mirror).await.unwrap();
        download_metadata(&store, &dest, &mirror).await.unwrap();
        let targets = tokio::fs::read_to_string(mirror.join(format!("{published}.targets.json")))
            .await
            .unwrap();
        assert!(
            targets.contains("provider-sets/theirs.json"),
            "the concurrent publisher's signed target survived"
        );
    }

    /// The concurrent-publish guard must survive a root rotation. A rotation bumps root and
    /// nothing else, so any measure that collapses the roles into one maximum is parked above the
    /// timestamp — and every publish after it looks unchanged, letting a stale checkout overwrite
    /// a concurrent publisher's signed targets exactly as if there were no guard at all.
    #[tokio::test]
    async fn a_root_rotation_does_not_blind_the_concurrent_publish_guard() {
        let root = scratch("rotated-generation");
        let keys = repo::generate_keys(&root.join("keys")).await.unwrap();
        let origin = root.join("origin");
        repo::init(&origin, &keys, 365).await.unwrap();

        // Rotate the root once: root reaches version 2 while timestamp stays at 1.
        let successor = root.join("successor.pk8");
        repo::generate_root_key(&successor).await.unwrap();
        repo::rotate_root(&origin, &keys.roots[1..], &successor, 365)
            .await
            .unwrap();

        let store = InMemory::new();
        let dest = destination("releases/app");
        let backend = backend("releases/app");
        updatec::runtime::publish_repository(&store, &dest, &origin)
            .await
            .unwrap();

        let ours = checkout_metadata(&store, &dest, &backend).await.unwrap();
        let theirs = checkout_metadata(&store, &dest, &backend).await.unwrap();
        // The state the guard used to be blind to: root is ahead of every other role.
        assert!(
            ours.generation.0[0] > ours.generation.0[1],
            "root outranks timestamp after a rotation: {:?}",
            ours.generation
        );

        let file = root.join("theirs.json");
        tokio::fs::write(&file, b"{}").await.unwrap();
        repo::add_release(
            theirs.path(),
            &keys,
            vec![PublishTarget {
                name: "provider-sets/theirs.json".into(),
                source: file,
                custom: Default::default(),
            }],
            365,
        )
        .await
        .unwrap();
        theirs.publish(&store, &dest).await.unwrap();

        let error = ours
            .publish(&store, &dest)
            .await
            .expect_err("a stale checkout must abort even when root outranks timestamp")
            .to_string();
        assert!(error.contains("timestamp.json"), "{error}");
        assert!(error.contains("another publisher"), "{error}");

        // The concurrent publisher's target is still the one in verified metadata.
        let mirror = root.join("mirror");
        tokio::fs::create_dir_all(&mirror).await.unwrap();
        download_metadata(&store, &dest, &mirror).await.unwrap();
        // Under consistent_snapshot the targets role lives only at its versioned name.
        let mut survived = false;
        for entry in std::fs::read_dir(&mirror).unwrap() {
            let path = entry.unwrap().path();
            if path.to_string_lossy().ends_with(".targets.json") {
                survived |= std::fs::read_to_string(&path)
                    .unwrap()
                    .contains("provider-sets/theirs.json");
            }
        }
        assert!(
            survived,
            "the concurrent publisher's signed target survived"
        );
    }

    /// `trust-root` promises a *fresh* trust root, and an operator reaches for it after a key
    /// disclosure. `repo::generate_keys` is idempotent, so a directory still holding the exposed
    /// key would be reused and the new root signed by it — the command must refuse instead, before
    /// anything is minted, signed, or uploaded.
    #[test]
    fn trust_root_refuses_a_keys_dir_that_already_holds_a_role_key() {
        let dir = scratch("trust-root-keys");
        assert!(ensure_keys_dir_is_empty(&dir).is_ok(), "an empty dir mints");

        std::fs::write(dir.join("targets.pk8"), b"leaked").unwrap();
        let error = ensure_keys_dir_is_empty(&dir)
            .expect_err("a leftover role key must be refused, never silently reused")
            .to_string();
        assert!(error.contains("targets.pk8"), "{error}");
        assert!(error.contains("will not reuse"), "{error}");
        assert!(error.contains("Nothing was minted"), "{error}");

        // Every role key counts, including the standby root.
        std::fs::remove_file(dir.join("targets.pk8")).unwrap();
        std::fs::write(dir.join("root.next.pk8"), b"standby").unwrap();
        assert!(ensure_keys_dir_is_empty(&dir).is_err());
    }

    /// The provider set a release pins is signed into the app target and read exactly once —
    /// during an ordered-fallback descent on a node, mid-rollback. A well-formed but mismatched
    /// path/digest pair is therefore resolved against the checked-out signed metadata here, where
    /// the answer is already in hand, instead of stalling a node at recovery time.
    #[tokio::test]
    async fn deploy_resolves_the_pinned_provider_set_against_the_checked_out_metadata() {
        let root = scratch("provider-set-ref");
        let keys = repo::generate_keys(&root.join("keys")).await.unwrap();
        let origin = root.join("origin");
        repo::init(&origin, &keys, 365).await.unwrap();

        let store = InMemory::new();
        let dest = destination("releases/app");
        let backend = backend("releases/app");
        updatec::runtime::publish_repository(&store, &dest, &origin)
            .await
            .unwrap();

        // Publish one provider set, as `publish-provider-set` does.
        let published = checkout_metadata(&store, &dest, &backend).await.unwrap();
        let file = root.join("set.json");
        tokio::fs::write(&file, b"{}").await.unwrap();
        repo::add_release(
            published.path(),
            &keys,
            vec![PublishTarget {
                name: "provider-sets/web-v4.json".into(),
                source: file,
                custom: Default::default(),
            }],
            365,
        )
        .await
        .unwrap();
        let sha = repo::target_sha256(published.path(), "provider-sets/web-v4.json")
            .await
            .unwrap();
        published.publish(&store, &dest).await.unwrap();

        let checkout = checkout_metadata(&store, &dest, &backend).await.unwrap();
        assert_eq!(
            resolve_provider_set(&checkout, Some("provider-sets/web-v4.json"), Some(&sha))
                .await
                .unwrap(),
            Some(("provider-sets/web-v4.json".to_string(), sha.clone())),
            "the published set resolves and is signed in its lowercase form"
        );
        assert_eq!(
            resolve_provider_set(&checkout, None, None).await.unwrap(),
            None,
            "omitting the flags leaves provider selection to the assignment head"
        );
        assert_eq!(
            resolve_provider_set(
                &checkout,
                Some("provider-sets/web-v4.json"),
                Some(&sha.to_ascii_uppercase())
            )
            .await
            .unwrap()
            .unwrap()
            .1,
            sha,
            "digests compare case-insensitively and are normalized before signing"
        );

        // The stale copy-paste: a path that was never published, paired with a valid digest.
        let error = resolve_provider_set(&checkout, Some("provider-sets/web-v3.json"), Some(&sha))
            .await
            .expect_err("an unresolvable provider set path must not be signed")
            .to_string();
        assert!(error.contains("does not resolve"), "{error}");
        assert!(error.contains("Nothing was signed"), "{error}");

        // A real path against the wrong release's digest.
        let error = resolve_provider_set(
            &checkout,
            Some("provider-sets/web-v4.json"),
            Some(&"b".repeat(64)),
        )
        .await
        .expect_err("a digest that is not this target's must not be signed")
        .to_string();
        assert!(
            error.contains("does not match the signed digest"),
            "{error}"
        );

        let error =
            resolve_provider_set(&checkout, Some("provider-sets/web-v4.json"), Some("nope"))
                .await
                .expect_err("a malformed digest is still rejected")
                .to_string();
        assert!(error.contains("64-character hex"), "{error}");
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

    /// The root rotation is mint-then-publish and the publish is allowed to fail (generation
    /// guard, S3 transient), which uploads nothing and leaves the root unrotated. The identical
    /// re-run — the only thing an operator answering a key disclosure should have to do — must
    /// complete the ceremony, and the failed attempt must leave no key material behind for it to
    /// stumble over.
    #[tokio::test]
    async fn an_interrupted_root_rotation_leaves_no_key_and_is_completed_by_an_identical_re_run() {
        let root = scratch("rotate-retry");
        let keys = repo::generate_keys(&root.join("keys")).await.unwrap();
        let origin = root.join("origin");
        repo::init(&origin, &keys, 365).await.unwrap();
        let store = InMemory::new();
        let dest = destination("releases/app");
        updatec::runtime::publish_repository(&store, &dest, &origin)
            .await
            .unwrap();

        // Attempt one: the key is staged, then the publish fails and uploads nothing. Dropping
        // the guard — what the process exit does — removes the staged key.
        let successor = root.join("successor.pk8");
        ensure_new_key_out_is_free(&successor).unwrap();
        let staged = {
            let pending = PendingRootKey::mint(&successor).await.unwrap();
            pending.path().to_path_buf()
        };
        assert!(
            !staged.exists(),
            "the failed attempt removed its staged key"
        );
        assert!(
            !successor.exists(),
            "a rotation that did not publish writes nothing to --new-key-out"
        );

        // Attempt two: the same command, from the state attempt one left behind.
        ensure_new_key_out_is_free(&successor)
            .expect("the re-run is not blocked by the interrupted attempt");
        let work = root.join("work");
        let work_metadata = work.join("metadata");
        tokio::fs::create_dir_all(&work_metadata).await.unwrap();
        download_metadata(&store, &dest, &work_metadata)
            .await
            .unwrap();
        let pending = PendingRootKey::mint(&successor).await.unwrap();
        repo::rotate_root(&work, &keys.roots[1..], pending.path(), 365)
            .await
            .unwrap();
        updatec::runtime::publish_repository(&store, &dest, &work)
            .await
            .unwrap();
        pending.commit().unwrap();
        let published = store
            .get(&ObjectPath::from(object_key(
                &dest.prefix,
                "metadata/root.json",
            )))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(
            document_version(&published),
            2,
            "the retry published the rotated root"
        );
        assert!(
            successor.exists(),
            "the successor key is delivered once the rotation published"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&successor).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the delivered key stays private");
        }
    }

    /// Whatever sits at `--new-key-out` would be signed into the new root at threshold 1, so a
    /// file the ceremony did not mint is refused — a private-looking mode is not provenance, and
    /// nothing is signed or uploaded.
    #[tokio::test]
    async fn a_pre_existing_file_at_new_key_out_is_never_adopted_as_root_key_material() {
        let root = scratch("rotate-planted");

        // A key of the attacker's own making, at exactly the mode a minted key carries.
        let planted = root.join("planted.pk8");
        repo::generate_root_key(&planted).await.unwrap();
        let bytes = std::fs::read(&planted).unwrap();
        let error = ensure_new_key_out_is_free(&planted)
            .unwrap_err()
            .to_string();
        assert!(error.contains("already exists"), "{error}");
        assert_eq!(
            std::fs::read(&planted).unwrap(),
            bytes,
            "the refusal leaves the operator's path untouched"
        );

        // Nor a directory, nor a symlink pointing at key material elsewhere.
        let dir = root.join("dir.pk8");
        std::fs::create_dir(&dir).unwrap();
        assert!(ensure_new_key_out_is_free(&dir).is_err());
        #[cfg(unix)]
        {
            let link = root.join("link.pk8");
            std::os::unix::fs::symlink(&planted, &link).unwrap();
            assert!(
                ensure_new_key_out_is_free(&link).is_err(),
                "a symlink is refused without following it"
            );
        }
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
