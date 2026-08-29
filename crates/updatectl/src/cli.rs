//! The command line: every subcommand, its arguments, and the shared release-repository
//! backend they are all parameterised by.

use crate::*;

/// Mint trust roots and publish signed releases from CI, without kubectl.
#[derive(Parser, Debug)]
#[command(name = "updatectl", about, long_about = None, disable_version_flag = true)]
pub(crate) struct Cli {
    #[command(subcommand)]
    pub(crate) command: Command,
}

#[derive(Subcommand, Debug)]
pub(crate) enum Command {
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
    /// Check a release's node reconciler against the published protocol: replay tolerance,
    /// observation purity, fingerprint stability, and the two refusals. Runs the hook against a
    /// scratch install root; needs no repository, keys, or Kubernetes access.
    ReconcilerCheck(reconciler_check::ReconcilerCheckArgs),
    /// Sign and publish an immutable provider set (`provider-sets/<id>.json`) as a target,
    /// binding the required lifecycle provider artifact by path+sha256. This is the
    /// S3-native counterpart of `server publish-provider-set`.
    PublishProviderSet(ProviderSetArgs),
    /// Print the canonical public-key pin for an operator-provisioned node private key.
    NodePublicKey(NodePublicKeyArgs),
}

#[derive(Args, Debug)]
pub(crate) struct NodePublicKeyArgs {
    /// PEM-encoded P-256 node private key. The key is read locally and never written or uploaded.
    #[arg(long, env = "UPDATECTL_NODE_KEY")]
    pub(crate) key: PathBuf,
}

/// The release repository backend, shared by every subcommand. AWS credentials come from
/// the standard `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` environment.
#[derive(Args, Debug)]
pub(crate) struct Backend {
    /// Directory of ed25519 role keys. `deploy` needs only the online keys (`targets.pk8`,
    /// `snapshot.pk8`, `timestamp.pk8`) — in production a Vault-backed Secret mounted
    /// read-only. `trust-root`/`rotate-root` also use the root keys (`root.pk8` active plus
    /// `root.next.pk8` standby). `trust-root` mints freshly generated keys here and refuses a
    /// directory that already holds any role key — a fresh trust root never reuses one, and no
    /// key it did not mint itself is ever signed into it. A `trust-root` whose publish does not
    /// land writes nothing here, so retrying the bootstrap is the identical re-run.
    #[arg(long, env = "UPDATECTL_KEYS_DIR")]
    pub(crate) keys_dir: PathBuf,

    /// Release-repository S3 bucket.
    #[arg(long, env = "UPDATECTL_BUCKET")]
    pub(crate) bucket: String,

    /// Release-repository S3 region.
    #[arg(long, env = "UPDATECTL_REGION")]
    pub(crate) region: String,

    /// Key prefix within the bucket. Empty means the bucket root.
    #[arg(long, env = "UPDATECTL_PREFIX", default_value = "")]
    pub(crate) prefix: String,

    /// Optional S3 endpoint override (e.g. MinIO). Omit for real AWS.
    #[arg(long, env = "UPDATECTL_ENDPOINT")]
    pub(crate) endpoint: Option<String>,
}

#[derive(Args, Debug)]
pub(crate) struct TrustRootArgs {
    #[command(flatten)]
    pub(crate) backend: Backend,

    /// Days until the freshly signed root/targets/snapshot/timestamp metadata expires.
    #[arg(long, env = "UPDATECTL_EXPIRY_DAYS", default_value_t = 365)]
    pub(crate) expiry_days: i64,

    /// Write root.json here instead of stdout. Either way it is the value to paste into a
    /// group's `release_repository.root_json`.
    #[arg(long, env = "UPDATECTL_ROOT_OUT")]
    pub(crate) root_out: Option<PathBuf>,

    /// Re-initialize an already-initialized repository. This invalidates everything signed
    /// under the old root — used deliberately.
    #[arg(long)]
    pub(crate) force: bool,

    #[arg(long, value_enum, env = "UPDATECTL_OUTPUT", default_value_t = OutputFormat::Text)]
    pub(crate) output: OutputFormat,
}

#[derive(Args, Debug)]
pub(crate) struct RotateRootArgs {
    #[command(flatten)]
    pub(crate) backend: Backend,

    /// Where the freshly minted successor root key is written (mode 0600), once the rotation has
    /// published. Load it into Vault as the new standby after rotation. Must not already exist —
    /// an attempt whose publish does not land writes nothing here, so retrying the ceremony is
    /// the identical re-run.
    #[arg(long, env = "UPDATECTL_NEW_KEY_OUT")]
    pub(crate) new_key_out: PathBuf,

    /// Days until the new root metadata expires.
    #[arg(long, env = "UPDATECTL_EXPIRY_DAYS", default_value_t = 365)]
    pub(crate) expiry_days: i64,

    /// Write the new root.json here instead of stdout (the anchor for new enrollments).
    #[arg(long, env = "UPDATECTL_ROOT_OUT")]
    pub(crate) root_out: Option<PathBuf>,

    #[arg(long, value_enum, env = "UPDATECTL_OUTPUT", default_value_t = OutputFormat::Text)]
    pub(crate) output: OutputFormat,
}

#[derive(Args, Debug)]
pub(crate) struct DeployArgs {
    #[command(flatten)]
    pub(crate) backend: Backend,

    /// Namespace holding the UpdateGroup.
    #[arg(long, env = "UPDATECTL_NAMESPACE", default_value = "updated-system")]
    pub(crate) namespace: String,

    /// UpdateGroup to roll onto the new bundle (its `spec.deployment.application`).
    #[arg(long, env = "UPDATECTL_GROUP")]
    pub(crate) group: String,

    /// Product name; also the bundle target's component segment.
    #[arg(long, env = "UPDATECTL_PRODUCT")]
    pub(crate) product: String,

    /// Release channel.
    #[arg(long, env = "UPDATECTL_CHANNEL", default_value = "stable")]
    pub(crate) channel: String,

    /// Semantic version of this release.
    #[arg(long, env = "UPDATECTL_VERSION")]
    pub(crate) version: String,

    /// Bundle-relative path of the launched executable (e.g. `bin/app`).
    #[arg(long, env = "UPDATECTL_ENTRYPOINT")]
    pub(crate) entrypoint: String,

    /// Source to publish: a prepared directory tree, or a single executable file that is
    /// wrapped into a one-file bundle at `--entrypoint`.
    #[arg(long, env = "UPDATECTL_SOURCE")]
    pub(crate) source: PathBuf,

    /// Target platform `<os>-<arch>`. Defaults to the host's `linux-<arch>`.
    #[arg(long, env = "UPDATECTL_PLATFORM")]
    pub(crate) platform: Option<String>,

    /// Target path of the provider set this release ships with. When set (together with
    /// `--provider-set-sha256`), it is signed into the app target's custom metadata, so an
    /// cold-install-fallback descent to this version re-selects exactly these providers — app and
    /// providers roll back as one unit. Omit to leave provider selection to the assignment head.
    #[arg(
        long,
        env = "UPDATECTL_PROVIDER_SET_PATH",
        requires = "provider_set_sha256"
    )]
    pub(crate) provider_set_path: Option<String>,

    /// sha256 of the provider set named by `--provider-set-path`.
    #[arg(
        long,
        env = "UPDATECTL_PROVIDER_SET_SHA256",
        requires = "provider_set_path",
        value_parser = canonical_sha256
    )]
    pub(crate) provider_set_sha256: Option<String>,

    /// Days until the re-signed TUF metadata expires.
    #[arg(long, env = "UPDATECTL_EXPIRY_DAYS", default_value_t = 365)]
    pub(crate) expiry_days: i64,

    /// Declare this publish an EMERGENCY CORRECTION: the operator admits it immediately, without
    /// waiting for the governing `UpdateGroupSet`'s rollout schedule. Nothing else is bypassed —
    /// concurrency slots, `maxUnavailable` staging, inputs, and prerequisites all still apply.
    ///
    /// Use it to escape a release the fleet cannot report on at all (one that bricks the agent),
    /// which is precisely the case no health signal could ever detect. The flag is written into
    /// `spec.emergencyCorrection` on every deploy, set or cleared, so an ordinary deploy of this
    /// group afterwards turns it back off — an override can never be silently permanent.
    #[arg(long, env = "UPDATECTL_EMERGENCY")]
    pub(crate) emergency: bool,

    /// Result format written to stdout. Diagnostics always go to stderr, so `json` yields a
    /// single clean object a pipeline can capture and parse.
    #[arg(long, value_enum, env = "UPDATECTL_OUTPUT", default_value_t = OutputFormat::Text)]
    pub(crate) output: OutputFormat,
}

#[derive(Args, Debug)]
pub(crate) struct ProviderArtifactArgs {
    #[command(flatten)]
    pub(crate) backend: Backend,

    /// Product name; also the bundle target's component segment. The published target is
    /// `products/<product>/<channel>/<version>/<platform>/<product>`.
    #[arg(long, env = "UPDATECTL_PRODUCT")]
    pub(crate) product: String,

    /// Release channel.
    #[arg(long, env = "UPDATECTL_CHANNEL", default_value = "stable")]
    pub(crate) channel: String,

    /// Semantic version of this provider artifact.
    #[arg(long, env = "UPDATECTL_VERSION")]
    pub(crate) version: String,

    /// Bundle-relative path of the provider executable (e.g. `bin/lifecycle`).
    #[arg(long, env = "UPDATECTL_ENTRYPOINT")]
    pub(crate) entrypoint: String,

    /// Source to publish: a prepared directory tree, or a single executable file that is
    /// wrapped into a one-file bundle at `--entrypoint`.
    #[arg(long, env = "UPDATECTL_SOURCE")]
    pub(crate) source: PathBuf,

    /// Target platform `<os>-<arch>`. Defaults to the host's `linux-<arch>`.
    #[arg(long, env = "UPDATECTL_PLATFORM")]
    pub(crate) platform: Option<String>,

    /// Days until the re-signed TUF metadata expires.
    #[arg(long, env = "UPDATECTL_EXPIRY_DAYS", default_value_t = 365)]
    pub(crate) expiry_days: i64,
}

#[derive(Args, Debug)]
pub(crate) struct ProviderSetArgs {
    #[command(flatten)]
    pub(crate) backend: Backend,

    /// Provider set id; the published target is `provider-sets/<id>.json`.
    #[arg(long, env = "UPDATECTL_PROVIDER_SET_ID")]
    pub(crate) id: String,

    /// Lifecycle provider artifact target path (from `publish-provider-artifact`).
    #[arg(long)]
    pub(crate) provider_path: String,

    /// sha256 of the lifecycle provider artifact.
    #[arg(long, value_parser = canonical_sha256)]
    pub(crate) provider_sha256: String,

    /// Extra argument passed to the lifecycle provider (repeatable).
    #[arg(long)]
    pub(crate) provider_arg: Vec<String>,

    /// Lifecycle provider timeout, milliseconds.
    #[arg(long, default_value_t = 300_000)]
    pub(crate) provider_timeout_ms: u64,

    /// Days until the re-signed TUF metadata expires.
    #[arg(long, env = "UPDATECTL_EXPIRY_DAYS", default_value_t = 365)]
    pub(crate) expiry_days: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum OutputFormat {
    Text,
    Json,
}

/// Refuse a non-canonical digest where the operator typed it, through the same grammar the wire
/// format and the object store use. `clap` names the offending flag, so the message says only what
/// was wrong with the value.
fn canonical_sha256(value: &str) -> Result<String, String> {
    updated_contracts::digest::parse_canonical_sha256(value)
}
