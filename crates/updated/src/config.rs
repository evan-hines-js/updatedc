//! Runtime types materialized exclusively from a TUF-verified managed configuration.
//! The only node-local configuration is the URL-and-key enrollment bootstrap.

use std::path::{Path, PathBuf};
use std::time::Duration;

use updated_contracts::assignment::{ManagedRuntime, RuntimeMode, SecretReference};

/// Fully verified, materialized runtime configuration.
#[derive(Debug)]
pub struct Config {
    pub deployment: String,
    pub routing: Routing,
    pub application: Application,
    pub storage: Storage,
    pub timeouts: Timeouts,
}

/// Bootstrap trust for the small routing repository. `base_url` is the only
/// repository URL configured on a node; its `metadata/` and `targets/` children
/// contain a TUF repository whose verified assignment selects the release CDN.
#[derive(Debug, Clone)]
pub struct Routing {
    pub root: PathBuf,
    pub base_url: String,
    /// Exact TUF target to resolve (for example `assignments/agents/agent-123.json`).
    pub assignment: String,
    pub transport_timeout: Duration,
    /// The agent's mTLS identity for reaching the gateway — mandatory, never plaintext. The
    /// routing and release repositories are the same externally-exposed gateway, so both fetch
    /// under this identity.
    pub mtls: crate::tls::Identity,
}

impl Routing {
    /// Whether this routing repository is local (a `file:` URL or an absolute directory path)
    /// rather than a network gateway. See [`base_url_is_local`].
    pub fn is_local(&self) -> bool {
        base_url_is_local(&self.base_url)
    }
}

/// Whether a routing `base_url` names a local repository (a `file:` URL or an absolute directory
/// path) rather than a network gateway. The single definition of "local" — the offline-repair path,
/// the secrets manager, and enrollment all gate on it, and must agree: one deciding to reach the
/// network while another assumes offline would split the trust model.
pub fn base_url_is_local(base_url: &str) -> bool {
    base_url.starts_with("file:") || Path::new(base_url).is_absolute()
}

/// Fully resolved repository input. Values of this type are constructed only
/// after parsing a TUF-verified [`RepositoryAssignment`].
#[derive(Debug, Clone)]
pub struct RepositorySource {
    pub root: PathBuf,
    pub metadata_url: String,
    pub targets_url: String,
    pub metadata_limit: u64,
    pub target_limit: u64,
    pub transport_timeout: Duration,
    /// The agent's mTLS identity for this gateway fetch — mandatory, never plaintext.
    pub mtls: crate::tls::Identity,
}

pub trait MaterializeRuntime {
    /// The launch spec and probes derived from this runtime. The single construction path
    /// for [`Application`] — used both when the config is first materialized and when a
    /// running supervisor reconciles a control-plane reassignment (which may change the
    /// launch args or health checks independently of the release version).
    fn application(&self) -> Application;
    fn storage(&self) -> Storage;
    fn timeouts(&self) -> Timeouts;
    fn materialize(&self, deployment: &str, routing: Routing) -> Result<Config, String>;
}

impl MaterializeRuntime for ManagedRuntime {
    fn application(&self) -> Application {
        Application {
            mode: self.mode,
            product: self.product.clone(),
            channel: self.channel.clone(),
            install_root: self.install_root.clone(),
            args: self.args.clone(),
            secrets: self.secrets.clone(),
            inputs: self.inputs.clone(),
        }
    }

    /// The inactive-material retention bounds this runtime signs. Single construction path
    /// for [`Storage`], shared by materialization and steady-state reassignment.
    fn storage(&self) -> Storage {
        Storage {
            inactive_releases: self.storage.inactive_releases,
            inactive_providers: self.storage.inactive_providers,
            inactive_supervisors: self.storage.inactive_supervisors,
            inactive_bytes: self.storage.inactive_bytes,
            inactive_repository_caches: self.storage.inactive_repository_caches,
        }
    }

    /// The cadence and health-gate windows this runtime signs. Single construction path for
    /// [`Timeouts`], shared by materialization and steady-state reassignment.
    fn timeouts(&self) -> Timeouts {
        Timeouts {
            check_interval: Duration::from_secs(self.timeouts.check_interval_seconds),
            health_grace: Duration::from_secs(self.timeouts.health_grace_seconds),
            health_successes: self.timeouts.health_successes,
            health_interval: Duration::from_secs(self.timeouts.health_interval_seconds),
            retry_after: Duration::from_secs(self.timeouts.retry_after_seconds),
            refresh_retry: Duration::from_secs(self.timeouts.refresh_retry_seconds),
            confirmation_window: Duration::from_secs(self.timeouts.confirmation_window_seconds),
            supervisor_check_interval: Duration::from_secs(
                self.timeouts.supervisor_check_interval_seconds,
            ),
            // Carried through as-is; see [`Timeouts::drain_hold`] for what each value means.
            drain_hold: self.timeouts.drain_hold_seconds.map(Duration::from_secs),
        }
    }

    fn materialize(&self, deployment: &str, routing: Routing) -> Result<Config, String> {
        self.validate()?;
        // The release root is NOT materialized here. `TrustedRepository::assigned` writes the root
        // it actually pins, into the per-assignment datastore, from the assignment it just
        // verified. Writing a second copy from here — out of a config that may have come from an
        // unverified persisted file — produced a durable trust anchor nothing ever read.
        Ok(Config {
            deployment: deployment.to_owned(),
            routing,
            application: self.application(),
            storage: self.storage(),
            timeouts: self.timeouts(),
        })
    }
}

/// Bounds for inactive immutable material. Releases needed by installed state,
/// rollback state, or an active transaction are always protected regardless of these
/// limits; the limits apply only to disposable history.
#[derive(Debug, Clone)]
pub struct Storage {
    pub inactive_releases: usize,
    pub inactive_providers: usize,
    pub inactive_supervisors: usize,
    pub inactive_bytes: u64,
    pub inactive_repository_caches: usize,
}

impl Default for Storage {
    fn default() -> Self {
        Self {
            inactive_releases: 2,
            inactive_providers: 2,
            inactive_supervisors: 1,
            inactive_bytes: 1024 * 1024 * 1024,
            inactive_repository_caches: 2,
        }
    }
}

/// The program being kept current.
#[derive(Debug)]
pub struct Application {
    pub mode: RuntimeMode,
    pub product: String,
    pub channel: String,
    /// Root containing active-release, immutable versions, staging, and durable state.
    pub install_root: PathBuf,
    /// Arguments appended to the manifest-owned entrypoint.
    pub args: Vec<String>,
    pub secrets: Vec<SecretReference>,
    pub inputs: std::collections::BTreeMap<String, updated_contracts::telemetry::OutputValue>,
}

/// Every tunable duration in the system, in one place. Omit any (or the whole
/// `[timeouts]` table) to take the default.
#[derive(Debug, Clone)]
pub struct Timeouts {
    /// How often to check for an application update.
    pub check_interval: Duration,
    /// Window for the child to become healthy after a (re)start. With a startup or
    /// readiness health check
    /// this is how long a slow-starting app has to answer — set it to minutes if
    /// needed; a *crash* is still detected instantly (the process exits), so a long
    /// grace never slows crash detection.
    pub health_grace: Duration,
    /// Consecutive good health responses required to declare the app ready (a
    /// readiness `successThreshold`). Default 1 — the first good answer commits;
    /// raise it to require sustained health before trusting a new version.
    pub health_successes: u32,
    /// Spacing between those confirmation probes (a readiness `periodSeconds`), so
    /// `health_successes > 1` proves health over time, not a 100 ms burst. Ignored
    /// when `health_successes` is 1.
    pub health_interval: Duration,
    /// How often a health-check-failed release is retried (not permanently blocked).
    pub retry_after: Duration,
    /// Backoff base for retrying a transient metadata transport failure.
    pub refresh_retry: Duration,
    /// How long a just-committed update stays unconfirmed. A crash within it reverts the
    /// update (one strike); surviving it confirms the update and drops the rollback image.
    pub confirmation_window: Duration,
    /// How often to check for a supervisor release.
    pub supervisor_check_interval: Duration,
    /// Ceiling on the managed drain hold — how long to wait, after readiness is withdrawn, for the
    /// load balancer to drop this node before stopping the running release. `None` or
    /// `Some(Duration::ZERO)` = no hold (stop immediately); `Some(n)` = wait up to `n`. Never an
    /// indefinite wait. See [`ManagedTimeouts::drain_hold_seconds`].
    pub drain_hold: Option<Duration>,
}

impl Default for Timeouts {
    fn default() -> Self {
        Timeouts {
            check_interval: Duration::from_secs(15),
            // Forgiving enough for an app that takes a few seconds to bind; a *crash*
            // is still caught instantly (process exit), and the first good answer
            // returns immediately, so a longer window never slows a fast app. Raise it
            // for an app that legitimately takes tens of seconds or minutes to start.
            health_grace: Duration::from_secs(10),
            health_successes: 1,
            health_interval: Duration::from_secs(1),
            retry_after: Duration::from_secs(300),
            refresh_retry: Duration::from_secs(5),
            confirmation_window: Duration::from_secs(120),
            supervisor_check_interval: Duration::from_secs(3600),
            // No hold by default: a deployment opts into the drain hold explicitly.
            drain_hold: Some(Duration::ZERO),
        }
    }
}

/// The one canonical immutable-release layout shared by supervisor and one-shot mode.
#[derive(Debug, Clone)]
pub struct Paths {
    pub install_root: PathBuf,
    pub versions: PathBuf,
    pub staging: PathBuf,
    /// Per-release writable working directories for the managed application — the launch `cwd`.
    /// Deliberately a sibling of `versions/`, never a child of it: `versions/<release>` is the
    /// content-addressed tree `bundle::verify_release` re-hashes on every check, so a single file
    /// an ordinary application writes to its own working directory would make the supervisor
    /// condemn, re-download and republish the release forever. See [`crate::provider::BundleStore`].
    pub work: PathBuf,
    pub active_release: PathBuf,
    pub download: PathBuf,
    pub state: PathBuf,
    pub datastore: PathBuf,
    pub routing_datastore: PathBuf,
    pub assignment: PathBuf,
    pub journal: PathBuf,
    pub install_journal: PathBuf,
    pub rejected: PathBuf,
    pub provider_versions: PathBuf,
    pub provider_staging: PathBuf,
    pub provider_download: PathBuf,
    /// The same writable working directories for lifecycle-provider releases, which are re-verified
    /// on exactly the same terms every time one is invoked.
    pub provider_work: PathBuf,
}

/// Where the last live routing assignment is kept: beside the enrollment material in the
/// guardian's state directory, never under `install_root`.
///
/// This file is read *before any network fetch* to decide what the managed application is
/// launched with — its args, which secret populates which environment variable, which product and
/// channel are acceptable. Nothing local can re-verify it at that moment, so it may only live
/// where every other boot input already lives: the enrollment directory that also holds the
/// bootstrap config, the enrollment bundle, and the node's private key. Kept under `install_root`
/// it would let write access to a directory full of otherwise-recoverable state choose the
/// managed process's arguments and secrets.
pub fn persisted_assignment_path(enrollment_state: &Path) -> PathBuf {
    enrollment_state.join("repository-assignment.json")
}

impl Paths {
    /// The canonical layout, derived from the only two roots it depends on: the install root that
    /// holds every replaceable artifact, and the enrollment state directory that holds every
    /// boot-time input. This is the single definition — production, tooling and tests all call it,
    /// so no second copy of the layout can drift from it.
    pub fn resolve(install_root: &Path, enrollment_state: &Path) -> Paths {
        let state_dir = install_root.join("state");
        Paths {
            install_root: install_root.to_path_buf(),
            versions: install_root.join("versions"),
            staging: install_root.join("staging"),
            work: install_root.join("work"),
            active_release: install_root.join("active-release"),
            download: install_root.join("staging/bundle.download"),
            state: state_dir.join("installed.json"),
            datastore: state_dir.join("tuf"),
            routing_datastore: state_dir.join("routing-tuf"),
            assignment: persisted_assignment_path(enrollment_state),
            journal: state_dir.join("transaction.json"),
            install_journal: state_dir.join("install.json"),
            rejected: state_dir.join("rejected"),
            provider_versions: install_root.join("providers/versions"),
            provider_staging: install_root.join("providers/staging"),
            provider_download: install_root.join("providers/staging/bundle.download"),
            provider_work: install_root.join("providers/work"),
        }
    }
}

impl Config {
    /// Resolve the canonical bundle layout. The installer creates `install_root` and
    /// seeds its first active release before starting the service.
    pub fn resolve_paths(&self) -> Paths {
        // `routing.root` is the routing anchor materialized into the enrollment state directory,
        // so its parent is that directory — the one place boot-time inputs may come from.
        Paths::resolve(
            &self.application.install_root,
            foundation::durable::parent_dir(&self.routing.root),
        )
    }
}

/// Append `suffix` to a path's final component. Used for independent lock/download
/// siblings in the supervisor self-update path.
pub fn with_suffix(base: &Path, suffix: &str) -> PathBuf {
    let mut value = base.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}
