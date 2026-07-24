//! Runtime types materialized exclusively from a TUF-verified managed configuration.
//! The only node-local configuration is the URL-and-key enrollment bootstrap.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;
use url::{Host, Url};

/// Fully verified, materialized runtime configuration.
#[derive(Debug)]
pub struct Config {
    pub deployment: String,
    pub routing: Routing,
    pub repository: Repository,
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
    pub datastore: Option<PathBuf>,
    pub metadata_limit: u64,
    pub transport_timeout: Duration,
    /// The agent's mTLS identity for reaching the gateway — mandatory, never plaintext. The
    /// routing and release repositories are the same externally-exposed gateway, so both fetch
    /// under this identity.
    pub mtls: crate::tls::Identity,
}

impl Routing {
    /// Whether this routing repository is local (a `file:` URL or an absolute directory path)
    /// rather than a network gateway. The single definition of "local" — the offline-repair path
    /// and the secrets manager both gate on it, and must agree: one deciding to reach the network
    /// while the other assumes offline would split the trust model.
    pub fn is_local(&self) -> bool {
        self.base_url.starts_with("file:") || Path::new(&self.base_url).is_absolute()
    }
}

/// Locally pinned trust and resource limits for the repository selected by the
/// routing assignment. Its URLs deliberately do not live in local config.
#[derive(Debug, Clone)]
pub struct Repository {
    /// Installer-pinned trust anchor (read-only).
    pub root: PathBuf,
    /// Parent of per-assigned-repository TUF metadata caches; defaults to
    /// `<install_root>/state/tuf`.
    pub datastore: Option<PathBuf>,
    pub metadata_limit: u64,
    pub target_limit: u64,
    pub transport_timeout: Duration,
}

/// Strict payload carried as a verified target in the routing repository.
/// TUF supplies authenticity, expiry, and rollback protection; this document
/// supplies only the two release-repository transport endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryAssignment {
    pub schema: u32,
    /// Monotonic, operator-visible identity of this desired deployment.
    pub deployment: String,
    pub metadata_url: String,
    pub targets_url: String,
    /// Optional location the node writes its running-state document to, so the control
    /// plane can read rollout progress without ever reaching the node. Decoupled from
    /// `metadata_url`/`targets_url` on purpose: it happens to be the same gateway in the
    /// demo, but a deployment may point telemetry somewhere else. Absent means the node
    /// reports nothing and the control plane rolls without completion gating.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report_url: Option<String>,
    /// Exact application bytes selected by the control plane.
    pub application: TargetReference,
    /// Signed opt-in to ordered fallback on *first install only*. When true, a node
    /// with no installed state (and thus no anti-rollback floor) may, if the exact
    /// assigned bytes prove unusable, descend from the assigned version to the newest
    /// healthy, non-rejected, policy-authorized target at or below it. Gated to first
    /// install so an established node keeps exact-pin reject-and-hold and its version
    /// floor still bounds any descent; authenticated here so only the publisher — not
    /// an attacker replaying old metadata — can authorize a stateless downgrade.
    pub ordered_install_fallback: bool,
    /// Exact reconciler manifest for the assigned application head. Historical application
    /// targets carry their own reference for ordered fallback.
    pub provider_set: TargetReference,
    /// Pinned public TUF root for the selected release lineage. It is authenticated as
    /// part of this routing target and materialized locally before the release is opened.
    pub release_root: serde_json::Value,
    /// Complete operator-managed runtime configuration. No operational policy remains
    /// in the two-field bootstrap file.
    pub runtime: ManagedRuntime,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRuntime {
    /// Who owns the application process. The default is the hardened guardian-owned runtime.
    /// `provider-managed` never launches, signals, probes, or stops an application process; the
    /// signed node reconciler owns every application-specific effect.
    #[serde(default)]
    pub mode: RuntimeMode,
    pub product: String,
    pub channel: String,
    pub install_root: PathBuf,
    pub args: Vec<String>,
    /// Environment variables whose values are resolved by the authenticated control plane.
    /// Only references are signed into the assignment; secret bytes never enter TUF.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secrets: Vec<SecretReference>,
    pub repository: ManagedRepositoryLimits,
    pub storage: ManagedStorage,
    pub timeouts: ManagedTimeouts,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SecretReference {
    /// Environment variable exposed to the managed application.
    pub environment: String,
    /// Kubernetes Secret name in the control-plane namespace.
    pub secret: String,
    /// Key within the Kubernetes Secret.
    pub key: String,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeMode {
    #[default]
    Managed,
    ProviderManaged,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedRepositoryLimits {
    pub metadata_limit: u64,
    pub target_limit: u64,
    pub transport_timeout_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedStorage {
    pub inactive_releases: usize,
    pub inactive_providers: usize,
    pub inactive_supervisors: usize,
    pub inactive_bytes: u64,
    pub inactive_repository_caches: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ManagedTimeouts {
    pub check_interval_seconds: u64,
    pub health_grace_seconds: u64,
    pub health_successes: u32,
    pub health_interval_seconds: u64,
    pub retry_after_seconds: u64,
    pub refresh_retry_seconds: u64,
    pub confirmation_window_seconds: u64,
    pub supervisor_check_interval_seconds: u64,
    /// The *drain hold*, in seconds: how long a managed (stop-start) node waits after withdrawing
    /// readiness before it stops the running release, so the load balancer has removed it from
    /// rotation first (no in-flight request lands on a stopping process).
    ///
    /// `Some(0)` or absent = **no hold**; `Some(n)` = hold up to `n` seconds (a bounded ceiling, a
    /// fixed sleep today). A `provider-managed` deployment ignores this — its own Drain hook owns the wait.
    /// Absent deserializes to no-hold, matching the struct default, so an assignment that omits the
    /// field never accidentally stalls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain_hold_seconds: Option<u64>,
}

/// Minimal per-node routing document. A node begins with only the routing trust root,
/// repository URL, and path to this document; the exact opaque config reference leads
/// it to the full [`RepositoryAssignment`]. Why that reference changes is exclusively a
/// control-plane concern.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDocument {
    pub schema: u32,
    pub config: TargetReference,
}

/// A content-addressed reference to a target authenticated by release-repository TUF
/// metadata. Both fields must match; a path that is republished with different bytes
/// never silently satisfies an older deployment document.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetReference {
    pub path: String,
    pub sha256: String,
}

/// Immutable description of the one signed node reconciler required by a release.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSet {
    pub schema: u32,
    pub id: String,
    pub reconciler: Reconciler,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reconciler {
    pub artifact: TargetReference,
    pub args: Vec<String>,
    pub timeout_millis: u64,
}

impl ProviderSet {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != 1 {
            return Err(format!("unsupported provider-set schema {}", self.schema));
        }
        let valid_id = !self.id.is_empty()
            && self.id.len() <= 128
            && self.id.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
            });
        if !valid_id {
            return Err("provider-set id is invalid".into());
        }
        if !(1..=86_400_000).contains(&self.reconciler.timeout_millis) {
            return Err("node reconciler has an invalid timeout".into());
        }
        if self.reconciler.args.len() > 256
            || self.reconciler.args.iter().any(|arg| arg.len() > 16_384)
        {
            return Err("node reconciler has invalid arguments".into());
        }
        if !valid_target_reference(&self.reconciler.artifact) {
            return Err("node reconciler artifact reference is invalid".into());
        }
        Ok(())
    }
}

fn valid_target_reference(reference: &TargetReference) -> bool {
    // Path-traversal safety is decided once, in `crate::path`; a target reference is a confined
    // relative path (it may carry subdirectories) plus a well-formed digest.
    crate::path::is_confined_relative(&reference.path)
        && crate::hash::is_sha256_hex(&reference.sha256)
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

impl RepositoryAssignment {
    /// Validate the signed assignment contract independently of node-local repository
    /// configuration. Producers call the same validator as consumers before signing.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != 2 {
            return Err(format!(
                "unsupported repository assignment schema {}",
                self.schema
            ));
        }
        if self.deployment.is_empty() {
            return Err("repository assignment deployment must not be empty".into());
        }
        for (name, reference) in [
            ("application", &self.application),
            ("provider_set", &self.provider_set),
        ] {
            if !valid_target_reference(reference) {
                return Err(format!("repository assignment {name} reference is invalid"));
            }
        }
        if !self.release_root.is_object() {
            return Err("repository assignment release_root must be a JSON object".into());
        }
        // `metadata_url`/`targets_url` carry the offline-repair grammar (HTTP(S), `file://`,
        // or an absolute directory path) and are validated by the single canonical
        // `repository_base` parser on the trust path before any fetch — duplicating that
        // grammar here is what previously rejected a legitimate local repository. `report_url`
        // is a network report endpoint with no other validator, so it is checked here.
        if let Some(report_url) = &self.report_url {
            validate_report_url(report_url)?;
        }
        self.runtime.validate()?;
        Ok(())
    }
}

impl ManagedRuntime {
    fn validate(&self) -> Result<(), String> {
        // `product` is joined onto the install root as a single directory name (per-product state,
        // staged trees), so it must be a safe path component — the same traversal guard the bundle
        // and target paths use — not merely non-empty, or a signed `../…` product could escape it.
        if !crate::path::is_safe_component(&self.product)
            || self.channel.is_empty()
            || !self.install_root.is_absolute()
        {
            return Err("managed runtime product/channel/install_root is invalid".into());
        }
        if self.repository.metadata_limit == 0
            || self.repository.target_limit == 0
            || self.repository.transport_timeout_seconds == 0
            || self.storage.inactive_bytes == 0
            || self.timeouts.check_interval_seconds == 0
            || self.timeouts.health_grace_seconds == 0
            || self.timeouts.health_successes == 0
            || self.timeouts.health_interval_seconds == 0
            || self.timeouts.retry_after_seconds == 0
            || self.timeouts.refresh_retry_seconds == 0
            || self.timeouts.confirmation_window_seconds == 0
            || self.timeouts.supervisor_check_interval_seconds == 0
        {
            return Err("managed runtime limits and timeouts must be non-zero".into());
        }
        if self.secrets.len() > 64 {
            return Err("managed runtime may declare at most 64 secret references".into());
        }
        if self.mode == RuntimeMode::ProviderManaged && !self.secrets.is_empty() {
            return Err("provider-managed runtime cannot declare application secrets".into());
        }
        let mut environments = std::collections::BTreeSet::new();
        for reference in &self.secrets {
            let valid_environment = !reference.environment.is_empty()
                && reference.environment.len() <= 128
                && reference
                    .environment
                    .bytes()
                    .enumerate()
                    .all(|(index, byte)| {
                        byte == b'_'
                            || byte.is_ascii_uppercase()
                            || (index > 0 && byte.is_ascii_digit())
                    })
                // Defence-in-depth: a secret is injected into the application's environment, so a
                // signed-but-hostile assignment must not name it a dynamic-loader hook
                // (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, …) and load attacker
                // code into the launched process. These prefixes are never legitimate secret names.
                && !reference.environment.starts_with("LD_")
                && !reference.environment.starts_with("DYLD_");
            if !valid_environment
                || reference.secret.is_empty()
                || reference.secret.len() > 253
                || reference.key.is_empty()
                || reference.key.len() > 253
                || !environments.insert(&reference.environment)
            {
                return Err("managed runtime secret references are invalid or duplicated".into());
            }
        }
        // A health streak of N successes spaced by `interval` needs at least (N-1)*interval of
        // grace to ever complete; otherwise a perfectly healthy app is failed on every gate and
        // its provisional head is needlessly rejected. (interval is ignored when successes == 1.)
        let min_grace = u64::from(self.timeouts.health_successes.saturating_sub(1))
            .saturating_mul(self.timeouts.health_interval_seconds);
        if self.timeouts.health_grace_seconds < min_grace {
            return Err(format!(
                "health_grace_seconds ({}) must be >= (health_successes-1)*health_interval_seconds \
                 ({min_grace}); otherwise the health streak can never complete within the grace window",
                self.timeouts.health_grace_seconds
            ));
        }
        Ok(())
    }

    /// The launch spec and probes derived from this runtime. The single construction path
    /// for [`Application`] — used both when the config is first materialized and when a
    /// running supervisor reconciles a control-plane reassignment (which may change the
    /// launch args or health checks independently of the release version).
    pub fn application(&self) -> Application {
        Application {
            mode: self.mode,
            product: self.product.clone(),
            channel: self.channel.clone(),
            install_root: self.install_root.clone(),
            args: self.args.clone(),
            secrets: self.secrets.clone(),
        }
    }

    /// The inactive-material retention bounds this runtime signs. Single construction path
    /// for [`Storage`], shared by materialization and steady-state reassignment.
    pub fn storage(&self) -> Storage {
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
    pub fn timeouts(&self) -> Timeouts {
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
            // `None` (indefinite) is preserved; a finite value (including 0 = no hold) becomes
            // a bounded ceiling.
            drain_hold: self.timeouts.drain_hold_seconds.map(Duration::from_secs),
        }
    }

    pub fn materialize(
        &self,
        deployment: &str,
        routing: Routing,
        release_root: &serde_json::Value,
        state_dir: &Path,
    ) -> Result<Config, String> {
        self.validate()?;
        let root = state_dir.join("release-root.json");
        foundation::durable::atomic_write(
            &root,
            ".release-root-",
            &serde_json::to_vec(release_root).map_err(|error| error.to_string())?,
        )
        .map_err(|error| format!("materializing release root: {error}"))?;
        Ok(Config {
            deployment: deployment.to_owned(),
            routing,
            repository: Repository {
                root,
                datastore: None,
                metadata_limit: self.repository.metadata_limit,
                target_limit: self.repository.target_limit,
                transport_timeout: Duration::from_secs(self.repository.transport_timeout_seconds),
            },
            application: self.application(),
            storage: self.storage(),
            timeouts: self.timeouts(),
        })
    }
}

impl AgentDocument {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != 1 {
            return Err(format!("unsupported agent document schema {}", self.schema));
        }
        if !valid_target_reference(&self.config) {
            return Err("agent document config reference is invalid".into());
        }
        Ok(())
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
}

impl Config {
    /// Resolve the canonical bundle layout. The installer creates `install_root` and
    /// seeds its first active release before starting the service.
    pub fn resolve_paths(&self) -> Result<Paths, String> {
        let install_root = self.application.install_root.clone();
        let state_dir = install_root.join("state");
        let state = state_dir.join("installed.json");
        let datastore = self
            .repository
            .datastore
            .clone()
            .unwrap_or_else(|| state_dir.join("tuf"));
        let routing_datastore = self
            .routing
            .datastore
            .clone()
            .unwrap_or_else(|| state_dir.join("routing-tuf"));
        Ok(Paths {
            versions: install_root.join("versions"),
            staging: install_root.join("staging"),
            active_release: install_root.join("active-release"),
            download: install_root.join("staging/bundle.download"),
            journal: state_dir.join("transaction.json"),
            install_journal: state_dir.join("install.json"),
            rejected: state_dir.join("rejected"),
            provider_versions: install_root.join("providers/versions"),
            provider_staging: install_root.join("providers/staging"),
            provider_download: install_root.join("providers/staging/bundle.download"),
            datastore,
            routing_datastore,
            assignment: state_dir.join("repository-assignment.json"),
            state,
            install_root,
        })
    }
}

/// Append `suffix` to a path's final component. Used for independent lock/download
/// siblings in the supervisor self-update path.
pub fn with_suffix(base: &Path, suffix: &str) -> PathBuf {
    let mut value = base.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

/// A repository transport endpoint must be a well-formed absolute HTTP(S) URL with a real
/// host and no embedded credentials or fragment, so an empty or garbage assignment fails
/// closed here in `validate()` rather than masquerading as a valid lineage until a fetch
/// tries to use it. Unlike a health check these point at a remote gateway, so any host is
/// allowed — the check mirrors the health-check validator's rigor without the loopback pin.
/// The heartbeat report endpoint is always a remote HTTP(S) POST target (never the
/// offline `file://`/directory form the metadata/targets bases allow), so it is held to
/// the same rigor as the health-check URLs.
fn validate_report_url(raw: &str) -> Result<(), String> {
    let url =
        Url::parse(raw).map_err(|error| format!("repository assignment report_url: {error}"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.cannot_be_a_base()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(
            "repository assignment report_url must be an absolute HTTP(S) URL without credentials, a query, or a fragment"
                .into(),
        );
    }
    match url.host() {
        Some(Host::Domain(domain)) if !domain.is_empty() => {}
        Some(Host::Ipv4(_)) | Some(Host::Ipv6(_)) => {}
        _ => {
            return Err("repository assignment report_url must have a host".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn managed_runtime() -> ManagedRuntime {
        ManagedRuntime {
            mode: RuntimeMode::Managed,
            product: "app".into(),
            channel: "stable".into(),
            install_root: "/app".into(),
            args: vec![],
            secrets: vec![],
            repository: ManagedRepositoryLimits {
                metadata_limit: 1 << 20,
                target_limit: 512 << 20,
                transport_timeout_seconds: 30,
            },
            storage: ManagedStorage {
                inactive_releases: 2,
                inactive_providers: 2,
                inactive_supervisors: 2,
                inactive_bytes: 1_073_741_824,
                inactive_repository_caches: 2,
            },
            timeouts: ManagedTimeouts {
                check_interval_seconds: 60,
                health_grace_seconds: 30,
                health_successes: 2,
                health_interval_seconds: 1,
                retry_after_seconds: 60,
                refresh_retry_seconds: 5,
                confirmation_window_seconds: 120,
                supervisor_check_interval_seconds: 3600,
                drain_hold_seconds: Some(0),
            },
        }
    }

    #[test]
    fn runtime_mode_defaults_to_managed_and_accepts_provider_managed() {
        let managed: RuntimeMode = serde_json::from_str("\"managed\"").unwrap();
        let provider_managed: RuntimeMode = serde_json::from_str("\"provider-managed\"").unwrap();
        assert_eq!(managed, RuntimeMode::Managed);
        assert_eq!(provider_managed, RuntimeMode::ProviderManaged);

        let value = serde_json::to_value(managed_runtime()).unwrap();
        let mut without_mode = value.as_object().unwrap().clone();
        without_mode.remove("mode");
        let parsed: ManagedRuntime =
            serde_json::from_value(serde_json::Value::Object(without_mode)).unwrap();
        assert_eq!(parsed.mode, RuntimeMode::Managed);
    }

    #[test]
    fn secret_references_are_strict_and_never_carry_values() {
        let mut runtime = managed_runtime();
        runtime.secrets.push(SecretReference {
            environment: "DATABASE_PASSWORD".into(),
            secret: "production-database".into(),
            key: "password".into(),
        });
        runtime.validate().unwrap();
        let json = serde_json::to_string(&runtime).unwrap();
        assert!(json.contains("production-database"));
        assert!(!json.contains("secretValue"));

        runtime.secrets.push(SecretReference {
            environment: "DATABASE_PASSWORD".into(),
            secret: "other".into(),
            key: "password".into(),
        });
        assert!(runtime.validate().is_err());
        runtime.secrets[1].environment = "lowercase".into();
        assert!(runtime.validate().is_err());
    }

    #[test]
    fn agent_document_round_trips_and_validates_its_config_reference() {
        let valid = AgentDocument {
            schema: 1,
            config: TargetReference {
                path: "assignments/configs/abc.json".into(),
                sha256: "a".repeat(64),
            },
        };
        valid.validate().unwrap();
        assert_eq!(
            serde_json::from_str::<AgentDocument>(&serde_json::to_string(&valid).unwrap()).unwrap(),
            valid
        );

        // A malformed config reference fails closed.
        let mut invalid = valid;
        invalid.config.sha256 = "not-a-sha".into();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn assignment_is_strict_and_carries_the_release_trust_and_runtime() {
        let assignment = RepositoryAssignment {
            schema: 2,
            deployment: "d1".into(),
            metadata_url: "https://cdn/m/".into(),
            targets_url: "https://cdn/t/".into(),
            report_url: None,
            application: TargetReference {
                path: "app".into(),
                sha256: "a".repeat(64),
            },
            ordered_install_fallback: false,
            provider_set: TargetReference {
                path: "providers".into(),
                sha256: "b".repeat(64),
            },
            release_root: serde_json::json!({"signed": {}, "signatures": []}),
            runtime: managed_runtime(),
        };
        assignment.validate().unwrap();

        // A report_url is optional but, when present, must be a well-formed remote endpoint.
        let mut with_report = assignment.clone();
        with_report.report_url = Some("https://cdn/report".into());
        with_report.validate().unwrap();

        // metadata_url/targets_url deliberately accept the offline signed-repair grammar
        // (a `file://` URL or an absolute directory path); their well-formedness is enforced
        // by the canonical trust-path parser, not here.
        let mut offline = assignment.clone();
        offline.metadata_url = "/opt/update/metadata/".into();
        offline.targets_url = "file:///opt/update/targets/".into();
        offline.validate().unwrap();

        // The report endpoint, by contrast, is always a remote HTTP(S) target: empty,
        // relative, scheme-less, or credentialed values fail closed here rather than
        // masquerading as a valid endpoint until the first heartbeat tries to use them.
        for bad in [
            "",
            "not-a-url",
            "/relative/only",
            "ftp://cdn/m/",
            "https://",
            "https://user:pass@cdn/report",
        ] {
            let mut invalid = assignment.clone();
            invalid.report_url = Some(bad.into());
            assert!(
                invalid.validate().is_err(),
                "expected report_url {bad:?} to be rejected"
            );
        }

        let unknown = r#"{"schema":2,"deployment":"d1","unexpected":true}"#;
        assert!(serde_json::from_str::<RepositoryAssignment>(unknown).is_err());
        let future = RepositoryAssignment {
            schema: 1,
            deployment: "future".into(),
            metadata_url: "https://cdn/m/".into(),
            targets_url: "https://cdn/t/".into(),
            report_url: None,
            application: TargetReference {
                path: "app".into(),
                sha256: "a".repeat(64),
            },
            ordered_install_fallback: false,
            provider_set: TargetReference {
                path: "providers".into(),
                sha256: "b".repeat(64),
            },
            release_root: serde_json::json!({}),
            runtime: managed_runtime(),
        };
        assert!(future.validate().is_err());
    }

    fn reconciler() -> Reconciler {
        Reconciler {
            artifact: TargetReference {
                path: "providers/lifecycle.bundle".into(),
                sha256: "a".repeat(64),
            },
            args: Vec::new(),
            timeout_millis: 30_000,
        }
    }

    #[test]
    fn provider_set_requires_one_valid_node_reconciler() {
        ProviderSet {
            schema: 1,
            id: "application-policy".into(),
            reconciler: reconciler(),
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn node_reconciler_is_strict_and_bounded() {
        let unknown = r#"{"schema":1,"id":"future","reconciler":{"artifact":{"path":"provider","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"args":[],"timeout_millis":1,"future":true}}"#;
        assert!(serde_json::from_str::<ProviderSet>(unknown).is_err());

        let invalid_reference = ProviderSet {
            schema: 1,
            id: "unsafe".into(),
            reconciler: Reconciler {
                artifact: TargetReference {
                    path: "../escape".into(),
                    sha256: "a".repeat(64),
                },
                ..reconciler()
            },
        };
        assert!(invalid_reference
            .validate()
            .unwrap_err()
            .contains("artifact reference"));
    }
}
