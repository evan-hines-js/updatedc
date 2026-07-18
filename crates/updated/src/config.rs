//! The update tower's operator configuration: one TOML file describing the managed
//! application, the signed repository, and the timeouts. The guardian
//! (`bootstrap`) parses none of it — it is passed through verbatim to the supervisor,
//! which reads it. Every timeout has a default, so `[timeouts]` — and any field within
//! it — may be omitted.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The whole configuration, deserialized from the TOML file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub routing: Routing,
    pub repository: Repository,
    pub application: Application,
    #[serde(default)]
    pub storage: Storage,
    #[serde(default)]
    pub timeouts: Timeouts,
}

/// Bootstrap trust for the small routing repository. `base_url` is the only
/// repository URL configured on a node; its `metadata/` and `targets/` children
/// contain a TUF repository whose verified assignment selects the release CDN.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Routing {
    pub root: PathBuf,
    pub base_url: String,
    /// Exact TUF target to resolve (for example `assignments/nodes/node-123.json`).
    pub assignment: String,
    #[serde(default)]
    pub datastore: Option<PathBuf>,
    #[serde(default = "meg")]
    pub metadata_limit: u64,
    #[serde(default = "transport_timeout", deserialize_with = "de_dur")]
    pub transport_timeout: Duration,
}

/// Locally pinned trust and resource limits for the repository selected by the
/// routing assignment. Its URLs deliberately do not live in local config.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Repository {
    /// Installer-pinned trust anchor (read-only).
    pub root: PathBuf,
    /// Parent of per-assigned-repository TUF metadata caches; defaults to
    /// `<install_root>/state/tuf`.
    #[serde(default)]
    pub datastore: Option<PathBuf>,
    #[serde(default = "meg")]
    pub metadata_limit: u64,
    #[serde(default = "half_gib")]
    pub target_limit: u64,
    #[serde(default = "transport_timeout", deserialize_with = "de_dur")]
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
    /// Exact application bytes selected by the control plane.
    pub application: TargetReference,
    /// Exact immutable provider-set document selected independently of the app.
    pub provider_set: TargetReference,
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

/// Immutable collection of overrides for capabilities normally supplied by the
/// supervisor-owned built-in provider. The built-in provider is deliberately absent:
/// it is compiled into, and has exactly the same version as, the supervisor.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSet {
    pub schema: u32,
    pub id: String,
    pub overrides: Vec<ProviderOverride>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderOverride {
    pub capability: ProviderCapability,
    pub artifact: TargetReference,
    pub args: Vec<String>,
    pub timeout_millis: u64,
}

/// Capabilities that can be replaced by a separately signed provider artifact.
/// Adding a capability is an explicit supervisor protocol change; arbitrary names are
/// never accepted and silently ignored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProviderCapability {
    Lifecycle,
}

impl ProviderSet {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != 2 {
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
        if self.overrides.len() > 64 {
            return Err("provider set has too many overrides".into());
        }
        let mut capabilities = std::collections::BTreeSet::new();
        for provider in &self.overrides {
            if !capabilities.insert(provider.capability) {
                return Err(format!(
                    "provider set contains duplicate {:?} overrides",
                    provider.capability
                ));
            }
            if !(1..=86_400_000).contains(&provider.timeout_millis) {
                return Err(format!(
                    "provider override {:?} has an invalid timeout",
                    provider.capability
                ));
            }
            if provider.args.len() > 256 || provider.args.iter().any(|arg| arg.len() > 16_384) {
                return Err(format!(
                    "provider override {:?} has invalid arguments",
                    provider.capability
                ));
            }
            if !valid_target_reference(&provider.artifact) {
                return Err(format!(
                    "provider override {:?} artifact reference is invalid",
                    provider.capability
                ));
            }
        }
        Ok(())
    }
}

fn valid_target_reference(reference: &TargetReference) -> bool {
    !reference.path.is_empty()
        && !reference.path.starts_with('/')
        && !reference
            .path
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
        && !reference.path.contains(['\\', ':'])
        && !reference.path.chars().any(char::is_control)
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
}

impl Repository {
    pub fn resolve(&self, assignment: RepositoryAssignment) -> Result<RepositorySource, String> {
        if assignment.schema != 2 {
            return Err(format!(
                "unsupported repository assignment schema {}",
                assignment.schema
            ));
        }
        if assignment.deployment.is_empty() {
            return Err("repository assignment deployment must not be empty".into());
        }
        for (name, reference) in [
            ("application", &assignment.application),
            ("provider_set", &assignment.provider_set),
        ] {
            if !valid_target_reference(reference) {
                return Err(format!("repository assignment {name} reference is invalid"));
            }
        }
        Ok(RepositorySource {
            root: self.root.clone(),
            metadata_url: assignment.metadata_url,
            targets_url: assignment.targets_url,
            metadata_limit: self.metadata_limit,
            target_limit: self.target_limit,
            transport_timeout: self.transport_timeout,
        })
    }
}

fn meg() -> u64 {
    1 << 20
}
fn half_gib() -> u64 {
    512 << 20
}
fn transport_timeout() -> Duration {
    Duration::from_secs(30)
}

/// Bounds for inactive immutable material. Releases needed by installed state,
/// rollback state, or an active transaction are always protected regardless of these
/// limits; the limits apply only to disposable history.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
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
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Application {
    pub product: String,
    #[serde(default = "stable")]
    pub channel: String,
    /// Root containing active-release, immutable versions, staging, and durable state.
    pub install_root: PathBuf,
    /// Arguments appended to the manifest-owned entrypoint.
    #[serde(default)]
    pub args: Vec<String>,
    /// Readiness probe; omit for liveness-only (survive the health grace = healthy).
    #[serde(default)]
    pub health_url: Option<String>,
    /// How a staged release enters service. The default is a portable stop/start;
    /// reexec keeps the existing master alive and delegates its program-specific
    /// handoff to the lifecycle provider.
    #[serde(default)]
    pub activation: Activation,
}

/// The one application activation model. The signed lifecycle entrypoint is direct argv;
/// its inputs are supplied exclusively through the documented `UPDATED_*` environment.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Activation {
    /// Stop the managed process and launch the candidate entrypoint.
    #[default]
    StopStart,
    /// Keep the master PID alive. The lifecycle provider's `activate` and `rollback`
    /// phases perform the program-specific handoff.
    Reexec,
}

impl Activation {
    pub fn name(&self) -> &'static str {
        match self {
            Activation::StopStart => "stop-start",
            Activation::Reexec => "reexec",
        }
    }
}

fn stable() -> String {
    "stable".into()
}

/// Every tunable duration in the system, in one place. Omit any (or the whole
/// `[timeouts]` table) to take the default.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Timeouts {
    /// How often to check for an application update.
    #[serde(deserialize_with = "de_dur")]
    pub check_interval: Duration,
    /// Window for the child to become healthy after a (re)start. With `health_url`
    /// this is how long a slow-starting app has to answer — set it to minutes if
    /// needed; a *crash* is still detected instantly (the process exits), so a long
    /// grace never slows crash detection.
    #[serde(deserialize_with = "de_dur")]
    pub health_grace: Duration,
    /// Consecutive good health responses required to declare the app ready (a
    /// readiness `successThreshold`). Default 1 — the first good answer commits;
    /// raise it to require sustained health before trusting a new version.
    pub health_successes: u32,
    /// Spacing between those confirmation probes (a readiness `periodSeconds`), so
    /// `health_successes > 1` proves health over time, not a 100 ms burst. Ignored
    /// when `health_successes` is 1.
    #[serde(deserialize_with = "de_dur")]
    pub health_interval: Duration,
    /// How often a health-check-failed release is retried (not permanently blocked).
    #[serde(deserialize_with = "de_dur")]
    pub retry_after: Duration,
    /// Backoff base for retrying a transient metadata transport failure.
    #[serde(deserialize_with = "de_dur")]
    pub refresh_retry: Duration,
    /// How long a just-committed update stays unconfirmed. A crash within it reverts the
    /// update (one strike); surviving it confirms the update and drops the rollback image.
    #[serde(deserialize_with = "de_dur")]
    pub confirmation_window: Duration,
    /// How often to check for a supervisor release.
    #[serde(deserialize_with = "de_dur")]
    pub supervisor_check_interval: Duration,
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
        }
    }
}

impl Config {
    /// Read and validate the TOML config at `path`.
    pub fn load(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("reading config {}: {e}", path.display()))?;
        let cfg: Config =
            toml::from_str(&text).map_err(|e| format!("parsing config {}: {e}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), String> {
        if !self.application.install_root.is_absolute() {
            return Err("application.install_root must be absolute".into());
        }
        if let Activation::Reexec = &self.application.activation {
            if !cfg!(unix) {
                return Err("application.activation reexec mode is supported only on Unix".into());
            }
            if self.application.health_url.is_none() {
                return Err(
                    "application.activation reexec mode requires application.health_url".into(),
                );
            }
        }
        for (name, value) in [
            ("timeouts.check_interval", self.timeouts.check_interval),
            ("timeouts.health_grace", self.timeouts.health_grace),
            ("timeouts.health_interval", self.timeouts.health_interval),
            ("timeouts.retry_after", self.timeouts.retry_after),
            ("timeouts.refresh_retry", self.timeouts.refresh_retry),
            (
                "timeouts.confirmation_window",
                self.timeouts.confirmation_window,
            ),
            (
                "timeouts.supervisor_check_interval",
                self.timeouts.supervisor_check_interval,
            ),
        ] {
            if value.is_zero() {
                return Err(format!("{name} must be greater than zero"));
            }
        }
        if self.timeouts.health_successes == 0 {
            return Err("timeouts.health_successes must be greater than zero".into());
        }
        if self.repository.metadata_limit == 0 {
            return Err("repository.metadata_limit must be greater than zero".into());
        }
        if self.routing.metadata_limit == 0 {
            return Err("routing.metadata_limit must be greater than zero".into());
        }
        if self.routing.assignment.is_empty()
            || self.routing.assignment.starts_with('/')
            || self.routing.assignment.contains(['\\', ':'])
            || self.routing.assignment.chars().any(char::is_control)
            || self
                .routing
                .assignment
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err("routing.assignment must be a non-empty safe relative target path".into());
        }
        if self.repository.target_limit == 0 {
            return Err("repository.target_limit must be greater than zero".into());
        }
        if self.storage.inactive_bytes == 0 {
            return Err("storage.inactive_bytes must be greater than zero".into());
        }
        if self.routing.transport_timeout.is_zero() {
            return Err("routing.transport_timeout must be greater than zero".into());
        }
        if self.repository.transport_timeout.is_zero() {
            return Err("repository.transport_timeout must be greater than zero".into());
        }
        Ok(())
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
    pub rejected: PathBuf,
    pub app_token: PathBuf,
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
            rejected: state_dir.join("rejected"),
            app_token: state_dir.join("app-token"),
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

/// Parse the sole CLI contract shared by every entrypoint that loads this config
/// (the supervisor and the one-shot updater): `--config <path.toml>`. `-h`/`--help`
/// prints usage and exits; `prog` names the binary in that message. Returns the
/// config path, or an `Err` usage string the caller reports before exiting.
pub fn config_path(prog: &str) -> Result<PathBuf, String> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--config") => args
            .next()
            .map(PathBuf::from)
            .ok_or_else(|| "--config needs a path".into()),
        Some("-h") | Some("--help") => {
            println!("usage: {prog} --config <path.toml>");
            std::process::exit(0);
        }
        _ => Err(format!("usage: {prog} --config <path.toml>")),
    }
}

/// Human-friendly durations: `"15s"`, `"5m"`, `"2h"`, `"500ms"`, or a bare integer
/// (seconds). Keeps the config readable without a `humantime` dependency.
fn de_dur<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
    use serde::de::{Error, Visitor};
    struct V;
    impl Visitor<'_> for V {
        type Value = Duration;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str(r#"a duration like "15s", "5m", "2h", or an integer of seconds"#)
        }
        fn visit_str<E: Error>(self, s: &str) -> Result<Duration, E> {
            parse_duration(s).ok_or_else(|| E::custom(format!("invalid duration {s:?}")))
        }
        fn visit_i64<E: Error>(self, n: i64) -> Result<Duration, E> {
            let seconds =
                u64::try_from(n).map_err(|_| E::custom("duration must not be negative"))?;
            Ok(Duration::from_secs(seconds))
        }
    }
    d.deserialize_any(V)
}

fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let n: u64 = s[..split].parse().ok()?;
    match s[split..].trim() {
        "" | "s" | "sec" | "secs" | "second" | "seconds" => Some(Duration::from_secs(n)),
        "ms" => Some(Duration::from_millis(n)),
        "m" | "min" | "mins" | "minute" | "minutes" => n.checked_mul(60).map(Duration::from_secs),
        "h" | "hr" | "hrs" | "hour" | "hours" => n.checked_mul(3600).map(Duration::from_secs),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_install_root_native(cfg: &mut Config) {
        cfg.application.install_root = if cfg!(windows) {
            PathBuf::from(r"C:\app")
        } else {
            PathBuf::from("/app")
        };
    }

    #[test]
    fn durations_parse_human_and_bare() {
        assert_eq!(parse_duration("15s"), Some(Duration::from_secs(15)));
        assert_eq!(parse_duration("5m"), Some(Duration::from_secs(300)));
        assert_eq!(parse_duration("2h"), Some(Duration::from_secs(7200)));
        assert_eq!(parse_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_duration("120"), Some(Duration::from_secs(120)));
        assert_eq!(parse_duration("nonsense"), None);
        assert_eq!(parse_duration("18446744073709551615m"), None);
    }

    #[test]
    fn assignment_is_strict_and_cannot_replace_the_pinned_root() {
        let assignment: RepositoryAssignment = serde_json::from_str(
            r#"{"schema":2,"deployment":"d1","metadata_url":"https://cdn/m/","targets_url":"https://cdn/t/","application":{"path":"app","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"provider_set":{"path":"providers","sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}"#,
        )
        .unwrap();
        let repository = Repository {
            root: PathBuf::from("/pinned-root.json"),
            datastore: None,
            metadata_limit: meg(),
            target_limit: half_gib(),
            transport_timeout: transport_timeout(),
        };
        let source = repository.resolve(assignment).unwrap();
        assert_eq!(source.root, PathBuf::from("/pinned-root.json"));

        let unknown = r#"{"schema":2,"deployment":"d1","metadata_url":"https://cdn/m/","targets_url":"https://cdn/t/","application":{"path":"app","sha256":"aa"},"provider_set":{"path":"providers","sha256":"bb"},"root":"evil"}"#;
        assert!(serde_json::from_str::<RepositoryAssignment>(unknown).is_err());
        let future = RepositoryAssignment {
            schema: 3,
            deployment: "future".into(),
            metadata_url: "https://cdn/m/".into(),
            targets_url: "https://cdn/t/".into(),
            application: TargetReference {
                path: "app".into(),
                sha256: "a".repeat(64),
            },
            provider_set: TargetReference {
                path: "providers".into(),
                sha256: "b".repeat(64),
            },
        };
        assert!(repository.resolve(future).is_err());
    }

    fn provider_override(capability: ProviderCapability) -> ProviderOverride {
        ProviderOverride {
            capability,
            artifact: TargetReference {
                path: "providers/lifecycle.bundle".into(),
                sha256: "a".repeat(64),
            },
            args: Vec::new(),
            timeout_millis: 30_000,
        }
    }

    #[test]
    fn empty_provider_set_selects_the_supervisor_built_in_provider() {
        ProviderSet {
            schema: 2,
            id: "built-in".into(),
            overrides: Vec::new(),
        }
        .validate()
        .unwrap();
    }

    #[test]
    fn provider_overrides_are_strict_unique_and_bounded() {
        let provider = provider_override(ProviderCapability::Lifecycle);
        let duplicate = ProviderSet {
            schema: 2,
            id: "duplicate".into(),
            overrides: vec![provider.clone(), provider],
        };
        assert!(duplicate.validate().unwrap_err().contains("duplicate"));

        let unknown = r#"{"schema":2,"id":"future","overrides":[{"capability":"future-capability","artifact":{"path":"provider","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"args":[],"timeout_millis":1}]}"#;
        assert!(serde_json::from_str::<ProviderSet>(unknown).is_err());

        let invalid_reference = ProviderSet {
            schema: 2,
            id: "unsafe".into(),
            overrides: vec![ProviderOverride {
                artifact: TargetReference {
                    path: "../escape".into(),
                    sha256: "a".repeat(64),
                },
                ..provider_override(ProviderCapability::Lifecycle)
            }],
        };
        assert!(invalid_reference
            .validate()
            .unwrap_err()
            .contains("artifact reference"));
    }

    #[test]
    fn negative_duration_is_rejected() {
        #[derive(Debug, Deserialize)]
        #[allow(dead_code)]
        struct Wrapper {
            #[serde(deserialize_with = "de_dur")]
            duration: Duration,
        }

        let err = toml::from_str::<Wrapper>("duration = -1").unwrap_err();
        assert!(err.to_string().contains("must not be negative"));

        // A bare integer deserializes through visit_i64 as whole seconds.
        let ok = toml::from_str::<Wrapper>("duration = 42").unwrap();
        assert_eq!(ok.duration, Duration::from_secs(42));

        // A wrong type surfaces the human-readable "expecting" description, not an
        // empty one.
        let type_err = toml::from_str::<Wrapper>("duration = true").unwrap_err();
        assert!(type_err.to_string().contains("duration like"), "{type_err}");
    }

    #[test]
    fn unsafe_zero_timeouts_are_rejected() {
        let mut cfg: Config = toml::from_str(
            r#"
            [routing]
            root = "/r"
            base_url = "http://x/"
            assignment = "assignments/nodes/node.json"
            [repository]
            root = "/r"
            [application]
            product = "app"
            install_root = "/app"
            [timeouts]
            check_interval = 0
            "#,
        )
        .unwrap();
        make_install_root_native(&mut cfg);

        assert_eq!(
            cfg.validate().unwrap_err(),
            "timeouts.check_interval must be greater than zero"
        );
    }

    #[test]
    fn zero_health_threshold_and_limits_are_rejected() {
        let base = r#"
            [routing]
            root = "/r"
            base_url = "http://x/"
            assignment = "assignments/nodes/node.json"
            [repository]
            root = "/r"
            [application]
            product = "app"
            install_root = "/app"
        "#;
        let mut cfg: Config = toml::from_str(base).unwrap();
        make_install_root_native(&mut cfg);
        cfg.timeouts.health_successes = 0;
        assert!(cfg.validate().unwrap_err().contains("health_successes"));

        let mut cfg: Config = toml::from_str(base).unwrap();
        make_install_root_native(&mut cfg);
        cfg.repository.target_limit = 0;
        assert!(cfg.validate().unwrap_err().contains("target_limit"));

        let mut cfg: Config = toml::from_str(base).unwrap();
        make_install_root_native(&mut cfg);
        cfg.routing.transport_timeout = Duration::ZERO;
        assert!(cfg.validate().unwrap_err().contains("transport_timeout"));
    }

    #[test]
    fn omitted_timeouts_take_defaults_partial_override() {
        let mut cfg: Config = toml::from_str(
            r#"
            [routing]
            root = "/etc/selfupdate/root.json"
            base_url = "http://x/"
            assignment = "assignments/nodes/node.json"
            [repository]
            root = "/etc/selfupdate/root.json"
            [application]
            product = "app"
            install_root = "/app"
            args = ["--addr", "127.0.0.1:9090"]
            [timeouts]
            health_grace = "2m"
            "#,
        )
        .unwrap();
        make_install_root_native(&mut cfg);
        cfg.validate().unwrap();
        // Overridden field takes the file value; the rest fall back to defaults.
        assert_eq!(cfg.timeouts.health_grace, Duration::from_secs(120));
        assert_eq!(cfg.timeouts.check_interval, Duration::from_secs(15));
        assert_eq!(cfg.timeouts.retry_after, Duration::from_secs(300));
        assert_eq!(cfg.repository.metadata_limit, 1 << 20);
        assert_eq!(cfg.repository.target_limit, 512 << 20);
        assert_eq!(cfg.routing.transport_timeout, Duration::from_secs(30));
        assert_eq!(cfg.repository.transport_timeout, Duration::from_secs(30));
        assert_eq!(cfg.application.channel, "stable");
    }

    #[test]
    fn reexec_without_health_url_is_rejected() {
        let cfg: Result<Config, _> = toml::from_str(
            r#"
            [routing]
            root = "/r"
            base_url = "http://x/"
            assignment = "assignments/nodes/node.json"
            [repository]
            root = "/r"
            [application]
            product = "app"
            install_root = "/app"
            [application.activation]
            mode = "reexec"
            [application.lifecycle]
            product = "app-lifecycle"
            "#,
        );
        // Parses, but validation rejects it (Unix) or the platform guard does.
        if let Ok(cfg) = cfg {
            assert!(cfg.validate().is_err());
        }

        // With health_url present, reexec is valid on Unix — the case that
        // distinguishes the Unix-only platform guard from an unconditional reject.
        #[cfg(unix)]
        {
            let cfg: Config = toml::from_str(
                r#"
                [routing]
                root = "/r"
                base_url = "http://x/"
                assignment = "assignments/nodes/node.json"
                [repository]
                root = "/r"
                [application]
                product = "app"
                install_root = "/app"
                health_url = "http://127.0.0.1:9/healthz"
                [application.activation]
                mode = "reexec"
                "#,
            )
            .unwrap();
            cfg.validate().unwrap();
        }
    }

    #[test]
    fn resolve_paths_derives_the_canonical_install_layout() {
        let dir = std::env::temp_dir().join(format!("cfg-paths-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg: Config = toml::from_str(
            r#"
            [routing]
            root = "/r"
            base_url = "http://x/"
            assignment = "assignments/nodes/node.json"
            [repository]
            root = "/r"
            [application]
            product = "app"
            install_root = "/placeholder"
            "#,
        )
        .unwrap();
        let mut cfg = cfg;
        cfg.application.install_root = dir.clone();

        let paths = cfg.resolve_paths().unwrap();
        assert_eq!(paths.install_root, dir);
        assert_eq!(paths.versions, paths.install_root.join("versions"));
        assert_eq!(
            paths.active_release,
            paths.install_root.join("active-release")
        );
        assert_eq!(paths.state, paths.install_root.join("state/installed.json"));
        assert_eq!(paths.datastore, paths.install_root.join("state/tuf"));
        assert_eq!(
            paths.download,
            paths.install_root.join("staging/bundle.download")
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
