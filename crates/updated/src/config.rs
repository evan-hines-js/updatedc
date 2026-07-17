//! The update tower's operator configuration: one TOML file describing the managed
//! application, the signed repository, and the timeouts. The guardian
//! (`bootstrap`) parses none of it — it is passed through verbatim to the supervisor,
//! which reads it. Every timeout has a default, so `[timeouts]` — and any field within
//! it — may be omitted.

use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The whole configuration, deserialized from the TOML file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub repository: Repository,
    pub application: Application,
    #[serde(default)]
    pub timeouts: Timeouts,
}

/// The signed TUF repository the application and self targets come from.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Repository {
    /// Installer-pinned trust anchor (read-only).
    pub root: PathBuf,
    pub metadata_url: String,
    pub targets_url: String,
    /// Persistent TUF metadata cache; defaults to `<state>.tuf`.
    #[serde(default)]
    pub datastore: Option<PathBuf>,
    #[serde(default = "meg")]
    pub metadata_limit: u64,
    #[serde(default = "half_gib")]
    pub target_limit: u64,
}

fn meg() -> u64 {
    1 << 20
}
fn half_gib() -> u64 {
    512 << 20
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
    /// handoff to explicit argv commands.
    #[serde(default)]
    pub activation: Activation,
}

/// The one application activation model. Commands are argv arrays executed without a
/// shell; exact-token placeholders are expanded by the supervisor.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Activation {
    /// Stop the managed process and launch the candidate entrypoint.
    #[default]
    StopStart,
    /// Keep the master PID alive while operator code projects and activates a candidate.
    Reexec {
        /// Optional candidate validation, run before journaling, pointer mutation, or
        /// touching the live process. Failure rejects the candidate without rollback.
        #[serde(default)]
        preflight_command: Option<Vec<String>>,
        /// Symmetric handoff command, used for both forward activation and rollback.
        command: Vec<String>,
    },
}

impl Activation {
    pub fn name(&self) -> &'static str {
        match self {
            Activation::StopStart => "stop-start",
            Activation::Reexec { .. } => "reexec",
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
        if let Activation::Reexec {
            preflight_command,
            command,
        } = &self.application.activation
        {
            if !cfg!(unix) {
                return Err("application.activation reexec mode is supported only on Unix".into());
            }
            if self.application.health_url.is_none() {
                return Err(
                    "application.activation reexec mode requires application.health_url".into(),
                );
            }
            if command.is_empty() {
                return Err("application.activation.command must name a command".into());
            }
            if preflight_command.as_ref().is_some_and(Vec::is_empty) {
                return Err("application.activation.preflight_command must name a command".into());
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
        if self.repository.target_limit == 0 {
            return Err("repository.target_limit must be greater than zero".into());
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
    pub journal: PathBuf,
    pub rejected: PathBuf,
    pub app_token: PathBuf,
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
        Ok(Paths {
            versions: install_root.join("versions"),
            staging: install_root.join("staging"),
            active_release: install_root.join("active-release"),
            download: install_root.join("staging/bundle.download"),
            journal: state_dir.join("transaction.json"),
            rejected: state_dir.join("rejected"),
            app_token: state_dir.join("app-token"),
            datastore,
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
        fn visit_u64<E: Error>(self, n: u64) -> Result<Duration, E> {
            Ok(Duration::from_secs(n))
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
    fn negative_duration_is_rejected() {
        #[derive(Debug, Deserialize)]
        #[allow(dead_code)]
        struct Wrapper {
            #[serde(deserialize_with = "de_dur")]
            duration: Duration,
        }

        let err = toml::from_str::<Wrapper>("duration = -1").unwrap_err();
        assert!(err.to_string().contains("must not be negative"));

        // A bare integer deserializes through visit_u64 as whole seconds.
        let ok = toml::from_str::<Wrapper>("duration = 42").unwrap();
        assert_eq!(ok.duration, Duration::from_secs(42));

        // A wrong type surfaces the human-readable "expecting" description, not an
        // empty one.
        let type_err = toml::from_str::<Wrapper>("duration = true").unwrap_err();
        assert!(type_err.to_string().contains("duration like"), "{type_err}");
    }

    #[test]
    fn unsafe_zero_timeouts_are_rejected() {
        let cfg: Config = toml::from_str(
            r#"
            [repository]
            root = "/r"
            metadata_url = "http://x/m/"
            targets_url = "http://x/t/"
            [application]
            product = "app"
            install_root = "/app"
            [timeouts]
            check_interval = 0
            "#,
        )
        .unwrap();

        assert_eq!(
            cfg.validate().unwrap_err(),
            "timeouts.check_interval must be greater than zero"
        );
    }

    #[test]
    fn zero_health_threshold_and_limits_are_rejected() {
        let base = r#"
            [repository]
            root = "/r"
            metadata_url = "http://x/m/"
            targets_url = "http://x/t/"
            [application]
            product = "app"
            install_root = "/app"
        "#;
        let mut cfg: Config = toml::from_str(base).unwrap();
        cfg.timeouts.health_successes = 0;
        assert!(cfg.validate().unwrap_err().contains("health_successes"));

        let mut cfg: Config = toml::from_str(base).unwrap();
        cfg.repository.target_limit = 0;
        assert!(cfg.validate().unwrap_err().contains("target_limit"));
    }

    #[test]
    fn omitted_timeouts_take_defaults_partial_override() {
        let cfg: Config = toml::from_str(
            r#"
            [repository]
            root = "/etc/selfupdate/root.json"
            metadata_url = "http://x/m/"
            targets_url = "http://x/t/"
            [application]
            product = "app"
            install_root = "/app"
            args = ["--addr", "127.0.0.1:9090"]
            [timeouts]
            health_grace = "2m"
            "#,
        )
        .unwrap();
        cfg.validate().unwrap();
        // Overridden field takes the file value; the rest fall back to defaults.
        assert_eq!(cfg.timeouts.health_grace, Duration::from_secs(120));
        assert_eq!(cfg.timeouts.check_interval, Duration::from_secs(15));
        assert_eq!(cfg.timeouts.retry_after, Duration::from_secs(300));
        assert_eq!(cfg.repository.metadata_limit, 1 << 20);
        assert_eq!(cfg.repository.target_limit, 512 << 20);
        assert_eq!(cfg.application.channel, "stable");
    }

    #[test]
    fn reexec_without_health_url_is_rejected() {
        let cfg: Result<Config, _> = toml::from_str(
            r#"
            [repository]
            root = "/r"
            metadata_url = "http://x/m/"
            targets_url = "http://x/t/"
            [application]
            product = "app"
            install_root = "/app"
            [application.activation]
            mode = "reexec"
            command = ["kill", "-HUP", "{pid}"]
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
                [repository]
                root = "/r"
                metadata_url = "http://x/m/"
                targets_url = "http://x/t/"
                [application]
                product = "app"
                install_root = "/app"
                health_url = "http://127.0.0.1:9/healthz"
                [application.activation]
                mode = "reexec"
                command = ["kill", "-HUP", "{pid}"]
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
            [repository]
            root = "/r"
            metadata_url = "http://x/m/"
            targets_url = "http://x/t/"
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
