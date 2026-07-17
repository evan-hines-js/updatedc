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
    /// First-install baseline version, used only until an update commits real state.
    #[serde(default)]
    pub current_version: Option<String>,
    /// Installer-provisioned SHA-256 of the first-install baseline. Required together
    /// with `current_version` when no installed-state record exists.
    #[serde(default)]
    pub current_sha256: Option<String>,
    /// The managed program and its arguments; element 0 is the binary path.
    pub command: Vec<String>,
    /// Readiness probe; omit for liveness-only (survive the health grace = healthy).
    #[serde(default)]
    pub health_url: Option<String>,
    /// Zero-downtime reload executable and arguments (Unix, requires `health_url`).
    /// Exact `{pid}` and `{binary}` arguments are expanded without invoking a shell.
    #[serde(default)]
    pub reload_command: Option<Vec<String>>,
    /// Installed-target record location; defaults to `<binary>.installed`.
    #[serde(default)]
    pub state: Option<PathBuf>,
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
        if self.application.command.is_empty() {
            return Err("application.command must name the program to run".into());
        }
        if self.application.reload_command.is_some() && !cfg!(unix) {
            return Err("application.reload_command is supported only on Unix".into());
        }
        if self.application.reload_command.is_some() && self.application.health_url.is_none() {
            return Err("application.reload_command requires application.health_url".into());
        }
        if self
            .application
            .reload_command
            .as_ref()
            .is_some_and(Vec::is_empty)
        {
            return Err("application.reload_command must name an executable".into());
        }
        if let Some(v) = &self.application.current_version {
            semver::Version::parse(v).map_err(|e| format!("application.current_version: {e}"))?;
        }
        if self.application.current_version.is_some() != self.application.current_sha256.is_some() {
            return Err("application.current_version and application.current_sha256 must be configured together".into());
        }
        if let Some(sha) = &self.application.current_sha256 {
            if sha.len() != 64 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(
                    "application.current_sha256 must be a 64-character hexadecimal SHA-256 digest"
                        .into(),
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
        if self.repository.target_limit == 0 {
            return Err("repository.target_limit must be greater than zero".into());
        }
        Ok(())
    }
}

/// The canonical on-disk layout the tower derives from `[application]` +
/// `[repository]`: the (canonicalized) binary, its committed-state record, the TUF
/// metadata cache, the update staging file, and the transaction / rejected / app-token
/// siblings. Every consumer — the supervisor and the one-shot updater — resolves through
/// [`Config::resolve_paths`] so none of them re-derive `<binary>.installed` or
/// `<state>.tuf` by hand and drift apart.
#[derive(Debug, Clone)]
pub struct Paths {
    /// The managed binary (absolute; `application.command[0]` canonicalized).
    pub binary: PathBuf,
    /// Committed installed-target record (`application.state`, else `<binary>.installed`).
    pub state: PathBuf,
    /// Persistent TUF metadata cache (`repository.datastore`, else `<state>.tuf`).
    pub datastore: PathBuf,
    /// Where a verified target is streamed before the swap (`<binary>.download`).
    pub download: PathBuf,
    /// The update transaction journal (`<state>.transaction`).
    pub journal: PathBuf,
    /// Persisted hashes of releases that failed their health check (`<state>.rejected`).
    pub rejected: PathBuf,
    /// The current app launch's health token, persisted so a replacement supervisor
    /// that re-adopts the running app can still verify its health responses
    /// (`<state>.apptoken`). The guardian owns the process; this is the one bit of
    /// per-launch app state the supervisor keeps.
    pub app_token: PathBuf,
}

impl Config {
    /// Resolve the canonical [`Paths`], applying the tower-wide defaults. The binary
    /// is canonicalized, so it must already exist (the installer places the baseline).
    pub fn resolve_paths(&self) -> Result<Paths, String> {
        let binary = std::fs::canonicalize(&self.application.command[0]).map_err(|e| {
            format!(
                "cannot resolve application binary {:?}: {e} (use an absolute path)",
                self.application.command[0]
            )
        })?;
        let state = self
            .application
            .state
            .clone()
            .unwrap_or_else(|| default_state_path(&binary));
        let datastore = self
            .repository
            .datastore
            .clone()
            .unwrap_or_else(|| with_suffix(&state, ".tuf"));
        Ok(Paths {
            download: with_suffix(&binary, ".download"),
            journal: with_suffix(&state, ".transaction"),
            rejected: with_suffix(&state, ".rejected"),
            app_token: with_suffix(&state, ".apptoken"),
            datastore,
            state,
            binary,
        })
    }
}

/// Default committed-state record for an application binary.
fn default_state_path(binary: &Path) -> PathBuf {
    with_suffix(binary, ".installed")
}

/// Append `suffix` to a path's final component — `foo` + `.old` ⇒ `foo.old`. The
/// tower's one way to name a sibling of a state or binary file.
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
            command = ["app"]
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
            command = ["app"]
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
            command = ["app", "--addr", "127.0.0.1:9090"]
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
    fn reload_without_health_url_is_rejected() {
        let cfg: Result<Config, _> = toml::from_str(
            r#"
            [repository]
            root = "/r"
            metadata_url = "http://x/m/"
            targets_url = "http://x/t/"
            [application]
            product = "app"
            command = ["app"]
            reload_command = ["kill", "-HUP", "{pid}"]
            "#,
        );
        // Parses, but validation rejects it (Unix) or the platform guard does.
        if let Ok(cfg) = cfg {
            assert!(cfg.validate().is_err());
        }

        // With health_url present, a reload_command is valid on Unix — the case that
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
                command = ["app"]
                health_url = "http://127.0.0.1:9/healthz"
                reload_command = ["kill", "-HUP", "{pid}"]
                "#,
            )
            .unwrap();
            cfg.validate().unwrap();
        }
    }

    #[test]
    fn installer_baseline_requires_a_version_and_valid_digest_pair() {
        let base = r#"
            [repository]
            root = "/r"
            metadata_url = "http://x/m/"
            targets_url = "http://x/t/"
            [application]
            product = "app"
            command = ["app"]
        "#;
        let mut cfg: Config = toml::from_str(base).unwrap();
        cfg.application.current_version = Some("1.0.0".into());
        assert!(cfg.validate().unwrap_err().contains("configured together"));

        cfg.application.current_sha256 = Some("not-a-digest".into());
        assert!(cfg.validate().unwrap_err().contains("64-character"));

        // Right charset but wrong length is still rejected: the guard is "wrong length
        // OR non-hex", not "wrong length AND non-hex".
        cfg.application.current_sha256 = Some("a".repeat(63));
        assert!(cfg.validate().unwrap_err().contains("64-character"));
        // Right length but non-hex is rejected too.
        cfg.application.current_sha256 = Some("g".repeat(64));
        assert!(cfg.validate().unwrap_err().contains("64-character"));

        cfg.application.current_sha256 = Some("a".repeat(64));
        cfg.validate().unwrap();
    }

    #[test]
    fn resolve_paths_derives_the_canonical_sibling_layout() {
        let dir = std::env::temp_dir().join(format!("cfg-paths-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("app");
        std::fs::write(&bin, b"#!/bin/sh\n").unwrap();

        let mut cfg: Config = toml::from_str(
            r#"
            [repository]
            root = "/r"
            metadata_url = "http://x/m/"
            targets_url = "http://x/t/"
            [application]
            product = "app"
            command = ["app"]
            "#,
        )
        .unwrap();
        cfg.application.command = vec![bin.to_str().unwrap().to_string()];

        let paths = cfg.resolve_paths().unwrap();
        let canon = std::fs::canonicalize(&bin).unwrap();
        // Absent [application].state, the record defaults to `<binary>.installed`, and
        // every sibling is derived from it — not left empty.
        assert_eq!(paths.state, with_suffix(&canon, ".installed"));
        assert_eq!(paths.datastore, with_suffix(&paths.state, ".tuf"));
        assert_eq!(paths.download, with_suffix(&canon, ".download"));
        assert_eq!(paths.journal, with_suffix(&paths.state, ".transaction"));
        assert_eq!(paths.rejected, with_suffix(&paths.state, ".rejected"));
        assert_eq!(paths.app_token, with_suffix(&paths.state, ".apptoken"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
