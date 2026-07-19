use super::*;
use control::CommandSpec;
use std::ffi::OsString;

/// The managed application, as the supervisor sees it through the guardian.
///
/// The guardian — the permanent parent process — owns the application: it launches,
/// stops, and (if it crashes) rolls it up. The supervisor never touches the process
/// directly and never polls it for liveness: if this supervisor is alive, the app is
/// alive, because the guardian tears the whole tower down when the app exits. `App` is a
/// thin handle bundling the control connection, the app's PID, and the per-launch health
/// token (persisted so a replacement supervisor that adopts the running app can still
/// verify its health responses).
pub(crate) struct App {
    pub(crate) guardian: Guardian,
    pid: u32,
    health_token: String,
}

impl App {
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }

    pub(crate) fn health_token(&self) -> &str {
        &self.health_token
    }

    /// Prove to the guardian that this supervisor initialized — commits a candidate
    /// supervisor handoff, and is a harmless no-op for an ordinary launch.
    pub(crate) fn signal_ready(&mut self) -> Result<(), String> {
        self.guardian.signal_ready()
    }

    pub(crate) fn traffic_ready(&mut self, ready: bool) -> Result<(), String> {
        self.guardian.traffic_ready(ready)
    }

    /// Ask the guardian to (re)launch the application, updating our PID/token. The token
    /// is persisted *before* the launch so a crash mid-launch never leaves a running app
    /// whose token we forgot.
    pub(crate) fn launch(&mut self, opts: &Options) -> io::Result<()> {
        let token = updated::rand::token()?;
        write_app_token(&opts.paths.app_token, &token)?;
        let spec = app_spec(opts, &token)?;
        let pid = self.guardian.launch(&spec).map_err(io::Error::other)?;
        self.pid = pid;
        self.health_token = token;
        Ok(())
    }
}

/// Adopt the application the guardian is already running (no restart). The health token
/// the previous supervisor persisted is reloaded so health checks still verify responses.
pub(crate) fn adopt(guardian: Guardian, opts: &Options, pid: u32) -> io::Result<App> {
    let health_token = read_app_token(&opts.paths.app_token)?;
    log(&format!(
        "adopted the running application (pid {pid}) the guardian already owns"
    ));
    Ok(App {
        guardian,
        pid,
        health_token,
    })
}

/// Launch a fresh application from the active release entrypoint.
pub(crate) fn start(guardian: Guardian, opts: &Options) -> io::Result<App> {
    let mut app = App {
        guardian,
        pid: 0,
        health_token: String::new(),
    };
    app.launch(opts)?;
    log(&format!("started application pid {}", app.pid));
    Ok(app)
}

/// The guardian⇄supervisor launch contract, as it appears in this process's own
/// environment. Only the supervisor is a party to it: neither the managed application nor
/// the operator's lifecycle provider may see the control endpoint, the readiness nonce, or the
/// chaos injection point, so every process this supervisor causes to be launched is
/// stripped of all of it.
pub(crate) const CONTROL_PLANE_ENV: &[&str] = &[
    control::CONTROL_ENV,
    control::READY_NONCE_ENV,
    control::STATE_DIR_ENV,
    control::APP_PID_ENV,
    env::CHAOS_POINT,
];

pub(crate) fn is_control_plane_env(key: &std::ffi::OsStr) -> bool {
    CONTROL_PLANE_ENV
        .iter()
        .any(|candidate| key == std::ffi::OsStr::new(candidate))
}

/// Build the application launch spec: the configured command, plus the full environment
/// the guardian should apply — the supervisor's own environment with the control-channel
/// plumbing stripped and the per-launch health token added.
fn app_spec(opts: &Options, health_token: &str) -> io::Result<CommandSpec> {
    let release = updated::bundle::read_active(&opts.paths.active_release)?
        .ok_or_else(|| io::Error::other("active-release is missing"))?;
    // The supervisor never parses the release: it asks the provider how to launch the
    // identity it committed. The default provider resolves the manifested entrypoint.
    let launch = updated::provider::BundleStore::for_app(&opts.paths).resolve(&release)?;
    let mut envs: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(key, _)| !is_control_plane_env(key))
        .collect();
    envs.push((
        OsString::from(env::HEALTH_TOKEN),
        OsString::from(health_token),
    ));
    envs.push((
        OsString::from(env::INSTALL_ROOT),
        opts.paths.install_root.as_os_str().into(),
    ));
    Ok(CommandSpec {
        program: launch.program.into_os_string(),
        args: opts.application.args.iter().map(OsString::from).collect(),
        env: envs,
        cwd: Some(launch.cwd.into_os_string()),
    })
}

fn write_app_token(path: &Path, token: &str) -> io::Result<()> {
    foundation::durable::atomic_write(path, ".app-token-", token.as_bytes())
}

fn read_app_token(path: &Path) -> io::Result<String> {
    let token = std::fs::read_to_string(path)?.trim().to_string();
    if token.len() != 64 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "persisted application health token is invalid",
        ));
    }
    Ok(token)
}

fn clear_app_token(path: &Path) -> io::Result<()> {
    foundation::durable::remove_file(path)
}

/// Ask the guardian to stop the application (it escalates to a hard kill), then clear the
/// persisted health token. The single path for quiescing the running app — before
/// activating a release, and when the boot planner stops an uncommitted candidate.
pub(crate) fn stop(guardian: &mut Guardian, app_token: &Path) -> io::Result<()> {
    guardian.stop().map_err(io::Error::other)?;
    clear_app_token(app_token)
}

// ------------------------------- health probe -------------------------------

/// The one HTTP sampling path for every application-health policy.
///
/// A supervisor owns one of these and reuses its connection pool. More importantly,
/// callers can sample a URL once and feed that observation to every tagged policy that
/// references it; readiness and liveness must not disagree merely because a flapping
/// endpoint was requested twice in the same tick.
pub(crate) struct HealthProbe {
    client: reqwest::Client,
}

impl HealthProbe {
    pub(crate) fn new() -> io::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(1))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(io::Error::other)?;
        Ok(Self { client })
    }

    pub(crate) async fn sample(
        &self,
        app: &App,
        url: &str,
        expected_version: Option<&str>,
        timeout: Option<Duration>,
    ) -> bool {
        let mut request = self.client.get(url);
        if let Some(timeout) = timeout {
            request = request.timeout(timeout);
        }
        let Ok(response) = request.send().await else {
            return false;
        };
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|value| value.to_str().ok())
        };
        response.status().is_success()
            && health_headers_match(
                app.health_token(),
                expected_version,
                header(health::TOKEN_HEADER),
                header(health::VERSION_HEADER),
            )
    }
}

/// Whether the application became (and stayed) healthy within `grace`, via the HTTP readiness
/// probe. Without a health URL, simply surviving the window is healthy; with one, the URL must
/// answer with the launch token (and, for an in-place reload, `expected_version`) `successes`
/// times consecutively. A release that ships a health-check provider is gated by
/// [`crate::update::became_healthy_via_provider`] instead.
pub(crate) async fn became_healthy(
    app: &App,
    grace: Duration,
    health_check_url: Option<&str>,
    expected_version: Option<&str>,
    successes: u32,
    interval: Duration,
) -> io::Result<bool> {
    let deadline = Instant::now() + grace;

    let Some(url) = health_check_url else {
        tokio::time::sleep(grace).await;
        return Ok(true);
    };

    let probe = HealthProbe::new()?;
    let mut readiness = Readiness::new(successes);
    let mut next_probe = Instant::now();
    while Instant::now() < deadline {
        if Instant::now() >= next_probe {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let ok = probe
                .sample(
                    app,
                    url,
                    expected_version,
                    Some(remaining.min(Duration::from_secs(1))),
                )
                .await;
            if readiness.observe(ok) {
                return Ok(true);
            }
            // Space out the confirmation probes only after a success; keep polling promptly
            // until the app first answers.
            if ok {
                next_probe = Instant::now() + interval;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Ok(false)
}

/// Progress toward readiness: a run of `need` consecutive healthy probes, any failure
/// resetting the run. Pure — the async loop feeds it probe outcomes — so the
/// consecutive-successes gate is provable without a server. Shared by the HTTP probe here and
/// the health-check-provider probe in [`crate::update`].
pub(crate) struct Readiness {
    need: u32,
    consecutive: u32,
}

impl Readiness {
    pub(crate) fn new(successes: u32) -> Self {
        Readiness {
            need: successes.max(1),
            consecutive: 0,
        }
    }

    /// Fold in one probe outcome; `true` once enough consecutive successes are seen.
    pub(crate) fn observe(&mut self, healthy: bool) -> bool {
        if healthy {
            self.consecutive += 1;
            self.consecutive >= self.need
        } else {
            self.consecutive = 0;
            false
        }
    }
}

/// Whether the app's *optional* identity headers are consistent with this launch.
///
/// Both signals are best-effort. An app that echoes the launch token — and, for a reload,
/// its version — gets the stronger check: a forged or stale process answering on the port
/// is caught. An off-the-shelf app (Magnolia, nginx, …) that returns neither is trusted on
/// its 2xx alone. The supervisor observes the app; it never forces a protocol onto it.
///
/// A header that is *present but wrong* still fails — that is a forged or stale answer, not
/// an absent one. Only genuine absence is skipped.
pub(crate) fn health_headers_match(
    expected_token: &str,
    expected_version: Option<&str>,
    token: Option<&str>,
    version: Option<&str>,
) -> bool {
    token.is_none_or(|actual| actual == expected_token)
        && expected_version.is_none_or(|expected| version.is_none_or(|actual| actual == expected))
}

// ------------------------------- async waits --------------------------------

/// Sleep, returning `true` early if shutdown was requested.
pub(crate) async fn sleep_interruptible(delay: Duration, shutdown: &AtomicBool) -> bool {
    let deadline = Instant::now() + delay;
    while Instant::now() < deadline {
        if shutdown.load(Ordering::SeqCst) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    shutdown.load(Ordering::SeqCst)
}

/// Resolve when the OS asks the supervisor to stop.
#[cfg(unix)]
pub(crate) async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut int = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(_) => return,
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}
#[cfg(windows)]
pub(crate) async fn wait_for_shutdown_signal() {
    use tokio::signal::windows::{ctrl_c, ctrl_close, ctrl_shutdown};
    let (mut c, mut close, mut down) = match (ctrl_c(), ctrl_close(), ctrl_shutdown()) {
        (Ok(c), Ok(close), Ok(down)) => (c, close, down),
        _ => return,
    };
    tokio::select! {
        _ = c.recv() => {}
        _ = close.recv() => {}
        _ = down.recv() => {}
    }
}

#[cfg(test)]
mod tests {
    use super::{health_headers_match, read_app_token, Readiness};

    #[test]
    fn readiness_needs_consecutive_successes_and_a_failure_resets_the_run() {
        let mut r = Readiness::new(3);
        assert!(!r.observe(true)); // 1
        assert!(!r.observe(true)); // 2
        assert!(!r.observe(false), "a failure resets the run");
        assert!(!r.observe(true)); // 1 again
        assert!(!r.observe(true)); // 2
        assert!(r.observe(true), "the third consecutive success is ready");
    }

    #[test]
    fn a_single_required_success_is_ready_at_once() {
        let mut r = Readiness::new(1);
        assert!(!r.observe(false));
        assert!(r.observe(true));
    }

    #[test]
    fn zero_successes_is_treated_as_one() {
        // `successes` is clamped to at least 1 so a misconfig never declares readiness on
        // no evidence.
        let mut r = Readiness::new(0);
        assert!(r.observe(true));
    }

    #[test]
    fn persisted_health_tokens_fail_closed_when_missing_empty_or_malformed() {
        let root = std::env::temp_dir().join(format!("updated-app-token-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("token");

        assert!(read_app_token(&path).is_err());
        std::fs::write(&path, b"\n").unwrap();
        assert!(read_app_token(&path).is_err());
        std::fs::write(&path, b"not-a-token\n").unwrap();
        assert!(read_app_token(&path).is_err());
        let valid = "0123456789abcdef".repeat(4);
        std::fs::write(&path, format!("{valid}\n")).unwrap();
        assert_eq!(read_app_token(&path).unwrap(), valid);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn identity_headers_are_optional_but_a_wrong_one_still_fails() {
        // An off-the-shelf app (Magnolia, nginx) that returns no identity headers is healthy
        // on its 2xx alone — absence is skipped, never a failure.
        assert!(health_headers_match("tok", None, None, None));
        assert!(health_headers_match("tok", Some("2.0.0"), None, None));
        // A cooperating app that echoes the launch token keeps the stronger check.
        assert!(health_headers_match("tok", None, Some("tok"), None));
        assert!(health_headers_match("tok", Some("2.0.0"), Some("tok"), Some("2.0.0")));
        // A header that is present but wrong is a forged or stale answer — still rejected.
        assert!(!health_headers_match("tok", None, Some("forged"), None));
        assert!(!health_headers_match("tok", Some("2.0.0"), Some("tok"), Some("1.0.0")));
        // A missing version when one was expected is skipped (best-effort), not a failure.
        assert!(health_headers_match("tok", Some("2.0.0"), Some("tok"), None));
    }
}
