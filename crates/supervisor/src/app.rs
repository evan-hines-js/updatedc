use super::*;
use control::CommandSpec;
use std::ffi::OsString;

/// The managed application, as the supervisor sees it through the guardian.
///
/// The guardian — the permanent parent process — owns the application: it launches,
/// stops, and (if it crashes) rolls it up. The supervisor never touches the process
/// directly and never polls it for liveness: if this supervisor is alive, the app is
/// alive, because the guardian tears the whole tower down when the app exits. `App` is a
/// thin handle bundling the control connection and the app's PID.
pub(crate) struct App {
    pub(crate) guardian: Guardian,
    pid: Option<u32>,
    mode: updated::config::RuntimeMode,
}

impl App {
    pub(crate) fn pid(&self) -> Option<u32> {
        self.pid
    }

    /// Prove to the guardian that this supervisor initialized — commits a candidate
    /// supervisor handoff, and is a harmless no-op for an ordinary launch.
    pub(crate) fn signal_ready(&mut self) -> Result<(), String> {
        self.guardian.signal_ready()
    }

    pub(crate) fn traffic_ready(&mut self, ready: bool) -> Result<(), String> {
        self.guardian.traffic_ready(ready)
    }

    /// Ask the guardian to (re)launch the application, updating our PID.
    pub(crate) fn launch(&mut self, opts: &Options) -> io::Result<()> {
        self.mode = opts.application.mode;
        if self.mode == updated::config::RuntimeMode::ProviderManaged {
            self.pid = None;
            return Ok(());
        }
        let spec = app_spec(opts)?;
        // A guardian `Channel` failure becomes `io::ErrorKind::ConnectionReset` (see
        // `GuardianError`); the update path recognizes that and recovers instead of rejecting.
        let pid = self.guardian.launch(&spec)?;
        self.pid = Some(pid);
        Ok(())
    }
}

/// Adopt the application the guardian is already running (no restart).
pub(crate) fn adopt(mut guardian: Guardian, opts: &Options, pid: u32) -> io::Result<App> {
    if opts.application.mode == updated::config::RuntimeMode::ProviderManaged {
        // The guardian can only offer a PID for a process from the previous managed contract.
        // Retire that owned child exactly once before entering provider-managed mode; after this
        // agent never manipulates an application process.
        guardian.stop().map_err(io::Error::other)?;
        return start(guardian, opts);
    }
    log(&format!(
        "adopted the running application (pid {pid}) the guardian already owns"
    ));
    Ok(App {
        guardian,
        pid: Some(pid),
        mode: opts.application.mode,
    })
}

/// Launch a fresh application from the active release entrypoint.
pub(crate) fn start(guardian: Guardian, opts: &Options) -> io::Result<App> {
    let mut app = App {
        guardian,
        pid: None,
        mode: opts.application.mode,
    };
    app.launch(opts)?;
    match app.pid {
        Some(pid) => log(&format!("started managed application pid {pid}")),
        None => log("started provider-managed runtime (no application process is owned)"),
    }
    Ok(app)
}

/// Build the application launch spec: the configured command, plus the full environment
/// the guardian should apply. It is constructed explicitly: no supervisor ambient variable,
/// control-channel value, or fetched secret can cross this boundary accidentally.
fn app_spec(opts: &Options) -> io::Result<CommandSpec> {
    let release = updated::bundle::read_active(&opts.paths.active_release)?
        .ok_or_else(|| io::Error::other("active-release is missing"))?;
    // The supervisor never parses the release: it asks the provider how to launch the
    // identity it committed. The default provider resolves the manifested entrypoint.
    let launch = updated::provider::BundleStore::for_app(&opts.paths).resolve(&release)?;
    let mut envs = platform_environment();
    envs.push((
        OsString::from(env::INSTALL_ROOT),
        opts.paths.install_root.as_os_str().into(),
    ));
    apply_secret_environment(&mut envs, opts.secrets.values());
    Ok(CommandSpec {
        program: launch.program.into_os_string(),
        args: opts.application.args.iter().map(OsString::from).collect(),
        env: envs,
        cwd: Some(launch.cwd.into_os_string()),
    })
}

fn platform_environment() -> Vec<(OsString, OsString)> {
    #[cfg(windows)]
    {
        ["SystemRoot", "WINDIR"]
            .into_iter()
            .filter_map(|name| std::env::var_os(name).map(|value| (name.into(), value)))
            .collect()
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

fn apply_secret_environment(
    envs: &mut Vec<(OsString, OsString)>,
    secrets: &std::collections::BTreeMap<String, String>,
) {
    for (name, value) in secrets {
        envs.retain(|(key, _)| key != std::ffi::OsStr::new(name));
        envs.push((OsString::from(name), OsString::from(value)));
    }
}

/// Ask the guardian to stop the application (it escalates to a hard kill). The single path
/// for quiescing the running app — before activating a release, and when the boot planner
/// stops an uncommitted candidate.
pub(crate) fn stop(guardian: &mut Guardian) -> io::Result<()> {
    guardian.stop().map_err(io::Error::other)
}

/// Stop the runtime only when the guardian owns it. In provider-managed mode the signed node
/// reconciler is the sole authority for application effects.
pub(crate) fn stop_runtime(app: &mut App) -> io::Result<()> {
    if app.mode == updated::config::RuntimeMode::ProviderManaged {
        return Ok(());
    }
    stop(&mut app.guardian)
}

/// Progress toward readiness: a run of `need` consecutive healthy probes, any failure
/// resetting the run. Pure — the async loop feeds it probe outcomes — so the
/// consecutive-successes gate is provable without a provider process.
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
    use super::{apply_secret_environment, Readiness};
    use std::collections::BTreeMap;
    use std::ffi::OsString;

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
    fn assigned_secrets_replace_ambient_values_without_duplicates() {
        let mut environment = vec![
            (
                OsString::from("DATABASE_PASSWORD"),
                OsString::from("ambient"),
            ),
            (OsString::from("PATH"), OsString::from("/bin")),
        ];
        let secrets = BTreeMap::from([
            ("DATABASE_PASSWORD".into(), "assigned".into()),
            ("API_TOKEN".into(), "token".into()),
        ]);
        apply_secret_environment(&mut environment, &secrets);
        assert_eq!(
            environment
                .iter()
                .filter(|(name, _)| name == "DATABASE_PASSWORD")
                .count(),
            1
        );
        assert!(environment.contains(&(
            OsString::from("DATABASE_PASSWORD"),
            OsString::from("assigned")
        )));
        assert!(environment.contains(&(OsString::from("API_TOKEN"), OsString::from("token"))));
    }
}
