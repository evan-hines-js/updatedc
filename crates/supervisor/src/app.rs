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
    mode: updated_contracts::assignment::RuntimeMode,
}

impl App {
    /// The running application's PID, read from the guardian connection that launched and stops it
    /// rather than mirrored here: two copies of the same fact, written from the same call, diverge
    /// as soon as one launch path skips the other's write.
    pub(crate) fn pid(&self) -> Option<u32> {
        self.guardian.running_app()
    }

    pub(crate) fn traffic_ready(&mut self, ready: bool) -> Result<(), String> {
        self.guardian.traffic_ready(ready)
    }

    /// Ask the guardian to (re)launch the application, updating our PID.
    ///
    /// Provider-managed mode launches nothing — the signed node reconciler owns every application
    /// effect. Any process the guardian still holds when this mode is entered belongs to a previous
    /// managed contract (a supervisor that launched one and handed its PID across exec, or this
    /// process before an assignment changed the mode), so it is retired here, exactly once. That is
    /// what makes [`App::pid`] `None` for the whole of provider-managed mode: the agent neither
    /// exposes nor manipulates an application process, and there is no `--managed-pid` to leak into
    /// the reconciler's argv.
    pub(crate) fn launch(&mut self, opts: &Options) -> io::Result<()> {
        self.mode = opts.application.mode;
        if self.mode == updated_contracts::assignment::RuntimeMode::ProviderManaged {
            return match self.guardian.running_app() {
                Some(_) => self.guardian.stop().map_err(io::Error::other),
                None => Ok(()),
            };
        }
        let spec = app_spec(opts)?;
        // A guardian `Channel` failure becomes `io::ErrorKind::ConnectionReset` (see
        // `GuardianError`); the update path recognizes that and recovers instead of rejecting.
        self.guardian.launch(&spec)?;
        Ok(())
    }
}

/// Adopt the application the guardian is already running (no restart).
pub(crate) fn adopt(guardian: Guardian, opts: &Options, pid: u32) -> io::Result<App> {
    if opts.application.mode == updated_contracts::assignment::RuntimeMode::ProviderManaged {
        // There is nothing to adopt: the guardian can only offer a PID for a process from the
        // previous managed contract, and entering provider-managed mode retires that child (see
        // [`App::launch`]) rather than keeping it.
        return start(guardian, opts);
    }
    log(&format!(
        "adopted the running application (pid {pid}) the guardian already owns"
    ));
    Ok(App {
        guardian,
        mode: opts.application.mode,
    })
}

/// Launch a fresh application from the active release entrypoint.
pub(crate) fn start(guardian: Guardian, opts: &Options) -> io::Result<App> {
    let mut app = App {
        guardian,
        mode: opts.application.mode,
    };
    app.launch(opts)?;
    match app.pid() {
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
    if app.mode == updated_contracts::assignment::RuntimeMode::ProviderManaged {
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

    /// Options in the shape [`crate::options::parse_args`] produces for `mode`, with a local
    /// routing repository and no secrets so nothing here reaches the network. Only the runtime
    /// mode is under test; the rest is the layout every other field derives from.
    #[cfg(unix)]
    fn options(mode: updated_contracts::assignment::RuntimeMode) -> crate::Options {
        use updated::config::{Paths, Repository, Routing, Storage, Timeouts};
        let root = std::path::PathBuf::from("/nonexistent/updated-app-tests");
        let routing = Routing {
            root: root.join("enrollment/routing"),
            base_url: root.join("routing").display().to_string(),
            assignment: "assignments/agents/agent-test.json".into(),
            metadata_limit: 1 << 20,
            transport_timeout: std::time::Duration::from_secs(30),
            mtls: updated::tls::Identity::new(
                root.join("client.pem"),
                root.join("client.key"),
                root.join("ca.pem"),
            ),
        };
        crate::Options {
            deployment: "test".into(),
            secrets: crate::secrets::SecretManager::new(&routing, &[]).expect("a local repository"),
            paths: Paths::resolve(&root, &root.join("enrollment")),
            application: updated::config::Application {
                mode,
                product: "app".into(),
                channel: "stable".into(),
                install_root: root.clone(),
                args: Vec::new(),
                secrets: Vec::new(),
                inputs: BTreeMap::new(),
            },
            repository: Repository {
                metadata_limit: 1 << 20,
                target_limit: 1 << 20,
                transport_timeout: std::time::Duration::from_secs(30),
            },
            routing,
            timeouts: crate::BoundedTimeouts::new(Timeouts::default()),
            storage: Storage::default(),
            supervisor_update: crate::SupervisorUpdate {
                channel: "stable".into(),
                state_dir: root.join("state"),
                check_interval: std::time::Duration::from_secs(60),
            },
            identity_renewal: crate::IdentityRenewal {
                bootstrap: root.join("bootstrap.toml"),
                state_dir: root.join("enrollment"),
            },
        }
    }

    /// Entering provider-managed mode retires the application the guardian still owns, so the mode
    /// whose contract is that the agent never exposes or manipulates an application process has no
    /// PID to report. A boot that reaches this with a live app is ordinary: a rollback journal at
    /// `PredecessorStarted` plans `Acquire::Launch` while the recovery guard skips the quiesce, so
    /// the PID handed across exec is still on the connection. Leaving it there put a
    /// `--managed-pid` on every reconciler invocation and logged a managed PID for a runtime the
    /// agent does not own.
    #[cfg(unix)]
    #[test]
    fn entering_provider_managed_mode_retires_the_application_the_guardian_owns() {
        use updated_contracts::assignment::RuntimeMode;

        let (ours, theirs) = std::os::unix::net::UnixStream::pair().expect("socketpair");
        let peer = crate::guardian::answering(theirs, control::Response::Ok);
        let opts = options(RuntimeMode::ProviderManaged);
        let mut app = super::App {
            guardian: crate::guardian::Guardian::for_test(ours, Some(4321)),
            mode: RuntimeMode::Managed,
        };
        assert_eq!(app.pid(), Some(4321), "the launch environment seeded one");

        app.launch(&opts).expect("provider-managed launch");

        assert_eq!(app.pid(), None);
        peer.join().expect("the guardian was asked to stop it");
    }

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
