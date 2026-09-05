#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Native Windows SCM host for the installer-owned agent.
//!
//! The service owns the agent as a contained tree: it is spawned into a kill-on-close job object,
//! so it cannot outlive the service process that reports its state to the SCM.
//!
//! It reports an agent that exits on its own to the SCM as a service failure — restarts are
//! the SCM's recovery actions, not a second loop in here — and translates SERVICE_CONTROL_STOP
//! into CTRL_BREAK for the agent's process group.

#[cfg(not(windows))]
fn main() {
    eprintln!("updated-agent-service is only supported on Windows");
}

#[cfg(windows)]
mod windows {
    use std::ffi::{c_void, OsString};
    use std::io::Write as _;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
    use std::sync::OnceLock;
    use std::time::Duration;

    use windows_sys::Win32::Foundation::{ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR};
    use windows_sys::Win32::System::Services::*;

    use foundation::process::ContainedChild;

    const AGENT_LOG: &str = "agent.log";
    const PREVIOUS_AGENT_LOG: &str = "agent.previous.log";
    const MAX_AGENT_LOG_BYTES: u64 = 4 * 1024 * 1024;
    const STOP_GRACE: Duration = Duration::from_secs(20);
    /// How often the agent is re-checked while watching it and while stopping it.
    const POLL: Duration = Duration::from_millis(100);
    static STOP: AtomicBool = AtomicBool::new(false);
    static STATUS: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
    static ARGS: OnceLock<Args> = OnceLock::new();

    #[derive(Clone, Debug)]
    struct Args {
        state_dir: OsString,
        config: Option<OsString>,
        agent: OsString,
    }

    pub fn main() {
        match parse_args() {
            Ok(args) => {
                let _ = ARGS.set(args);
            }
            Err(e) => {
                eprintln!("updated-agent-service: {e}");
                std::process::exit(2);
            }
        }
        // SCM ignores this table name for an OWN_PROCESS service. Its actual registered name
        // arrives in service_main, so the installer remains the only source of that identity.
        let mut name = [0_u16];
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: name.as_mut_ptr(),
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: null_mut(),
                lpServiceProc: None,
            },
        ];
        if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } == 0 {
            service_diagnostic(&format!(
                "StartServiceCtrlDispatcherW failed: {}",
                std::io::Error::last_os_error()
            ));
            std::process::exit(1);
        }
    }

    fn parse_args() -> Result<Args, String> {
        parse_from(std::env::args_os().skip(1))
    }

    /// Every flag here takes a value, and a flag without one is an error — including the
    /// optional `--config`.
    fn parse_from(args: impl IntoIterator<Item = OsString>) -> Result<Args, String> {
        let mut state_dir = None;
        let mut config = None;
        let mut agent = None;
        fn value(it: &mut impl Iterator<Item = OsString>, flag: &str) -> Result<OsString, String> {
            it.next().ok_or_else(|| format!("{flag} needs a value"))
        }
        let mut it = args.into_iter();
        while let Some(arg) = it.next() {
            match arg.to_string_lossy().as_ref() {
                "--state-dir" => state_dir = Some(value(&mut it, "--state-dir")?),
                "--config" => config = Some(value(&mut it, "--config")?),
                "--agent" => agent = Some(value(&mut it, "--agent")?),
                other => return Err(format!("unknown argument {other:?}")),
            }
        }
        Ok(Args {
            state_dir: state_dir.ok_or("--state-dir <path> is required")?,
            config,
            agent: agent.ok_or("--agent <path> is required")?,
        })
    }

    unsafe extern "system" fn service_main(argc: u32, argv: *mut windows_sys::core::PWSTR) {
        if argc == 0 || argv.is_null() {
            service_diagnostic("SCM did not supply the registered service name");
            return;
        }
        // SAFETY: SCM supplies argc argument pointers for this callback; argv[0] is the
        // registered service name, valid until the callback returns.
        let name = unsafe { *argv };
        if name.is_null() {
            service_diagnostic("SCM supplied a null service name");
            return;
        }
        let handle = unsafe { RegisterServiceCtrlHandlerExW(name, Some(control_handler), null()) };
        if handle.is_null() {
            return;
        }
        STATUS.store(handle, Ordering::SeqCst);
        report(SERVICE_START_PENDING, 0, 5_000, NO_ERROR);
        // Accept SHUTDOWN as well as STOP. Without it the SCM sends nothing on an OS restart: the
        // agent is killed outright, skipping the clean stop a requested
        // stop performs — the one moment a graceful shutdown matters most.
        report(
            SERVICE_RUNNING,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
            0,
            NO_ERROR,
        );
        // Report the outcome to the SCM, not just to stderr: `sc failure`/`sc failureflag`
        // recovery actions (see deploy/windows/install-updated-agent.bat) fire only
        // on a STOPPED report carrying a non-zero exit code. Reporting a clean stop after a
        // failure leaves the whole stack down with the SCM believing all is well.
        let exit = run_service();
        if let Err(e) = &exit {
            service_diagnostic(e);
        }
        report(SERVICE_STOPPED, 0, 0, exit_code(&exit));
    }

    /// The SCM exit code for a service outcome: `NO_ERROR` for a requested stop, else
    /// `ERROR_SERVICE_SPECIFIC_ERROR` (which directs the SCM to `dwServiceSpecificExitCode`).
    fn exit_code(outcome: &Result<(), String>) -> u32 {
        match outcome {
            Ok(()) => NO_ERROR,
            Err(_) => ERROR_SERVICE_SPECIFIC_ERROR,
        }
    }

    unsafe extern "system" fn control_handler(
        control: u32,
        _event_type: u32,
        _event_data: *mut c_void,
        _context: *mut c_void,
    ) -> u32 {
        // An OS shutdown is handled exactly like a stop: stop the agent cleanly.
        if control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN {
            STOP.store(true, Ordering::SeqCst);
            // The hint must cover the FULL stop: the grace period AND the hard kill and reap that
            // follow it. Reporting exactly the grace tells the SCM the service is late at the very
            // moment it is doing the right thing, and it kills the agent mid-stop.
            report(
                SERVICE_STOP_PENDING,
                0,
                (STOP_GRACE + foundation::process::KILL_HEADROOM).as_millis() as u32,
                NO_ERROR,
            );
        }
        NO_ERROR
    }

    /// Restarting an agent that will not spawn is the SCM's job, not ours: reporting the
    /// failure (see `report`) triggers the `sc failure` recovery actions the installer
    /// configures, which retry with escalating backoff and give up cleanly. Retrying in
    /// here as well would be a second restart path that reports success while looping.
    fn run_service() -> Result<(), String> {
        let mut child = spawn_agent()?;
        if monitor(&mut child) {
            return Ok(());
        }
        // The agent exited on its own. Report it as a service failure instead of restarting
        // here: the SCM's recovery actions retry with escalating backoff and eventually give up
        // visibly, whereas an in-process retry loop restarts an agent that fails immediately —
        // forever, on a fixed delay — while the SCM is told the service is running fine.
        let status = child.try_wait().ok().flatten().and_then(|s| s.code());
        Err(match status {
            Some(code) => format!("the agent exited with code {code}"),
            None => "the agent exited".to_string(),
        })
    }

    /// Watch the agent until a stop is requested or it exits on its own. Returns true for the
    /// requested stop (the caller reports a clean STOPPED) and false when it exited by itself
    /// (reported to the SCM as a failure).
    ///
    /// It never returns while the agent is still running, and no failure inside it is
    /// propagated: a STOPPED report — clean or failed — is the moment the SCM may start another
    /// service process, and the configured recovery action does exactly that on a failure. A
    /// agent that outlived this wrapper would then meet a second agent over the same state.
    fn monitor(child: &mut ContainedChild) -> bool {
        loop {
            if STOP.load(Ordering::SeqCst) {
                stop_agent(child);
                return true;
            }
            match child.try_wait() {
                Ok(Some(_)) => return false,
                Ok(None) => std::thread::sleep(POLL),
                Err(error) => {
                    // The handle is unusable, so the agent can no longer be observed — it may
                    // well still be running. Take the tree down before reporting anything.
                    service_diagnostic(&format!("watching the agent failed ({error})"));
                    stop_agent(child);
                    return false;
                }
            }
        }
    }

    /// Stop the agent tree: a graceful console break first, then a hard kill of the whole
    /// job. Returns only once it is gone, or once the kill has been issued and the wait for it
    /// has been given [`foundation::process::KILL_HEADROOM`] — the same budget the SCM was told
    /// to expect.
    ///
    /// Failures are logged, never propagated, and the last resort is structural rather than
    /// reported: the tree lives in a kill-on-close job object, so dropping `child` when this
    /// wrapper exits takes down anything that survived. There is no path on which an agent
    /// outlives the service process that owns it.
    fn stop_agent(child: &mut ContainedChild) {
        // The whole sequence — graceful console break, grace, hard kill of the job, reap — is
        // `ContainedChild::stop`'s, including the decision to skip the grace when the break event
        // could not be delivered. This wrapper only reports what it took.
        match child.stop(STOP_GRACE) {
            foundation::process::Stopped::Gracefully | foundation::process::Stopped::Killed => {}
            foundation::process::Stopped::Surviving => service_diagnostic(
                "the agent did not exit after being killed; its kill-on-close job takes it \
                 down as this process exits",
            ),
        }
    }

    fn spawn_agent() -> Result<ContainedChild, String> {
        let args = ARGS.get().ok_or("service arguments unavailable")?;
        let mut command = Command::new(&args.agent);
        command.env("UPDATED_STATE_DIR", &args.state_dir);
        if let Some(config) = &args.config {
            command.arg("--config").arg(config);
        }
        // A service process has no console, and the fresh console the agent is given below is
        // attached to nothing: every line the agent writes to stderr — its only
        // diagnostics — would vanish with it. Append the whole tree's output to a file in the
        // state directory instead, where an operator (or CI) can read why a boot ended.
        let mut stdout = open_agent_log(Path::new(&args.state_dir))?;
        writeln!(
            stdout,
            "\n--- updated-agent-service starting agent {:?} ---",
            args.agent
        )
        .map_err(|e| format!("writing agent log header: {e}"))?;
        let stderr = stdout
            .try_clone()
            .map_err(|e| format!("duplicating agent log handle: {e}"))?;
        command
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        // Contained: the agent and everything below it belong to a kill-on-close job object
        // this process owns, so it can never survive the service process that reports its
        // state to the SCM. A service has no console, so the agent is given one — that is what
        // makes `request_stop`'s graceful break addressable at all.
        ContainedChild::spawn_in_new_console(command)
            .map_err(|e| format!("launching agent {:?}: {e}", args.agent))
    }

    /// Keep one bounded current log and one bounded predecessor. The SCM wrapper and agent share
    /// this sink so a process-boundary failure can never be hidden by
    /// the service's detached console.
    fn open_agent_log(state_dir: &Path) -> Result<std::fs::File, String> {
        let current = state_dir.join(AGENT_LOG);
        let previous = state_dir.join(PREVIOUS_AGENT_LOG);
        if current
            .metadata()
            .map(|metadata| metadata.len() >= MAX_AGENT_LOG_BYTES)
            .unwrap_or(false)
        {
            match std::fs::remove_file(&previous) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(format!("removing previous agent log {previous:?}: {error}"));
                }
            }
            std::fs::rename(&current, &previous).map_err(|error| {
                format!("rotating agent log {current:?} to {previous:?}: {error}")
            })?;
        }
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&current)
            .map_err(|error| format!("opening agent log {current:?}: {error}"))
    }

    /// Service-host diagnostics use the same durable stream as the agent. The
    /// `eprintln!` remains useful when this binary is run interactively; the append is what makes
    /// the message observable when the SCM owns a process with no attached console.
    fn service_diagnostic(message: &str) {
        eprintln!("updated-agent-service: {message}");
        let Some(args) = ARGS.get() else {
            return;
        };
        let path = Path::new(&args.state_dir).join(AGENT_LOG);
        if let Ok(mut log) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
        {
            let _ = writeln!(log, "updated-agent-service: {message}");
        }
    }

    fn report(
        state: SERVICE_STATUS_CURRENT_STATE,
        accepted: u32,
        wait_hint: u32,
        win32_exit_code: u32,
    ) {
        let handle = STATUS.load(Ordering::SeqCst);
        if handle.is_null() {
            return;
        }
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: accepted,
            dwWin32ExitCode: win32_exit_code,
            // Only consulted when dwWin32ExitCode is ERROR_SERVICE_SPECIFIC_ERROR.
            dwServiceSpecificExitCode: u32::from(win32_exit_code == ERROR_SERVICE_SPECIFIC_ERROR),
            dwCheckPoint: 0,
            dwWaitHint: wait_hint,
        };
        unsafe {
            if SetServiceStatus(handle, &status) == 0 {
                service_diagnostic(&format!(
                    "reporting status to the SCM failed ({})",
                    std::io::Error::last_os_error()
                ));
            }
        }
    }

    #[cfg(test)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    mod tests {
        use super::*;

        fn argv(args: &[&str]) -> Vec<OsString> {
            args.iter().map(OsString::from).collect()
        }

        const REQUIRED: [&str; 4] = ["--state-dir", "state", "--agent", "s.exe"];

        #[test]
        fn trailing_optional_flag_is_rejected() {
            let mut args = REQUIRED.to_vec();
            args.push("--config");
            let err = parse_from(argv(&args)).unwrap_err();
            assert_eq!(err, "--config needs a value");
        }

        #[test]
        fn trailing_required_flag_is_rejected() {
            let err = parse_from(argv(&["--agent"])).unwrap_err();
            assert_eq!(err, "--agent needs a value");
        }

        #[test]
        fn full_command_line_parses() {
            let mut args = REQUIRED.to_vec();
            args.extend(["--config", "c.toml"]);
            let parsed = parse_from(argv(&args)).expect("parses");
            assert_eq!(parsed.config, Some(OsString::from("c.toml")));
            assert_eq!(parsed.agent, OsString::from("s.exe"));
        }

        #[test]
        fn agent_log_rotation_preserves_the_previous_failure() {
            let unique = format!(
                "updated-windows-service-log-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("system time")
                    .as_nanos()
            );
            let state_dir = std::env::temp_dir().join(unique);
            std::fs::create_dir(&state_dir).expect("creates state directory");
            let current = state_dir.join(AGENT_LOG);
            let previous = state_dir.join(PREVIOUS_AGENT_LOG);
            std::fs::File::create(&current)
                .and_then(|file| file.set_len(MAX_AGENT_LOG_BYTES))
                .expect("creates an oversized current log");
            std::fs::write(&previous, b"obsolete").expect("creates an obsolete previous log");

            let mut log = open_agent_log(&state_dir).expect("rotates and opens the log");
            writeln!(log, "next boot").expect("writes the next boot");
            drop(log);

            assert_eq!(
                std::fs::metadata(&previous).expect("previous log").len(),
                MAX_AGENT_LOG_BYTES
            );
            assert_eq!(
                std::fs::read(&current).expect("current log"),
                b"next boot\n"
            );
            std::fs::remove_dir_all(state_dir).expect("removes test state");
        }
    }
}

#[cfg(windows)]
fn main() {
    windows::main();
}
