//! Native Windows SCM host for the installer-owned bootstrap.
//!
//! The service owns only the bootstrap, and owns it as a contained tree: it is spawned into a
//! kill-on-close job object, so a bootstrap can never outlive the service process that reports
//! its state to the SCM. That is what keeps the single-guardian invariant true across the SCM's
//! recovery restarts — a second service process would otherwise launch a second guardian over
//! the same state directory.
//!
//! It reports a bootstrap that exits on its own to the SCM as a service failure — restarts are
//! the SCM's recovery actions, not a second loop in here — and translates SERVICE_CONTROL_STOP
//! into CTRL_BREAK for the bootstrap's process group. The supervisor puts the managed
//! application in a different process group, so service maintenance never sends the application
//! a console event.

#[cfg(not(windows))]
fn main() {
    eprintln!("selfupdate-service is only supported on Windows");
}

#[cfg(windows)]
mod windows {
    use std::ffi::{c_void, OsString};
    use std::os::windows::ffi::OsStrExt;
    use std::process::Command;
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
    use std::sync::OnceLock;
    use std::time::Duration;

    use windows_sys::Win32::Foundation::{ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR};
    use windows_sys::Win32::System::Services::*;

    use foundation::process::ContainedChild;

    const SERVICE_NAME: &str = "SelfUpdateSupervisor";
    const STOP_GRACE: Duration = Duration::from_secs(20);
    /// How often the bootstrap is re-checked while watching it and while stopping it.
    const POLL: Duration = Duration::from_millis(100);
    static STOP: AtomicBool = AtomicBool::new(false);
    static STATUS: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
    static ARGS: OnceLock<Args> = OnceLock::new();

    #[derive(Clone, Debug)]
    struct Args {
        bootstrap: OsString,
        state_dir: OsString,
        /// Forwarded only when given: the bootstrap owns the canonical default, so this
        /// wrapper never needs to know where a node's config lives.
        supervisor_config: Option<OsString>,
        supervisor: OsString,
        probe_address: Option<OsString>,
    }

    pub fn main() {
        match parse_args() {
            Ok(args) => {
                let _ = ARGS.set(args);
            }
            Err(e) => {
                eprintln!("selfupdate-service: {e}");
                std::process::exit(2);
            }
        }
        let mut name = wide(SERVICE_NAME);
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
            eprintln!(
                "selfupdate-service: StartServiceCtrlDispatcherW failed: {}",
                std::io::Error::last_os_error()
            );
            std::process::exit(1);
        }
    }

    fn parse_args() -> Result<Args, String> {
        parse_from(std::env::args_os().skip(1))
    }

    /// Every flag here takes a value, and a flag without one is an error — including the
    /// optional `--supervisor-config` and `--probe-address`. Treating a valueless flag as
    /// "not given" would silently fall back to the bootstrap's defaults (its canonical config
    /// path, no probe listener) while the SCM reports SERVICE_RUNNING, making this wrapper
    /// weaker than the bootstrap it fronts, which rejects the same input.
    fn parse_from(args: impl IntoIterator<Item = OsString>) -> Result<Args, String> {
        let mut bootstrap = None;
        let mut state_dir = None;
        let mut supervisor_config = None;
        let mut supervisor = None;
        let mut probe_address = None;
        fn value(it: &mut impl Iterator<Item = OsString>, flag: &str) -> Result<OsString, String> {
            it.next().ok_or_else(|| format!("{flag} needs a value"))
        }
        let mut it = args.into_iter();
        while let Some(arg) = it.next() {
            match arg.to_string_lossy().as_ref() {
                "--bootstrap" => bootstrap = Some(value(&mut it, "--bootstrap")?),
                "--state-dir" => state_dir = Some(value(&mut it, "--state-dir")?),
                "--supervisor-config" => {
                    supervisor_config = Some(value(&mut it, "--supervisor-config")?)
                }
                "--supervisor" => supervisor = Some(value(&mut it, "--supervisor")?),
                "--probe-address" => probe_address = Some(value(&mut it, "--probe-address")?),
                other => return Err(format!("unknown argument {other:?}")),
            }
        }
        Ok(Args {
            bootstrap: bootstrap.ok_or("--bootstrap <path> is required")?,
            state_dir: state_dir.ok_or("--state-dir <path> is required")?,
            supervisor_config,
            supervisor: supervisor.ok_or("--supervisor <path> is required")?,
            probe_address,
        })
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut windows_sys::core::PWSTR) {
        let mut name = wide(SERVICE_NAME);
        let handle = unsafe {
            RegisterServiceCtrlHandlerExW(name.as_mut_ptr(), Some(control_handler), null())
        };
        if handle.is_null() {
            return;
        }
        STATUS.store(handle, Ordering::SeqCst);
        report(SERVICE_START_PENDING, 0, 5_000, NO_ERROR);
        // Accept SHUTDOWN as well as STOP. Without it the SCM sends nothing on an OS restart: the
        // tower is killed outright, skipping the drain and the clean application stop that a
        // requested stop performs — the one moment a graceful shutdown matters most.
        report(
            SERVICE_RUNNING,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN,
            0,
            NO_ERROR,
        );
        // Report the outcome to the SCM, not just to stderr: `sc failure`/`sc failureflag`
        // recovery actions (see deploy/windows/install-selfupdate-supervisor.bat) fire only
        // on a STOPPED report carrying a non-zero exit code. Reporting a clean stop after a
        // failure leaves the whole tower down with the SCM believing all is well.
        let exit = run_service();
        if let Err(e) = &exit {
            eprintln!("selfupdate-service: {e}");
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
        // An OS shutdown is handled exactly like a stop: drain and stop the tower cleanly.
        if control == SERVICE_CONTROL_STOP || control == SERVICE_CONTROL_SHUTDOWN {
            STOP.store(true, Ordering::SeqCst);
            // The hint must cover the FULL stop: the grace period AND the hard kill and reap that
            // follow it. Reporting exactly the grace tells the SCM the service is late at the very
            // moment it is doing the right thing, and it kills the tower mid-drain.
            report(
                SERVICE_STOP_PENDING,
                0,
                (STOP_GRACE + foundation::process::KILL_HEADROOM).as_millis() as u32,
                NO_ERROR,
            );
        }
        NO_ERROR
    }

    /// Restarting a bootstrap that will not spawn is the SCM's job, not ours: reporting the
    /// failure (see `report`) triggers the `sc failure` recovery actions the installer
    /// configures, which retry with escalating backoff and give up cleanly. Retrying in
    /// here as well would be a second restart path that reports success while looping.
    fn run_service() -> Result<(), String> {
        let mut child = spawn_bootstrap()?;
        if monitor(&mut child) {
            return Ok(());
        }
        // The bootstrap exited on its own. Report it as a service failure instead of restarting
        // here: the SCM's recovery actions retry with escalating backoff and eventually give up
        // visibly, whereas an in-process retry loop restarts a bootstrap that fails immediately —
        // forever, on a fixed delay — while the SCM is told the service is running fine.
        let status = child.try_wait().ok().flatten().and_then(|s| s.code());
        Err(match status {
            Some(code) => format!("the bootstrap exited with code {code}"),
            None => "the bootstrap exited".to_string(),
        })
    }

    /// Watch the bootstrap until a stop is requested or it exits on its own. Returns true for the
    /// requested stop (the caller reports a clean STOPPED) and false when it exited by itself
    /// (reported to the SCM as a failure).
    ///
    /// It never returns while the bootstrap is still running, and no failure inside it is
    /// propagated: a STOPPED report — clean or failed — is the moment the SCM may start another
    /// service process, and the configured recovery action does exactly that on a failure. A
    /// bootstrap that outlived this wrapper would then meet a second guardian over the same
    /// `--state-dir`, both owning `desired-supervisor` and `rejected-supervisor`.
    fn monitor(child: &mut ContainedChild) -> bool {
        loop {
            if STOP.load(Ordering::SeqCst) {
                stop_bootstrap(child);
                return true;
            }
            match child.try_wait() {
                Ok(Some(_)) => return false,
                Ok(None) => std::thread::sleep(POLL),
                Err(error) => {
                    // The handle is unusable, so the bootstrap can no longer be observed — it may
                    // well still be running. Take the tree down before reporting anything.
                    eprintln!("selfupdate-service: watching the bootstrap failed ({error})");
                    stop_bootstrap(child);
                    return false;
                }
            }
        }
    }

    /// Stop the bootstrap tree: a graceful console break first, then a hard kill of the whole
    /// job. Returns only once it is gone, or once the kill has been issued and the wait for it
    /// has been given [`foundation::process::KILL_HEADROOM`] — the same budget the SCM was told
    /// to expect.
    ///
    /// Failures are logged, never propagated, and the last resort is structural rather than
    /// reported: the tree lives in a kill-on-close job object, so dropping `child` when this
    /// wrapper exits takes down anything that survived. There is no path on which a bootstrap
    /// outlives the service process that owns it.
    fn stop_bootstrap(child: &mut ContainedChild) {
        // The whole sequence — graceful console break, grace, hard kill of the job, reap — is
        // `ContainedChild::stop`'s, including the decision to skip the grace when the break event
        // could not be delivered. This wrapper only reports what it took.
        match child.stop(STOP_GRACE) {
            foundation::process::Stopped::Gracefully | foundation::process::Stopped::Killed => {}
            foundation::process::Stopped::Surviving => eprintln!(
                "selfupdate-service: the bootstrap did not exit after being killed; its \
                 kill-on-close job takes it down as this process exits"
            ),
        }
    }

    fn spawn_bootstrap() -> Result<ContainedChild, String> {
        let args = ARGS.get().ok_or("service arguments unavailable")?;
        let mut command = Command::new(&args.bootstrap);
        command
            .arg("--state-dir")
            .arg(&args.state_dir)
            .arg("--supervisor")
            .arg(&args.supervisor);
        if let Some(config) = &args.supervisor_config {
            command.arg("--supervisor-config").arg(config);
        }
        if let Some(address) = &args.probe_address {
            command.arg("--probe-address").arg(address);
        }
        // Contained: the bootstrap and everything below it belong to a kill-on-close job object
        // this process owns, so the tower can never survive the service process that reports its
        // state to the SCM. A service has no console, so the bootstrap is given one — that is what
        // makes `request_stop`'s graceful break addressable at all.
        ContainedChild::spawn_in_new_console(command)
            .map_err(|e| format!("launching bootstrap {:?}: {e}", args.bootstrap))
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
                eprintln!(
                    "selfupdate-service: reporting status to the SCM failed ({})",
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(Some(0))
            .collect()
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn argv(args: &[&str]) -> Vec<OsString> {
            args.iter().map(OsString::from).collect()
        }

        const REQUIRED: [&str; 6] = [
            "--bootstrap",
            "b.exe",
            "--state-dir",
            "state",
            "--supervisor",
            "s.exe",
        ];

        #[test]
        fn trailing_optional_flag_is_rejected() {
            for flag in ["--supervisor-config", "--probe-address"] {
                let mut args = REQUIRED.to_vec();
                args.push(flag);
                let err = parse_from(argv(&args)).unwrap_err();
                assert_eq!(err, format!("{flag} needs a value"));
            }
        }

        #[test]
        fn trailing_required_flag_is_rejected() {
            let err = parse_from(argv(&["--bootstrap"])).unwrap_err();
            assert_eq!(err, "--bootstrap needs a value");
        }

        #[test]
        fn full_command_line_parses() {
            let mut args = REQUIRED.to_vec();
            args.extend([
                "--supervisor-config",
                "c.toml",
                "--probe-address",
                "1.2.3.4:9",
            ]);
            let parsed = parse_from(argv(&args)).expect("parses");
            assert_eq!(parsed.bootstrap, OsString::from("b.exe"));
            assert_eq!(parsed.supervisor_config, Some(OsString::from("c.toml")));
            assert_eq!(parsed.probe_address, Some(OsString::from("1.2.3.4:9")));
        }
    }
}

#[cfg(windows)]
fn main() {
    windows::main();
}
