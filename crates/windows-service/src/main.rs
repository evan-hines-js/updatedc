//! Native Windows SCM host for the installer-owned bootstrap.
//!
//! The service owns only the bootstrap process. It reports a bootstrap that exits on its own to
//! the SCM as a service failure — restarts are the SCM's recovery actions, not a second loop in
//! here — and translates SERVICE_CONTROL_STOP into CTRL_BREAK for the bootstrap's process
//! group. The supervisor puts the managed application in a different process
//! group, so service maintenance never sends the application a console event.

#[cfg(not(windows))]
fn main() {
    eprintln!("selfupdate-service is only supported on Windows");
}

#[cfg(windows)]
mod windows {
    use std::ffi::{c_void, OsString};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::process::CommandExt;
    use std::process::{Child, Command};
    use std::ptr::{null, null_mut};
    use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};

    use windows_sys::Win32::Foundation::{
        ERROR_INVALID_DATA, ERROR_SERVICE_SPECIFIC_ERROR, NO_ERROR,
    };
    use windows_sys::Win32::System::Console::{
        AttachConsole, FreeConsole, GenerateConsoleCtrlEvent, SetConsoleCtrlHandler,
        CTRL_BREAK_EVENT,
    };
    use windows_sys::Win32::System::Services::*;
    use windows_sys::Win32::System::Threading::{CREATE_NEW_CONSOLE, CREATE_NEW_PROCESS_GROUP};

    const SERVICE_NAME: &str = "SelfUpdateSupervisor";
    const STOP_GRACE: Duration = Duration::from_secs(20);
    /// Extra time reported to the SCM beyond [`STOP_GRACE`], covering the hard kill and reap that
    /// follow an expired grace.
    const STOP_KILL_HEADROOM: Duration = Duration::from_secs(10);
    static STOP: AtomicBool = AtomicBool::new(false);
    static STATUS: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
    static ARGS: OnceLock<Args> = OnceLock::new();

    #[derive(Clone)]
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
        let mut bootstrap = None;
        let mut state_dir = None;
        let mut supervisor_config = None;
        let mut supervisor = None;
        let mut probe_address = None;
        let mut it = std::env::args_os().skip(1);
        while let Some(arg) = it.next() {
            match arg.to_string_lossy().as_ref() {
                "--bootstrap" => bootstrap = it.next(),
                "--state-dir" => state_dir = it.next(),
                "--supervisor-config" => supervisor_config = it.next(),
                "--supervisor" => supervisor = it.next(),
                "--probe-address" => probe_address = it.next(),
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
                (STOP_GRACE + STOP_KILL_HEADROOM).as_millis() as u32,
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
        if monitor(&mut child)? {
            return Ok(());
        }
        // The bootstrap exited on its own. Report it as a service failure instead of restarting
        // here: the SCM's recovery actions retry with escalating backoff and eventually give up
        // visibly, whereas an in-process retry loop restarts a bootstrap that fails immediately —
        // forever, on a fixed delay — while the SCM is told the service is running fine.
        let status = child
            .try_wait()
            .map_err(|e| e.to_string())?
            .and_then(|status| status.code());
        Err(match status {
            Some(code) => format!("the bootstrap exited with code {code}"),
            None => "the bootstrap exited".to_string(),
        })
    }

    /// Returns true when service shutdown was requested, false when the bootstrap exited on its
    /// own (which the caller reports to the SCM as a failure).
    fn monitor(child: &mut Child) -> Result<bool, String> {
        loop {
            if STOP.load(Ordering::SeqCst) {
                // CREATE_NEW_PROCESS_GROUP makes the bootstrap PID its console group
                // id. The application is in another group and does not receive this.
                // SCM services have no console of their own. Attach briefly to the
                // bootstrap's private console, ignore the event in this wrapper,
                // target the bootstrap's group, then detach again.
                // If the console cannot be attached the break event is never delivered, so the
                // graceful path did not happen: waiting out the full grace only delays the kill
                // by 20 seconds and makes an operator-visible clean stop look like a hang. Say so,
                // and go straight to the kill.
                let signalled = unsafe {
                    if AttachConsole(child.id()) != 0 {
                        SetConsoleCtrlHandler(None, 1);
                        GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, child.id());
                        FreeConsole();
                        true
                    } else {
                        eprintln!(
                            "selfupdate-service: could not attach the bootstrap's console ({}); \
                             stopping it without the graceful break",
                            std::io::Error::last_os_error()
                        );
                        false
                    }
                };
                let deadline = Instant::now()
                    + if signalled {
                        STOP_GRACE
                    } else {
                        Duration::ZERO
                    };
                while Instant::now() < deadline {
                    if child.try_wait().map_err(|e| e.to_string())?.is_some() {
                        return Ok(true);
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }
                child
                    .kill()
                    .map_err(|e| format!("killing bootstrap: {e}"))?;
                let _ = child.wait();
                return Ok(true);
            }
            if child.try_wait().map_err(|e| e.to_string())?.is_some() {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn spawn_bootstrap() -> Result<Child, String> {
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
        command.creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NEW_CONSOLE);
        command
            .spawn()
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
                let _ = ERROR_INVALID_DATA; // retain Foundation feature on all SDKs
            }
        }
    }

    fn wide(value: &str) -> Vec<u16> {
        std::ffi::OsStr::new(value)
            .encode_wide()
            .chain(Some(0))
            .collect()
    }
}

#[cfg(windows)]
fn main() {
    windows::main();
}
