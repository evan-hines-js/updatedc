//! Native Windows SCM host for the installer-owned bootstrap.
//!
//! The service owns only the bootstrap process. It restarts a crashed bootstrap
//! and translates SERVICE_CONTROL_STOP into CTRL_BREAK for the bootstrap's process
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

    use windows_sys::Win32::Foundation::{ERROR_INVALID_DATA, NO_ERROR};
    use windows_sys::Win32::System::Console::{
        AttachConsole, FreeConsole, GenerateConsoleCtrlEvent, SetConsoleCtrlHandler,
        CTRL_BREAK_EVENT,
    };
    use windows_sys::Win32::System::Services::*;
    use windows_sys::Win32::System::Threading::{CREATE_NEW_CONSOLE, CREATE_NEW_PROCESS_GROUP};

    const SERVICE_NAME: &str = "SelfUpdateSupervisor";
    const STOP_GRACE: Duration = Duration::from_secs(20);
    const RESTART_DELAY: Duration = Duration::from_secs(2);
    static STOP: AtomicBool = AtomicBool::new(false);
    static STATUS: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
    static ARGS: OnceLock<Args> = OnceLock::new();

    #[derive(Clone)]
    struct Args {
        bootstrap: OsString,
        state_dir: OsString,
        supervisor_config: OsString,
        supervisor: OsString,
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
        let mut it = std::env::args_os().skip(1);
        while let Some(arg) = it.next() {
            match arg.to_string_lossy().as_ref() {
                "--bootstrap" => bootstrap = it.next(),
                "--state-dir" => state_dir = it.next(),
                "--supervisor-config" => supervisor_config = it.next(),
                "--supervisor" => supervisor = it.next(),
                other => return Err(format!("unknown argument {other:?}")),
            }
        }
        Ok(Args {
            bootstrap: bootstrap.ok_or("--bootstrap <path> is required")?,
            state_dir: state_dir.ok_or("--state-dir <path> is required")?,
            supervisor_config: supervisor_config.ok_or("--supervisor-config <path> is required")?,
            supervisor: supervisor.ok_or("--supervisor <path> is required")?,
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
        report(SERVICE_START_PENDING, 0, 5_000);
        report(SERVICE_RUNNING, SERVICE_ACCEPT_STOP, 0);
        let exit = run_service();
        report(SERVICE_STOPPED, 0, 0);
        if let Err(e) = exit {
            eprintln!("selfupdate-service: {e}");
        }
    }

    unsafe extern "system" fn control_handler(
        control: u32,
        _event_type: u32,
        _event_data: *mut c_void,
        _context: *mut c_void,
    ) -> u32 {
        if control == SERVICE_CONTROL_STOP {
            STOP.store(true, Ordering::SeqCst);
            report(SERVICE_STOP_PENDING, 0, STOP_GRACE.as_millis() as u32);
        }
        NO_ERROR
    }

    fn run_service() -> Result<(), String> {
        while !STOP.load(Ordering::SeqCst) {
            let mut child = spawn_bootstrap()?;
            if monitor(&mut child)? {
                break;
            }
            std::thread::sleep(RESTART_DELAY);
        }
        Ok(())
    }

    /// Returns true when service shutdown was requested, false when the bootstrap
    /// exited and should be restarted.
    fn monitor(child: &mut Child) -> Result<bool, String> {
        loop {
            if STOP.load(Ordering::SeqCst) {
                // CREATE_NEW_PROCESS_GROUP makes the bootstrap PID its console group
                // id. The application is in another group and does not receive this.
                // SCM services have no console of their own. Attach briefly to the
                // bootstrap's private console, ignore the event in this wrapper,
                // target the bootstrap's group, then detach again.
                unsafe {
                    if AttachConsole(child.id()) != 0 {
                        SetConsoleCtrlHandler(None, 1);
                        GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, child.id());
                        FreeConsole();
                    }
                }
                let deadline = Instant::now() + STOP_GRACE;
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
            .arg("--supervisor-config")
            .arg(&args.supervisor_config)
            .arg("--supervisor")
            .arg(&args.supervisor)
            .creation_flags(CREATE_NEW_PROCESS_GROUP | CREATE_NEW_CONSOLE);
        command
            .spawn()
            .map_err(|e| format!("launching bootstrap {:?}: {e}", args.bootstrap))
    }

    fn report(state: SERVICE_STATUS_CURRENT_STATE, accepted: u32, wait_hint: u32) {
        let handle = STATUS.load(Ordering::SeqCst);
        if handle.is_null() {
            return;
        }
        let status = SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: state,
            dwControlsAccepted: accepted,
            dwWin32ExitCode: if state == SERVICE_STOPPED {
                NO_ERROR
            } else {
                0
            },
            dwServiceSpecificExitCode: 0,
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
