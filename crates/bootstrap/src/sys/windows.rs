//! The Windows half of the guardian's operating-system surface: the launched application
//! process, assigned to a kill-on-close Job Object so it dies with the guardian. The
//! platform-agnostic guardian core (`app`) calls this; the cfg lives here. (The Windows
//! control channel and console handler keep their FFI inline where it is inseparable from
//! the handle logic they wrap.)

use control::CommandSpec;
use std::io;
use std::time::Duration;

use windows_sys::Win32::Foundation::HANDLE;

/// A launched application process, assigned to a kill-on-close Job Object so it dies with
/// the guardian — never an orphan, never a duplicate. There is no re-adoption across a
/// guardian restart.
struct Proc {
    pid: u32,
    process: HANDLE,
    job: HANDLE,
    exited: Option<i32>,
}

unsafe impl Send for Proc {}

/// Launch the contained application process from `spec` (the [`Process`](crate::sys::Process)
/// port's Windows adapter factory).
pub fn spawn(spec: &CommandSpec) -> io::Result<Box<dyn crate::sys::Process>> {
    Ok(Box::new(Proc::launch(spec)?))
}

impl Proc {
    fn launch(spec: &CommandSpec) -> io::Result<Proc> {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
            SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        };
        use windows_sys::Win32::System::Threading::{
            CreateProcessW, ResumeThread, TerminateProcess, CREATE_NEW_PROCESS_GROUP,
            CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTUPINFOW,
        };

        let mut command_line = command_line_utf16(spec);
        let mut environment = environment_block(spec);
        let cwd = spec
            .cwd
            .as_ref()
            .map(|c| to_wide_nul(c.as_os_str().encode_wide()));

        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return Err(io::Error::last_os_error());
            }
            let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &limits as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) == 0
            {
                let e = io::Error::last_os_error();
                CloseHandle(job);
                return Err(e);
            }

            let mut si: STARTUPINFOW = std::mem::zeroed();
            si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
            let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
            let cwd_ptr = cwd.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
            // Create suspended so the process is in the kill-on-close job before it can run
            // — no window in which a guardian crash could orphan an un-jobbed app.
            let ok = CreateProcessW(
                std::ptr::null(),
                command_line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT,
                environment.as_mut_ptr() as *mut _,
                cwd_ptr,
                &si,
                &mut pi,
            );
            if ok == 0 {
                let e = io::Error::last_os_error();
                CloseHandle(job);
                return Err(e);
            }
            if AssignProcessToJobObject(job, pi.hProcess) == 0 {
                let e = io::Error::last_os_error();
                TerminateProcess(pi.hProcess, 1);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                CloseHandle(job);
                return Err(e);
            }
            ResumeThread(pi.hThread);
            CloseHandle(pi.hThread);
            Ok(Proc {
                pid: pi.dwProcessId,
                process: pi.hProcess,
                job,
                exited: None,
            })
        }
    }
}

impl crate::sys::Process for Proc {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn poll_exit(&mut self) -> Option<i32> {
        use windows_sys::Win32::System::Threading::GetExitCodeProcess;
        const STILL_ACTIVE: u32 = 259;
        if self.exited.is_none() {
            let mut code = 0u32;
            let ok = unsafe { GetExitCodeProcess(self.process, &mut code) };
            if ok != 0 && code != STILL_ACTIVE {
                self.exited = Some(code as i32);
            }
        }
        self.exited
    }

    fn stop(&mut self, _grace: Duration) {
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;
        use windows_sys::Win32::System::Threading::WaitForSingleObject;
        if self.poll_exit().is_some() {
            return;
        }
        unsafe {
            TerminateJobObject(self.job, 1);
            WaitForSingleObject(self.process, 5_000);
        }
        self.exited.get_or_insert(1);
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        // Closing the kill-on-close job ends the app: on guardian exit that is intended.
        unsafe {
            CloseHandle(self.process);
            CloseHandle(self.job);
        }
    }
}

fn command_line_utf16(spec: &CommandSpec) -> Vec<u16> {
    let mut parts = Vec::with_capacity(spec.args.len() + 1);
    parts.push(quote_arg(&spec.program));
    for a in &spec.args {
        parts.push(quote_arg(a));
    }
    to_wide_nul(parts.join(" ").encode_utf16())
}

fn quote_arg(arg: &std::ffi::OsStr) -> String {
    let s = arg.to_string_lossy();
    if !s.is_empty() && !s.contains([' ', '\t', '"', '\\']) {
        return s.into_owned();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0usize;
    for c in s.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                out.extend(std::iter::repeat_n('\\', backslashes * 2 + 1));
                backslashes = 0;
                out.push('"');
            }
            _ => {
                out.extend(std::iter::repeat_n('\\', backslashes));
                backslashes = 0;
                out.push(c);
            }
        }
    }
    out.extend(std::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
    out
}

fn environment_block(spec: &CommandSpec) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    let mut block: Vec<u16> = Vec::new();
    for (k, v) in &spec.env {
        block.extend(k.encode_wide());
        block.push(b'=' as u16);
        block.extend(v.encode_wide());
        block.push(0);
    }
    block.push(0);
    if block.len() == 1 {
        block.push(0);
    }
    block
}

fn to_wide_nul(units: impl Iterator<Item = u16>) -> Vec<u16> {
    let mut v: Vec<u16> = units.collect();
    v.push(0);
    v
}

// ------------------------------- stop signals -------------------------------

/// A no-op on Windows (there is no `SIGPIPE`); present so the guardian core can call it
/// unconditionally, keeping its own code free of `cfg`.
pub fn ignore_sigpipe() {}

/// Install the stop handler: a console close/shutdown event sets the shutdown flag so the
/// guardian exits cleanly (forwarding the stop down to the application).
pub fn install_shutdown_handler() {
    unsafe {
        windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(handle_ctrl), 1);
    }
}

unsafe extern "system" fn handle_ctrl(_ctrl_type: u32) -> windows_sys::Win32::Foundation::BOOL {
    super::request_shutdown();
    1
}

/// A no-op on Windows: there is no graceful process signal, so the guardian simply waits
/// out the grace and then hard-kills the supervisor.
pub fn terminate_gracefully(_pid: u32) {}

// ------------------------------ the control channel ------------------------------

/// The guardian's end of the inherited control channel: a duplex pair of anonymous pipes
/// (Windows anonymous pipes are one-directional). The guardian reads supervisor→guardian
/// and writes guardian→supervisor; the supervisor inherits the complementary two handles.
pub struct Channel {
    read: std::fs::File,
    write: std::fs::File,
    child_read: HANDLE,
    child_write: HANDLE,
}

impl Channel {
    pub fn create() -> io::Result<Channel> {
        use std::os::windows::io::{
            AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle, RawHandle,
        };
        // g2s: guardian writes, supervisor reads. s2g: supervisor writes, guardian reads.
        // Own every handle the instant it exists so a failure part-way through closes them
        // all on unwind — the guardian relaunches on a loop, so a leak here would compound.
        let (g2s_read, g2s_write) = anon_pipe()?;
        let g2s_read = unsafe { OwnedHandle::from_raw_handle(g2s_read as RawHandle) };
        let g2s_write = unsafe { OwnedHandle::from_raw_handle(g2s_write as RawHandle) };
        let (s2g_read, s2g_write) = anon_pipe()?;
        let s2g_read = unsafe { OwnedHandle::from_raw_handle(s2g_read as RawHandle) };
        let s2g_write = unsafe { OwnedHandle::from_raw_handle(s2g_write as RawHandle) };
        // Each pipe's child-facing handle is inheritable; the guardian's is not.
        set_inherit(g2s_read.as_raw_handle() as HANDLE, true)?;
        set_inherit(g2s_write.as_raw_handle() as HANDLE, false)?;
        set_inherit(s2g_write.as_raw_handle() as HANDLE, true)?;
        set_inherit(s2g_read.as_raw_handle() as HANDLE, false)?;
        Ok(Channel {
            read: std::fs::File::from(s2g_read),
            write: std::fs::File::from(g2s_write),
            child_read: g2s_read.into_raw_handle() as HANDLE,
            child_write: s2g_write.into_raw_handle() as HANDLE,
        })
    }

    /// The `CONTROL_ENV` value: the two inherited handle values (child read, child write)
    /// as decimal, comma-separated.
    pub fn child_env_value(&self) -> String {
        format!("{},{}", self.child_read as usize, self.child_write as usize)
    }

    pub fn close_child_end(&mut self) {
        use windows_sys::Win32::Foundation::CloseHandle;
        unsafe {
            if !self.child_read.is_null() {
                CloseHandle(self.child_read);
                self.child_read = std::ptr::null_mut();
            }
            if !self.child_write.is_null() {
                CloseHandle(self.child_write);
                self.child_write = std::ptr::null_mut();
            }
        }
    }

    pub fn poll_readable(&self, timeout_ms: i32) -> super::Ready {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Pipes::PeekNamedPipe;
        // Anonymous pipes are not waitable for readability, so peek for buffered bytes,
        // sleeping between checks up to the timeout.
        let handle = self.read.as_raw_handle() as HANDLE;
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms.max(0) as u64);
        loop {
            let mut available: u32 = 0;
            let ok = unsafe {
                PeekNamedPipe(
                    handle,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut available,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                return super::Ready::Closed; // broken pipe: supervisor gone.
            }
            if available > 0 {
                return super::Ready::Readable;
            }
            if std::time::Instant::now() >= deadline {
                return super::Ready::TimedOut;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn send_hello(&mut self) -> control::Result<()> {
        control::Hello::current().write(&mut self.write)
    }

    pub fn read_request(&mut self) -> control::Result<control::Request> {
        control::Request::read(&mut TimeoutReader(&mut self.read))
    }

    pub fn send_response(&mut self, resp: &control::Response) -> control::Result<()> {
        resp.write(&mut self.write)
    }
}

/// How long a single control-channel read may stall the guardian's one thread before it
/// gives up on the frame. Mirrors the Unix end's `SO_RCVTIMEO`, which is likewise per-read.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Bounds a blocking pipe read. An anonymous pipe cannot carry a receive timeout, and
/// `ReadFile` on one blocks until at least a byte arrives — so peek until something is
/// buffered, and give up at the deadline. `ReadFile` never waits for more than the bytes
/// already present, so once the peek sees any, the read cannot block.
///
/// Without this, a supervisor that writes one byte and stops would block the guardian's only
/// thread inside `read_exact` forever, stranding its shutdown signal, its application-crash
/// check, and its readiness deadline while it still owns the application.
struct TimeoutReader<'a>(&'a mut std::fs::File);

impl std::io::Read for TimeoutReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::System::Pipes::PeekNamedPipe;
        if buf.is_empty() {
            return Ok(0);
        }
        let handle = self.0.as_raw_handle() as HANDLE;
        let deadline = std::time::Instant::now() + READ_TIMEOUT;
        loop {
            let mut available: u32 = 0;
            let ok = unsafe {
                PeekNamedPipe(
                    handle,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null_mut(),
                    &mut available,
                    std::ptr::null_mut(),
                )
            };
            // A failed peek means a broken pipe (the supervisor is gone) or a real error:
            // let the read itself surface it, so a closed peer still reads as a clean close
            // at a frame boundary rather than as a timeout.
            if ok == 0 || available > 0 {
                return self.0.read(buf);
            }
            if std::time::Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "control channel read timed out",
                ));
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        self.close_child_end();
    }
}

fn anon_pipe() -> io::Result<(HANDLE, HANDLE)> {
    use windows_sys::Win32::System::Pipes::CreatePipe;
    let mut read: HANDLE = std::ptr::null_mut();
    let mut write: HANDLE = std::ptr::null_mut();
    let ok = unsafe { CreatePipe(&mut read, &mut write, std::ptr::null(), 0) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((read, write))
}

fn set_inherit(handle: HANDLE, inherit: bool) -> io::Result<()> {
    use windows_sys::Win32::Foundation::{SetHandleInformation, HANDLE_FLAG_INHERIT};
    let flags = if inherit { HANDLE_FLAG_INHERIT } else { 0 };
    let ok = unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, flags) };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{OsStr, OsString};

    fn decode_nul(v: &[u16]) -> String {
        assert_eq!(v.last(), Some(&0));
        String::from_utf16(&v[..v.len() - 1]).unwrap()
    }

    #[test]
    fn windows_arguments_follow_create_process_quoting_rules() {
        assert_eq!(quote_arg(OsStr::new("plain")), "plain");
        assert_eq!(quote_arg(OsStr::new("")), "\"\"");
        assert_eq!(quote_arg(OsStr::new("two words")), "\"two words\"");
        assert_eq!(quote_arg(OsStr::new(r#"a\"b"#)), "\"a\\\\\\\"b\"");
        assert_eq!(quote_arg(OsStr::new(r#"trail\"#)), "\"trail\\\\\"");
    }

    #[test]
    fn command_line_contains_program_and_every_argument() {
        let spec = CommandSpec {
            program: OsString::from(r"C:\Program Files\app.exe"),
            args: vec![OsString::from("plain"), OsString::from("two words")],
            env: vec![],
            cwd: None,
        };
        assert_eq!(
            decode_nul(&command_line_utf16(&spec)),
            "\"C:\\Program Files\\app.exe\" plain \"two words\""
        );
    }

    #[test]
    fn environment_block_is_double_nul_terminated() {
        let empty = CommandSpec {
            program: OsString::from("app"),
            args: vec![],
            env: vec![],
            cwd: None,
        };
        assert_eq!(environment_block(&empty), vec![0, 0]);

        let spec = CommandSpec {
            env: vec![
                (OsString::from("A"), OsString::from("one")),
                (OsString::from("B"), OsString::from("two")),
            ],
            ..empty
        };
        let expected: Vec<u16> = "A=one\0B=two\0\0".encode_utf16().collect();
        assert_eq!(environment_block(&spec), expected);
    }

    #[test]
    fn wide_strings_receive_exactly_one_terminator() {
        assert_eq!(
            to_wide_nul("ab".encode_utf16()),
            vec![b'a' as u16, b'b' as u16, 0]
        );
    }
}
