//! The Windows half of the guardian's operating-system surface: the launched application
//! process, assigned to a kill-on-close Job Object so it dies with the guardian. The
//! platform-agnostic guardian core (`app`) calls this; the cfg lives here. (The Windows
//! control channel and console handler keep their FFI inline where it is inseparable from
//! the handle logic they wrap.)

use control::CommandSpec;
use std::io;
use std::time::{Duration, Instant};

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
        use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
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

        // Identical kill-on-close job setup as the portable containment; shared so the two
        // can never drift. The assign route below (a `CREATE_SUSPENDED` process) is what
        // differs, so only the setup is shared.
        let job = foundation::process::create_kill_on_close_job()?;

        unsafe {
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
        use windows_sys::Win32::Foundation::WAIT_OBJECT_0;
        use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
        if self.exited.is_none() {
            // Decide exited-vs-running by waiting on the process handle (signaled only once
            // the process has terminated), not by comparing the exit code against 259
            // (`STILL_ACTIVE`) — an app that genuinely exits with 259 must still be seen as
            // dead. Only after the handle signals is the exit code meaningful.
            if unsafe { WaitForSingleObject(self.process, 0) } == WAIT_OBJECT_0 {
                let mut code = 0u32;
                if unsafe { GetExitCodeProcess(self.process, &mut code) } != 0 {
                    self.exited = Some(code as i32);
                }
            }
        }
        self.exited
    }

    /// Stop the app: `CTRL_BREAK` to its process group, wait up to `grace` for a clean
    /// drain/flush, then `TerminateJobObject` as the hard fallback — mirroring the Unix
    /// `SIGTERM`→wait→`SIGKILL` path so a planned update/stop gets the same graceful window
    /// on every target rather than an abrupt kill.
    ///
    /// NOTE: needs Windows CI validation — this host cannot compile or exercise the
    /// `CREATE_NEW_PROCESS_GROUP` + `CTRL_BREAK_EVENT` interaction.
    fn stop(&mut self, grace: Duration) {
        use windows_sys::Win32::System::Console::{GenerateConsoleCtrlEvent, CTRL_BREAK_EVENT};
        use windows_sys::Win32::System::JobObjects::TerminateJobObject;
        use windows_sys::Win32::System::Threading::WaitForSingleObject;
        if self.poll_exit().is_some() {
            return;
        }
        // Graceful: the app was spawned `CREATE_NEW_PROCESS_GROUP`, so its process-group id
        // equals its PID; `CTRL_BREAK` lets it run its shutdown handler. (`CTRL_C` cannot be
        // targeted at a specific group, so `CTRL_BREAK` is the one usable graceful signal.)
        unsafe {
            GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, self.pid);
        }
        let deadline = Instant::now() + grace;
        while Instant::now() < deadline {
            if self.poll_exit().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        // Hard fallback: kill the whole job.
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
    // Build the command line in raw UTF-16 code units, never via `to_string_lossy`: a
    // `CommandSpec`'s program/args round-trip Windows WTF-16 faithfully (see `control`'s
    // `os_units`/`os_from_units`), so an unpaired surrogate or other non-UTF-8 code unit in a
    // valid path must reach `CreateProcessW` intact rather than be replaced with U+FFFD (which
    // would launch the wrong image or ENOENT). This mirrors the Unix path's raw-bytes fidelity.
    let mut line: Vec<u16> = Vec::new();
    quote_arg_into(&mut line, &spec.program);
    for a in &spec.args {
        line.push(u16::from(b' '));
        quote_arg_into(&mut line, a);
    }
    to_wide_nul(line.into_iter())
}

fn quote_arg_into(out: &mut Vec<u16>, arg: &std::ffi::OsStr) {
    use std::os::windows::ffi::OsStrExt;
    const SPACE: u16 = b' ' as u16;
    const TAB: u16 = b'\t' as u16;
    const QUOTE: u16 = b'"' as u16;
    const BACKSLASH: u16 = b'\\' as u16;
    let units: Vec<u16> = arg.encode_wide().collect();
    if !units.is_empty()
        && !units
            .iter()
            .any(|&u| matches!(u, SPACE | TAB | QUOTE | BACKSLASH))
    {
        out.extend_from_slice(&units);
        return;
    }
    out.push(QUOTE);
    let mut backslashes = 0usize;
    for &u in &units {
        match u {
            BACKSLASH => backslashes += 1,
            QUOTE => {
                out.extend(std::iter::repeat_n(BACKSLASH, backslashes * 2 + 1));
                backslashes = 0;
                out.push(QUOTE);
            }
            _ => {
                out.extend(std::iter::repeat_n(BACKSLASH, backslashes));
                backslashes = 0;
                out.push(u);
            }
        }
    }
    out.extend(std::iter::repeat_n(BACKSLASH, backslashes * 2));
    out.push(QUOTE);
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

    pub fn poll_readable(&self, timeout_ms: i32) -> bool {
        use std::os::windows::io::AsRawHandle;
        let handle = self.read.as_raw_handle() as HANDLE;
        let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms.max(0) as u64);
        // Only buffered bytes count as readable; a broken pipe or the deadline both read as
        // "not readable" and let the serve loop observe a death through the exit status.
        matches!(peek_until_readable(handle, deadline), Peek::Ready)
    }

    pub fn send_hello(&mut self) -> control::Result<()> {
        control::Hello::current().write(&mut TimeoutWriter(&mut self.write))
    }

    pub fn read_request(&mut self) -> control::Result<control::Request> {
        control::Request::read(&mut TimeoutReader(&mut self.read))
    }

    pub fn send_response(&mut self, resp: &control::Response) -> control::Result<()> {
        resp.write(&mut TimeoutWriter(&mut self.write))
    }
}

/// How long a single control-channel read or write may stall the guardian's one thread
/// before it gives up on the frame. Mirrors the Unix end's per-operation `SO_RCVTIMEO`/
/// `SO_SNDTIMEO`.
const IO_TIMEOUT: Duration = Duration::from_secs(5);

/// The outcome of waiting for a pipe to have buffered bytes.
enum Peek {
    /// Bytes are buffered — a read will not block.
    Ready,
    /// The peek failed: a broken pipe (peer gone) or a real error.
    Broken,
    /// The deadline passed with nothing buffered.
    TimedOut,
}

/// Wait until `handle` has buffered bytes, its peer is gone, or `deadline` passes. An
/// anonymous pipe is not waitable for readability, so peek for buffered bytes and sleep
/// between checks — `ReadFile` never waits for more than the bytes already present, so once
/// this returns [`Peek::Ready`] a read cannot block. Shared by [`Channel::poll_readable`]
/// and [`TimeoutReader`].
fn peek_until_readable(handle: HANDLE, deadline: std::time::Instant) -> Peek {
    use windows_sys::Win32::System::Pipes::PeekNamedPipe;
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
            return Peek::Broken;
        }
        if available > 0 {
            return Peek::Ready;
        }
        if std::time::Instant::now() >= deadline {
            return Peek::TimedOut;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Bounds a blocking pipe read. Without this a supervisor that writes one byte and stops
/// would block the guardian's only thread inside `read_exact` forever, stranding its
/// shutdown signal, its application-crash check, and its readiness deadline while it still
/// owns the application.
struct TimeoutReader<'a>(&'a mut std::fs::File);

impl std::io::Read for TimeoutReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::os::windows::io::AsRawHandle;
        if buf.is_empty() {
            return Ok(0);
        }
        let handle = self.0.as_raw_handle() as HANDLE;
        let deadline = std::time::Instant::now() + IO_TIMEOUT;
        match peek_until_readable(handle, deadline) {
            // Let the read itself surface a broken pipe, so a closed peer still reads as a
            // clean close at a frame boundary rather than as a timeout.
            Peek::Ready | Peek::Broken => self.0.read(buf),
            Peek::TimedOut => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "control channel read timed out",
            )),
        }
    }
}

/// Bounds a blocking pipe write to the same [`IO_TIMEOUT`] as the read, matching the Unix
/// channel's `SO_SNDTIMEO`. An anonymous pipe carries no write timeout, and `WriteFile`
/// blocks once the pipe buffer fills — so a supervisor that stops draining could otherwise
/// wedge the guardian's only thread inside `send_hello`/`send_response` forever, stranding
/// the shutdown signal and readiness deadline while it still owns the application.
///
/// The bound is enforced by writing each frame chunk on a scratch thread (holding a
/// duplicated handle) and waiting up to the deadline. On timeout the guardian abandons the
/// thread — it unblocks and closes its handle copy if the pipe ever drains or closes — and
/// reports the stall, which the serve loop treats as a lost supervisor.
struct TimeoutWriter<'a>(&'a mut std::fs::File);

impl std::io::Write for TimeoutWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        use std::os::windows::io::AsRawHandle;
        if buf.is_empty() {
            return Ok(0);
        }
        let handle = self.0.as_raw_handle() as HANDLE;
        bounded_pipe_write(handle, buf, IO_TIMEOUT)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// A duplicated write handle we deliberately move to a scratch thread. `RawHandle` is not
/// `Send`; the thread is the sole user of this copy, so moving the raw value is sound.
struct SendHandle(std::os::windows::io::RawHandle);
unsafe impl Send for SendHandle {}

/// Write all of `buf` to the pipe `handle`, giving up after `timeout`. Returns the bytes
/// written (`buf.len()` on success) or a `TimedOut`/OS error.
fn bounded_pipe_write(handle: HANDLE, buf: &[u8], timeout: Duration) -> io::Result<usize> {
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use windows_sys::Win32::Foundation::{
        DuplicateHandle, DUPLICATE_SAME_ACCESS, FALSE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    // Duplicate the write handle so the scratch thread owns a copy it can close on drop,
    // leaving the caller's `File` untouched even if we abandon a wedged write.
    let mut dup: HANDLE = INVALID_HANDLE_VALUE;
    let ok = unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            handle,
            GetCurrentProcess(),
            &mut dup,
            0,
            FALSE,
            DUPLICATE_SAME_ACCESS,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }

    let dup = SendHandle(dup as RawHandle);
    let payload = buf.to_vec();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        use std::io::Write;
        // Bind the whole `SendHandle` (not just `dup.0`) so the closure captures the `Send`
        // wrapper rather than the bare `*mut c_void`, which is not `Send`.
        let dup = dup;
        // Adopt the duplicated handle as a File so the write goes through std and the handle
        // is closed on drop — including when the guardian has already abandoned us.
        let mut file = unsafe { std::fs::File::from_raw_handle(dup.0) };
        let result = file.write_all(&payload).map(|()| payload.len());
        // The receiver may already be gone (we timed out); ignore the send failure.
        let _ = tx.send(result);
    });

    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "control channel write timed out",
        )),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            Err(io::Error::other("control channel write thread vanished"))
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

    /// The quoted form of one argument, decoded back to a `String` for comparison.
    fn quote_arg(arg: &OsStr) -> String {
        let mut out = Vec::new();
        quote_arg_into(&mut out, arg);
        String::from_utf16(&out).unwrap()
    }

    #[test]
    fn windows_arguments_follow_create_process_quoting_rules() {
        assert_eq!(quote_arg(OsStr::new("plain")), "plain");
        assert_eq!(quote_arg(OsStr::new("")), "\"\"");
        assert_eq!(quote_arg(OsStr::new("two words")), "\"two words\"");
        assert_eq!(quote_arg(OsStr::new(r#"a\"b"#)), r#""a\\\"b""#);
        assert_eq!(quote_arg(OsStr::new(r"trail\")), r#""trail\\""#);
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
