//! The Windows half of the launcher's operating-system surface: the inherited
//! control-channel pipes, polling, and the console stop handler. The platform-agnostic
//! launcher core (`agent`, `launcher`) calls these; the cfg lives here. The FFI stays
//! inline where it is inseparable from the handle logic it wraps.

use std::io;
use std::time::Duration;

use windows_sys::Win32::Foundation::HANDLE;

// ------------------------------- stop signals -------------------------------

/// A no-op on Windows (there is no `SIGPIPE`); present so the launcher core can call it
/// unconditionally, keeping its own code free of `cfg`.
pub fn ignore_sigpipe() {}

/// Install the stop handler: a console close/shutdown event sets the shutdown flag so the
/// launcher stops its agent and exits cleanly.
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

/// The launcher's end of the inherited control channel: a duplex pair of anonymous pipes
/// (Windows anonymous pipes are one-directional). The launcher reads agent→launcher
/// and writes launcher→agent; the agent inherits the complementary two handles.
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
        // g2s: launcher writes, agent reads. s2g: agent writes, launcher reads.
        // Own every handle the instant it exists so a failure part-way through closes them
        // all on unwind — the launcher relaunches on a loop, so a leak here would compound.
        let (g2s_read, g2s_write) = anon_pipe()?;
        let g2s_read = unsafe { OwnedHandle::from_raw_handle(g2s_read as RawHandle) };
        let g2s_write = unsafe { OwnedHandle::from_raw_handle(g2s_write as RawHandle) };
        let (s2g_read, s2g_write) = anon_pipe()?;
        let s2g_read = unsafe { OwnedHandle::from_raw_handle(s2g_read as RawHandle) };
        let s2g_write = unsafe { OwnedHandle::from_raw_handle(s2g_write as RawHandle) };
        // Each pipe's child-facing handle is inheritable; the launcher's is not.
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

/// How long a single control-channel read or write may stall the launcher's one thread
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

/// Bounds a blocking pipe read. Without this an agent that writes one byte and stops
/// would block the launcher's only thread inside `read_exact` forever, stranding its
/// shutdown signal and its readiness deadline.
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
/// blocks once the pipe buffer fills — so an agent that stops draining could otherwise
/// wedge the launcher's only thread inside `send_hello`/`send_response` forever, stranding
/// the shutdown signal and readiness deadline.
///
/// The bound is enforced by writing each frame chunk on a scratch thread (holding a
/// duplicated handle) and waiting up to the deadline. On timeout the launcher abandons the
/// thread — it unblocks and closes its handle copy if the pipe ever drains or closes — and
/// reports the stall, which the serve loop treats as a lost agent.
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
        // is closed on drop — including when the launcher has already abandoned us.
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
