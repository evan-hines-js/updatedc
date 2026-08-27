//! The Unix half of the launcher's operating-system surface: the inherited control-channel
//! socketpair, polling, and the stop signal — all as thin safe wrappers over `libc`. The
//! platform-agnostic launcher core (`agent`, `launcher`) calls these; the cfg lives here.

use control::{Hello, Request, Response};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;

/// A connected `AF_UNIX`/`SOCK_STREAM` pair; both ends close-on-exec by default so only
/// the one deliberately handed to a child (via [`clear_cloexec`]) survives an exec.
fn socketpair_cloexec() -> std::io::Result<[libc::c_int; 2]> {
    let mut sv = [0 as libc::c_int; 2];
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    set_cloexec(sv[0])?;
    set_cloexec(sv[1])?;
    Ok(sv)
}

fn set_cloexec(fd: libc::c_int) -> std::io::Result<()> {
    set_fd_flag(fd, libc::FD_CLOEXEC, true)
}

/// Clear close-on-exec so `fd` survives into an exec'd child (the control-channel end
/// handed to the agent).
fn clear_cloexec(fd: libc::c_int) -> std::io::Result<()> {
    set_fd_flag(fd, libc::FD_CLOEXEC, false)
}

fn set_fd_flag(fd: libc::c_int, flag: libc::c_int, on: bool) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let next = if on { flags | flag } else { flags & !flag };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, next) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn close_fd(fd: libc::c_int) {
    unsafe {
        libc::close(fd);
    }
}

/// Install `handler` for `signum` via `sigaction`, checking the result. `sigaction` is
/// preferred over `signal`: it has deterministic cross-platform semantics (no BSD/System-V
/// disagreement, no one-shot handler reset) and reports failure, where `signal` returns an
/// opaque sentinel. `SA_RESTART` is set to match the glibc `signal` behaviour these calls
/// replaced. SAFETY: `action` is fully initialised before use and `handler` is a valid
/// disposition (a handler function pointer, `SIG_IGN`, or `SIG_DFL`).
fn set_signal_action(signum: libc::c_int, handler: libc::sighandler_t) -> io::Result<()> {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler;
        libc::sigemptyset(&mut action.sa_mask);
        action.sa_flags = libc::SA_RESTART;
        if libc::sigaction(signum, &action, std::ptr::null_mut()) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Ignore `SIGPIPE` process-wide so a write to a control channel whose peer has died
/// returns `EPIPE` instead of killing the launcher.
pub fn ignore_sigpipe() {
    if let Err(e) = set_signal_action(libc::SIGPIPE, libc::SIG_IGN) {
        crate::log::warn(&format!("ignoring SIGPIPE: {e}"));
    }
}

/// Install the stop-signal handler: a `SIGTERM`/`SIGINT` sets the shutdown flag so the
/// launcher stops its agent and exits cleanly.
pub fn install_shutdown_handler() {
    let handler = handle_signal as *const () as libc::sighandler_t;
    for signum in [libc::SIGTERM, libc::SIGINT] {
        if let Err(e) = set_signal_action(signum, handler) {
            crate::log::warn(&format!("installing stop handler for signal {signum}: {e}"));
        }
    }
}

extern "C" fn handle_signal(_sig: libc::c_int) {
    super::request_shutdown();
}

/// Wait up to `timeout_ms` for `fd` to become readable, so the single-threaded launcher
/// can watch the control channel while still periodically checking the agent.
fn poll_readable(fd: libc::c_int, timeout_ms: libc::c_int) -> bool {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let r = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    if r <= 0 {
        return false;
    }
    if pfd.revents & libc::POLLIN != 0 {
        return true;
    }
    // POLLHUP/POLLERR/POLLNVAL: the peer is gone. Report "not readable" and let the
    // serve loop observe the death through the agent's exit status.
    false
}

// ------------------------------ the control channel ------------------------------

/// How long a single control-channel read or write may stall the launcher's one thread
/// before it gives up on the frame. Generous next to any honest exchange (both ends are
/// local and the frames are tiny), and short next to the readiness gate and the stop grace
/// it must keep servicing.
const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The launcher's end of the inherited control channel: a connected `socketpair` whose
/// other end survives the agent's exec (its descriptor number is passed in the
/// environment). When the agent dies the channel closes, which is how the launcher
/// notices.
pub struct Channel {
    stream: UnixStream,
    child_fd: RawFd,
}

impl Channel {
    /// Create the pair; the launcher keeps one end, the other is handed to the agent.
    pub fn create() -> io::Result<Channel> {
        let [launcher, child] = socketpair_cloexec()?;
        // The child's end must survive its exec; the launcher's end stays close-on-exec.
        clear_cloexec(child)?;
        let stream = unsafe { UnixStream::from_raw_fd(launcher) };
        // The launcher serves everything — the agent channel, the shutdown signal, the
        // readiness deadline — from one thread, so no channel operation may block it
        // indefinitely. The agent is the less-trusted end and the one being replaced: a
        // half-written frame or an unread response must cost the launcher a bounded stall.
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        Ok(Channel {
            stream,
            child_fd: child,
        })
    }

    /// The `CONTROL_ENV` value the agent reads: the inherited descriptor number.
    pub fn child_env_value(&self) -> String {
        self.child_fd.to_string()
    }

    /// After the agent has inherited the child end, the launcher drops its own copy so
    /// it is the sole holder of the launcher end.
    pub fn close_child_end(&mut self) {
        if self.child_fd >= 0 {
            close_fd(self.child_fd);
            self.child_fd = -1;
        }
    }

    pub fn poll_readable(&self, timeout_ms: i32) -> bool {
        poll_readable(self.stream.as_raw_fd(), timeout_ms)
    }

    pub fn send_hello(&mut self) -> control::Result<()> {
        Hello::current().write(&mut self.stream)
    }

    pub fn read_request(&mut self) -> control::Result<Request> {
        Request::read(&mut self.stream)
    }

    pub fn send_response(&mut self, resp: &Response) -> control::Result<()> {
        resp.write(&mut self.stream)
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        self.close_child_end();
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::io::Write;

    fn fd_flags(fd: RawFd) -> libc::c_int {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert!(flags >= 0, "F_GETFD failed: {}", io::Error::last_os_error());
        flags
    }

    #[test]
    fn socketpair_starts_close_on_exec_and_can_clear_one_end() {
        let [a, b] = socketpair_cloexec().unwrap();
        assert_ne!(fd_flags(a) & libc::FD_CLOEXEC, 0);
        assert_ne!(fd_flags(b) & libc::FD_CLOEXEC, 0);
        clear_cloexec(b).unwrap();
        assert_ne!(fd_flags(a) & libc::FD_CLOEXEC, 0);
        assert_eq!(fd_flags(b) & libc::FD_CLOEXEC, 0);
        close_fd(a);
        close_fd(b);
    }

    #[test]
    fn setting_flags_on_an_invalid_fd_reports_an_error() {
        assert!(set_cloexec(-1).is_err());
        assert!(clear_cloexec(-1).is_err());
    }

    #[test]
    fn channel_sends_hello_over_the_inherited_endpoint() {
        let mut channel = Channel::create().unwrap();
        let child_fd: RawFd = channel.child_env_value().parse().unwrap();
        let peer_fd = unsafe { libc::dup(child_fd) };
        assert!(peer_fd >= 0);
        let mut peer = unsafe { UnixStream::from_raw_fd(peer_fd) };
        channel.close_child_end();

        channel.send_hello().unwrap();
        assert_eq!(Hello::read(&mut peer).unwrap(), Hello::current());
        assert!(!channel.poll_readable(0));

        Request::Ready([7u8; 16]).write(&mut peer).unwrap();
        assert!(channel.poll_readable(100));
        assert_eq!(channel.read_request().unwrap(), Request::Ready([7u8; 16]));

        channel.send_response(&Response::Ok).unwrap();
        assert_eq!(Response::read(&mut peer).unwrap(), Response::Ok);
        drop(peer);
        // A closed stream can report POLLIN together with POLLHUP; the read is the
        // authoritative observation that the peer is gone.
        assert!(channel.poll_readable(100));
        assert!(matches!(
            channel.read_request(),
            Err(control::Error::Closed)
        ));
    }

    #[test]
    fn closing_the_child_endpoint_is_idempotent_and_invalidates_its_value() {
        let mut channel = Channel::create().unwrap();
        channel.close_child_end();
        channel.close_child_end();
        assert_eq!(channel.child_env_value(), "-1");
    }

    /// `poll_readable` must answer `false` — never spin, never panic — for a descriptor that is
    /// not open (POLLNVAL). Asked of a number provably beyond the process's descriptor table
    /// rather than of a just-closed pair: descriptor numbers are reused lowest-first, so under the
    /// multi-threaded test runner another test could reclaim the closed number between the close
    /// and the poll and hand this assertion a live, readable descriptor.
    #[test]
    fn poll_reports_invalid_descriptors_closed() {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) },
            0
        );
        let beyond_table = i32::try_from(limit.rlim_cur)
            .ok()
            .and_then(|limit| limit.checked_add(1))
            .unwrap_or(i32::MAX);
        assert!(!poll_readable(beyond_table, 0));
    }

    #[test]
    fn writing_after_peer_close_returns_an_error_instead_of_sigpipe() {
        ignore_sigpipe();
        let [a, b] = socketpair_cloexec().unwrap();
        close_fd(b);
        let mut stream = unsafe { UnixStream::from_raw_fd(a) };
        assert!(stream.write_all(b"x").is_err());
    }
}
