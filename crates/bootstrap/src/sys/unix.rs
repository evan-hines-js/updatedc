//! The Unix half of the guardian's operating-system surface: the launched application
//! process (contained so it dies with the guardian), the inherited control-channel
//! socketpair, and polling — all as thin safe wrappers over `libc`. The platform-agnostic
//! guardian core (`app`, `supervisor`, `guardian`) calls these; the cfg lives here.

use control::{CommandSpec, Hello, Request, Response};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// A launched application process, contained so it dies with the guardian: it runs in its
/// own process group (so the guardian can signal its whole tree) and, on Linux, sets
/// `PR_SET_PDEATHSIG(SIGKILL)` so the kernel kills it if the guardian dies. There is no
/// re-adoption across a guardian restart — the app simply does not survive one.
struct Proc {
    child: Child,
    pid: u32,
    exited: Option<i32>,
}

/// Launch the contained application process from `spec` (the [`Process`](crate::sys::Process)
/// port's Unix adapter factory).
pub fn spawn(spec: &CommandSpec) -> io::Result<Box<dyn crate::sys::Process>> {
    Ok(Box::new(Proc::launch(spec)?))
}

impl Proc {
    /// Launch the application from `spec`, contained. The spec carries the complete
    /// environment; the guardian inherits nothing into the app but its standard I/O.
    fn launch(spec: &CommandSpec) -> io::Result<Proc> {
        use std::os::unix::process::CommandExt;

        let mut cmd = Command::new(&spec.program);
        cmd.args(&spec.args);
        cmd.env_clear();
        cmd.envs(spec.env.iter().map(|(k, v)| (k, v)));
        if let Some(cwd) = &spec.cwd {
            cmd.current_dir(cwd);
        }
        let expected_ppid = std::process::id() as libc::pid_t;
        // Safety: the hook runs in the forked child before exec and calls only
        // async-signal-safe functions.
        unsafe {
            cmd.pre_exec(move || {
                // Own process group, so the guardian can signal the app's whole tree.
                if libc::setpgid(0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                // Die with the guardian: if it exits, the kernel kills this process, so a
                // guardian crash can never orphan a running app into a duplicate. Linux
                // only; on macOS the init system's process teardown covers this (macOS is
                // a dev/test target, not a service target).
                #[cfg(target_os = "linux")]
                {
                    libc::prctl(
                        libc::PR_SET_PDEATHSIG,
                        libc::SIGKILL as libc::c_ulong,
                        0,
                        0,
                        0,
                    );
                    // Close the race: if the guardian already died between fork and here,
                    // we will not get the signal, so check our parent is still the guardian.
                    if libc::getppid() != expected_ppid {
                        libc::_exit(0);
                    }
                }
                let _ = expected_ppid;
                Ok(())
            });
        }
        let child = cmd.spawn()?;
        let pid = child.id();
        Ok(Proc {
            child,
            pid,
            exited: None,
        })
    }
}

impl crate::sys::Process for Proc {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn poll_exit(&mut self) -> Option<i32> {
        if self.exited.is_none() {
            if let Ok(Some(status)) = self.child.try_wait() {
                self.exited = Some(exit_code(status));
            }
        }
        self.exited
    }

    /// Stop the process group (SIGTERM, then SIGKILL after `grace`).
    fn stop(&mut self, grace: Duration) {
        if self.poll_exit().is_some() {
            return;
        }
        let group = -(self.pid as libc::pid_t);
        unsafe {
            libc::kill(group, libc::SIGTERM);
        }
        let deadline = Instant::now() + grace;
        while Instant::now() < deadline {
            if self.poll_exit().is_some() {
                return;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        unsafe {
            libc::kill(group, libc::SIGKILL);
        }
        let _ = self.child.wait();
        self.exited.get_or_insert(137);
    }
}

/// The application's exit code the way a shell reports it (128 + signal for a killed
/// process), so the guardian can roll it up to the init system.
fn exit_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0))
}

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
/// handed to the supervisor).
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

/// Ignore `SIGPIPE` process-wide so a write to a control channel whose peer has died
/// returns `EPIPE` instead of killing the guardian.
pub fn ignore_sigpipe() {
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
}

/// Install the stop-signal handler: a `SIGTERM`/`SIGINT` sets the shutdown flag so the
/// guardian exits cleanly (forwarding the stop down to the application).
pub fn install_shutdown_handler() {
    let handler = handle_signal as *const () as libc::sighandler_t;
    unsafe {
        libc::signal(libc::SIGTERM, handler);
        libc::signal(libc::SIGINT, handler);
    }
}

extern "C" fn handle_signal(_sig: libc::c_int) {
    super::request_shutdown();
}

/// Ask a supervisor process to stop gracefully (the guardian hard-kills it if the grace
/// expires). On Unix that is a `SIGTERM`.
pub fn terminate_gracefully(pid: u32) {
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
}

/// Wait up to `timeout_ms` for `fd` to become readable, so the single-threaded guardian
/// can watch the control channel while still periodically checking the app and supervisor.
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
    // serve loop observe the death through the supervisor's exit status.
    false
}

// ------------------------------ the control channel ------------------------------

/// How long a single control-channel read or write may stall the guardian's one thread
/// before it gives up on the frame. Generous next to any honest exchange (both ends are
/// local and the frames are tiny), and short next to the readiness gate and the stop grace
/// it must keep servicing.
const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// The guardian's end of the inherited control channel: a connected `socketpair` whose
/// other end survives the supervisor's exec (its descriptor number is passed in the
/// environment). When the supervisor dies the channel closes, which is how the guardian
/// notices.
pub struct Channel {
    stream: UnixStream,
    child_fd: RawFd,
}

impl Channel {
    /// Create the pair; the guardian keeps one end, the other is handed to the supervisor.
    pub fn create() -> io::Result<Channel> {
        let [guardian, child] = socketpair_cloexec()?;
        // The child's end must survive its exec; the guardian's end stays close-on-exec so
        // it never leaks into the application's fork.
        clear_cloexec(child)?;
        let stream = unsafe { UnixStream::from_raw_fd(guardian) };
        // The guardian serves everything — the supervisor channel, the shutdown signal, the
        // application-crash check, the readiness deadline — from one thread, so no channel
        // operation may block it indefinitely. The supervisor is the less-trusted end and
        // the one being replaced: a half-written frame or an unread response must cost the
        // guardian a bounded stall, never the application.
        stream.set_read_timeout(Some(IO_TIMEOUT))?;
        stream.set_write_timeout(Some(IO_TIMEOUT))?;
        Ok(Channel {
            stream,
            child_fd: child,
        })
    }

    /// The `CONTROL_ENV` value the supervisor reads: the inherited descriptor number.
    pub fn child_env_value(&self) -> String {
        self.child_fd.to_string()
    }

    /// After the supervisor has inherited the child end, the guardian drops its own copy so
    /// it is the sole holder of the guardian end.
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
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::process::ExitStatusExt;

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

        Request::Stop.write(&mut peer).unwrap();
        assert!(channel.poll_readable(100));
        assert_eq!(channel.read_request().unwrap(), Request::Stop);

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

    #[test]
    fn exit_codes_preserve_normal_exit_and_shell_signal_conventions() {
        let normal = Command::new("/bin/sh")
            .args(["-c", "exit 23"])
            .status()
            .unwrap();
        assert_eq!(exit_code(normal), 23);
        let signalled = std::process::ExitStatus::from_raw(libc::SIGTERM);
        assert_eq!(exit_code(signalled), 128 + libc::SIGTERM);
    }

    #[test]
    fn poll_reports_invalid_descriptors_closed() {
        let [read, write] = socketpair_cloexec().unwrap();
        close_fd(read);
        close_fd(write);
        assert!(!poll_readable(read, 0));
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
