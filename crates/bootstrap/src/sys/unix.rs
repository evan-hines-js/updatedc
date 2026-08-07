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
///
/// `PR_SET_PDEATHSIG` covers the leader alone, so the workers it forked are reachable only
/// through the group — and only through this handle. Every way this handle ends
/// ([`stop`](crate::sys::Process::stop), an observed exit, or a plain drop) therefore takes the
/// group down with it, which is the same guarantee the Windows adapter gets from its
/// kill-on-close job object.
struct Proc {
    child: Child,
    pid: u32,
    exited: Option<i32>,
    /// Set once the group is over — killed here, or observed empty. The group id IS the leader's
    /// PID, and the kernel reserves that PID only while the group still has members, so naming it
    /// again could reach a group some unrelated process built on a recycled PID.
    group_ended: bool,
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
        // Own process group, so the guardian can signal the app's whole tree; and die with the
        // guardian, so a guardian crash can never orphan a running app into a duplicate. Both are
        // the workspace's one implementation of process containment.
        cmd.process_group(0);
        foundation::process::arrange_parent_death_signal(&mut cmd);
        let child = cmd.spawn()?;
        let pid = child.id();
        Ok(Proc {
            child,
            pid,
            exited: None,
            group_ended: false,
        })
    }

    /// `SIGKILL` whatever is left in the application's process group, once.
    ///
    /// The kill is hard and immediate by design: the graceful window belongs to
    /// [`stop`](crate::sys::Process::stop), which quiesces a *live* application, and by the time
    /// this runs the whole group has either been given that window and spent it, or the leader has
    /// exited on its own — taking the tower down with it — or this handle is being dropped, after
    /// which nothing can name the group to stop it gracefully or otherwise.
    ///
    /// The group id is never a stranger's: the kernel keeps a group's number allocated while any
    /// member survives, so `-pid` either reaches the application's own descendants or fails with
    /// `ESRCH` because the group is already empty. Never naming the group once it is over is what
    /// keeps that true — the moment it drains, its number is the kernel's to hand out again.
    fn kill_group(&mut self) {
        if self.group_ended {
            return;
        }
        self.group_ended = true;
        unsafe {
            libc::kill(-(self.pid as libc::pid_t), libc::SIGKILL);
        }
    }

    /// Reap the leader if it has exited, recording its code. The rest of the group is left
    /// alone: who ends it, and when, is the caller's decision.
    fn reap(&mut self) -> Option<i32> {
        if self.exited.is_none() {
            if let Ok(Some(status)) = self.child.try_wait() {
                self.exited = Some(exit_code(status));
            }
        }
        self.exited
    }

    /// Whether any member of the application's process group is still there. An unreaped leader
    /// counts as a member, so [`Proc::reap`] must run first for this to mean "still working".
    fn group_alive(&self) -> bool {
        unsafe { libc::kill(-(self.pid as libc::pid_t), 0) == 0 }
    }

    /// Whether the leader has exited, observed WITHOUT reaping it (`WNOWAIT`).
    ///
    /// Reaping is what frees the leader's PID, and the group id IS that PID: for the common case
    /// of a leaf application with no surviving workers, the group empties at the reap and its
    /// number is the kernel's to hand out again the same instant. Anything that must name the
    /// group after seeing the leader die therefore has to see it die without reaping it — the
    /// zombie holds the number until we choose to release it.
    fn leader_exited(&self) -> bool {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            libc::waitid(
                libc::P_PID,
                self.pid as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        // With `WNOHANG` a leader that is still running is reported as success with a zeroed
        // `si_pid`, so the pid — not the return value — is the observation.
        ok == 0 && unsafe { siginfo_pid(&info) } == self.pid as libc::pid_t
    }
}

/// The pid a `waitid` result reports. libc exposes it as a plain field on the BSDs and behind an
/// accessor on Linux, where the union is private.
///
/// SAFETY: `info` was filled in by a successful `waitid`, so its pid member is initialised.
#[cfg(target_os = "linux")]
unsafe fn siginfo_pid(info: &libc::siginfo_t) -> libc::pid_t {
    unsafe { info.si_pid() }
}

#[cfg(not(target_os = "linux"))]
unsafe fn siginfo_pid(info: &libc::siginfo_t) -> libc::pid_t {
    info.si_pid
}

impl crate::sys::Process for Proc {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn poll_exit(&mut self) -> Option<i32> {
        if self.exited.is_some() {
            return self.exited;
        }
        // Observe the leader's exit without reaping it. The caller drops this handle the moment it
        // takes the exit code, and the leader's own exit leaves its workers running in the group,
        // so they must be taken down here — and the group is only ours to name while the leader's
        // PID is still held by its zombie. Reaping first would release that number to the kernel
        // with the group possibly already empty, and the kill could then land on a stranger's
        // group built on the recycled PID. A *stop* does not come through here: its window belongs
        // to the whole group, not to the leader.
        if !self.leader_exited() {
            return None;
        }
        self.kill_group();
        self.reap()
    }

    /// Stop the process group (SIGTERM, then SIGKILL after `grace`).
    ///
    /// The window is the group's, not the leader's. A launcher-style application forwards the
    /// SIGTERM to its workers and its leader exits immediately, and those workers finishing their
    /// in-flight work are exactly what the operator configured the grace for — so the wait ends on
    /// the *group* draining, never on the leader's own exit, which would truncate the drain to
    /// whatever fraction of the window happened to have elapsed.
    fn stop(&mut self, grace: Duration) {
        if self.group_ended {
            // The group is over (an observed exit killed it, or an earlier stop did); its number
            // is the kernel's again, so naming it now could reach an unrelated process.
            return;
        }
        // PID-reuse is not a hazard for this signal: `self.child` is our own descendant and, since
        // the group has not ended, it has not been reaped (the one path that reaps without a stop
        // — `poll_exit` — ends the group in the same breath), so its PID, and the process group
        // whose id equals that PID, cannot have been recycled to some unrelated process. The worst
        // case is signalling a group that just went empty, which is a harmless no-op.
        unsafe {
            libc::kill(-(self.pid as libc::pid_t), libc::SIGTERM);
        }
        let deadline = Instant::now() + grace;
        loop {
            // Reap first, so an unreaped leader is never mistaken for a worker still draining.
            self.reap();
            if !self.group_alive() {
                self.group_ended = true;
                break;
            }
            if Instant::now() >= deadline {
                self.kill_group();
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = self.child.wait();
        self.exited.get_or_insert(137);
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        // Nothing can name this process group once the handle is gone, so the group dies with
        // the handle — the Unix counterpart of the Windows adapter's kill-on-close job object.
        // For a `Proc` dropped while the application is still running this is the only thing
        // that stops it; after an observed exit or a completed stop the group is already over.
        self.kill_group();
        if self.exited.is_none() {
            // Reap the leader that kill just took down: a `Child` dropped unwaited leaves a
            // zombie for the rest of the guardian's life.
            let _ = self.child.wait();
        }
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
/// returns `EPIPE` instead of killing the guardian.
pub fn ignore_sigpipe() {
    if let Err(e) = set_signal_action(libc::SIGPIPE, libc::SIG_IGN) {
        crate::log::warn(&format!("ignoring SIGPIPE: {e}"));
    }
}

/// Install the stop-signal handler: a `SIGTERM`/`SIGINT` sets the shutdown flag so the
/// guardian exits cleanly (forwarding the stop down to the application).
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
    use crate::sys::Process as _;
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

    fn spec(script: &str) -> CommandSpec {
        CommandSpec {
            program: std::ffi::OsString::from("/bin/sh"),
            args: vec![
                std::ffi::OsString::from("-c"),
                std::ffi::OsString::from(script),
            ],
            env: vec![],
            cwd: None,
        }
    }

    #[test]
    fn an_observed_exit_takes_the_leftover_workers_with_it() {
        // A launcher-style app: the leader exits while a worker it forked keeps running in the
        // group. The exit code is the leader's, and the worker must not be left behind — the
        // caller drops the handle right after taking the code, and nothing else can name the
        // group once it does.
        let mut proc = Proc::launch(&spec("sleep 60 &\nexit 7")).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let code = loop {
            if let Some(code) = proc.poll_exit() {
                break code;
            }
            assert!(Instant::now() < deadline, "the leader never exited");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(code, 7);
        assert_eq!(
            proc.poll_exit(),
            Some(7),
            "the code is remembered, not re-reaped"
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while proc.group_alive() {
            assert!(
                Instant::now() < deadline,
                "the leftover worker survived the observed exit"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn an_exit_is_observed_before_the_leader_is_reaped() {
        // The group id IS the leader's PID, and reaping releases it. `poll_exit` must therefore
        // see the exit through a non-reaping wait, so the zombie still holds the number while the
        // group kill names it; a `try_wait`-first ordering would kill a recycled group.
        let mut proc = Proc::launch(&spec("exit 3")).unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while !proc.leader_exited() {
            assert!(Instant::now() < deadline, "the leader never exited");
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            proc.exited.is_none(),
            "observing the exit must not reap it — that would free the group id"
        );
        assert_eq!(proc.poll_exit(), Some(3));
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
