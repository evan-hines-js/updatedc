//! Contained subprocess execution: spawn a child whose entire descendant tree can be
//! killed as a unit — a Unix process group, a Windows job object.
//!
//! This is the one home for that primitive. A caller that runs an untrusted or
//! long-running helper (the agent's lifecycle-hook runner is the motivating case)
//! must be able to time it out and take down *the whole tree* it spawned, not just the
//! immediate child — otherwise a wrapper shell dies while the `curl`/vendor-CLI it
//! launched keeps running. Re-implementing that per-OS at each call site is exactly the
//! kind of platform leak this crate exists to prevent.
//!
//! Windows closes the otherwise-fatal `CreateProcess`/job-assignment gap in two layers. The
//! caller first joins a private kill-on-close guard job, so every new child is death-contained
//! from the instant the kernel creates it. Each child is then created suspended, assigned to its
//! own independently killable job, and resumed. No child instruction can run between creation
//! and per-tree containment, while the inherited guard still covers a caller killed inside that
//! setup window.

use std::io;
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

/// How long [`ContainedChild::stop`] waits for the tree to be reaped after the hard kill. A
/// caller that has to promise a shutdown budget to something else (a service manager) adds this
/// to the grace it passes.
pub const KILL_HEADROOM: Duration = Duration::from_secs(10);

/// The exit-poll cadence of [`ContainedChild::stop`].
const STOP_POLL: Duration = Duration::from_millis(100);

/// What [`ContainedChild::stop`] had to do to end the tree.
#[derive(Debug)]
pub enum Stopped {
    /// The tree exited on the graceful request, within the grace.
    Gracefully,
    /// The grace expired (or the graceful request could not be delivered, in which case there is
    /// no grace to sit out) and the tree was killed.
    Killed,
    /// The kill was issued and something was still unreaped when [`KILL_HEADROOM`] expired.
    Surviving,
}

/// A spawned child plus the OS mechanism that binds its descendants into one killable
/// tree. Dropping it kills the tree on Windows and macOS. Other Unix callers must
/// explicitly wait or stop it; the process group alone is not a drop guard.
pub struct ContainedChild {
    child: Child,
    /// Set once the root child has been reaped by [`try_wait`](Self::try_wait) or
    /// [`wait`](Self::wait). From that moment its PID belongs to the kernel again and may name
    /// an unrelated process, so [`kill_tree`](Self::kill_tree) must never signal it directly.
    reaped: bool,
    #[cfg(windows)]
    job: windows::Job,
    #[cfg(target_os = "macos")]
    _parent_liveness: std::os::unix::net::UnixStream,
}

impl ContainedChild {
    /// Spawn `command` as the root of a fresh, killable process tree. The child leads a new
    /// process group on BOTH platforms — `process_group(0)` on Unix, `CREATE_NEW_PROCESS_GROUP`
    /// on Windows — and on Windows it is additionally assigned to a kill-on-close job object
    /// before it can spawn descendants of its own.
    ///
    /// The group is established here, not by the caller, because
    /// [`request_stop`](Self::request_stop) *depends* on it: a Windows `CTRL_BREAK` reaches only a
    /// child that leads its own group, so a caller that forgot the flag would get a graceful stop
    /// that silently did nothing (or, worse, an event aimed at the wrong group). Making it part of
    /// spawning is what turns that from a convention into a guarantee — the same reason `reaped`
    /// lives in this type rather than in each caller's head.
    pub fn spawn(command: Command) -> io::Result<Self> {
        #[cfg(windows)]
        {
            Self::spawn_windows(command, 0)
        }
        #[cfg(not(windows))]
        {
            Self::spawn_contained(command)
        }
    }

    /// [`spawn`](Self::spawn) for a caller that has no console of its own — an SCM service, whose
    /// process is created without one. A console control event can only be raised inside a
    /// console, so such a caller can never address a child that has none either: the child is
    /// given a fresh console here, and [`request_stop`](Self::request_stop) borrows it for the
    /// instant it takes to raise the event. Every other caller shares its own console with the
    /// child and must NOT use this.
    #[cfg(windows)]
    pub fn spawn_in_new_console(command: Command) -> io::Result<Self> {
        Self::spawn_windows(
            command,
            windows_sys::Win32::System::Threading::CREATE_NEW_CONSOLE,
        )
    }

    /// The Windows creation flags belong to this type, not to its callers: `std::process::Command`
    /// exposes no getter for them, so a caller-set flag and a type-set one cannot coexist — and
    /// [`request_stop`](Self::request_stop) is only correct when the process-group flag is present.
    #[cfg(windows)]
    fn spawn_windows(mut command: Command, extra_flags: u32) -> io::Result<Self> {
        use std::os::windows::process::CommandExt;
        // This job contains the caller itself and is installed BEFORE CreateProcess. A normal
        // child inherits it atomically at creation, so killing the caller in any later setup
        // window closes the last guard handle and kills the suspended child too.
        windows::ensure_parent_death_guard()?;
        // The Windows analogue of `process_group(0)`: the child's process-group id becomes its
        // PID, which is what `GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid)` addresses.
        command.creation_flags(
            windows_sys::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP
                | windows_sys::Win32::System::Threading::CREATE_SUSPENDED
                | extra_flags,
        );
        let mut child = command.spawn()?;
        // The child cannot execute or create descendants until it belongs to its own job. Its
        // inherited parent guard is already live, so even an abrupt caller death here cannot
        // leave the suspended process behind.
        let job = match windows::Job::assign(&child) {
            Ok(job) => job,
            Err(error) => {
                kill_and_reap(&mut child);
                return Err(error);
            }
        };
        if let Err(error) = windows::resume_suspended_process(child.id()) {
            let _ = job.terminate();
            let _ = child.wait();
            return Err(error);
        }
        Ok(ContainedChild {
            child,
            reaped: false,
            job,
        })
    }

    #[cfg(not(windows))]
    fn spawn_contained(mut command: Command) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // The child leads a new group whose ID is its PID, so a later kill of the
            // negated PID reaches the whole tree and never the caller's other children.
            command.process_group(0);
        }
        // Parent-death containment is part of the same spawn primitive as process-tree
        // containment. No caller can remember one while forgetting the other.
        #[cfg(target_os = "linux")]
        unix::arrange_parent_death_signal(&mut command);
        #[cfg(target_os = "macos")]
        let parent_liveness = unix::arrange_parent_death_watchdog(&mut command)?;
        let child = command.spawn()?;
        Ok(ContainedChild {
            child,
            reaped: false,
            #[cfg(target_os = "macos")]
            _parent_liveness: parent_liveness,
        })
    }

    /// The root child's PID.
    pub fn id(&self) -> u32 {
        self.child.id()
    }

    /// Take the root child's captured stdout (present only when the command was spawned with
    /// `Stdio::piped()`). Used to read a small line of output, e.g. a PID a provider prints.
    pub fn take_stdout(&mut self) -> Option<std::process::ChildStdout> {
        self.child.stdout.take()
    }

    /// Take the root child's captured stderr.
    pub fn take_stderr(&mut self) -> Option<std::process::ChildStderr> {
        self.child.stderr.take()
    }

    /// Observe only whether the root has exited, without reaping it or cleaning its descendants.
    ///
    /// This exists for diagnostics that must inspect the interval between a wrapper exiting and
    /// [`wait`](Self::wait) enforcing tree cleanup (the reconciler conformance checker detects
    /// inherited pipes there). It is not a completion operation: every caller must still finish
    /// through `wait`, `stop`, or `kill_tree` followed by `wait`.
    pub fn root_has_exited(&self) -> io::Result<bool> {
        #[cfg(unix)]
        {
            unix::child_exited_unreaped(self.child.id(), true)
        }
        #[cfg(windows)]
        {
            windows::child_exited(&self.child)
        }
    }

    /// Non-blocking exit check of the root child.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        if self.reaped {
            #[cfg(windows)]
            self.job.terminate()?;
            return self.child.try_wait();
        }
        #[cfg(unix)]
        {
            if !unix::child_exited_unreaped(self.child.id(), true)? {
                return Ok(None);
            }
            // Keep the leader as a zombie until the group is gone. Its unreaped PID pins the
            // process-group id, so cleanup can never hit a recycled, unrelated group.
            unix::cleanup_exited_tree(self.child.id())?;
            let status = self.child.wait()?;
            self.reaped = true;
            Ok(Some(status))
        }
        #[cfg(windows)]
        {
            let status = self.child.try_wait()?;
            if status.is_some() {
                self.reaped = true;
                // A job handle remains stable after its root exits, so clean any descendants
                // before reporting the tree complete.
                self.job.terminate()?;
            }
            Ok(status)
        }
    }

    /// Block until the root exits, tear down every undetached descendant, then reap it.
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        if self.reaped {
            #[cfg(windows)]
            self.job.terminate()?;
            return self.child.wait();
        }
        #[cfg(unix)]
        {
            unix::child_exited_unreaped(self.child.id(), false)?;
            unix::cleanup_exited_tree(self.child.id())?;
            let status = self.child.wait()?;
            self.reaped = true;
            Ok(status)
        }
        #[cfg(windows)]
        {
            let status = self.child.wait()?;
            self.reaped = true;
            self.job.terminate()?;
            Ok(status)
        }
    }

    /// Ask the tree to stop *gracefully* — `SIGTERM` on Unix, a `CTRL_BREAK` console event on
    /// Windows — leaving the caller to wait out a grace period and then [`kill_tree`](Self::kill_tree).
    /// This is the only graceful stop this type offers, and the only one a caller should need:
    /// signalling a PID by hand is exactly the hazard `reaped` exists to remove.
    ///
    /// Once the root has been reaped this is a no-op that reports success: `try_wait` and `wait`
    /// tear down its undetached descendants before reaping, so there is nothing left to ask
    /// politely. The Windows event needs two things: the child
    /// must lead its own process group, which spawning guarantees for every `ContainedChild` so
    /// no call site has to arrange it (and none can forget to); and it must be reachable in a
    /// console this process can raise an event in, which spawning does NOT guarantee on its own.
    /// Console reachability holds for a caller that owns a console — it shares it with the child
    /// — and for a console-less caller that spawned via
    /// [`spawn_in_new_console`](Self::spawn_in_new_console), whose child's console is borrowed for
    /// the instant the event takes. A console-less caller that used plain
    /// [`spawn`](Self::spawn) has a console-less child too, and gets `Err` here rather than a
    /// silent no-op — the caller then waits out its grace and
    /// [`kill_tree`](Self::kill_tree)s. On Unix spawning does not return until the child's
    /// pre-exec `setpgid` has landed, so `SIGTERM` is sent to the group and reaches wrappers and
    /// the helpers they launched together.
    pub fn request_stop(&mut self) -> io::Result<()> {
        if self.reaped {
            return Ok(());
        }
        #[cfg(unix)]
        {
            unix::request_stop(self.child.id())
        }
        #[cfg(windows)]
        {
            windows::request_stop(self.child.id())
        }
    }

    /// Stop the whole tree: ask gracefully, wait out `grace`, then kill it and give the reap
    /// [`KILL_HEADROOM`]. The one stop sequence in the workspace — every caller that owns a
    /// contained tree wants exactly this, and hand-rolling it per call site is how two of them
    /// came to disagree about what a failed graceful request means.
    ///
    /// It means: skip the grace. A break event that could not be delivered did not happen, so
    /// sitting out the full grace only delays the kill and makes a clean stop look like a hang.
    pub fn stop(&mut self, grace: Duration) -> Stopped {
        let grace = match self.request_stop() {
            Ok(()) => grace,
            Err(_) => Duration::ZERO,
        };
        if self.reaped_within(grace) {
            return Stopped::Gracefully;
        }
        let _ = self.kill_tree();
        if self.reaped_within(KILL_HEADROOM) {
            Stopped::Killed
        } else {
            Stopped::Surviving
        }
    }

    /// Poll for the root child's exit for up to `budget`. An unusable handle ends the wait at
    /// once — it can never start reporting an exit again.
    fn reaped_within(&mut self, budget: Duration) -> bool {
        let deadline = Instant::now() + budget;
        loop {
            match self.try_wait() {
                Ok(Some(_)) => return true,
                Err(_) => return false,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        return false;
                    }
                    std::thread::sleep(STOP_POLL.min(budget));
                }
            }
        }
    }

    /// Kill the entire tree — the process group on Unix, the job object on Windows — not just
    /// the root child. Correct at every point in the child's life, which is what makes it the
    /// only kill this type offers: while the root is unreaped its group (including the root) is
    /// signalled.
    /// Once it is reaped this is a no-op because the only reaping methods clean the still-PID-
    /// pinned group first. A tree whose members are all gone is success, so this is idempotent.
    pub fn kill_tree(&mut self) -> io::Result<()> {
        #[cfg(unix)]
        {
            unix::kill_tree(self.child.id(), self.reaped)
        }
        #[cfg(windows)]
        {
            self.job.terminate()
        }
    }
}

#[cfg(windows)]
fn kill_and_reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(unix)]
mod unix {
    use std::io;

    /// Darwin has no parent-death signal. Arm a watchdog inside the child's group BEFORE
    /// allowing the hook to exec. Its private socket reaches EOF when this owner's descriptor
    /// closes, including SIGKILL; it then kills the entire group. Normal tree cleanup kills the
    /// watchdog too, while the unreaped leader still pins the group identity.
    ///
    /// The watchdog execs the platform shell with a fixed program (never caller-supplied text).
    /// Exec discards inherited CLOEXEC descriptors, particularly the agent's instance lock and
    /// Rust's spawn-error pipe. A fork-only watcher would retain them and deadlock recovery.
    #[cfg(target_os = "macos")]
    pub(super) fn arrange_parent_death_watchdog(
        command: &mut std::process::Command,
    ) -> io::Result<std::os::unix::net::UnixStream> {
        use std::os::fd::{AsRawFd, FromRawFd};
        use std::os::unix::{net::UnixStream, process::CommandExt};
        let (owner, watcher) = UnixStream::pair()?;
        // Command may replace descriptors 0..2 when it installs the requested stdio. Keep
        // the liveness channel outside that range even when the caller closed its own stdio.
        let above_stdio = |socket: UnixStream| -> io::Result<UnixStream> {
            if socket.as_raw_fd() >= 3 {
                return Ok(socket);
            }
            let fd = unsafe { libc::fcntl(socket.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: fcntl returned a newly owned descriptor for this socket.
            Ok(unsafe { UnixStream::from_raw_fd(fd) })
        };
        let owner = above_stdio(owner)?;
        let watcher = above_stdio(watcher)?;
        let owner_fd = owner.as_raw_fd();
        // Darwin's pipe/socket creation and CLOEXEC assignment are separate syscalls. A
        // concurrent fork can inherit another spawn's error pipe before that assignment,
        // blocking the other spawn indefinitely. Sanitize the child's actual descriptor
        // table, not a parent snapshot; this needs no process-wide spawn lock.
        let estimated_bytes = unsafe {
            libc::proc_pidinfo(
                libc::getpid(),
                libc::PROC_PIDLISTFDS,
                0,
                std::ptr::null_mut(),
                0,
            )
        };
        if estimated_bytes <= 0 {
            return Err(io::Error::last_os_error());
        }
        let entry_size = std::mem::size_of::<libc::proc_fdinfo>();
        // Allocate before fork. Leave room for concurrent opens; if even that is exhausted,
        // fail this spawn rather than execute with an incomplete descriptor inventory.
        let mut descriptors = vec![
            libc::proc_fdinfo {
                proc_fd: 0,
                proc_fdtype: 0
            };
            estimated_bytes as usize / entry_size + 1024
        ];
        let capacity_bytes = i32::try_from(descriptors.len() * entry_size)
            .map_err(|_| io::Error::from_raw_os_error(libc::EMFILE))?;
        // SAFETY: after fork this callback uses only raw descriptor/process operations and
        // stack arithmetic; it never allocates, locks Rust state, or unwinds in the watchdog.
        unsafe {
            command.pre_exec(move || {
                // proc_pidinfo is a thin syscall wrapper: no allocation or user-space lock.
                let bytes = libc::proc_pidinfo(
                    libc::getpid(),
                    libc::PROC_PIDLISTFDS,
                    0,
                    descriptors.as_mut_ptr().cast(),
                    capacity_bytes,
                );
                if bytes <= 0 {
                    return Err(io::Error::last_os_error());
                }
                if bytes >= capacity_bytes || !(bytes as usize).is_multiple_of(entry_size) {
                    return Err(io::Error::from_raw_os_error(libc::EAGAIN));
                }
                for descriptor in &descriptors[..bytes as usize / entry_size] {
                    let fd = descriptor.proc_fd;
                    if fd >= 3 && libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                libc::close(owner_fd);
                let group = libc::getpid();
                let watchdog = libc::fork();
                if watchdog < 0 {
                    return Err(io::Error::last_os_error());
                }
                if watchdog == 0 {
                    if libc::dup2(watcher.as_raw_fd(), 0) < 0
                        || libc::fcntl(0, libc::F_SETFD, 0) < 0
                    {
                        libc::kill(-group, libc::SIGKILL);
                        libc::_exit(127);
                    }
                    libc::close(1);
                    libc::close(2);
                    // A decimal PID is the only dynamic argument; the command is fixed.
                    let mut digits = [0u8; 32];
                    let mut offset = digits.len() - 1;
                    let mut number = group as u32;
                    while number != 0 {
                        offset -= 1;
                        digits[offset] = b'0' + (number % 10) as u8;
                        number /= 10;
                    }
                    let args = [
                        c"sh".as_ptr(),
                        c"-c".as_ptr(),
                        c"while IFS= read -r line; do :; done; /bin/kill -KILL -- \"-$1\"".as_ptr(),
                        c"updated-parent-watchdog".as_ptr(),
                        digits.as_ptr().add(offset).cast(),
                        std::ptr::null(),
                    ];
                    let environment = [std::ptr::null()];
                    libc::execve(c"/bin/sh".as_ptr(), args.as_ptr(), environment.as_ptr());
                    // No watchdog means no permission to run an uncontained hook.
                    libc::kill(-group, libc::SIGKILL);
                    libc::_exit(127);
                }
                Ok(())
            });
        }
        Ok(owner)
    }

    /// Tie every contained Linux child to its parent in the kernel, including the fork/exec race
    /// where the parent dies before `PR_SET_PDEATHSIG` is armed. This is private because the only
    /// valid parent-death-contained process is one spawned through [`ContainedChild`], which also
    /// owns the tree-kill and reap invariants.
    #[cfg(target_os = "linux")]
    pub(super) fn arrange_parent_death_signal(command: &mut std::process::Command) {
        use std::os::unix::process::CommandExt;
        let expected_ppid = std::process::id() as libc::pid_t;
        // Safety: the hook runs in the forked child before exec and calls only
        // async-signal-safe functions.
        unsafe {
            command.pre_exec(move || {
                libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL as libc::c_ulong,
                    0,
                    0,
                    0,
                );
                // If the parent already died between fork and here, the signal will never
                // arrive; check the parent is still who we expect and self-exit if not.
                if libc::getppid() != expected_ppid {
                    libc::_exit(0);
                }
                Ok(())
            });
        }
    }

    /// Observe a direct child's exit without reaping it. `WNOWAIT` is the key containment detail:
    /// the zombie keeps its PID (and therefore its process-group id) reserved until the caller has
    /// killed every undetached descendant and deliberately reaps it.
    pub(super) fn child_exited_unreaped(id: u32, nonblocking: bool) -> io::Result<bool> {
        let pid = i32::try_from(id)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "child PID exceeds pid_t"))?;
        let options = libc::WEXITED | libc::WNOWAIT | if nonblocking { libc::WNOHANG } else { 0 };
        loop {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            // SAFETY: `info` is writable for its full size; P_PID selects only our direct child,
            // and WNOWAIT explicitly leaves its wait status available for `Child::wait`.
            let rc = unsafe { libc::waitid(libc::P_PID, pid as libc::id_t, &mut info, options) };
            if rc == 0 {
                // POSIX permits no state change to be reported for WNOHANG; the zeroed si_pid is
                // therefore the unambiguous "still running" result.
                return Ok(unsafe { info.si_pid() } != 0);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    /// Kill descendants after `waitid(WNOWAIT)` proved the leader has exited, while its zombie
    /// still pins the process-group id. The leader itself needs no signal; reaping follows only
    /// after this returns.
    pub(super) fn cleanup_exited_tree(id: u32) -> io::Result<()> {
        let error = match signal_group(id, libc::SIGKILL) {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };
        // Darwin reports EPERM when the group contains only the unsignalable zombie leader. A
        // live same-user descendant makes the group kill succeed, so this is the empty-tree case
        // reached by ordinary single-process commands.
        #[cfg(target_os = "macos")]
        if error.raw_os_error() == Some(libc::EPERM) {
            return Ok(());
        }
        Err(error)
    }

    pub(super) fn kill_tree(id: u32, leader_reaped: bool) -> io::Result<()> {
        if leader_reaped {
            // `try_wait` and `wait` kill the PID-pinned group before setting this bit. Signalling
            // the numeric group after reaping would reintroduce a process-id reuse race.
            return Ok(());
        }
        signal_group(id, libc::SIGKILL)
    }

    /// `SIGTERM` the still-PID-pinned process group so wrappers and helpers receive the graceful
    /// request together. `CommandExt::process_group` runs before exec, and `spawn` does not return
    /// before that setup completes.
    pub(super) fn request_stop(id: u32) -> io::Result<()> {
        signal_group(id, libc::SIGTERM)
    }

    /// The one Unix signalling path. Spawning establishes `pid` as the root and group id before it
    /// returns, so addressing the group reaches both the root and every undetached descendant; a
    /// second root-only signal is redundant and would create another policy path.
    fn signal_group(id: u32, signal: libc::c_int) -> io::Result<()> {
        let pid = i32::try_from(id)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "child PID exceeds pid_t"))?;
        // SAFETY: `-pid` names the fresh group established for this unreaped direct child.
        let rc = unsafe { libc::kill(-pid, signal) };
        accept_kill(rc, io::Error::last_os_error())
    }

    /// A `kill(2)` outcome is success when the signal was delivered (`rc == 0`) or the
    /// target had already exited (`ESRCH`); anything else (e.g. `EPERM`) is a real error.
    fn accept_kill(rc: libc::c_int, error: io::Error) -> io::Result<()> {
        if rc == 0 || error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(error)
        }
    }
}

#[cfg(windows)]
mod windows {
    use std::io;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use std::process::Child;
    use std::sync::Mutex;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    /// The handle is intentionally process-global and never dropped: the OS closes it after this
    /// process exits, which is exactly when kill-on-close must reap any child whose per-tree setup
    /// was interrupted. A mutex makes first use atomic across caller threads; creating two guard
    /// jobs and dropping the losing one would kill this process because it belongs to both.
    static PARENT_DEATH_GUARD: Mutex<Option<Job>> = Mutex::new(None);

    pub(super) fn ensure_parent_death_guard() -> io::Result<()> {
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        let mut guard = PARENT_DEATH_GUARD
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if guard.is_none() {
            let job = Job::assign_handle(unsafe { GetCurrentProcess() })?;
            *guard = Some(job);
        }
        Ok(())
    }

    /// The process handle is stable and signalled at exit; unlike `Child::try_wait`, this observes
    /// it without consuming the exit status or changing the cleanup state.
    pub(super) fn child_exited(child: &Child) -> io::Result<bool> {
        use windows_sys::Win32::Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::WaitForSingleObject;

        match unsafe { WaitForSingleObject(child.as_raw_handle() as HANDLE, 0) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            WAIT_FAILED => Err(io::Error::last_os_error()),
            result => Err(io::Error::other(format!(
                "unexpected process wait result {result}"
            ))),
        }
    }

    /// Resume the sole primary thread of a process created with `CREATE_SUSPENDED`.
    /// `std::process::Child` exposes the process handle but not the primary thread handle, so use
    /// the documented ToolHelp snapshot to recover it. A suspended process cannot create another
    /// thread; finding zero or multiple threads therefore fails closed and the caller terminates
    /// its already-assigned job instead of guessing which thread to resume.
    pub(super) fn resume_suspended_process(id: u32) -> io::Result<()> {
        use std::os::windows::io::RawHandle;
        use windows_sys::Win32::Foundation::{ERROR_NO_MORE_FILES, FALSE};
        use windows_sys::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Thread32First, Thread32Next, TH32CS_SNAPTHREAD, THREADENTRY32,
        };
        use windows_sys::Win32::System::Threading::{
            OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
        };

        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `snapshot` is a newly owned, non-null kernel handle.
        let snapshot = unsafe { OwnedHandle::from_raw_handle(snapshot as RawHandle) };
        let mut entry: THREADENTRY32 = unsafe { std::mem::zeroed() };
        entry.dwSize = std::mem::size_of::<THREADENTRY32>() as u32;
        let mut thread_id = None;
        let mut more = unsafe { Thread32First(snapshot.as_raw_handle() as HANDLE, &mut entry) };
        loop {
            if more == 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(ERROR_NO_MORE_FILES as i32) {
                    return Err(error);
                }
                break;
            }
            if entry.th32OwnerProcessID == id && thread_id.replace(entry.th32ThreadID).is_some() {
                return Err(io::Error::other(
                    "suspended child exposed more than one thread before job assignment",
                ));
            }
            more = unsafe { Thread32Next(snapshot.as_raw_handle() as HANDLE, &mut entry) };
        }
        let thread_id = thread_id.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "suspended child's primary thread was not visible",
            )
        })?;
        let thread = unsafe { OpenThread(THREAD_SUSPEND_RESUME, FALSE, thread_id) };
        if thread.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `thread` is a newly owned primary-thread handle.
        let thread = unsafe { OwnedHandle::from_raw_handle(thread as RawHandle) };
        if unsafe { ResumeThread(thread.as_raw_handle() as HANDLE) } == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Send `CTRL_BREAK` to the still-unreaped child's process group — the Windows analogue of
    /// `SIGTERM`. `ContainedChild::spawn` always sets `CREATE_NEW_PROCESS_GROUP`, so the group id
    /// is the child's PID and the event reaches it and only it.
    ///
    /// A control event is delivered within the CALLER's console, so a caller that has none — every
    /// SCM service — could otherwise never stop its child gracefully. Such a child was spawned
    /// into a console of its own (`spawn_in_new_console`), and this borrows it for the instant the
    /// event takes: attach, deafen this process to the event it is about to raise, raise it,
    /// detach. A caller that already has a console shares it with the child and signals directly.
    ///
    /// NOTE: needs Windows CI validation — the console-event path cannot be exercised on the
    /// development host.
    pub(super) fn request_stop(id: u32) -> io::Result<()> {
        use windows_sys::Win32::System::Console::{
            AttachConsole, FreeConsole, GenerateConsoleCtrlEvent, GetConsoleWindow,
            SetConsoleCtrlHandler, CTRL_BREAK_EVENT,
        };
        // SAFETY: plain FFI calls taking a PID/process-group id by value; the console this
        // attaches is released on every path out.
        unsafe {
            let borrowed = GetConsoleWindow().is_null();
            if borrowed {
                if AttachConsole(id) == 0 {
                    return Err(io::Error::last_os_error());
                }
                SetConsoleCtrlHandler(None, 1);
            }
            let sent = GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, id);
            let error = io::Error::last_os_error();
            if borrowed {
                FreeConsole();
                SetConsoleCtrlHandler(None, 0);
            }
            if sent == 0 {
                return Err(error);
            }
        }
        Ok(())
    }

    /// Create the job object every contained tree on this platform is held by; the returned handle
    /// is owned by the caller. On any failure the partially-created handle is closed before
    /// returning the error.
    ///
    /// The tree is killed as a unit when the job closes, and a child that explicitly asks to break
    /// away (`CREATE_BREAKAWAY_FROM_JOB`) is permitted to leave it. That permission is the only
    /// supported way for a reconciler hook to hand a workload to the release rather than to the
    /// agent's disposable hook attempt: this one helper builds every job in the nested chain
    /// (service -> agent -> hook), so the workload can leave all of them. Containment is
    /// unweakened for everything that does not ask, since the agent never sets the flag.
    pub fn create_kill_on_close_job() -> io::Result<HANDLE> {
        unsafe {
            let handle = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_BREAKAWAY_OK;
            if SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) == 0
            {
                let e = io::Error::last_os_error();
                CloseHandle(handle);
                return Err(e);
            }
            Ok(handle)
        }
    }

    /// A Windows job object holding a spawned process tree, configured to kill every
    /// member when the handle closes.
    pub(super) struct Job(HANDLE);

    // Kernel job handles may be closed or queried from any thread. Ownership remains unique and
    // Drop closes exactly once, so moving this RAII wrapper through the guard mutex is sound.
    unsafe impl Send for Job {}

    impl Job {
        pub(super) fn assign(child: &Child) -> io::Result<Self> {
            Self::assign_handle(child.as_raw_handle() as HANDLE)
        }

        fn assign_handle(process: HANDLE) -> io::Result<Self> {
            // Own the handle immediately so an assign failure closes it on the `?`/return.
            let job = Job(create_kill_on_close_job()?);
            if unsafe { AssignProcessToJobObject(job.0, process) } == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(job)
        }

        pub(super) fn terminate(&self) -> io::Result<()> {
            if unsafe { TerminateJobObject(self.0, 1) } == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    impl Drop for Job {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

#[cfg(all(test, windows))]
mod windows_spawn_tests {
    use super::*;

    #[test]
    fn a_suspended_child_is_assigned_and_resumed_before_spawn_returns() {
        // A CREATE_SUSPENDED process would wait forever if the primary-thread recovery or resume
        // step drifted. This native Windows test exercises the complete guard -> suspended spawn
        // -> per-tree assignment -> resume path rather than merely compiling its FFI surface.
        let mut command = Command::new("cmd.exe");
        command.args(["/D", "/C", "exit", "0"]);
        let mut child = ContainedChild::spawn(command).unwrap();
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn a_windows_job_still_hard_kills_its_running_root() {
        let mut command = Command::new("cmd.exe");
        command.args(["/D", "/C", "ping -n 30 127.0.0.1 >NUL"]);
        let mut child = ContainedChild::spawn(command).unwrap();
        child.kill_tree().unwrap();
        assert!(!child.wait().unwrap().success());
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Read;
    use std::time::{Duration, Instant};

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_parent_death_worker() {
        let Some(root) = std::env::var_os("FOUNDATION_PARENT_DEATH_PROBE") else {
            return;
        };
        let root = std::path::PathBuf::from(root);
        if std::env::var_os("FOUNDATION_PROBE_CLOSED_STDIO").is_some() {
            // Exercise socketpair returning descriptors that Command will replace for stdio.
            unsafe {
                libc::close(0);
                libc::close(1);
                libc::close(2);
            }
        }
        let lock = crate::file::open_lock_file(
            &root.join("lock"),
            crate::file::LockFileDisposition::OpenOrCreate,
        )
        .unwrap();
        lock.lock().unwrap();
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "(sleep 1; echo stale > \"$1/stale\") & touch \"$1/started\"; wait",
                "hook",
            ])
            .arg(&root)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let _child = ContainedChild::spawn(command).unwrap();
        std::fs::write(root.join("spawned"), b"ready").unwrap();
        std::thread::sleep(Duration::from_secs(30));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_parent_death_stops_hooks_and_releases_the_owner_lock() {
        check_macos_parent_death(false);
        check_macos_parent_death(true);
    }

    #[cfg(target_os = "macos")]
    fn check_macos_parent_death(closed_stdio: bool) {
        let root = tempfile::tempdir().unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        if closed_stdio {
            command.env("FOUNDATION_PROBE_CLOSED_STDIO", "1");
        }
        let mut parent = command
            .args([
                "--exact",
                "process::tests::macos_parent_death_worker",
                "--nocapture",
            ])
            .env("FOUNDATION_PARENT_DEATH_PROBE", root.path())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !(root.path().join("spawned").exists() && root.path().join("started").exists())
            && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        let started = root.path().join("started").exists();
        parent.kill().unwrap();
        parent.wait().unwrap();
        assert!(started, "the hook must start before its owner is killed");
        std::thread::sleep(Duration::from_secs(2));
        assert!(
            !root.path().join("stale").exists(),
            "the orphan hook kept mutating after owner death"
        );
        let lock = crate::file::open_lock_file(
            &root.path().join("lock"),
            crate::file::LockFileDisposition::OpenOrCreate,
        )
        .unwrap();
        assert!(
            lock.try_lock().is_ok(),
            "watchdog retained the dead owner's instance lock"
        );
    }

    #[test]
    fn kill_tree_reaps_a_shell_and_its_backgrounded_grandchild() {
        // A shell that backgrounds a long sleep and exits would, without group
        // containment, orphan the sleep. kill_tree must take the whole group down.
        let mut cmd = Command::new("sh");
        cmd.args(["-c", "sleep 30 & echo $!; wait"]);
        cmd.stdout(std::process::Stdio::piped());
        let mut contained = ContainedChild::spawn(cmd).unwrap();
        contained.kill_tree().unwrap();
        let status = contained.wait().unwrap();
        assert!(!status.success(), "the killed tree does not exit cleanly");
    }

    #[test]
    fn try_wait_observes_a_quick_exit() {
        let contained = ContainedChild::spawn(Command::new("true"));
        let mut contained = contained.unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = contained.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline, "`true` should exit promptly");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn kill_tree_on_an_already_exited_tree_is_ok() {
        let mut contained = ContainedChild::spawn(Command::new("true")).unwrap();
        let _ = contained.wait().unwrap();
        // Waiting already cleaned the PID-pinned group. A later kill is an idempotent no-op, not
        // a signal sent to a numeric process-group id the kernel may since have recycled.
        contained.kill_tree().unwrap();
    }

    #[test]
    fn try_wait_and_wait_both_mark_the_leader_reaped() {
        let mut contained = ContainedChild::spawn(Command::new("true")).unwrap();
        while contained.try_wait().unwrap().is_none() {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            contained.reaped,
            "try_wait observing an exit reaps the leader"
        );
        let mut contained = ContainedChild::spawn(Command::new("true")).unwrap();
        contained.wait().unwrap();
        assert!(contained.reaped, "wait reaps the leader");
    }

    #[test]
    fn every_contained_child_leads_its_own_process_group() {
        // `request_stop` is only correct for a child that leads its own group — on Windows a
        // CTRL_BREAK reaches nothing else — so spawning establishes the group rather than trusting
        // each caller to ask for it. Unix is where it can be observed; the Windows equivalent
        // (`CREATE_NEW_PROCESS_GROUP`) is set in the same function, for the same reason.
        let mut command = Command::new("sleep");
        command.arg("30");
        let mut contained = ContainedChild::spawn(command).unwrap();
        let pid = contained.id() as libc::pid_t;
        assert_eq!(
            unsafe { libc::getpgid(pid) },
            pid,
            "the child's process-group id must be its own PID"
        );
        contained.kill_tree().unwrap();
        contained.wait().unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn concurrent_children_cannot_inherit_another_spawns_descriptors() {
        use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
        let file = tempfile::tempfile().unwrap();
        // Deterministically model the interval between pipe() and std setting CLOEXEC.
        // A high descriptor avoids collision with descriptors the shell opens itself.
        let raw = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 200) };
        assert!(raw >= 200);
        let inherited = unsafe { OwnedFd::from_raw_fd(raw) };
        std::thread::scope(|scope| {
            for _ in 0..8 {
                scope.spawn(|| {
                    let mut command = Command::new("/bin/sh");
                    command.args(["-c", &format!("test ! -e /dev/fd/{raw}")]);
                    assert!(ContainedChild::spawn(command)
                        .unwrap()
                        .wait()
                        .unwrap()
                        .success());
                });
            }
        });
        assert_eq!(
            unsafe { libc::fcntl(inherited.as_raw_fd(), libc::F_GETFD) },
            0,
            "child sanitization must not change the parent's descriptors"
        );
    }

    #[test]
    fn a_graceful_stop_terminates_a_live_child_and_ignores_a_reaped_one() {
        // The graceful stop lives on the same reap-aware type as the kill, so no caller has a
        // reason to signal a raw PID: after the leader is reaped there is no PID left to name.
        use std::os::unix::process::ExitStatusExt;
        let mut command = Command::new("sleep");
        command.arg("30");
        let mut contained = ContainedChild::spawn(command).unwrap();
        contained.request_stop().unwrap();
        let status = contained.wait().unwrap();
        assert_eq!(
            status.signal(),
            Some(libc::SIGTERM),
            "the child saw the graceful signal, not a kill"
        );

        // Reaped: a second stop must be a silent no-op rather than a signal to whatever now
        // owns that PID.
        contained
            .request_stop()
            .expect("stopping a reaped tree is success");
    }

    #[test]
    fn descendants_are_killed_after_the_leader_exits_and_release_its_pipes() {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "sleep 30 & exit 0"])
            .stdout(std::process::Stdio::piped());
        let mut contained = ContainedChild::spawn(command).unwrap();
        let mut stdout = contained.take_stdout().unwrap();
        assert!(contained.wait().unwrap().success());
        let started = Instant::now();
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "an inherited pipe remained open after descendant cleanup"
        );
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use windows_sys::Win32::System::JobObjects::{
        JobObjectExtendedLimitInformation, QueryInformationJobObject,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_BREAKAWAY_OK,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    /// The two limits are one design, not two settings: kill-on-close is what makes a hook's tree
    /// disposable, and breakaway is what lets the workload the hook starts survive it. Without
    /// breakaway, `CreateProcess` with `CREATE_BREAKAWAY_FROM_JOB` fails with ACCESS_DENIED and a
    /// reconciler cannot start a workload on Windows at all.
    #[test]
    fn the_contained_tree_is_killable_as_a_unit_and_escapable_on_request() {
        // Through its own module: the function is private to `windows`, and a child of `process`
        // may reach it there. It carried a `pub use` re-export for years so this line could say
        // `super::`, which made an internal helper part of `foundation`'s public API for the sake
        // of one test. The Windows service adapter contains its agent through `ContainedChild`,
        // which assigns the job itself, so it does not need a public job-object helper.
        let job = super::windows::create_kill_on_close_job().unwrap();
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        let mut returned = 0u32;
        let ok = unsafe {
            QueryInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &mut info as *mut _ as *mut _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                &mut returned,
            )
        };
        let flags = info.BasicLimitInformation.LimitFlags;
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(job);
        }
        assert_ne!(ok, 0, "the job's limits must be readable back");
        assert_ne!(flags & JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, 0);
        assert_ne!(
            flags & JOB_OBJECT_LIMIT_BREAKAWAY_OK,
            0,
            "a hook-started workload could not leave the agent's disposable tree"
        );
    }
}

/// Run one contained command under an absolute deadline. Every exit path reaps its process tree.
/// Shared by package commands and migration helpers; no lock or pipe join is involved.
pub fn run_to_exit(
    command: std::process::Command,
    deadline: std::time::Instant,
) -> std::io::Result<Option<i32>> {
    if std::time::Instant::now() >= deadline {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "command deadline exceeded",
        ));
    }
    let mut child = ContainedChild::spawn(command)?;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status.code()),
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(20))
            }
            outcome => {
                child.stop(std::time::Duration::ZERO);
                return Err(match outcome {
                    Err(error) => error,
                    _ => std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "command deadline exceeded",
                    ),
                });
            }
        }
    }
}
