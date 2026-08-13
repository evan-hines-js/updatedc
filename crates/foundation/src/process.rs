//! Contained subprocess execution: spawn a child whose entire descendant tree can be
//! killed as a unit — a Unix process group, a Windows job object.
//!
//! This is the one home for that primitive. A caller that runs an untrusted or
//! long-running helper (the supervisor's lifecycle-hook runner is the motivating case)
//! must be able to time it out and take down *the whole tree* it spawned, not just the
//! immediate child — otherwise a wrapper shell dies while the `curl`/vendor-CLI it
//! launched keeps running. Re-implementing that per-OS at each call site is exactly the
//! kind of platform leak this crate exists to prevent.
//!
//! The permanent guardian owns application processes through its own lower-level `sys`
//! seam (it drives a raw suspended-spawn/assign/resume on Windows for a stronger no-orphan
//! guarantee); this module is the portable, `std::process::Command`-based containment used
//! by the churning tower.

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
/// tree. Dropping it releases that mechanism (on Windows, closing the job handle kills
/// the tree via kill-on-close; on Unix the group is left to exit on its own).
pub struct ContainedChild {
    child: Child,
    /// Set once the root child has been reaped by [`try_wait`](Self::try_wait) or
    /// [`wait`](Self::wait). From that moment its PID belongs to the kernel again and may name
    /// an unrelated process, so [`kill_tree`](Self::kill_tree) must never signal it directly.
    reaped: bool,
    #[cfg(windows)]
    job: windows::Job,
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
        // The Windows analogue of `process_group(0)`: the child's process-group id becomes its
        // PID, which is what `GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, pid)` addresses.
        command.creation_flags(
            windows_sys::Win32::System::Threading::CREATE_NEW_PROCESS_GROUP | extra_flags,
        );
        Self::spawn_contained(command)
    }

    fn spawn_contained(mut command: Command) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // The child leads a new group whose ID is its PID, so a later kill of the
            // negated PID reaches the whole tree and never the caller's other children.
            command.process_group(0);
        }
        let child = command.spawn()?;
        // The child is ALREADY RUNNING by the time containment is established. Letting an assign
        // failure propagate would drop `child` here, and `std::process::Child`'s Drop neither kills
        // nor reaps — leaving an uncontained process running with no handle to it while the caller
        // is told the launch failed. Kill it before reporting.
        #[cfg(windows)]
        let job = match windows::Job::assign(&child) {
            Ok(job) => job,
            Err(error) => {
                let mut orphan = child;
                let _ = orphan.kill();
                let _ = orphan.wait();
                return Err(error);
            }
        };
        Ok(ContainedChild {
            child,
            reaped: false,
            #[cfg(windows)]
            job,
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

    /// Non-blocking exit check of the root child.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let status = self.child.try_wait()?;
        self.reaped |= status.is_some();
        Ok(status)
    }

    /// Block until the root child has been reaped.
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        let status = self.child.wait()?;
        self.reaped = true;
        Ok(status)
    }

    /// Ask the tree to stop *gracefully* — `SIGTERM` on Unix, a `CTRL_BREAK` console event on
    /// Windows — leaving the caller to wait out a grace period and then [`kill_tree`](Self::kill_tree).
    /// This is the only graceful stop this type offers, and the only one a caller should need:
    /// signalling a PID by hand is exactly the hazard `reaped` exists to remove, and a bare
    /// `kill(pid, SIGTERM)` from a call site is indistinguishable from one aimed at whatever the
    /// kernel handed that number to next.
    ///
    /// Once the root has been reaped this is a no-op that reports success: the tree it named is
    /// gone, and there is nothing to ask politely. The Windows event needs two things: the child
    /// must lead its own process group, which spawning guarantees for every `ContainedChild` so
    /// no call site has to arrange it (and none can forget to); and it must be reachable in a
    /// console this process can raise an event in, which spawning does NOT guarantee on its own.
    /// Console reachability holds for a caller that owns a console — it shares it with the child
    /// — and for a console-less caller that spawned via
    /// [`spawn_in_new_console`](Self::spawn_in_new_console), whose child's console is borrowed for
    /// the instant the event takes. A console-less caller that used plain
    /// [`spawn`](Self::spawn) has a console-less child too, and gets `Err` here rather than a
    /// silent no-op — the caller then waits out its grace and
    /// [`kill_tree`](Self::kill_tree)s. On Unix a `SIGTERM`
    /// to the group would reach the caller's own group before the child's `setpgid` lands, so the
    /// leader alone is signalled and its children inherit the shutdown from it.
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
    /// only kill this type offers: while the root is still unreaped both it and its group are
    /// signalled (the root may not have reached its `setpgid` yet), and once it has been reaped
    /// only the group is, because the root's PID is then the kernel's to hand to anyone. A tree
    /// whose members are all gone is success, so this is idempotent.
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

/// Additively arrange for a child spawned from `command` to be killed if THIS process
/// dies — parent-death containment for a child that is *not* wrapped in [`ContainedChild`],
/// such as the guardian's disposable supervisor. On Linux this installs a `pre_exec` hook
/// setting `PR_SET_PDEATHSIG(SIGKILL)` and re-checks the parent immediately after, closing
/// the fork/exec race where the guardian already died before the signal was armed. Off
/// Linux it is a no-op — macOS is a dev/test target, and Windows death-containment is a
/// kill-on-close job object ([`ContainedChild`]) rather than a signal.
///
/// It only *adds* a `pre_exec` hook: it changes no other command configuration and does not
/// disturb a hook the caller already installed, so it composes with [`ContainedChild::spawn`]
/// and with the existing `updated`/app spawn paths (this is a new function, added additively).
pub fn arrange_parent_death_signal(command: &mut Command) {
    #[cfg(target_os = "linux")]
    {
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
                // If the guardian already died between fork and here, the signal will never
                // arrive; check the parent is still who we expect and self-exit if not.
                if libc::getppid() != expected_ppid {
                    libc::_exit(0);
                }
                Ok(())
            });
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = command;
    }
}

#[cfg(unix)]
mod unix {
    use std::io;

    pub(super) fn kill_tree(id: u32, leader_reaped: bool) -> io::Result<()> {
        let pid = i32::try_from(id)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "child PID exceeds pid_t"))?;
        for target in kill_targets(pid, leader_reaped) {
            // ESRCH from a target means *that* target is already gone, which is the outcome we
            // want — but it is accepted per-target: a not-yet-`setpgid` child (group ESRCH,
            // leader killed) is never mistaken for an already-dead tree, because the leader
            // kill succeeds.
            //
            // SAFETY: the targets are derived from this child's own PID — the negated value
            // names only the group it leads, the positive value only the child itself.
            let rc = unsafe { libc::kill(target, libc::SIGKILL) };
            accept_kill(rc, io::Error::last_os_error())?;
        }
        Ok(())
    }

    /// The `kill(2)` targets for one tree, in signalling order.
    ///
    /// The group (`-pid`) is always signalled: it reaches every descendant, and the kernel keeps
    /// the group's number allocated while any member survives, so it cannot name a stranger.
    ///
    /// The leader (`pid`) is signalled ONLY while it is still an unreaped child of ours. It has
    /// to be, because between fork and the `process_group(0)` that runs before exec the child is
    /// still in the caller's group and no group named `pid` exists yet — a kill of `-pid` in that
    /// window returns ESRCH while the child is very much alive. But the instant the child is
    /// reaped that same PID becomes the kernel's to reassign, and signalling it could SIGKILL an
    /// unrelated process (silently: ESRCH-tolerant `accept_kill` would report success either
    /// way). `reaped` is owned by [`ContainedChild`](super::ContainedChild) and set by the only
    /// two calls that can reap, so no caller has to remember this ordering.
    pub(super) fn kill_targets(pid: i32, leader_reaped: bool) -> Vec<i32> {
        if leader_reaped {
            vec![-pid]
        } else {
            vec![-pid, pid]
        }
    }

    /// `SIGTERM` the still-unreaped leader. Only ever called with `reaped == false`, so the PID
    /// is our own live child's and cannot have been recycled.
    pub(super) fn request_stop(id: u32) -> io::Result<()> {
        let pid = i32::try_from(id)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "child PID exceeds pid_t"))?;
        // SAFETY: `pid` is this process's own unreaped child.
        let rc = unsafe { libc::kill(pid, libc::SIGTERM) };
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

/// Shared kill-on-close job-object setup: the guardian's suspended-spawn adapter
/// (`bootstrap::sys::windows`) assigns to the job differently than this crate's
/// `Command`-based containment but needs the identical creation, so it lives here once.
#[cfg(windows)]
pub use windows::create_kill_on_close_job;

#[cfg(windows)]
mod windows {
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use std::process::Child;

    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_BREAKAWAY_OK, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

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
    /// (service -> launcher -> agent -> hook), so the workload can leave all of them. Containment is
    /// unweakened for everything that does not ask, since neither the agent nor the launcher ever
    /// sets the flag.
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

    impl Job {
        pub(super) fn assign(child: &Child) -> io::Result<Self> {
            // Own the handle immediately so an assign failure closes it on the `?`/return.
            let job = Job(create_kill_on_close_job()?);
            if unsafe { AssignProcessToJobObject(job.0, child.as_raw_handle() as _) } == 0 {
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Read;
    use std::time::{Duration, Instant};

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
        // ESRCH is swallowed: killing a group that already exited is success.
        contained.kill_tree().unwrap();
    }

    #[test]
    fn a_reaped_leaders_pid_is_never_signalled() {
        // The leader's PID is the kernel's to reassign the moment it is reaped, so the
        // documented `wait(); kill_tree()` ordering must signal the group alone — signalling a
        // recycled PID would SIGKILL an unrelated process, and ESRCH tolerance would hide it.
        assert_eq!(unix::kill_targets(4242, true), vec![-4242]);
        // Still unreaped: the leader must also be signalled directly, or a child killed between
        // fork and its `setpgid` survives (the group named by its PID does not exist yet).
        assert_eq!(unix::kill_targets(4242, false), vec![-4242, 4242]);
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
        contained.kill_tree().unwrap();
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
        let job = super::create_kill_on_close_job().unwrap();
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
