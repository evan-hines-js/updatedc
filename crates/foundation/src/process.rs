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

/// A spawned child plus the OS mechanism that binds its descendants into one killable
/// tree. Dropping it releases that mechanism (on Windows, closing the job handle kills
/// the tree via kill-on-close; on Unix the group is left to exit on its own).
pub struct ContainedChild {
    child: Child,
    #[cfg(windows)]
    job: windows::Job,
}

impl ContainedChild {
    /// Spawn `command` as the root of a fresh, killable process tree. On Unix the child
    /// leads a new process group; on Windows it is assigned to a kill-on-close job object
    /// before it can spawn descendants of its own.
    pub fn spawn(mut command: Command) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // The child leads a new group whose ID is its PID, so a later kill of the
            // negated PID reaches the whole tree and never the caller's other children.
            command.process_group(0);
        }
        let child = command.spawn()?;
        #[cfg(windows)]
        let job = windows::Job::assign(&child)?;
        Ok(ContainedChild {
            child,
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

    /// Non-blocking exit check of the root child.
    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }

    /// Block until the root child has been reaped.
    pub fn wait(&mut self) -> io::Result<ExitStatus> {
        self.child.wait()
    }

    /// Kill the entire tree — the process group on Unix, the job object on Windows — not
    /// just the root child. Idempotent with respect to an already-exited tree.
    pub fn kill_tree(&mut self) -> io::Result<()> {
        #[cfg(unix)]
        {
            unix::kill_group(&self.child)
        }
        #[cfg(windows)]
        {
            self.job.terminate()
        }
        #[cfg(not(any(unix, windows)))]
        {
            self.child.kill()
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
    use std::process::Child;

    pub(super) fn kill_group(child: &Child) -> io::Result<()> {
        let pid = i32::try_from(child.id())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "child PID exceeds pid_t"))?;
        // Signal both the process group *and* the leader PID directly. Once the child has
        // led its own group (set via `process_group(0)` before exec), the negated PID takes
        // down the whole tree. But between fork and that `setpgid` the child still lives in
        // the caller's group and the group whose ID is `pid` does not yet exist — a kill of
        // `-pid` in that window returns ESRCH while the child is very much alive. Killing
        // `pid` directly closes that window; the group kill still reaches any descendants
        // once the group exists.
        //
        // ESRCH from either target means *that* target is already gone, which is the
        // outcome we want — but we accept it only per-target: a not-yet-`setpgid` child
        // (group ESRCH, leader killed) is never mistaken for an already-dead tree, because
        // the leader kill succeeds. Reused PIDs are not a hazard here: the child is our own
        // unreaped descendant, so its PID cannot have been recycled.
        //
        // SAFETY: the checked negative PID targets only the child's own group; the positive
        // PID targets only the child.
        let group = unsafe { libc::kill(-pid, libc::SIGKILL) };
        let group_err = io::Error::last_os_error();
        let leader = unsafe { libc::kill(pid, libc::SIGKILL) };
        let leader_err = io::Error::last_os_error();
        accept_kill(group, group_err)?;
        accept_kill(leader, leader_err)
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
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    /// Create a kill-on-close job object; the returned handle is owned by the caller. On
    /// any failure the partially-created handle is closed before returning the error.
    pub fn create_kill_on_close_job() -> io::Result<HANDLE> {
        unsafe {
            let handle = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if handle.is_null() {
                return Err(io::Error::last_os_error());
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
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
}
