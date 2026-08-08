//! The application the guardian owns.
//!
//! The guardian owns the application only so it can control the app's lifecycle during
//! an update (stop → the supervisor swaps the bytes → start) and so the app dies with
//! the guardian — never an orphan, never a duplicate. It does *not* keep the app alive:
//! that is the init system's job. When the app exits on its own the guardian rolls its
//! exact exit code up and the whole tower goes down. Exit zero is still a spontaneous
//! service exit; the outer lifecycle owner decides whether that warrants a restart.
//!
//! This is the platform-agnostic lifecycle over the [`Process`] port;
//! the contained process itself (native launch, containment, stop, exit polling) lives in
//! the per-platform adapter behind the [`sys`](crate::sys) seam.

use std::io;
use std::time::Duration;

use control::CommandSpec;

use crate::sys::Process;

/// How the guardian launches a contained process: `crate::sys::spawn` in production, a
/// fake in tests — the [`Process`] port's factory.
type Spawn = fn(&CommandSpec) -> io::Result<Box<dyn Process>>;

/// The guardian's view of the application: a running process, or none.
pub struct App {
    spawn: Spawn,
    proc: Option<Box<dyn Process>>,
}

impl App {
    pub fn none() -> App {
        App {
            spawn: crate::sys::spawn,
            proc: None,
        }
    }

    /// A test App over an injected process factory, so the guardian's `dispatch`/`serve`
    /// launch-and-stop paths can be driven without a real subprocess.
    #[cfg(test)]
    pub(crate) fn with_spawn(spawn: Spawn) -> App {
        App { spawn, proc: None }
    }

    /// Ask the OS to launch the application from `spec`, contained so it dies with the
    /// guardian. Any prior process is stopped first.
    pub fn launch(&mut self, spec: &CommandSpec, stop_grace: Duration) -> io::Result<u32> {
        self.stop(stop_grace);
        let proc = (self.spawn)(spec)?;
        let pid = proc.pid();
        self.proc = Some(proc);
        Ok(pid)
    }

    /// Stop the application (intentional — quiescing it to swap its binary). After this
    /// there is no process, so a later [`poll_exit`](App::poll_exit) never mistakes
    /// the stop for a spontaneous exit.
    pub fn stop(&mut self, grace: Duration) {
        if let Some(mut proc) = self.proc.take() {
            proc.stop(grace);
        }
    }

    /// The PID of the process the guardian holds, and so also the ONE answer to "is an
    /// application running" — `Some` exactly when one is held.
    ///
    /// Deliberately does NOT poll: polling the [`Process`] port here would observe — and on Unix
    /// reap and tear down the group of — a spontaneous exit whose code this method has nowhere to
    /// put, silently dropping the one thing [`poll_exit`](App::poll_exit) exists to roll up. The
    /// exit clears the process there, so this answers `None` from the next call onwards.
    pub fn pid(&self) -> Option<u32> {
        self.proc.as_ref().map(|p| p.pid())
    }

    /// If the service exited on its own, take its exact exit code. This process wrapper
    /// deliberately attaches no success/failure policy to that code; the guardian's
    /// service state machine rolls every spontaneous exit up. An intentional stop clears
    /// the process first, so it never surfaces here.
    pub fn poll_exit(&mut self) -> Option<i32> {
        let code = self.proc.as_mut()?.poll_exit()?;
        self.proc = None;
        Some(code)
    }
}

// The lifecycle logic, proved against a fake process — no real subprocess, so it runs on
// every target and covers the branches (crash surfaces once then clears; a stop is never a
// crash) deterministically.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::{fake_spawn, fake_spec as spec};

    fn app() -> App {
        App {
            spawn: fake_spawn,
            proc: None,
        }
    }

    const GRACE: Duration = Duration::from_millis(10);

    #[test]
    fn a_spontaneous_exit_surfaces_once_then_clears() {
        let mut app = app();
        app.launch(&spec("exit:7"), GRACE).unwrap();
        assert_eq!(app.poll_exit(), Some(7), "the crash surfaces its exit code");
        assert_eq!(app.poll_exit(), None, "and only once — it is then cleared");
        assert!(app.pid().is_none());
    }

    #[test]
    fn an_intentional_stop_is_not_an_exit_event() {
        let mut app = app();
        app.launch(&spec("run-forever"), GRACE).unwrap();
        assert!(app.pid().is_some());
        app.stop(GRACE);
        assert!(app.pid().is_none());
        assert_eq!(app.poll_exit(), None, "a stopped app has no exit event");
    }

    #[test]
    fn exit_zero_is_preserved_as_a_spontaneous_service_exit() {
        let mut app = app();
        app.launch(&spec("exit:0"), GRACE).unwrap();
        assert_eq!(app.poll_exit(), Some(0));
    }

    #[test]
    fn launching_over_a_running_app_replaces_it() {
        let mut app = app();
        app.launch(&spec("run-forever"), GRACE).unwrap();
        // A relaunch stops the previous process first (it is taken and stopped), leaving a
        // single running process — never a leaked duplicate.
        app.launch(&spec("run-forever"), GRACE).unwrap();
        assert!(app.pid().is_some());
        assert_eq!(app.pid(), Some(4242));
    }
}

// The real Unix adapter, exercised end-to-end (real exit codes, real process-group stop).
#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;
    use std::ffi::OsString;
    use std::path::{Path, PathBuf};

    fn spec(program: &str, args: &[&str]) -> CommandSpec {
        CommandSpec {
            program: OsString::from(program),
            args: args.iter().map(OsString::from).collect(),
            env: std::env::vars_os().collect(),
            cwd: None,
        }
    }

    /// An application that forks a worker into its process group, reports the worker's PID, and
    /// then does `then`. The worker is the thing only the group can reach: its parent is the
    /// leader, so once the leader is gone and the handle is dropped, nothing else names it.
    fn forking_app(reported: &Path, then: &str) -> CommandSpec {
        let mut spec = spec("/bin/sh", &["-c"]);
        spec.args.push(OsString::from(format!(
            "sleep 30 & echo $! > '{}'; {then}",
            reported.display()
        )));
        spec
    }

    /// A launcher-shaped application: the leader exits the instant a SIGTERM arrives, and the
    /// worker it forked ignores the signal and keeps working for about a second before touching
    /// `finished`. This is the shape the operator's stop grace exists for — the leader is done
    /// early, the in-flight work is not.
    ///
    /// Both halves are written to survive the group-wide SIGTERM deterministically: the leader
    /// waits in a *builtin* (a forked `sleep` started just after the signal would outlive it and
    /// hold the leader open), and the worker's wait is a loop of short sleeps (its current `sleep`
    /// is killed outright — only the shell ignores the signal — so one long sleep would end the
    /// moment the stop began).
    ///
    /// The worker reports its OWN pid, and only after its `trap` is installed, so the test's
    /// `reported_pid` is evidence the signal is already ignored there. Having the leader report
    /// `$!` instead is a race the test loses under load: the pid is knowable the instant the
    /// worker is forked, but the forked shell still has to exec and parse its way to the trap,
    /// and a stop that lands in that window kills the worker outright with the default
    /// disposition — the group then drains at once and the drain the test exists to prove never
    /// happens.
    fn launcher_app(reported: &Path, finished: &Path) -> CommandSpec {
        let mut spec = spec("/bin/sh", &["-c"]);
        spec.args.push(OsString::from(format!(
            "trap 'exit 0' TERM; \
             /bin/sh -c 'trap \"\" TERM; echo $$ > \"{reported}\"; \
             n=0; while [ $n -lt 10 ]; do sleep 0.1; n=$((n+1)); \
             done; : > \"{finished}\"' & wait",
            finished = finished.display(),
            reported = reported.display()
        )));
        spec
    }

    /// A fresh path for the helper application to report through.
    fn fresh_path(tag: &str) -> (tempfile::TempDir, PathBuf) {
        let guard = tempfile::tempdir().unwrap();
        let path = guard.path().join(tag);
        (guard, path)
    }

    fn reported_pid(path: &Path) -> libc::pid_t {
        for _ in 0..200 {
            if let Some(pid) = std::fs::read_to_string(path)
                .ok()
                .and_then(|s| s.trim().parse().ok())
            {
                return pid;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("the helper never reported its worker's pid");
    }

    /// Whether `pid` is gone. A killed worker is an orphan by then, so the init process reaps it
    /// promptly and its PID stops existing; polling absorbs that delay.
    fn gone(pid: libc::pid_t) -> bool {
        for _ in 0..200 {
            if unsafe { libc::kill(pid, 0) } != 0 {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    #[test]
    fn a_real_crash_surfaces_its_exit_code() {
        crate::sys::ignore_sigpipe();
        let mut app = App::none();
        app.launch(&spec("/bin/sh", &["-c", "exit 3"]), Duration::from_secs(1))
            .unwrap();
        let mut code = None;
        for _ in 0..200 {
            if let Some(c) = app.poll_exit() {
                code = Some(c);
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(code, Some(3), "the guardian sees the app's real exit code");
        assert!(app.pid().is_none());
    }

    #[test]
    fn a_real_stop_kills_the_process() {
        crate::sys::ignore_sigpipe();
        let mut app = App::none();
        app.launch(
            &spec("/bin/sh", &["-c", "sleep 30"]),
            Duration::from_secs(1),
        )
        .unwrap();
        assert!(app.pid().is_some());
        app.stop(Duration::from_secs(2));
        assert!(app.pid().is_none());
        assert_eq!(app.poll_exit(), None, "a stopped app has no exit event");
    }

    #[test]
    fn a_stop_gives_the_workers_the_rest_of_the_grace_when_the_leader_exits_first() {
        // The grace is the operator's contract with the whole application, not with its leader.
        // A launcher forwards the stop to its workers and exits at once; ending the window there
        // SIGKILLs every worker mid-drain, silently truncating a multi-second configured grace to
        // however long the leader took to notice the signal.
        crate::sys::ignore_sigpipe();
        let (_reported_tmp, reported) = fresh_path("early-leader-exit.pid");
        let (_finished_tmp, finished) = fresh_path("early-leader-exit.done");
        let grace = Duration::from_secs(10);
        let mut app = App::none();
        app.launch(&launcher_app(&reported, &finished), Duration::from_secs(1))
            .unwrap();
        let worker = reported_pid(&reported);

        let started = std::time::Instant::now();
        app.stop(grace);

        assert!(
            finished.exists(),
            "the worker must keep its remaining grace after the leader exits"
        );
        assert!(
            started.elapsed() < grace,
            "and the stop must return as soon as the group drains, not sit out the window"
        );
        assert!(gone(worker), "a drained group leaves nothing running");
    }

    #[test]
    fn an_observed_exit_takes_the_apps_whole_process_group_down() {
        // `poll_exit` drops the process handle the instant it takes the exit code, so if the
        // group is not taken down with it the workers the leader forked are unreachable forever
        // — live processes the guardian can no longer signal. That is reachable in a plain
        // update: a launcher-style app whose leader exits while its workers keep serving.
        crate::sys::ignore_sigpipe();
        let (_reported_tmp, reported) = fresh_path("observed-exit");
        let mut app = App::none();
        app.launch(&forking_app(&reported, "exit 5"), Duration::from_secs(1))
            .unwrap();
        let worker = reported_pid(&reported);

        let mut code = None;
        for _ in 0..200 {
            if let Some(c) = app.poll_exit() {
                code = Some(c);
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(code, Some(5), "the leader's own exit code still surfaces");
        assert!(gone(worker), "the app's workers must not outlive the app");
    }

    #[test]
    fn dropping_a_running_app_takes_its_whole_process_group_down() {
        // The application never outlives the guardian. `PR_SET_PDEATHSIG` promises that for the
        // leader alone (and only on Linux), so dropping the handle is what has to end the group.
        crate::sys::ignore_sigpipe();
        let (_reported_tmp, reported) = fresh_path("dropped");
        let mut app = App::none();
        app.launch(&forking_app(&reported, "sleep 30"), Duration::from_secs(1))
            .unwrap();
        let worker = reported_pid(&reported);
        let leader = app.pid().unwrap() as libc::pid_t;
        assert!(app.pid().is_some());

        drop(app);

        assert!(gone(leader), "the application must not outlive its handle");
        assert!(gone(worker), "and neither must the workers it forked");
    }

    #[test]
    fn a_missing_program_fails_to_launch() {
        let mut app = App::none();
        assert!(app
            .launch(
                &spec("/nonexistent/guardian-app", &[]),
                Duration::from_secs(1)
            )
            .is_err());
    }
}
