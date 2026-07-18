//! The application the guardian owns.
//!
//! The guardian owns the application only so it can control the app's lifecycle during
//! an update (stop → the supervisor swaps the bytes → start) and so the app dies with
//! the guardian — never an orphan, never a duplicate. It does *not* keep the app alive:
//! that is the init system's job. When the app exits on its own the guardian rolls the
//! exit code up and the whole tower goes down, and the init system restarts it fresh.
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
    /// there is no process, so a later [`poll_crash`](App::poll_crash) never mistakes
    /// the stop for a crash.
    pub fn stop(&mut self, grace: Duration) {
        if let Some(mut proc) = self.proc.take() {
            proc.stop(grace);
        }
    }

    pub fn is_running(&mut self) -> bool {
        self.proc.as_mut().is_some_and(|p| p.poll_exit().is_none())
    }

    pub fn pid(&self) -> Option<u32> {
        self.proc.as_ref().map(|p| p.pid())
    }

    /// If the application has exited on its own, take its exit code. From the guardian's
    /// view this is a crash: an intentional stop clears the process first, so an
    /// intentional exit never surfaces here.
    pub fn poll_crash(&mut self) -> Option<i32> {
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
    use std::ffi::OsString;

    /// A fake process whose behaviour is encoded in the spec's program: `exit:N` has
    /// already exited with code `N`; anything else runs until stopped.
    struct Fake {
        exit: Option<i32>,
    }

    impl Process for Fake {
        fn pid(&self) -> u32 {
            4242
        }
        fn poll_exit(&mut self) -> Option<i32> {
            self.exit
        }
        fn stop(&mut self, _grace: Duration) {
            self.exit.get_or_insert(137);
        }
    }

    fn fake_spawn(spec: &CommandSpec) -> io::Result<Box<dyn Process>> {
        let exit = spec
            .program
            .to_str()
            .and_then(|s| s.strip_prefix("exit:"))
            .and_then(|n| n.parse().ok());
        Ok(Box::new(Fake { exit }))
    }

    fn app() -> App {
        App {
            spawn: fake_spawn,
            proc: None,
        }
    }

    fn spec(program: &str) -> CommandSpec {
        CommandSpec {
            program: OsString::from(program),
            args: vec![],
            env: vec![],
            cwd: None,
        }
    }

    const GRACE: Duration = Duration::from_millis(10);

    #[test]
    fn a_crash_surfaces_once_then_clears() {
        let mut app = app();
        app.launch(&spec("exit:7"), GRACE).unwrap();
        assert_eq!(
            app.poll_crash(),
            Some(7),
            "the crash surfaces its exit code"
        );
        assert_eq!(app.poll_crash(), None, "and only once — it is then cleared");
        assert!(!app.is_running());
    }

    #[test]
    fn an_intentional_stop_is_not_a_crash() {
        let mut app = app();
        app.launch(&spec("run-forever"), GRACE).unwrap();
        assert!(app.is_running());
        app.stop(GRACE);
        assert!(!app.is_running());
        assert_eq!(app.poll_crash(), None, "a stopped app is not a crash");
    }

    #[test]
    fn launching_over_a_running_app_replaces_it() {
        let mut app = app();
        app.launch(&spec("run-forever"), GRACE).unwrap();
        // A relaunch stops the previous process first (it is taken and stopped), leaving a
        // single running process — never a leaked duplicate.
        app.launch(&spec("run-forever"), GRACE).unwrap();
        assert!(app.is_running());
        assert_eq!(app.pid(), Some(4242));
    }
}

// The real Unix adapter, exercised end-to-end (real exit codes, real process-group stop).
#[cfg(all(test, unix))]
mod unix_tests {
    use super::*;
    use std::ffi::OsString;

    fn spec(program: &str, args: &[&str]) -> CommandSpec {
        CommandSpec {
            program: OsString::from(program),
            args: args.iter().map(OsString::from).collect(),
            env: std::env::vars_os().collect(),
            cwd: None,
        }
    }

    #[test]
    fn a_real_crash_surfaces_its_exit_code() {
        crate::sys::ignore_sigpipe();
        let mut app = App::none();
        app.launch(&spec("/bin/sh", &["-c", "exit 3"]), Duration::from_secs(1))
            .unwrap();
        let mut code = None;
        for _ in 0..200 {
            if let Some(c) = app.poll_crash() {
                code = Some(c);
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(code, Some(3), "the guardian sees the app's real exit code");
        assert!(!app.is_running());
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
        assert!(app.is_running());
        app.stop(Duration::from_secs(2));
        assert!(!app.is_running());
        assert_eq!(app.poll_crash(), None, "a stopped app is not a crash");
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
