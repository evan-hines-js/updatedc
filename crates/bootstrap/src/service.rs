//! The perpetual-service execution state machine.
//!
//! This type is the single owner of service-specific runtime state: the child process,
//! traffic eligibility, and terminal outcomes. The HTTP probe machine is only an atomic
//! projection of this state for external observers; it does not make lifecycle decisions.
//! Keeping that policy here prevents the guardian and supervisor-activation machines from
//! each carrying their own version of "the application failed".

use std::time::Duration;

use control::CommandSpec;

use crate::app::App;
use crate::probe::{Machine as ProbeMachine, State as ProbeState};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Starting,
    Serving,
    Unready,
    Draining,
    Failed,
    Exited(i32),
}

/// A perpetual managed service and its complete execution state machine.
pub struct Service {
    process: App,
    probes: ProbeMachine,
    state: State,
}

impl Service {
    pub fn new(probes: ProbeMachine) -> Self {
        Self {
            process: App::none(),
            probes,
            state: State::Starting,
        }
    }

    #[cfg(test)]
    pub fn with_process(process: App) -> Self {
        Self {
            process,
            probes: ProbeMachine::new(),
            state: State::Starting,
        }
    }

    pub fn launch(&mut self, spec: &CommandSpec, stop_grace: Duration) -> std::io::Result<u32> {
        self.process.launch(spec, stop_grace)
    }

    pub fn stop(&mut self, stop_grace: Duration) {
        self.transition(State::Draining);
        self.process.stop(stop_grace);
    }

    /// Update traffic eligibility, returning whether readiness actually changed. The
    /// supervisor re-asserts the current state on every loop, so callers that log the
    /// transition rely on this to fire once per edge rather than once per poll.
    pub fn traffic_ready(&mut self, ready: bool) -> bool {
        let changed = (self.state == State::Serving) != ready;
        self.transition(if ready {
            State::Serving
        } else {
            State::Unready
        });
        changed
    }

    /// Fail the service because its required application health check failed.
    /// This is an abnormal service outcome even though stopping the child is intentional.
    pub fn fail(&mut self, stop_grace: Duration) {
        self.transition(State::Failed);
        self.process.stop(stop_grace);
    }

    /// Return a terminal service outcome exactly once it becomes observable.
    /// A spontaneous child exit preserves its exact code, including zero.
    pub fn poll_exit(&mut self) -> Option<i32> {
        if self.state == State::Failed {
            return Some(1);
        }
        let code = self.process.poll_exit()?;
        // A candidate launched after a planned stop inherits Draining until the
        // supervisor proves it healthy and explicitly returns it to traffic. Its exit is
        // an update-transaction failure for the supervisor to roll back, not a failure
        // of the permanent guardian tower. A spontaneous exit of the committed Serving
        // process remains terminal and is rolled up to the outer init system.
        if self.state == State::Draining {
            return None;
        }
        self.transition(State::Exited(code));
        Some(code)
    }

    pub fn is_running(&mut self) -> bool {
        self.process.is_running()
    }

    pub fn pid(&self) -> Option<u32> {
        self.process.pid()
    }

    fn transition(&mut self, next: State) {
        self.state = next;
        self.probes.transition(match next {
            State::Starting => ProbeState::Starting,
            State::Serving => ProbeState::Serving,
            State::Unready => ProbeState::Unready,
            State::Draining => ProbeState::Draining,
            State::Failed | State::Exited(_) => ProbeState::Failed,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::Process;

    struct Exits(i32);

    impl Process for Exits {
        fn pid(&self) -> u32 {
            7
        }

        fn poll_exit(&mut self) -> Option<i32> {
            Some(self.0)
        }

        fn stop(&mut self, _grace: Duration) {}
    }

    fn spawn_zero(_spec: &CommandSpec) -> std::io::Result<Box<dyn Process>> {
        Ok(Box::new(Exits(0)))
    }

    #[test]
    fn the_service_machine_owns_process_exit_and_probe_failure_together() {
        let probes = ProbeMachine::new();
        let mut service = Service::new(probes.clone());
        service.process = App::with_spawn(spawn_zero);
        service
            .launch(
                &CommandSpec {
                    program: "ignored".into(),
                    args: vec![],
                    env: vec![],
                    cwd: None,
                },
                Duration::ZERO,
            )
            .unwrap();
        service.traffic_ready(true);

        assert_eq!(probes.state(), ProbeState::Serving);
        assert_eq!(service.poll_exit(), Some(0));
        assert_eq!(probes.state(), ProbeState::Failed);
    }

    #[test]
    fn failed_health_is_a_terminal_service_outcome() {
        let probes = ProbeMachine::new();
        let mut service = Service::new(probes.clone());

        service.fail(Duration::ZERO);

        assert_eq!(service.poll_exit(), Some(1));
        assert_eq!(probes.state(), ProbeState::Failed);
    }

    #[test]
    fn planned_stop_drains_without_inventing_a_terminal_exit() {
        let probes = ProbeMachine::new();
        let mut service = Service::new(probes.clone());

        service.stop(Duration::ZERO);

        assert_eq!(service.poll_exit(), None);
        assert_eq!(probes.state(), ProbeState::Draining);
    }

    #[test]
    fn candidate_exit_while_drained_stays_live_for_supervisor_rollback() {
        let probes = ProbeMachine::new();
        let mut service = Service::new(probes.clone());
        service.process = App::with_spawn(spawn_zero);
        service.stop(Duration::ZERO);
        service
            .launch(
                &CommandSpec {
                    program: "ignored".into(),
                    args: vec![],
                    env: vec![],
                    cwd: None,
                },
                Duration::ZERO,
            )
            .unwrap();

        assert_eq!(service.poll_exit(), None);
        assert_eq!(probes.state(), ProbeState::Draining);
    }
}
