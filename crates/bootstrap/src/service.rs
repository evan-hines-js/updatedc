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
    /// A spontaneous exit observed while the service was drained, held until it becomes
    /// observable. Reaping the exit is unavoidable — it is how it is observed at all, and
    /// taking it drops the process handle — so the only way it can still be rolled up is to
    /// keep it here. It belongs to a process that no longer exists, so it is superseded by
    /// the next process the supervisor puts in its place — a [`launch`](Service::launch) —
    /// and by an intentional [`stop`](Service::stop). It is rolled up only if the service
    /// leaves Draining with no replacement, which is the tower genuinely having no
    /// application.
    drained_exit: Option<i32>,
}

impl Service {
    pub fn new(probes: ProbeMachine) -> Self {
        Self {
            process: App::none(),
            probes,
            state: State::Starting,
            drained_exit: None,
        }
    }

    #[cfg(test)]
    pub fn with_process(process: App) -> Self {
        Self {
            process,
            probes: ProbeMachine::new(),
            state: State::Starting,
            drained_exit: None,
        }
    }

    pub fn launch(&mut self, spec: &CommandSpec, stop_grace: Duration) -> std::io::Result<u32> {
        let pid = self.process.launch(spec, stop_grace)?;
        // A running process supersedes an exit deferred by an earlier drain: whatever died in
        // the drained window is not this service's outcome once the supervisor has put a
        // replacement in its place. The rollback after a candidate crashes reaches here
        // WITHOUT an intervening stop — the crashed candidate is already gone, so the
        // recovery boot plans no quiesce — and surfacing the dead candidate's code over the
        // restored predecessor would tear the whole tower down after a rollback that had
        // already succeeded. A launch that fails leaves it parked: there is then no
        // application, and the deferred exit is still the service's outcome.
        self.drained_exit = None;
        Ok(pid)
    }

    pub fn stop(&mut self, stop_grace: Duration) {
        self.transition(State::Draining);
        // An intentional stop likewise supersedes it: the supervisor is quiescing to replace
        // this process, so the dead candidate is no longer the service's outcome.
        self.drained_exit = None;
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

    /// Return a terminal service outcome once it becomes observable, and keep returning it:
    /// a terminal outcome is sticky, so the guardian can re-observe it to retry the durable
    /// record of it. A spontaneous child exit preserves its exact code, including zero.
    pub fn poll_exit(&mut self) -> Option<i32> {
        match self.state {
            State::Failed => return Some(1),
            State::Exited(code) => return Some(code),
            _ => {}
        }
        // A candidate launched after a planned stop inherits Draining until the supervisor
        // proves it healthy and explicitly returns it to traffic. Its exit is an
        // update-transaction failure for the supervisor to roll back in place, not a failure
        // of the permanent guardian tower, so it does not surface here yet — but it is
        // DEFERRED, never discarded: dropping it would leave the tower "serving" with no
        // application and no `service-exited` marker, so a crashed release that had already
        // committed would be confirmed instead of reverted. It surfaces the moment the
        // service leaves Draining — the supervisor returned the candidate to traffic, or
        // withdrew it — which is exactly when the transaction stopped owning its failure,
        // and only if no replacement process superseded it in the meantime.
        if let Some(code) = self.process.poll_exit() {
            self.drained_exit = Some(code);
        }
        if self.state == State::Draining {
            return None;
        }
        let code = self.drained_exit.take()?;
        self.transition(State::Exited(code));
        Some(code)
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
    use crate::sys::{fake_spawn, fake_spec as spec};

    #[test]
    fn the_service_machine_owns_process_exit_and_probe_failure_together() {
        let probes = ProbeMachine::new();
        let mut service = Service::new(probes.clone());
        service.process = App::with_spawn(fake_spawn);
        service.launch(&spec("exit:0"), Duration::ZERO).unwrap();
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

    /// A candidate launched into the drained window of an update, which exits at once.
    fn drained_candidate(probes: &ProbeMachine) -> Service {
        let mut service = Service::new(probes.clone());
        service.process = App::with_spawn(fake_spawn);
        service.stop(Duration::ZERO);
        service.launch(&spec("exit:0"), Duration::ZERO).unwrap();
        service
    }

    #[test]
    fn candidate_exit_while_drained_stays_live_for_supervisor_rollback() {
        let probes = ProbeMachine::new();
        let mut service = drained_candidate(&probes);

        assert_eq!(service.poll_exit(), None);
        assert_eq!(probes.state(), ProbeState::Draining);
    }

    #[test]
    fn a_candidate_that_dies_while_drained_is_rolled_up_when_it_returns_to_traffic() {
        // The exit is reaped to be observed at all (taking it drops the handle, killing the
        // app's process group), so discarding it while Draining lost it forever: the tower
        // went back to Serving with no application, no `service-exited` marker was written,
        // and a committed-but-unconfirmed release that had just crashed was confirmed by the
        // next boot instead of reverted. Deferring it keeps the roll-up machinery working.
        let probes = ProbeMachine::new();
        let mut service = drained_candidate(&probes);
        assert_eq!(service.poll_exit(), None, "drained: not yet the tower's");

        // The supervisor proved the candidate healthy and returned it to traffic.
        service.traffic_ready(true);

        assert_eq!(
            service.poll_exit(),
            Some(0),
            "the deferred exit is rolled up once the transaction hands the service back"
        );
        assert_eq!(probes.state(), ProbeState::Failed);
        assert_eq!(
            service.poll_exit(),
            Some(0),
            "and stays observable, so a failed marker write can be retried"
        );
    }

    #[test]
    fn withdrawing_traffic_also_surfaces_a_deferred_drained_exit() {
        let probes = ProbeMachine::new();
        let mut service = drained_candidate(&probes);
        assert_eq!(service.poll_exit(), None);

        service.traffic_ready(false);

        assert_eq!(service.poll_exit(), Some(0));
    }

    #[test]
    fn an_intentional_stop_supersedes_a_deferred_drained_exit() {
        // The rollback path: the supervisor gives up on the dead candidate and quiesces before
        // relaunching the predecessor. The candidate's exit is no longer the service's outcome
        // — surfacing it later would tear a recovered tower down.
        let probes = ProbeMachine::new();
        let mut service = drained_candidate(&probes);
        assert_eq!(service.poll_exit(), None);

        service.stop(Duration::ZERO);
        service.traffic_ready(true);

        assert_eq!(service.poll_exit(), None);
        assert_eq!(probes.state(), ProbeState::Serving);
    }

    #[test]
    fn a_relaunch_without_a_quiesce_supersedes_a_deferred_drained_exit() {
        // The rollback that actually happens when a candidate crashes on start. The dead
        // candidate's process is already gone, so the recovery boot sees no running
        // application, plans no quiesce, and reaches `Request::Launch` for the predecessor
        // with no `Request::Stop` in between — the one path that used to clear the deferred
        // exit is unreachable on the one path that sets it. Surfacing the candidate's code
        // over the restored predecessor tore the whole tower down (and wrote a
        // `service-exited` marker blaming a healthy process) right after a successful
        // rollback.
        let probes = ProbeMachine::new();
        let mut service = drained_candidate(&probes);
        assert_eq!(service.poll_exit(), None, "drained: not yet the tower's");

        service
            .launch(&spec("run-forever"), Duration::ZERO)
            .unwrap();
        service.traffic_ready(true);

        assert_eq!(
            service.poll_exit(),
            None,
            "the restored predecessor is running; the dead candidate is not the outcome"
        );
        assert_eq!(probes.state(), ProbeState::Serving);
    }

    #[test]
    fn a_failed_relaunch_leaves_the_deferred_exit_to_be_rolled_up() {
        // The replacement is what supersedes the dead candidate, so a launch that never
        // produced one must not swallow it: the tower has no application at all, and the
        // exit is still its outcome.
        let probes = ProbeMachine::new();
        let mut service = Service::new(probes.clone());
        service.process = App::with_spawn(|spec| {
            if spec.program == "unlaunchable" {
                Err(std::io::Error::other("no such program"))
            } else {
                fake_spawn(spec)
            }
        });
        service.stop(Duration::ZERO);
        service.launch(&spec("exit:9"), Duration::ZERO).unwrap();
        assert_eq!(service.poll_exit(), None);

        service
            .launch(&spec("unlaunchable"), Duration::ZERO)
            .unwrap_err();
        service.traffic_ready(false);

        assert_eq!(service.poll_exit(), Some(9));
        assert_eq!(probes.state(), ProbeState::Failed);
    }
}
