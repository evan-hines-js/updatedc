#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct FleetNode {
    pub(crate) node: String,
    pub(crate) resource: String,
    pub(crate) selected_group: Option<String>,
    /// The version the node is actually running, straight from the control plane
    /// (`UpdateAgent.status.reportedVersion`) — never probed off the managed app, so it works
    /// for any app kind, a Rust service or a real Magnolia CMS alike.
    pub(crate) version: Option<String>,
    /// The app kind this node runs (`demo.updated.dev/kind`, e.g. `magnolia`); `None` is the
    /// default sample application. The UI marks non-default kinds distinctly.
    pub(crate) kind: Option<String>,
    pub(crate) healthy: bool,
    pub(crate) in_load_balancer: bool,
    /// Telemetry: how long the /readyz probe took, in ms.
    pub(crate) readyz_probe_millis: u64,
    /// Telemetry: why the node read out of the load balancer, if it did — distinguishes a
    /// real not-ready ("readyz 503") from the demo's own probe timing out, so the UI can tell
    /// a genuine flap from a slow probe.
    pub(crate) probe_note: Option<String>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GroupView {
    pub(crate) name: String,
    /// The group's display set (from its `set` label) — its box in the grid.
    pub(crate) set: String,
    pub(crate) selector: String,
    pub(crate) desired_version: String,
    pub(crate) selected_nodes: Vec<String>,
}

/// One `UpdateGroupSet`'s rollout calendar and the operator's live gate verdict, for the
/// UI's "add a date" panel. The calendar comes straight from the CRD spec (so it updates the
/// instant the demo patches it); `frozen` is the operator's authoritative status, `None`
/// until it has reconciled the set at least once.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SetCalendarView {
    pub(crate) name: String,
    pub(crate) calendar: Vec<CalendarEntryView>,
    pub(crate) frozen: Option<bool>,
    pub(crate) member_count: Option<u32>,
    pub(crate) rolling_count: Option<u32>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CalendarEntryView {
    pub(crate) date: String,
    pub(crate) start: String,
    pub(crate) end: String,
}

#[derive(Clone, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ChaosState {
    pub(crate) running: bool,
    pub(crate) complete: bool,
    pub(crate) seed: u64,
    /// Monotonic generation counter. Within an epoch it counts up 1 per generation;
    /// at convergence it jumps to `100 * epoch + 1` (…101, 201, 301…), so the hundreds
    /// digit names the epoch and the low digits count generations inside it.
    pub(crate) loop_number: usize,
    /// 1-based convergence epoch. Every epoch diverges the fleet across cohorts, then
    /// converges all of them onto a single new version before the next epoch begins.
    pub(crate) epoch: usize,
    pub(crate) completed_epochs: usize,
    pub(crate) bad_version: String,
    pub(crate) good_version: String,
    pub(crate) completed_nodes: usize,
    /// Cohorts taking a broken release in the current generation (authoritative — the
    /// UI must never infer broken-vs-valid from version numbers).
    pub(crate) active_broken: Vec<String>,
    /// Cohorts taking a valid release in the current generation.
    pub(crate) active_valid: Vec<String>,
    /// True while the whole fleet is converging onto the epoch's final version.
    pub(crate) converging: bool,
    pub(crate) updated_groups: Vec<String>,
    pub(crate) rolled_back_groups: Vec<String>,
    pub(crate) events: Vec<String>,
    pub(crate) error: Option<String>,
}

impl ChaosState {
    /// Reset every field that describes *one* chaos run and return the loop number the
    /// run resumes from.
    ///
    /// `completed_epochs` counts the epochs finished by this run — `run_chaos` keeps a
    /// run-local counter and publishes it here — so it must start at zero. Leaving the
    /// previous run's value live makes any poller that gates on it (the `exercise` soak
    /// driver) read the *last* run's result the instant the new run starts.
    ///
    /// Cross-run progress is deliberately preserved: `loop_number`, `epoch`, and the
    /// per-cohort `updated_groups` / `rolled_back_groups` are what a mid-epoch restart
    /// resumes from instead of re-exercising cohorts it already drove.
    pub(crate) fn begin_run(&mut self, seed: u64) -> usize {
        self.running = true;
        self.complete = false;
        self.completed_epochs = 0;
        self.seed = seed;
        self.error = None;
        self.active_broken.clear();
        self.active_valid.clear();
        self.converging = false;
        self.loop_number
    }
}

#[cfg(test)]
mod tests {
    use super::ChaosState;

    /// Regression: a restart must not inherit the previous run's completed-epoch count.
    /// The `exercise` soak driver starts chaos and then waits for `completedEpochs >= 1`;
    /// with a stale count every pass after the first passed vacuously in seconds, against
    /// the fleet the *previous* pass had already converged.
    #[test]
    fn begin_run_clears_the_previous_runs_completed_epochs() {
        let mut state = ChaosState {
            running: false,
            complete: true,
            completed_epochs: 3,
            seed: 1,
            loop_number: 301,
            epoch: 4,
            error: Some("boom".into()),
            active_broken: vec!["set-0".into()],
            active_valid: vec!["set-1".into()],
            converging: true,
            updated_groups: vec!["set-1".into()],
            rolled_back_groups: vec!["set-0".into()],
            ..Default::default()
        };

        let first_loop = state.begin_run(7);

        assert_eq!(state.completed_epochs, 0);
        assert!(state.running);
        assert!(!state.complete);
        assert_eq!(state.seed, 7);
        assert_eq!(state.error, None);
        assert!(state.active_broken.is_empty());
        assert!(state.active_valid.is_empty());
        assert!(!state.converging);
        // Mid-epoch resume: cross-run progress survives so divergence continues where
        // it left off rather than re-exercising already-driven cohorts.
        assert_eq!(first_loop, 301);
        assert_eq!(state.loop_number, 301);
        assert_eq!(state.epoch, 4);
        assert_eq!(state.updated_groups, vec!["set-1".to_owned()]);
        assert_eq!(state.rolled_back_groups, vec!["set-0".to_owned()]);
    }
}
