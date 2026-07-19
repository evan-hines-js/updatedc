
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


