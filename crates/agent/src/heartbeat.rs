//! The signed node report this agent files each cycle, and the settlement it reports: which
//! release is running, whether it is healthy, and whether the assigned one was rejected.

use crate::*;

/// The rollout heartbeat's per-process inputs.
///
/// There is exactly one report writer in the agent and exactly one call to it — at the end of
/// every cycle, outside the block that does the cycle's work, so no early exit can reach the top of
/// the loop without it. That report is the only thing keeping this node inside `REPORT_FRESHNESS`
/// at the health proxy: a cycle that ends in silence spends the node's freshness budget, and a
/// fault that recurs every cycle (drift that survives a repair, an unconfirmed update) spends it to
/// zero and the node is drained for a reason no reader can see.
pub(crate) struct Heartbeat {
    /// Presents the node identity only to the gateway and refuses redirects.
    pub(crate) control_client: reqwest::Client,
    /// Spends bearer capabilities without presenting the node identity or following redirects.
    pub(crate) object_client: reqwest::Client,
    /// The node identity reports are keyed by; absent on a node with no derivable identity, which
    /// simply never reports.
    pub(crate) node: Option<String>,
    /// The per-node key each report is signed with (PKCS#8 DER).
    pub(crate) signing_key: Option<Vec<u8>>,
    /// Whether the report endpoint is currently refusing this node, and when to try again. A
    /// refusal is a standing verdict about identity (see [`telemetry::Refusal`]), so it paces the
    /// writer down to the agent-check cadence instead of spending a request and a warning per cycle
    /// on a report no reader could ever accept.
    pub(crate) refusal: telemetry::Refusal,
    pub(crate) outputs: telemetry::OutputPublisher,
}

/// Load the one key that authenticates reports and output bindings. `None` is reserved for local
/// repositories, which have no remote report channel; every remote node must prove at startup that
/// its durable owner-only key is readable and parseable instead of running silently unobservable.
pub(crate) fn load_report_signing_key(path: Option<&Path>) -> io::Result<Option<Vec<u8>>> {
    path.map(|path| {
        let pem = updated::tls::read_private_key_pem(path, foundation::file::FinalSymlink::Refuse)?;
        updated::csr::key_pem_to_pkcs8_der(&pem)
    })
    .transpose()
}

/// What this node can say about its own settlement on the assignment it is acting on: the two
/// independent facts a report carries, gathered where both are known.
#[derive(Clone, Copy)]
pub(crate) struct Settlement {
    /// The running app is ready AND no update is still unconfirmed.
    pub(crate) settled: bool,
    /// An update transaction is committed and its confirmation window is still open.
    pub(crate) updating: bool,
}

/// Whether this node has durably rejected either half of the release `assignment` names — the
/// application archive or the signed provider set. A node that has is finished with that unit for
/// good: it never retries it, so no
/// later report of it will ever name that release as running, and the control plane has to be told
/// or it waits for a convergence that cannot happen.
pub(crate) fn rejects_assigned_release(
    store: &dyn Store,
    assignment: &updated_contracts::assignment::RepositoryAssignment,
) -> bool {
    let lineage = updated::state::RepositoryLineage::from_metadata_url(&assignment.metadata_url);
    store.is_rejected(&lineage, &assignment.application.sha256)
        || store.is_rejected(&lineage, &assignment.provider_set.sha256)
}

impl Heartbeat {
    /// Write one best-effort report of what this node is running.
    ///
    /// `state.settled` is true only when the running app is ready AND no update is still
    /// unconfirmed — so a node that has merely *fetched* a new assignment, or is mid-rollout, or
    /// was just relaunched onto repaired bytes, is never reported as settled on it. That is what
    /// lets the control plane hold a pair's second member until the first has genuinely completed.
    /// Remote routing always provides the capability origin; local/offline routing emits no
    /// heartbeat because there is no control-plane endpoint.
    ///
    /// `state.updating` is the other half of an unsettled report: an update transaction is
    /// committed and its confirmation window is still open. It is reported rather than inferred
    /// from `settled`, which is also false for a plain readiness failure.
    ///
    /// `repo` is the last repository this node resolved — `None` only before the first successful
    /// resolution, when there is no assignment and so no report target yet.
    pub(crate) async fn emit(
        &mut self,
        opts: &Options,
        repo: Option<&TrustedRepository>,
        store: &dyn Store,
        version: Option<&str>,
        state: Settlement,
        fingerprint: Option<&updated_contracts::telemetry::Fingerprint>,
    ) {
        let Some(assignment) = repo.and_then(|repo| repo.assignment()) else {
            return;
        };
        let repo = repo.expect("an assignment came from a repository");
        let (archive_sha256, provider_set_sha256, manifest_sha256) =
            installed_release_identity(store);
        let rejected = rejects_assigned_release(store, assignment);
        let runtime_converged = opts.runtime_is_converged(&assignment.runtime);
        let healthy = state.settled && runtime_converged;
        telemetry::report_running_state(
            &telemetry::ReportChannel {
                control_client: &self.control_client,
                object_client: &self.object_client,
                control_base: (!opts.routing.is_local()).then_some(opts.routing.base_url.as_str()),
                node: self.node.as_deref(),
                signing_key: self.signing_key.as_deref(),
                // The slowest cadence the agent already has, read fresh each cycle so an
                // assignment that changes it moves the backoff with it.
                refusal_backoff: opts.timeouts.agent_check_interval,
            },
            &telemetry::RunningState {
                deployment: &assignment.deployment,
                assignment_sha256: repo.assignment_sha256().unwrap_or_default(),
                version: version.unwrap_or_default(),
                archive_sha256: &archive_sha256,
                provider_set_sha256: &provider_set_sha256,
                healthy,
                updating: state.updating,
                rejected,
                fingerprint,
                paths: &opts.paths,
                manifest_sha256: &manifest_sha256,
            },
            &mut self.refusal,
            &mut self.outputs,
        )
        .await;
    }
}
