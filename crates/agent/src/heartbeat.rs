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
    /// The authenticated gateway origin for remote reporting. Its absence is the one durable
    /// local/remote decision made when the loop starts, after the shared repository parser accepts
    /// the routing base; report cycles never reinterpret the raw string.
    pub(crate) control_base: Option<String>,
    /// The node identity reports are keyed by; absent on a node with no derivable identity, which
    /// simply never reports.
    pub(crate) node: Option<String>,
    /// The per-node key each report is signed with (PKCS#8 DER).
    pub(crate) signing_key: Option<Vec<u8>>,
    /// Whether the report endpoint is currently refusing this node, and when to try again. A
    /// refusal is a standing verdict about identity (see [`telemetry::Refusal`]), so it paces the
    /// writer down to a bounded retry cadence instead of spending a request and a warning per cycle
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

/// The complete release identity a heartbeat may attest, read from one durable installed record.
/// Keeping the version with its archive, provider set, and manifest makes it impossible to combine
/// loop memory from one commit boundary with digests from another.
#[derive(Default)]
struct InstalledReleaseIdentity {
    version: String,
    archive_sha256: String,
    definition_sha256: String,
    manifest_sha256: String,
}

fn installed_release_identity(store: &Store) -> io::Result<InstalledReleaseIdentity> {
    Ok(match store.installed()? {
        updated::state::Installed::Present(state) => InstalledReleaseIdentity {
            version: state.release.version,
            archive_sha256: state.archive_sha256,
            definition_sha256: state.reconciler.definition_sha256.clone(),
            manifest_sha256: state.release.manifest_sha256,
        },
        updated::state::Installed::Missing => InstalledReleaseIdentity::default(),
        updated::state::Installed::Invalid => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "installed state is corrupt; it cannot be reported as a fresh installation",
            ))
        }
    })
}

/// Whether durable artifact or deployment rejections block every route in this assignment.
/// The control plane needs this explicit verdict to avoid waiting for unreachable convergence.
pub(super) fn rejects_release(
    store: &Store,
    lineage: &updated::state::RepositoryLineage,
    assignment: &updated_contracts::assignment::RepositoryAssignment,
) -> bool {
    let graph = &assignment.application;
    let (installed, provisional_rejected) = match store.installed() {
        Ok(updated::state::Installed::Present(state)) => {
            // A version string alone cannot anchor a route or attribute its failures.
            if graph
                .check_source(&state.release.version, &state.archive_sha256)
                .is_err()
            {
                return false;
            }
            // A provisional first install has not established a usable starting state. An
            // empty route to that same version must not hide its durable boot rejection.
            let rejected = !state.is_proven()
                && store.rejects_deployment(&state.repository_lineage, &state.archive_sha256);
            (Some(state.release.version), rejected)
        }
        Ok(updated::state::Installed::Missing) => (None, false),
        _ => return false,
    };
    // A rejected intermediate blocks the assignment only when no alternative route survives.
    // Configuration mistakes are not durable rejections of release bytes.
    graph.route(installed.as_deref(), |_, _| true).is_ok()
        && (provisional_rejected
            || graph
                .route(installed.as_deref(), |_, release| {
                    !store.rejects_deployment(lineage, &release.package.sha256)
                })
                .is_err())
}

pub(crate) fn rejects_assigned_release(
    store: &Store,
    assignment: &updated_tuf::AssignmentContext,
) -> bool {
    rejects_release(
        store,
        assignment.repository_lineage(),
        assignment.document(),
    )
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
        store: &Store,
        state: Settlement,
        fingerprint: Option<&updated_contracts::telemetry::Fingerprint>,
    ) {
        let Some(assignment) = repo.and_then(|repo| repo.assignment_context()) else {
            return;
        };
        let document = assignment.document();
        let installed = match installed_release_identity(store) {
            Ok(installed) => installed,
            Err(error) => {
                warn(&format!(
                    "omitting rollout telemetry because installed state could not be read: {error}"
                ));
                return;
            }
        };
        let rejected = rejects_assigned_release(store, assignment);
        let runtime_converged = opts.runtime_is_converged(&document.runtime);
        let healthy = state.settled && runtime_converged;
        telemetry::report_running_state(
            &telemetry::ReportChannel {
                control_client: &self.control_client,
                object_client: &self.object_client,
                control_base: self.control_base.as_deref(),
                node: self.node.as_deref(),
                signing_key: self.signing_key.as_deref(),
                // A refused identity is retried on the signed refresh-retry cadence.
                refusal_backoff: opts.timeouts.refresh_retry,
            },
            &telemetry::RunningState {
                deployment: &document.deployment,
                assignment_sha256: assignment.sha256(),
                version: &installed.version,
                archive_sha256: &installed.archive_sha256,
                definition_sha256: &installed.definition_sha256,
                healthy,
                updating: state.updating,
                rejected,
                fingerprint,
                paths: &opts.paths,
                manifest_sha256: &installed.manifest_sha256,
            },
            &mut self.refusal,
            &mut self.outputs,
        )
        .await;
    }
}
