use super::*;

pub(crate) enum Outcome {
    Committed,
    RolledBack,
    RejectedBeforeActivation,
    Deferred,
}

#[derive(Clone, Copy)]
pub(crate) enum LifecyclePhase {
    Preflight,
    Drain,
    Prepare,
    Stop,
    Activate,
    Start,
    Verify,
    Finalize,
    Rollback,
}

impl LifecyclePhase {
    fn name(self) -> &'static str {
        match self {
            Self::Preflight => "preflight",
            Self::Drain => "drain",
            Self::Prepare => "prepare",
            Self::Stop => "stop",
            Self::Activate => "activate",
            Self::Start => "start",
            Self::Verify => "verify",
            Self::Finalize => "finalize",
            Self::Rollback => "rollback",
        }
    }
}

/// Crashes at a configured transaction boundary, for the e2e's crash-recovery scenarios.
/// Compiled in only under the `chaos` feature (which the e2e enables); a production build
/// has no injection points, so a stray `UPDATED_CHAOS_POINT` can never crash it. One-shot:
/// after it fires it drops a sentinel, so the relaunched supervisor recovers instead of
/// crashing again at the same boundary forever.
pub(crate) struct Chaos {
    #[cfg(feature = "chaos")]
    point: Option<String>,
    #[cfg(feature = "chaos")]
    sentinel: Option<PathBuf>,
}

impl Chaos {
    #[cfg(feature = "chaos")]
    pub(crate) fn from_env() -> Self {
        Chaos {
            point: std::env::var(env::CHAOS_POINT).ok(),
            sentinel: std::env::var(control::STATE_DIR_ENV)
                .ok()
                .map(|d| PathBuf::from(d).join("chaos-fired")),
        }
    }
    #[cfg(not(feature = "chaos"))]
    pub(crate) fn from_env() -> Self {
        Chaos {}
    }

    #[cfg(feature = "chaos")]
    pub(crate) fn crossing(&self, phase: &str) {
        if self.point.as_deref() != Some(phase) {
            return;
        }
        if let Some(sentinel) = &self.sentinel {
            if sentinel.exists() {
                return; // already crashed here once; let recovery proceed.
            }
            let _ = std::fs::write(sentinel, phase);
        }
        eprintln!("[supervisor] CHAOS: exiting at boundary {phase:?}");
        std::process::exit(137);
    }

    #[cfg(not(feature = "chaos"))]
    #[inline]
    pub(crate) fn crossing(&self, _phase: &str) {}
}

/// The transaction boundaries chaos can crash at, as named constants. The crossing points
/// in [`apply_update`] and the `BOUNDARIES` list the e2e enumerates both reference these,
/// so the two cannot drift — a crossing and its list entry are the *same* string.
pub(crate) mod boundary {
    use crate::domain::TransactionPhase;

    pub const PREFLIGHT_APPLIED: &str = "preflight-applied";
    pub const PREFLIGHT_STARTED: &str = "preflight-started";
    pub const PREFLIGHT_COMPLETED: &str = "preflight-completed";
    pub const PREPARE_STARTED: &str = "prepare-started";
    pub const PREPARED: &str = "prepared";
    pub const PREPARE_APPLIED: &str = "prepare-applied";
    pub const DRAIN_STARTED: &str = "drain-started";
    pub const DRAINED: &str = "drained";
    pub const DRAIN_APPLIED: &str = "drain-applied";
    pub const STOP_STARTED: &str = "stop-started";
    pub const STOP_APPLIED: &str = "stop-applied";
    pub const STOPPED: &str = "stopped";
    pub const ACTIVATE_STARTED: &str = "activate-started";
    pub const CANDIDATE_POINTER_APPLIED: &str = "candidate-pointer-applied";
    pub const CANDIDATE_LIFECYCLE_APPLIED: &str = "candidate-lifecycle-applied";
    pub const CANDIDATE_ACTIVATED: &str = "candidate-activated";
    pub const CANDIDATE_STARTED: &str = "candidate-started";
    pub const START_STARTED: &str = "start-started";
    pub const CANDIDATE_START_APPLIED: &str = "candidate-start-applied";
    pub const CANDIDATE_HEALTHY: &str = "candidate-healthy";
    pub const HEALTH_STARTED: &str = "health-started";
    pub const CANDIDATE_HEALTH_APPLIED: &str = "candidate-health-applied";
    pub const FINALIZED: &str = "finalized";
    pub const FINALIZE_STARTED: &str = "finalize-started";
    pub const FINALIZE_APPLIED: &str = "finalize-applied";
    pub const COMMITTED: &str = "committed";
    pub const COMMIT_STARTED: &str = "commit-started";
    pub const COMMIT_APPLIED: &str = "commit-applied";
    pub const ROLLBACK_STARTED: &str = "rollback-started";
    pub const ROLLBACK_STOP_STARTED: &str = "rollback-stop-started";
    pub const ROLLBACK_STOP_APPLIED: &str = "rollback-stop-applied";
    pub const ROLLBACK_STOPPED: &str = "rollback-stopped";
    pub const ROLLBACK_ACTIVATE_STARTED: &str = "rollback-activate-started";
    pub const PREDECESSOR_POINTER_APPLIED: &str = "predecessor-pointer-applied";
    pub const PREDECESSOR_LIFECYCLE_APPLIED: &str = "predecessor-lifecycle-applied";
    pub const PREDECESSOR_ACTIVATED: &str = "predecessor-activated";
    pub const PREDECESSOR_START_APPLIED: &str = "predecessor-start-applied";
    pub const PREDECESSOR_STARTED: &str = "predecessor-started";
    pub const ROLLBACK_START_STARTED: &str = "rollback-start-started";
    pub const PREDECESSOR_HEALTH_APPLIED: &str = "predecessor-health-applied";
    pub const PREDECESSOR_HEALTHY: &str = "predecessor-healthy";
    pub const ROLLBACK_HEALTH_STARTED: &str = "rollback-health-started";
    pub const ROLLBACK_FINALIZE_STARTED: &str = "rollback-finalize-started";
    pub const ROLLBACK_ADAPTER_APPLIED: &str = "rollback-lifecycle-applied";
    pub const ROLLED_BACK: &str = "rolled-back";
    pub const ABORTED: &str = "aborted";

    pub fn durable_phase(phase: TransactionPhase) -> &'static str {
        match phase {
            TransactionPhase::PreflightStarted => PREFLIGHT_STARTED,
            TransactionPhase::PreflightCompleted => PREFLIGHT_COMPLETED,
            TransactionPhase::PrepareStarted => PREPARE_STARTED,
            TransactionPhase::Prepared => PREPARED,
            TransactionPhase::DrainStarted => DRAIN_STARTED,
            TransactionPhase::Drained => DRAINED,
            TransactionPhase::StopStarted => STOP_STARTED,
            TransactionPhase::Stopped => STOPPED,
            TransactionPhase::ActivateStarted => ACTIVATE_STARTED,
            TransactionPhase::CandidateActivated => CANDIDATE_ACTIVATED,
            TransactionPhase::CandidateVerified => "on-launch-candidate-verified",
            TransactionPhase::StartStarted => START_STARTED,
            TransactionPhase::CandidateStarted => CANDIDATE_STARTED,
            TransactionPhase::HealthStarted => HEALTH_STARTED,
            TransactionPhase::CandidateHealthy => CANDIDATE_HEALTHY,
            TransactionPhase::FinalizeStarted => FINALIZE_STARTED,
            TransactionPhase::Finalized => FINALIZED,
            TransactionPhase::CommitStarted => COMMIT_STARTED,
            TransactionPhase::Committed => COMMITTED,
            TransactionPhase::RollbackStarted => ROLLBACK_STARTED,
            TransactionPhase::RollbackStopStarted => ROLLBACK_STOP_STARTED,
            TransactionPhase::RollbackStopped => ROLLBACK_STOPPED,
            TransactionPhase::RollbackActivateStarted => ROLLBACK_ACTIVATE_STARTED,
            TransactionPhase::PredecessorActivated => PREDECESSOR_ACTIVATED,
            TransactionPhase::RollbackStartStarted => ROLLBACK_START_STARTED,
            TransactionPhase::PredecessorStarted => PREDECESSOR_STARTED,
            TransactionPhase::RollbackHealthStarted => ROLLBACK_HEALTH_STARTED,
            TransactionPhase::PredecessorHealthy => PREDECESSOR_HEALTHY,
            TransactionPhase::RollbackFinalizeStarted => ROLLBACK_FINALIZE_STARTED,
            TransactionPhase::RolledBack => ROLLED_BACK,
            TransactionPhase::Aborted => ABORTED,
            TransactionPhase::Started => "on-launch-started",
        }
    }
}

/// The ordered boundary list, emitted by `supervisor --list-chaos-boundaries` so the e2e
/// drives exactly these — one source of truth across the crate boundary (the e2e runs the
/// supervisor as a subprocess and cannot share a `const`).
#[cfg(any(feature = "chaos", test))]
pub(crate) const BOUNDARIES: &[&str] = &[
    boundary::PREFLIGHT_STARTED,
    boundary::PREFLIGHT_APPLIED,
    boundary::PREFLIGHT_COMPLETED,
    boundary::PREPARE_STARTED,
    boundary::PREPARE_APPLIED,
    boundary::PREPARED,
    boundary::DRAIN_STARTED,
    boundary::DRAIN_APPLIED,
    boundary::DRAINED,
    boundary::STOP_STARTED,
    boundary::STOP_APPLIED,
    boundary::STOPPED,
    boundary::ACTIVATE_STARTED,
    boundary::CANDIDATE_POINTER_APPLIED,
    boundary::CANDIDATE_LIFECYCLE_APPLIED,
    boundary::CANDIDATE_ACTIVATED,
    boundary::START_STARTED,
    boundary::CANDIDATE_START_APPLIED,
    boundary::CANDIDATE_STARTED,
    boundary::HEALTH_STARTED,
    boundary::CANDIDATE_HEALTH_APPLIED,
    boundary::CANDIDATE_HEALTHY,
    boundary::FINALIZE_STARTED,
    boundary::FINALIZE_APPLIED,
    boundary::FINALIZED,
    boundary::COMMIT_STARTED,
    boundary::COMMIT_APPLIED,
    boundary::COMMITTED,
];

#[cfg(any(feature = "chaos", test))]
pub(crate) const ROLLBACK_BOUNDARIES: &[&str] = &[
    boundary::ROLLBACK_STARTED,
    boundary::ROLLBACK_STOP_STARTED,
    boundary::ROLLBACK_STOP_APPLIED,
    boundary::ROLLBACK_STOPPED,
    boundary::ROLLBACK_ACTIVATE_STARTED,
    boundary::PREDECESSOR_POINTER_APPLIED,
    boundary::PREDECESSOR_LIFECYCLE_APPLIED,
    boundary::PREDECESSOR_ACTIVATED,
    boundary::ROLLBACK_START_STARTED,
    boundary::PREDECESSOR_START_APPLIED,
    boundary::PREDECESSOR_STARTED,
    boundary::ROLLBACK_HEALTH_STARTED,
    boundary::PREDECESSOR_HEALTH_APPLIED,
    boundary::PREDECESSOR_HEALTHY,
    boundary::ROLLBACK_FINALIZE_STARTED,
    boundary::ROLLBACK_ADAPTER_APPLIED,
    boundary::ROLLED_BACK,
];

#[cfg(any(feature = "chaos", test))]
pub(crate) const ABORT_BOUNDARIES: &[&str] = &[boundary::ABORTED];

// ============================ the live-application port ============================
//
// What the transaction drives on the *live* side — the running application and its
// readiness — behind a port, exactly as [`Store`] ports the durable side. The production
// [`DefaultProvider`] performs the configured `Restart` mode over the guardian-owned [`App`]; a
// test fake scripts control outcomes and health, so every fault path of [`apply_update`] is
// provable without a guardian, an HTTP server, or a real process.

/// Bring a staged release into (or back out of) service — the two hand-off moments plus the
/// quiesce a failed rollback needs. The port the transaction drives; the sole restart
/// abstraction (the `Restart` mode is data the [`DefaultProvider`] lifecycle acts on).
pub(crate) trait DeploymentProvider {
    /// Invoke the optional operator-owned lifecycle provider.
    fn lifecycle(
        &mut self,
        phase: LifecyclePhase,
        lifecycle_attempt_id: &str,
        candidate: &updated::bundle::ReleaseId,
        predecessor: &updated::bundle::ReleaseId,
    ) -> io::Result<()>;
    /// Stop the predecessor when the activation strategy requires a process stop.
    fn stop(&mut self);
    /// Apply the selected release to the surrounding service environment.
    fn activate(
        &mut self,
        lifecycle_attempt_id: &str,
        candidate: &updated::bundle::ReleaseId,
        predecessor: &updated::bundle::ReleaseId,
    ) -> io::Result<()>;
    /// Start the selected release when activation requires a fresh process.
    fn start(&mut self) -> io::Result<()>;
    /// Stop the app — used when a rollback itself fails its health check.
    fn quiesce(&mut self);
    /// A same-PID reload keeps the launch token, so readiness must additionally prove the
    /// running image's version; a fresh launch's per-launch token already identifies it.
    fn requires_version_proof(&self) -> bool;
}

/// Probe the application to readiness. `expected_version` is required only for a reload.
/// The future is not `Send`-bound: the update loop is driven by `block_on` on one thread,
/// never spawned, so the transaction never crosses threads (as before this port existed).
pub(crate) trait Health {
    fn became_healthy(
        &self,
        expected_version: Option<&str>,
    ) -> impl std::future::Future<Output = bool>;
}

/// The production lifecycle: `DeploymentProvider` performs the configured `Restart` mode over the
/// guardian-owned [`App`]; `Health` is the real HTTP readiness probe.
pub(crate) struct DefaultProvider<'a> {
    app: &'a mut App,
    opts: &'a Options,
    phases: LoadedPhaseProvider<'a>,
}

/// One lifecycle protocol with two loading strategies. The default implementation is
/// statically linked into this supervisor; an external implementation is the same
/// protocol resolved from a signed bundle. Callers never branch around the provider.
enum LoadedPhaseProvider<'a> {
    BuiltIn(BuiltInPhases),
    External {
        release: &'a updated::state::LifecycleProviderRelease,
        opts: &'a Options,
    },
}

struct BuiltInPhases;

impl BuiltInPhases {
    fn invoke(&self, _invocation: LifecycleInvocation<'_>) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> LoadedPhaseProvider<'a> {
    fn load(
        opts: &'a Options,
        external: Option<&'a updated::state::LifecycleProviderRelease>,
    ) -> Self {
        match external {
            Some(release) => Self::External { release, opts },
            None => Self::BuiltIn(BuiltInPhases),
        }
    }

    fn invoke(&self, invocation: LifecycleInvocation<'_>) -> io::Result<()> {
        match self {
            Self::BuiltIn(provider) => provider.invoke(invocation),
            Self::External { release, opts } => run_lifecycle_command(release, opts, invocation),
        }
    }
}

pub(crate) fn invoke_deployment_provider(
    external: Option<&updated::state::LifecycleProviderRelease>,
    opts: &Options,
    invocation: LifecycleInvocation<'_>,
) -> io::Result<()> {
    LoadedPhaseProvider::load(opts, external).invoke(invocation)
}

impl<'a> DefaultProvider<'a> {
    /// The built-in provider is part of this binary, never an independently upgraded
    /// artifact. Exposing this constant prevents inventing a second version source.
    pub(crate) const VERSION: &'static str = SELF_VERSION;

    pub(crate) fn new(
        app: &'a mut App,
        opts: &'a Options,
        lifecycle: Option<&'a updated::state::LifecycleProviderRelease>,
    ) -> Self {
        DefaultProvider {
            app,
            opts,
            phases: LoadedPhaseProvider::load(opts, lifecycle),
        }
    }
}

impl DeploymentProvider for DefaultProvider<'_> {
    fn lifecycle(
        &mut self,
        phase: LifecyclePhase,
        lifecycle_attempt_id: &str,
        candidate: &updated::bundle::ReleaseId,
        predecessor: &updated::bundle::ReleaseId,
    ) -> io::Result<()> {
        self.phases.invoke(LifecycleInvocation {
            phase,
            id: lifecycle_attempt_id,
            pid: Some(self.app.pid()),
            candidate,
            predecessor,
        })
    }
    fn stop(&mut self) {
        match &self.opts.application.activation {
            // StopStart quiesces the app before activation; a reload keeps serving.
            Activation::StopStart => stop(&mut self.app.guardian, &self.opts.paths.app_token),
            Activation::Reexec => {}
        }
    }
    fn activate(
        &mut self,
        lifecycle_attempt_id: &str,
        candidate: &updated::bundle::ReleaseId,
        predecessor: &updated::bundle::ReleaseId,
    ) -> io::Result<()> {
        let pid =
            matches!(self.opts.application.activation, Activation::Reexec).then(|| self.app.pid());
        self.phases.invoke(LifecycleInvocation {
            phase: LifecyclePhase::Activate,
            id: lifecycle_attempt_id,
            pid,
            candidate,
            predecessor,
        })
    }
    fn start(&mut self) -> io::Result<()> {
        match &self.opts.application.activation {
            Activation::StopStart => self.app.launch(self.opts),
            Activation::Reexec => Ok(()),
        }
    }
    fn quiesce(&mut self) {
        stop(&mut self.app.guardian, &self.opts.paths.app_token);
    }
    fn requires_version_proof(&self) -> bool {
        matches!(self.opts.application.activation, Activation::Reexec)
    }
}

impl Health for DefaultProvider<'_> {
    async fn became_healthy(&self, expected_version: Option<&str>) -> bool {
        // A probe-infrastructure error (a client that will not even build) is a health
        // failure like any other: fail closed to a rollback rather than propagate.
        became_healthy(
            self.app,
            self.opts.timeouts.health_grace,
            self.opts.application.health_url.as_deref(),
            expected_version,
            self.opts.timeouts.health_successes,
            self.opts.timeouts.health_interval,
        )
        .await
        .unwrap_or(false)
    }
}

// ================================ the transaction ================================

/// Drive one application update through the durable transaction, over the [`Store`] and
/// live-application ([`DeploymentProvider`] + [`Health`]) ports.
pub(crate) async fn apply_update<T: DeploymentProvider + Health>(
    tower: &mut T,
    store: &mut dyn Store,
    candidate: &updated::bundle::ReleaseId,
    candidate_archive_sha256: &str,
    lifecycle: Option<updated::state::LifecycleProviderRelease>,
) -> io::Result<Outcome> {
    // Recovery belongs to the boot state machine. A live supervisor must never mutate
    // recovery evidence or restore an executable underneath a guardian-owned process.
    // Any transaction error terminates this disposable supervisor; bootstrap keeps the
    // application alive and relaunches us through the one recovery path.
    if store.journal()?.is_some() {
        return Err(io::Error::other(
            "an unreconciled update journal requires supervisor restart",
        ));
    }

    let installed = match store.installed() {
        Installed::Present(state) => state,
        _ => return Err(io::Error::other("a verified installed release is required")),
    };
    let chaos = Chaos::from_env();
    let mut tx = Transaction {
        id: updated::rand::token()?,
        kind: updated::transaction::Kind::Supervised,
        previous_release: installed.release.clone(),
        previous_archive_sha256: installed.archive_sha256.clone(),
        candidate_release: candidate.clone(),
        candidate_archive_sha256: candidate_archive_sha256.to_string(),
        candidate_rejection_required: false,
        lifecycle: lifecycle.map(Box::new),
        phase: TransactionPhase::PreflightStarted,
    };
    persist_transaction(store, &tx)?;
    if let Err(error) = tower.lifecycle(
        LifecyclePhase::Preflight,
        &tx.id,
        candidate,
        &installed.release,
    ) {
        warn(&format!(
            "candidate {} failed lifecycle preflight ({error}); the running release was not touched",
            candidate.version
        ));
        require_candidate_rejection(store, &mut tx)?;
        abort_before_activation(tower, store, &mut tx)?;
        return Ok(Outcome::RejectedBeforeActivation);
    }
    chaos.crossing(boundary::PREFLIGHT_APPLIED);
    advance_transaction(store, &mut tx, TransactionPhase::PreflightCompleted)?;

    advance_transaction(store, &mut tx, TransactionPhase::PrepareStarted)?;
    if let Err(error) = tower.lifecycle(
        LifecyclePhase::Prepare,
        &tx.id,
        candidate,
        &installed.release,
    ) {
        warn(&format!(
            "candidate {} was deferred while preparing its environment ({error}); the running release remains active",
            candidate.version
        ));
        abort_before_activation(tower, store, &mut tx)?;
        return Ok(Outcome::Deferred);
    }
    chaos.crossing(boundary::PREPARE_APPLIED);
    advance_transaction(store, &mut tx, TransactionPhase::Prepared)?;

    advance_transaction(store, &mut tx, TransactionPhase::DrainStarted)?;
    if let Err(error) =
        tower.lifecycle(LifecyclePhase::Drain, &tx.id, candidate, &installed.release)
    {
        warn(&format!(
            "candidate {} was deferred while draining ({error}); the running release remains active",
            candidate.version
        ));
        abort_before_activation(tower, store, &mut tx)?;
        return Ok(Outcome::Deferred);
    }
    chaos.crossing(boundary::DRAIN_APPLIED);
    advance_transaction(store, &mut tx, TransactionPhase::Drained)?;

    advance_transaction(store, &mut tx, TransactionPhase::StopStarted)?;
    if let Err(error) = tower.lifecycle(LifecyclePhase::Stop, &tx.id, candidate, &installed.release)
    {
        warn(&format!(
            "candidate {} was deferred before stopping its predecessor ({error})",
            candidate.version
        ));
        abort_before_activation(tower, store, &mut tx)?;
        return Ok(Outcome::Deferred);
    }
    tower.stop();
    chaos.crossing(boundary::STOP_APPLIED);
    advance_transaction(store, &mut tx, TransactionPhase::Stopped)?;

    advance_transaction(store, &mut tx, TransactionPhase::ActivateStarted)?;
    if let Err(e) = store.activate(candidate) {
        warn(&format!("release activation failed before commit ({e})"));
        require_candidate_rejection(store, &mut tx)?;
        roll_back(tower, store, &mut tx).await?;
        return Ok(Outcome::RolledBack);
    }
    chaos.crossing(boundary::CANDIDATE_POINTER_APPLIED);

    if let Err(e) = tower.activate(&tx.id, candidate, &tx.previous_release) {
        warn(&format!("activating the new version failed ({e})"));
        require_candidate_rejection(store, &mut tx)?;
        roll_back(tower, store, &mut tx).await?;
        return Ok(Outcome::RolledBack);
    }
    chaos.crossing(boundary::CANDIDATE_LIFECYCLE_APPLIED);
    advance_transaction(store, &mut tx, TransactionPhase::CandidateActivated)?;
    advance_transaction(store, &mut tx, TransactionPhase::StartStarted)?;
    if let Err(e) = tower.start() {
        warn(&format!("starting the new version failed ({e})"));
        require_candidate_rejection(store, &mut tx)?;
        roll_back(tower, store, &mut tx).await?;
        return Ok(Outcome::RolledBack);
    }
    if let Err(e) = tower.lifecycle(LifecyclePhase::Start, &tx.id, candidate, &installed.release) {
        warn(&format!("candidate start provider phase failed ({e})"));
        require_candidate_rejection(store, &mut tx)?;
        roll_back(tower, store, &mut tx).await?;
        return Ok(Outcome::RolledBack);
    }
    chaos.crossing(boundary::CANDIDATE_START_APPLIED);
    advance_transaction(store, &mut tx, TransactionPhase::CandidateStarted)?;

    advance_transaction(store, &mut tx, TransactionPhase::HealthStarted)?;
    let version_proof = tower
        .requires_version_proof()
        .then_some(candidate.version.as_str());
    if !tower.became_healthy(version_proof).await {
        require_candidate_rejection(store, &mut tx)?;
        roll_back(tower, store, &mut tx).await?;
        return Ok(Outcome::RolledBack);
    }
    if let Err(e) = tower.lifecycle(
        LifecyclePhase::Verify,
        &tx.id,
        candidate,
        &installed.release,
    ) {
        warn(&format!("candidate verify provider phase failed ({e})"));
        require_candidate_rejection(store, &mut tx)?;
        roll_back(tower, store, &mut tx).await?;
        return Ok(Outcome::RolledBack);
    }
    chaos.crossing(boundary::CANDIDATE_HEALTH_APPLIED);
    advance_transaction(store, &mut tx, TransactionPhase::CandidateHealthy)?;

    advance_transaction(store, &mut tx, TransactionPhase::FinalizeStarted)?;
    if let Err(error) = tower.lifecycle(
        LifecyclePhase::Finalize,
        &tx.id,
        candidate,
        &installed.release,
    ) {
        warn(&format!(
            "candidate {} failed lifecycle finalization ({error})",
            candidate.version
        ));
        roll_back(tower, store, &mut tx).await?;
        return Ok(Outcome::Deferred);
    }
    chaos.crossing(boundary::FINALIZE_APPLIED);
    advance_transaction(store, &mut tx, TransactionPhase::Finalized)?;

    // Commit atomically WITH the pending rollback intent: the update is unconfirmed until
    // it survives its window. Folding the rollback intent into one write means there is no
    // separate "arm" step to be interrupted — if a crash lands after this, the pending
    // record is already durable; if before, the journal reactivates the predecessor.
    let pending = Some(Pending {
        lifecycle_attempt_id: tx.id.clone(),
        previous_release: installed.release,
        previous_archive_sha256: installed.archive_sha256,
        committed_at: now_unix(),
        lifecycle: tx.lifecycle.clone(),
    });
    advance_transaction(store, &mut tx, TransactionPhase::CommitStarted)?;
    store.commit_installed(&InstalledState {
        release: candidate.clone(),
        archive_sha256: candidate_archive_sha256.to_string(),
        pending,
    })?;
    chaos.crossing(boundary::COMMIT_APPLIED);
    advance_transaction(store, &mut tx, TransactionPhase::Committed)?;
    // The update is durable now: the active pointer and installed state (with its
    // pending intent) is committed. Failing to delete the spent journal must NOT report the
    // transaction as failed — that would leave the loop's in-memory state stale (still the
    // old version, not pending) while disk records the new one, letting a second update
    // start over this unconfirmed one. Return Committed and let recovery remove the journal
    // (it resolves as already-committed).
    if let Err(e) = store.clear_journal() {
        warn(&format!(
            "update committed but clearing its journal failed ({e}); recovery will remove it"
        ));
    }
    Ok(Outcome::Committed)
}

/// Undo operator-side work when neither the active release nor its process changed.
/// Every pre-activation exit uses this state-machine path so an interrupted lifecycle
/// rollback remains recoverable through the ordinary boot journal.
fn abort_before_activation<T: DeploymentProvider>(
    tower: &mut T,
    store: &mut dyn Store,
    tx: &mut Transaction,
) -> io::Result<()> {
    advance_transaction(store, tx, TransactionPhase::RollbackStarted)?;
    tower.lifecycle(
        LifecyclePhase::Rollback,
        &tx.id,
        &tx.previous_release,
        &tx.candidate_release,
    )?;
    advance_transaction(store, tx, TransactionPhase::Aborted)?;
    store.clear_journal()
}

/// Persist the rejection decision before applying it. If the process dies in the gap,
/// boot recovery replays the idempotent rejection from the transaction rather than
/// forgetting why rollback began and selecting the same bad archive again.
fn require_candidate_rejection(store: &mut dyn Store, tx: &mut Transaction) -> io::Result<()> {
    if !tx.candidate_rejection_required {
        tx.candidate_rejection_required = true;
        store.write_journal(tx)?;
    }
    store.reject(&tx.candidate_archive_sha256)
}

/// Reactivate the previous release and get it running again through the same strategy (so a
/// reload strategy rolls back with zero downtime too). This is the only in-process
/// rollback — for an update whose new version stayed *alive* but never became healthy; a
/// crash instead tears the tower down and recovery rolls back on the next boot.
async fn roll_back<T: DeploymentProvider + Health>(
    tower: &mut T,
    store: &mut dyn Store,
    tx: &mut Transaction,
) -> io::Result<()> {
    let chaos = Chaos::from_env();
    advance_transaction(store, tx, TransactionPhase::RollbackStarted)?;
    advance_transaction(store, tx, TransactionPhase::RollbackStopStarted)?;
    tower.lifecycle(
        LifecyclePhase::Stop,
        &tx.id,
        &tx.previous_release,
        &tx.candidate_release,
    )?;
    tower.stop();
    chaos.crossing(boundary::ROLLBACK_STOP_APPLIED);
    advance_transaction(store, tx, TransactionPhase::RollbackStopped)?;
    advance_transaction(store, tx, TransactionPhase::RollbackActivateStarted)?;
    store.activate(&tx.previous_release)?;
    chaos.crossing(boundary::PREDECESSOR_POINTER_APPLIED);
    tower.activate(&tx.id, &tx.previous_release, &tx.candidate_release)?;
    chaos.crossing(boundary::PREDECESSOR_LIFECYCLE_APPLIED);
    advance_transaction(store, tx, TransactionPhase::PredecessorActivated)?;
    advance_transaction(store, tx, TransactionPhase::RollbackStartStarted)?;
    tower.start()?;
    tower.lifecycle(
        LifecyclePhase::Start,
        &tx.id,
        &tx.previous_release,
        &tx.candidate_release,
    )?;
    chaos.crossing(boundary::PREDECESSOR_START_APPLIED);
    advance_transaction(store, tx, TransactionPhase::PredecessorStarted)?;
    // Prove the rollback landed with the same evidence the forward path demands. A reload
    // keeps the PID and the launch token, so under that strategy the token proves nothing
    // about *which* image is answering: without the predecessor's version, an app that
    // never re-execed would have the just-rejected new version answer this probe and pass
    // it — leaving the release recorded as rolled back and rejected while it is still the
    // one running. A stop/start relaunch mints a fresh token, which already identifies it.
    let rollback_version = tx.previous_release.version.clone();
    let version_proof = if tower.requires_version_proof() {
        Some(rollback_version.as_str())
    } else {
        None
    };
    advance_transaction(store, tx, TransactionPhase::RollbackHealthStarted)?;
    if !tower.became_healthy(version_proof).await {
        tower.quiesce();
        return Err(io::Error::other(
            "restored application failed its rollback health check",
        ));
    }
    tower.lifecycle(
        LifecyclePhase::Verify,
        &tx.id,
        &tx.previous_release,
        &tx.candidate_release,
    )?;
    chaos.crossing(boundary::PREDECESSOR_HEALTH_APPLIED);
    advance_transaction(store, tx, TransactionPhase::PredecessorHealthy)?;
    advance_transaction(store, tx, TransactionPhase::RollbackFinalizeStarted)?;
    tower.lifecycle(
        LifecyclePhase::Rollback,
        &tx.id,
        &tx.previous_release,
        &tx.candidate_release,
    )?;
    chaos.crossing(boundary::ROLLBACK_ADAPTER_APPLIED);
    advance_transaction(store, tx, TransactionPhase::RolledBack)?;
    store.clear_journal()?;
    Ok(())
}

pub(crate) fn advance_transaction(
    store: &mut dyn Store,
    tx: &mut Transaction,
    phase: TransactionPhase,
) -> io::Result<()> {
    tx.advance(phase)?;
    persist_transaction(store, tx)
}

pub(crate) fn persist_transaction(store: &mut dyn Store, tx: &Transaction) -> io::Result<()> {
    store.write_journal(tx)?;
    Chaos::from_env().crossing(boundary::durable_phase(tx.phase));
    Ok(())
}

/// Invoke the single operator lifecycle provider with a stable phase and transaction
/// identity. Commands are direct argv, never shell text. A bounded wait prevents a
/// wedged enterprise integration from wedging the updater forever.
pub(crate) struct LifecycleInvocation<'a> {
    pub(crate) phase: LifecyclePhase,
    pub(crate) id: &'a str,
    pub(crate) pid: Option<u32>,
    pub(crate) candidate: &'a updated::bundle::ReleaseId,
    pub(crate) predecessor: &'a updated::bundle::ReleaseId,
}

pub(crate) fn run_lifecycle_command(
    lifecycle: &updated::state::LifecycleProviderRelease,
    opts: &Options,
    invocation: LifecycleInvocation<'_>,
) -> io::Result<()> {
    let LifecycleInvocation {
        phase,
        id: lifecycle_attempt_id,
        pid,
        candidate,
        predecessor,
    } = invocation;
    let resolved =
        updated::provider::BundleStore::for_lifecycle(&opts.paths).resolve(&lifecycle.release)?;
    if resolved.product != lifecycle.product {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "staged lifecycle manifest has the wrong product",
        ));
    }
    let timeout = Duration::from_millis(lifecycle.timeout_millis);
    let phase_name = phase.name();
    let app_provider = updated::provider::BundleStore::for_app(&opts.paths);
    let candidate_dir = app_provider.location(candidate);
    let predecessor_dir = app_provider.location(predecessor);
    let mut cmd = Command::new(resolved.program);
    cmd.args(&lifecycle.args);
    // A wrapper commonly waits on vendor CLIs, curl, or mount helpers. Give the whole
    // lifecycle tree its own group so a timeout cannot kill only the shell and orphan the
    // foreground operation. Windows wrappers must obey the no-background-child contract.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    for key in crate::app::CONTROL_PLANE_ENV {
        cmd.env_remove(key);
    }
    let command = cmd
        .env(env::LIFECYCLE_PHASE, phase_name)
        .env(env::LIFECYCLE_ATTEMPT_ID, lifecycle_attempt_id)
        .env(env::INSTALL_ROOT, &opts.paths.install_root)
        .env(env::CANDIDATE, &candidate_dir)
        .env(env::PREDECESSOR, &predecessor_dir)
        .env(env::CANDIDATE_VERSION, &candidate.version)
        .env(env::PREDECESSOR_VERSION, &predecessor.version);
    if let Some(pid) = pid {
        command.env(env::CHILD_PID, pid.to_string());
    } else {
        command.env_remove(env::CHILD_PID);
    }
    let mut child = command.spawn()?;
    let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "lifecycle timeout is too large",
        )
    })?;
    loop {
        if let Some(status) = child.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err(io::Error::other(format!(
                    "lifecycle {phase_name} exited with {status}"
                )))
            };
        }
        if Instant::now() >= deadline {
            #[cfg(unix)]
            // SAFETY: the child was spawned as leader of a fresh process group whose ID
            // is its PID. A negative PID targets only that group, never the managed app.
            unsafe {
                libc::kill(-(child.id() as i32), libc::SIGKILL);
            }
            #[cfg(not(unix))]
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "lifecycle {phase_name} exceeded its {}s timeout",
                    timeout.as_secs_f64()
                ),
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(version: &str, digest: &str) -> updated::bundle::ReleaseId {
        updated::bundle::ReleaseId {
            version: version.into(),
            manifest_sha256: digest.into(),
        }
    }

    #[test]
    fn built_in_provider_is_supervisor_versioned_and_accepts_the_full_phase_protocol() {
        assert_eq!(DefaultProvider::VERSION, SELF_VERSION);
        let candidate = release("2.0.0", "two");
        let predecessor = release("1.0.0", "one");
        let provider = BuiltInPhases;
        for phase in [
            LifecyclePhase::Preflight,
            LifecyclePhase::Prepare,
            LifecyclePhase::Drain,
            LifecyclePhase::Stop,
            LifecyclePhase::Activate,
            LifecyclePhase::Start,
            LifecyclePhase::Verify,
            LifecyclePhase::Finalize,
            LifecyclePhase::Rollback,
        ] {
            provider
                .invoke(LifecycleInvocation {
                    phase,
                    id: "attempt",
                    pid: Some(42),
                    candidate: &candidate,
                    predecessor: &predecessor,
                })
                .unwrap();
        }
    }

    struct MemoryStore {
        installed: Installed,
        journal: Option<Transaction>,
        active: updated::bundle::ReleaseId,
        rejected: Vec<String>,
    }

    impl MemoryStore {
        fn new(previous: updated::bundle::ReleaseId) -> Self {
            Self {
                installed: Installed::Present(InstalledState::confirmed(
                    previous.clone(),
                    "previous-archive".into(),
                )),
                journal: None,
                active: previous,
                rejected: Vec::new(),
            }
        }
    }

    impl Store for MemoryStore {
        fn installed(&self) -> Installed {
            match &self.installed {
                Installed::Present(state) => Installed::Present(state.clone()),
                Installed::Missing => Installed::Missing,
                Installed::Invalid => Installed::Invalid,
            }
        }
        fn journal(&self) -> io::Result<Option<Transaction>> {
            Ok(self.journal.clone())
        }
        fn active_release(&self) -> io::Result<Option<updated::bundle::ReleaseId>> {
            Ok(Some(self.active.clone()))
        }
        fn is_rejected(&self, _: &str) -> bool {
            false
        }
        fn commit_installed(&mut self, state: &InstalledState) -> io::Result<()> {
            self.installed = Installed::Present(state.clone());
            Ok(())
        }
        fn write_journal(&mut self, tx: &Transaction) -> io::Result<()> {
            self.journal = Some(tx.clone());
            Ok(())
        }
        fn clear_journal(&mut self) -> io::Result<()> {
            self.journal = None;
            Ok(())
        }
        fn reject(&mut self, digest: &str) -> io::Result<()> {
            self.rejected.push(digest.into());
            Ok(())
        }
        fn clear_rejection(&mut self, _: &str) -> io::Result<()> {
            Ok(())
        }
        fn activate(&mut self, release: &updated::bundle::ReleaseId) -> io::Result<()> {
            self.active = release.clone();
            Ok(())
        }
    }

    #[derive(Default)]
    struct FakeTower {
        phases: Vec<&'static str>,
        fail_drain: bool,
        fail_stop: bool,
        fail_finalize: bool,
        fail_rollback: bool,
        fail_first_start_phase: bool,
        start_phase_calls: usize,
        fail_first_verify_phase: bool,
        verify_phase_calls: usize,
        fail_first_activation: bool,
        activations: usize,
    }

    impl DeploymentProvider for FakeTower {
        fn lifecycle(
            &mut self,
            phase: LifecyclePhase,
            _: &str,
            _: &updated::bundle::ReleaseId,
            _: &updated::bundle::ReleaseId,
        ) -> io::Result<()> {
            self.phases.push(phase.name());
            if matches!(phase, LifecyclePhase::Start) {
                self.start_phase_calls += 1;
            }
            if matches!(phase, LifecyclePhase::Verify) {
                self.verify_phase_calls += 1;
            }
            if (matches!(phase, LifecyclePhase::Drain) && self.fail_drain)
                || (matches!(phase, LifecyclePhase::Stop) && self.fail_stop)
                || (matches!(phase, LifecyclePhase::Finalize) && self.fail_finalize)
                || (matches!(phase, LifecyclePhase::Rollback) && self.fail_rollback)
                || (matches!(phase, LifecyclePhase::Start)
                    && self.fail_first_start_phase
                    && self.start_phase_calls == 1)
                || (matches!(phase, LifecyclePhase::Verify)
                    && self.fail_first_verify_phase
                    && self.verify_phase_calls == 1)
            {
                return Err(io::Error::other("injected lifecycle failure"));
            }
            Ok(())
        }
        fn stop(&mut self) {}
        fn activate(
            &mut self,
            _: &str,
            _: &updated::bundle::ReleaseId,
            _: &updated::bundle::ReleaseId,
        ) -> io::Result<()> {
            self.activations += 1;
            if self.fail_first_activation && self.activations == 1 {
                return Err(io::Error::other("injected activation failure"));
            }
            Ok(())
        }
        fn start(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn quiesce(&mut self) {}
        fn requires_version_proof(&self) -> bool {
            false
        }
    }

    impl Health for FakeTower {
        async fn became_healthy(&self, _: Option<&str>) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn a_partial_drain_is_rolled_back_before_its_journal_is_cleared() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = MemoryStore::new(previous);
        let mut tower = FakeTower {
            fail_drain: true,
            ..Default::default()
        };

        let outcome = apply_update(&mut tower, &mut store, &candidate, "archive-two", None)
            .await
            .unwrap();

        assert!(matches!(outcome, Outcome::Deferred));
        assert_eq!(tower.phases, ["preflight", "prepare", "drain", "rollback"]);
        assert_eq!(tower.activations, 0);
        assert!(store.journal.is_none());
    }

    #[tokio::test]
    async fn a_failed_drain_rollback_preserves_recovery_evidence() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = MemoryStore::new(previous);
        let mut tower = FakeTower {
            fail_drain: true,
            fail_rollback: true,
            ..Default::default()
        };

        assert!(
            apply_update(&mut tower, &mut store, &candidate, "archive-two", None)
                .await
                .is_err()
        );
        assert!(store.journal.is_some());
    }

    #[tokio::test]
    async fn failed_finalization_restores_the_predecessor_without_rejecting_the_candidate() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = MemoryStore::new(previous.clone());
        let mut tower = FakeTower {
            fail_finalize: true,
            ..Default::default()
        };

        let outcome = apply_update(&mut tower, &mut store, &candidate, "archive-two", None)
            .await
            .unwrap();

        assert!(matches!(outcome, Outcome::Deferred));
        assert_eq!(
            tower.phases,
            [
                "preflight",
                "prepare",
                "drain",
                "stop",
                "start",
                "verify",
                "finalize",
                "stop",
                "start",
                "verify",
                "rollback",
            ]
        );
        assert_eq!(
            tower.activations, 2,
            "candidate start plus predecessor restore"
        );
        assert_eq!(store.active, previous);
        assert!(
            store.rejected.is_empty(),
            "operator deferral remains retryable"
        );
        assert!(
            store.journal.is_none(),
            "completed rollback clears its evidence"
        );
    }

    #[tokio::test]
    async fn failed_stop_phase_defers_before_the_guardian_or_active_pointer_is_touched() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = MemoryStore::new(previous.clone());
        let mut provider = FakeTower {
            fail_stop: true,
            ..Default::default()
        };

        let outcome = apply_update(&mut provider, &mut store, &candidate, "archive-two", None)
            .await
            .unwrap();

        assert!(matches!(outcome, Outcome::Deferred));
        assert_eq!(store.active, previous);
        assert_eq!(provider.activations, 0);
        assert_eq!(
            provider.phases,
            ["preflight", "prepare", "drain", "stop", "rollback"]
        );
    }

    #[tokio::test]
    async fn failed_start_or_verify_phase_rolls_back_through_the_same_provider() {
        for failure in [LifecyclePhase::Start, LifecyclePhase::Verify] {
            let previous = release("1.0.0", "one");
            let candidate = release("2.0.0", "two");
            let mut store = MemoryStore::new(previous.clone());
            let mut provider = FakeTower {
                fail_first_start_phase: matches!(failure, LifecyclePhase::Start),
                fail_first_verify_phase: matches!(failure, LifecyclePhase::Verify),
                ..Default::default()
            };

            let outcome = apply_update(&mut provider, &mut store, &candidate, "archive-two", None)
                .await
                .unwrap();

            assert!(matches!(outcome, Outcome::RolledBack));
            assert_eq!(store.active, previous);
            assert_eq!(store.rejected, ["archive-two"]);
            assert!(provider
                .phases
                .ends_with(&["stop", "start", "verify", "rollback"]));
        }
    }

    #[tokio::test]
    async fn candidate_failure_is_rejected_before_rollback_can_fail() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = MemoryStore::new(previous);
        let mut tower = FakeTower {
            fail_first_activation: true,
            fail_rollback: true,
            ..Default::default()
        };

        assert!(
            apply_update(&mut tower, &mut store, &candidate, "archive-two", None)
                .await
                .is_err()
        );
        assert_eq!(store.rejected, ["archive-two"]);
        assert!(
            store
                .journal
                .as_ref()
                .is_some_and(|tx| tx.candidate_rejection_required),
            "rollback evidence must retain the rejection decision"
        );
    }

    #[test]
    fn chaos_catalog_is_unique_and_covers_every_supervised_durable_phase() {
        use std::collections::HashSet;

        let catalog: Vec<&str> = BOUNDARIES
            .iter()
            .chain(ROLLBACK_BOUNDARIES)
            .chain(ABORT_BOUNDARIES)
            .copied()
            .collect();
        assert_eq!(catalog.len(), catalog.iter().collect::<HashSet<_>>().len());
        for phase in [
            TransactionPhase::PreflightStarted,
            TransactionPhase::PreflightCompleted,
            TransactionPhase::PrepareStarted,
            TransactionPhase::Prepared,
            TransactionPhase::DrainStarted,
            TransactionPhase::Drained,
            TransactionPhase::StopStarted,
            TransactionPhase::Stopped,
            TransactionPhase::ActivateStarted,
            TransactionPhase::CandidateActivated,
            TransactionPhase::StartStarted,
            TransactionPhase::CandidateStarted,
            TransactionPhase::HealthStarted,
            TransactionPhase::CandidateHealthy,
            TransactionPhase::FinalizeStarted,
            TransactionPhase::Finalized,
            TransactionPhase::CommitStarted,
            TransactionPhase::Committed,
            TransactionPhase::RollbackStarted,
            TransactionPhase::RollbackStopStarted,
            TransactionPhase::RollbackStopped,
            TransactionPhase::RollbackActivateStarted,
            TransactionPhase::PredecessorActivated,
            TransactionPhase::RollbackStartStarted,
            TransactionPhase::PredecessorStarted,
            TransactionPhase::RollbackHealthStarted,
            TransactionPhase::PredecessorHealthy,
            TransactionPhase::RollbackFinalizeStarted,
            TransactionPhase::RolledBack,
            TransactionPhase::Aborted,
        ] {
            assert!(catalog.contains(&boundary::durable_phase(phase)));
        }
    }
}
