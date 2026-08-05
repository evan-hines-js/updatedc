use super::*;

pub(crate) enum Outcome {
    Committed,
    /// A candidate failed *after* activation: it is rejected and the durable rollback journal is
    /// left in place, but the actual rollback is performed by the one rollback implementation — the
    /// boot state machine — after this disposable supervisor terminates and the guardian relaunches
    /// it. There is no in-process rollback path.
    RollbackPending,
}

/// Why the application is being launched — passed to the provider as
/// `--reason` so one program can branch (first-boot seeding vs. per-restart
/// cleanup vs. an update) instead of needing a hook per situation.
#[derive(Clone, Copy)]
pub(crate) enum LifecycleReason {
    Install,
    Restart,
    Update,
}

impl LifecycleReason {
    fn name(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Restart => "restart",
            Self::Update => "update",
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
        eprintln!("supervisor: CHAOS: exiting at boundary {phase:?}");
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
    pub const PRE_DRAIN_STARTED: &str = "pre-drain-started";
    pub const PRE_DRAIN_APPLIED: &str = "pre-drain-applied";
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

    pub fn durable_phase(phase: TransactionPhase) -> &'static str {
        match phase {
            TransactionPhase::PreflightStarted => PREFLIGHT_STARTED,
            TransactionPhase::PreflightCompleted => PREFLIGHT_COMPLETED,
            TransactionPhase::PrepareStarted => PREPARE_STARTED,
            TransactionPhase::Prepared => PREPARED,
            TransactionPhase::PreDrainStarted => PRE_DRAIN_STARTED,
            TransactionPhase::DrainStarted => DRAIN_STARTED,
            TransactionPhase::Drained => DRAINED,
            TransactionPhase::StopStarted => STOP_STARTED,
            TransactionPhase::Stopped => STOPPED,
            TransactionPhase::ActivateStarted => ACTIVATE_STARTED,
            TransactionPhase::CandidateActivated => CANDIDATE_ACTIVATED,
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
    boundary::PRE_DRAIN_STARTED,
    boundary::PRE_DRAIN_APPLIED,
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

// ============================ the live-application port ============================
//
// What the transaction drives on the *live* side — the running application and its
// readiness — behind a port, exactly as [`Store`] ports the durable side. The production
// [`DefaultProvider`] performs the configured `Restart` mode over the guardian-owned [`App`]; a
// test fake scripts control outcomes and health, so every fault path of [`apply_update`] is
// provable without a guardian, an HTTP server, or a real process.

/// Bring a staged release into service — the activation hand-off moments. The port the transaction
/// drives; the sole restart abstraction (the `Restart` mode is data the [`DefaultProvider`]
/// lifecycle acts on). A post-activation failure does not roll back in-process: the transaction
/// rejects the candidate, leaves a durable rollback journal, and the supervisor terminates so boot
/// recovery performs the one rollback path.
/// How the built-in drain waits, after readiness is withdrawn and before the running release is
/// stopped, so the load balancer has removed this node from rotation first (no in-flight request
/// lands on a stopping process).
pub(crate) enum DrainHold {
    /// Stop immediately — a `provider-managed` deployment (its provider owns the drain), or a
    /// managed one that set the hold to zero.
    None,
    /// Hold up to this long — a bounded ceiling on how long we wait after withdrawing readiness
    /// before stopping the running release, giving a readiness-aware load balancer time to remove
    /// this node. A fixed sleep.
    Bounded(Duration),
}

pub(crate) trait DeploymentProvider {
    /// Change whether external traffic may reach the managed application.
    fn traffic_ready(&mut self, ready: bool) -> io::Result<()>;
    /// The drain hold policy: how long to wait, after readiness is withdrawn, before stopping.
    fn drain_hold(&self) -> DrainHold;
    /// Invoke the release's signed node reconciler.
    fn lifecycle(
        &mut self,
        phase: Operation,
        lifecycle_attempt_id: &str,
        candidate: &updated::bundle::ReleaseId,
        predecessor: &updated::bundle::ReleaseId,
    ) -> io::Result<()>;
    /// Stop the predecessor when the activation strategy requires a process stop.
    fn stop(&mut self) -> io::Result<()>;
    /// Apply the selected release to the surrounding service environment.
    fn activate(
        &mut self,
        lifecycle_attempt_id: &str,
        candidate: &updated::bundle::ReleaseId,
        predecessor: &updated::bundle::ReleaseId,
    ) -> io::Result<()>;
    /// Start the selected release when activation requires a fresh process.
    fn start(&mut self) -> io::Result<()>;
    /// Agent-owned retry policy for the provider's single-observation `verify` hook.
    fn verification_policy(&self) -> (Duration, u32, Duration);
}

/// The production tower combines the guardian-owned process seam with the signed node
/// reconciler. In provider-managed mode every guardian process operation is a no-op.
pub(crate) struct DefaultProvider<'a> {
    app: &'a mut App,
    opts: &'a Options,
    phases: LoadedPhaseProvider<'a>,
}

/// The release-bound provider: the signed node reconciler that always travels with the install.
struct LoadedPhaseProvider<'a> {
    release: &'a updated::state::ProviderRelease,
    opts: &'a Options,
}

impl<'a> LoadedPhaseProvider<'a> {
    fn load(opts: &'a Options, release: &'a updated::state::ProviderRelease) -> Self {
        Self { release, opts }
    }

    fn invoke(&self, invocation: LifecycleInvocation<'_>) -> io::Result<()> {
        run_lifecycle_command(self.release, self.opts, invocation)
    }
}

pub(crate) fn invoke_deployment_provider(
    release: &updated::state::ProviderRelease,
    opts: &Options,
    invocation: LifecycleInvocation<'_>,
) -> io::Result<()> {
    LoadedPhaseProvider::load(opts, release).invoke(invocation)
}

pub(crate) struct FingerprintJob {
    command: PreparedLifecycleCommand,
    definition_sha256: String,
}

impl FingerprintJob {
    pub(crate) fn run(
        self,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> io::Result<updated_contracts::telemetry::Fingerprint> {
        let output = run_prepared_lifecycle_command(self.command, Some(cancelled))?;
        fingerprint_from_output(&self.definition_sha256, output)
    }
}

pub(crate) fn prepare_fingerprint_job(
    release: &updated::state::ProviderRelease,
    opts: &Options,
    invocation: LifecycleInvocation<'_>,
) -> io::Result<FingerprintJob> {
    if invocation.phase != Operation::Inspect {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "fingerprint job requires the fingerprint lifecycle phase",
        ));
    }
    Ok(FingerprintJob {
        command: prepare_lifecycle_command(release, opts, invocation)?,
        definition_sha256: release.archive_sha256.clone(),
    })
}

fn fingerprint_from_output(
    definition_sha256: &str,
    output: ReconcilerOutput,
) -> io::Result<updated_contracts::telemetry::Fingerprint> {
    if output.stdout_truncated {
        return Err(io::Error::other(format!(
            "node fingerprint exceeded the {RECONCILER_OUTPUT_LIMIT}-byte output limit"
        )));
    }
    if output.stdout.is_empty() {
        return Err(io::Error::other(
            "node fingerprint produced no measured state on stdout",
        ));
    }
    updated_contracts::telemetry::Fingerprint::from_output(definition_sha256, &output.stdout)
        .map_err(io::Error::other)
}

/// Launch a fresh application, converging the environment with the reconciler's `apply`
/// operation first — the one launch path for a first install or a plain restart. `apply` gets
/// `--reason` (`install`/`restart`) so one reconciler can do per-boot prep (seed a JBoss home,
/// clear a wedged NFS mount) and tell a first boot from a restart.
///
/// `reason` is `None` when the boot is resuming an interrupted transaction: recovery replays
/// only that transaction's own minimal, idempotent steps, so the per-boot converge is skipped
/// and the application is launched directly.
///
/// Fail-closed: if `apply` fails the application is *not* launched — the error propagates
/// and the guardian retries the whole tower with backoff. Readiness always requires the signed
/// reconciler's `healthcheck`.
pub(crate) fn launch_after_boot_apply(
    guardian: Guardian,
    opts: &Options,
    store: &dyn Store,
    reason: Option<LifecycleReason>,
) -> io::Result<App> {
    if let Some(reason) = reason {
        if let updated::state::Installed::Present(installed) = store.installed() {
            let installed = *installed;
            let release = installed.release;
            let lifecycle = installed.lifecycle;
            // This is the per-boot environment converge, run on every launch. Release placement
            // already happened durably — in the install machine on a first boot, in the update
            // transaction on an upgrade — so this path never places; it only prepares the
            // environment before the launch.
            invoke_deployment_provider(
                lifecycle.as_ref(),
                opts,
                LifecycleInvocation {
                    phase: Operation::Apply,
                    reason,
                    id: attempt::BOOT,
                    pid: None,
                    candidate: &release,
                    predecessor: &release,
                },
            )?;
            return crate::app::start(guardian, opts);
        }
    }
    crate::app::start(guardian, opts)
}

impl<'a> DefaultProvider<'a> {
    /// The built-in provider is part of this binary, never an independently upgraded
    /// artifact. Exposing this constant prevents inventing a second version source.
    pub(crate) const VERSION: &'static str = SELF_VERSION;

    pub(crate) fn new(
        app: &'a mut App,
        opts: &'a Options,
        lifecycle: &'a updated::state::ProviderRelease,
    ) -> Self {
        DefaultProvider {
            app,
            opts,
            phases: LoadedPhaseProvider::load(opts, lifecycle),
        }
    }

    /// The PID handed to the hooks / used for health: the guardian's launched PID (the guardian
    /// always holds the process).
    fn hook_pid(&self) -> Option<u32> {
        self.app.pid()
    }
}

impl DeploymentProvider for DefaultProvider<'_> {
    /// Readiness is the TOWER's, not the process owner's: the guardian's probe endpoint is what a
    /// load balancer reads in both runtime modes. A provider-managed deployment is switched over by
    /// the operator's own `apply` hook, and there is no drain hook for it to own — so skipping the
    /// withdrawal here meant its switchover happened with the node still in rotation, which is the
    /// one thing the drain step exists to prevent.
    fn traffic_ready(&mut self, ready: bool) -> io::Result<()> {
        self.app
            .guardian
            .traffic_ready(ready)
            .map_err(io::Error::other)
    }
    fn drain_hold(&self) -> DrainHold {
        match self.opts.timeouts.drain_hold {
            Some(hold) if hold.is_zero() => DrainHold::None,
            Some(hold) => DrainHold::Bounded(hold),
            // An unset drain hold is *no* hold — deterministic and never a stall.
            None => DrainHold::None,
        }
    }
    fn lifecycle(
        &mut self,
        phase: Operation,
        lifecycle_attempt_id: &str,
        candidate: &updated::bundle::ReleaseId,
        predecessor: &updated::bundle::ReleaseId,
    ) -> io::Result<()> {
        // The reconciler receives the guardian-owned PID while that managed process exists.
        let pid = self.hook_pid();
        self.phases.invoke(LifecycleInvocation {
            phase,
            reason: LifecycleReason::Update,
            id: lifecycle_attempt_id,
            pid,
            candidate,
            predecessor,
        })
    }
    fn stop(&mut self) -> io::Result<()> {
        if self.opts.application.mode == updated_contracts::assignment::RuntimeMode::ProviderManaged
        {
            return Ok(());
        }
        crate::app::stop_runtime(self.app)
    }
    fn activate(
        &mut self,
        lifecycle_attempt_id: &str,
        candidate: &updated::bundle::ReleaseId,
        predecessor: &updated::bundle::ReleaseId,
    ) -> io::Result<()> {
        self.phases.invoke(LifecycleInvocation {
            phase: Operation::Apply,
            reason: LifecycleReason::Update,
            id: lifecycle_attempt_id,
            pid: None,
            candidate,
            predecessor,
        })
    }
    fn start(&mut self) -> io::Result<()> {
        if self.opts.application.mode == updated_contracts::assignment::RuntimeMode::ProviderManaged
        {
            return Ok(());
        }
        self.app.launch(self.opts)
    }
    fn verification_policy(&self) -> (Duration, u32, Duration) {
        (
            self.opts.timeouts.health_grace,
            self.opts.timeouts.health_successes,
            self.opts.timeouts.health_interval,
        )
    }
}

/// THE readiness gate. Every readiness decision in this supervisor — the boot gate, a
/// candidate's transaction gate, a crash-recovered rollback's gate — is this one function, and
/// it can only ever ask the signed reconciler for [`Operation::Healthcheck`]: the operation is
/// not a parameter, so no caller can gate readiness on anything else.
///
/// It repeatedly invokes that one observation until the reconciler supplies the configured
/// consecutive-success evidence or the agent-owned deadline expires. The reconciler performs one
/// application-specific observation; the agent owns cadence, bounds, cancellation, and policy.
///
/// `lifecycle_attempt_id` is the transaction's own token when a transaction is gating its
/// candidate — the reconciler may then rely on effects written by earlier operations of that exact
/// attempt — and [`attempt::BOOT`] for a boot or restart, which observes only durable steady state
/// and never impersonates a transaction whose attempt markers no longer exist.
pub(crate) async fn became_healthy<T: DeploymentProvider>(
    tower: &mut T,
    lifecycle_attempt_id: &str,
    candidate: &updated::bundle::ReleaseId,
    predecessor: &updated::bundle::ReleaseId,
) -> bool {
    let (grace, successes, interval) = tower.verification_policy();
    let deadline = Instant::now() + grace;
    let mut readiness = crate::app::Readiness::new(successes);
    let mut next = Instant::now();
    while Instant::now() < deadline {
        if Instant::now() >= next {
            let ok = tower
                .lifecycle(
                    Operation::Healthcheck,
                    lifecycle_attempt_id,
                    candidate,
                    predecessor,
                )
                .is_ok();
            if readiness.observe(ok) {
                return true;
            }
            next = Instant::now()
                + if ok {
                    interval
                } else {
                    Duration::from_millis(100)
                };
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

// ================================ the transaction ================================

/// Drive one application update through the durable transaction, over the [`Store`] and
/// live-application [`DeploymentProvider`] port.
pub(crate) async fn apply_update<T: DeploymentProvider>(
    tower: &mut T,
    store: &mut dyn Store,
    candidate: &updated::bundle::ReleaseId,
    candidate_archive_sha256: &str,
    candidate_repository_lineage: updated::state::RepositoryLineage,
    lifecycle: updated::state::ProviderRelease,
) -> io::Result<Outcome> {
    // Recovery belongs to the boot state machine. A live supervisor must never mutate
    // recovery evidence or restore an executable underneath a guardian-owned process.
    // Any transaction error terminates this disposable supervisor; bootstrap keeps the
    // application alive and relaunches us through the one recovery path.
    match store.journal()? {
        None => {}
        // A journal in a terminal phase is SPENT — its transaction already reached its end state
        // and everything durable is written. The only reason one is still here is that the delete
        // after commit failed (a read-only remount, an EIO). Retrying that delete is not recovery:
        // there is nothing left to reconcile, and treating it as fatal instead ends every boot on
        // a transient filesystem error — a relaunch loop that re-derives the same spent journal
        // and gets no further.
        Some(journal)
            if matches!(
                journal.phase,
                TransactionPhase::Committed | TransactionPhase::RolledBack
            ) =>
        {
            store.clear_journal()?;
            log("removed a spent update journal left behind by a failed post-commit cleanup");
        }
        Some(_) => {
            return Err(io::Error::other(
                "an unreconciled update journal requires supervisor restart",
            ));
        }
    }

    let installed = match store.installed() {
        Installed::Present(state) => state,
        _ => return Err(io::Error::other("a verified installed release is required")),
    };
    let chaos = Chaos::from_env();
    let mut tx = Transaction {
        id: updated::rand::token()?,
        previous_release: installed.release.clone(),
        previous_archive_sha256: installed.archive_sha256.clone(),
        previous_repository_lineage: installed.repository_lineage.clone(),
        candidate_release: candidate.clone(),
        candidate_archive_sha256: candidate_archive_sha256.to_string(),
        candidate_repository_lineage: candidate_repository_lineage.clone(),
        candidate_rejection_required: false,
        // These fields drive ROLLBACK recovery (restoring the predecessor), so they carry the
        // PREDECESSOR's own signed providers — app and providers are one signed unit, and a revert
        // must gate/watch the old release with the old hooks, not the candidate's. The forward path
        // runs the candidate through the `tower`, never these fields; the candidate's providers
        // become the new head's providers at commit below. This keeps the journal-driven recovery
        // (an in-process rollback that crashed) consistent with the pending-driven one, which
        // already carries the predecessor's providers.
        lifecycle: installed.lifecycle.clone(),
        rollback_health_failures: 0,
        phase: TransactionPhase::PreflightStarted,
    };
    persist_transaction(store, &tx)?;
    chaos.crossing(boundary::PREFLIGHT_APPLIED);
    advance_transaction(store, &mut tx, TransactionPhase::PreflightCompleted)?;

    advance_transaction(store, &mut tx, TransactionPhase::PrepareStarted)?;
    chaos.crossing(boundary::PREPARE_APPLIED);
    advance_transaction(store, &mut tx, TransactionPhase::Prepared)?;

    // Pre-drain: custom logic *before* we withdraw from traffic — e.g. tell the app to
    // begin shedding work — while the predecessor is still serving. Nothing has changed
    // yet, so a failure here defers cleanly. No-op when the provider defines no pre-drain
    // phase.
    advance_transaction(store, &mut tx, TransactionPhase::PreDrainStarted)?;
    chaos.crossing(boundary::PRE_DRAIN_APPLIED);

    // Built-in drain: the guardian flips its readiness probe to unready and only
    // acknowledges once its probe machine is in the drained state — that acknowledgement
    // is the go-ahead. We never stop the running binary until it returns, so the node is
    // out of readiness before switchover.
    tower.traffic_ready(false)?;
    // Readiness is withdrawn: this node is out of rotation and its running release is about to be
    // stopped, so no failure past this point may surface as `Err`. `Err` maps to
    // `AppOutcome::Fatal`, which abandons the update mid-drain and ends the process; the node then
    // serves nothing until the guardian's backoff relaunches this supervisor and boot recovery
    // restarts a release from the journal. Recovering in place is strictly better, so
    // `switch_over` returns [`Outcome`] rather than `io::Result<Outcome>` — a type error instead of
    // a rule every future call site has to remember.
    Ok(switch_over(tower, store, tx, lifecycle).await)
}

/// The post-drain half of an update: readiness is already withdrawn, so every failure from here on
/// is answered by restarting into boot recovery, which restores and starts a release from the
/// journal's last durable phase (always a valid checkpoint). The infallible return type is the
/// enforcement: there is no way to propagate an error out of the drained window.
async fn switch_over<T: DeploymentProvider>(
    tower: &mut T,
    store: &mut dyn Store,
    mut tx: Transaction,
    lifecycle: updated::state::ProviderRelease,
) -> Outcome {
    let chaos = Chaos::from_env();
    let candidate = tx.candidate_release.clone();
    macro_rules! recover_on_error {
        ($what:expr, $result:expr) => {
            match $result {
                Ok(value) => value,
                Err(error) => {
                    warn(&format!(
                        "{} failed after the application was drained ({error}); restarting for \
                         boot recovery",
                        $what
                    ));
                    return Outcome::RollbackPending;
                }
            }
        };
    }
    recover_on_error!(
        "recording the drain checkpoint",
        advance_transaction(store, &mut tx, TransactionPhase::DrainStarted)
    );

    // Built-in drain hold: having withdrawn readiness, wait for the load balancer to actually
    // remove this node before we stop the running release — otherwise an in-flight request lands
    // on a stopping process (the downtime a bare readiness flip leaves when endpoint removal lags
    // the switchover). Bounded is a ceiling; a `provider-managed` deployment and an unset hold wait
    // nothing here (the provider-managed Drain hook owns it, or the operator opted out).
    match tower.drain_hold() {
        DrainHold::None => {}
        DrainHold::Bounded(hold) => tokio::time::sleep(hold).await,
    }

    // Post-drain: custom logic *after* we are unready but *before* switchover — e.g. wait
    // for the orchestrator to observe the failed probe and stop routing, or for in-flight
    // connections to finish. Must run to completion before the predecessor is stopped.
    chaos.crossing(boundary::DRAIN_APPLIED);
    recover_on_error!(
        "recording the drained checkpoint",
        advance_transaction(store, &mut tx, TransactionPhase::Drained)
    );
    recover_on_error!(
        "recording the stop checkpoint",
        advance_transaction(store, &mut tx, TransactionPhase::StopStarted)
    );
    recover_on_error!("stopping the running release", tower.stop());
    chaos.crossing(boundary::STOP_APPLIED);
    recover_on_error!(
        "recording the stopped checkpoint",
        advance_transaction(store, &mut tx, TransactionPhase::Stopped)
    );

    recover_on_error!(
        "recording the activation checkpoint",
        advance_transaction(store, &mut tx, TransactionPhase::ActivateStarted)
    );
    // Split the activation into its two failure classes. A re-verification failure means the
    // candidate's on-disk bytes are corrupt — genuinely its fault — so reject. A pointer-write
    // failure is pure infrastructure (ENOSPC, transient I/O), never the candidate's fault: restart
    // for boot recovery WITHOUT rejecting, so the healthy release is retried instead of stranded a
    // version behind (same fail-safe class as the guardian-channel case below).
    if let Err(e) = store.verify_release(&candidate) {
        warn(&format!(
            "release re-verification failed before commit ({e})"
        ));
        return reject_then_recover(store, &mut tx);
    }
    if let Err(e) = store.point_active(&candidate) {
        warn(&format!(
            "writing the active-release pointer failed ({e}); restarting for boot recovery"
        ));
        return Outcome::RollbackPending;
    }
    chaos.crossing(boundary::CANDIDATE_POINTER_APPLIED);

    if let Err(e) = tower.activate(&tx.id, &candidate, &tx.previous_release) {
        warn(&format!("activating the new version failed ({e})"));
        return reject_then_recover(store, &mut tx);
    }
    chaos.crossing(boundary::CANDIDATE_LIFECYCLE_APPLIED);
    recover_on_error!(
        "recording the activated checkpoint",
        advance_transaction(store, &mut tx, TransactionPhase::CandidateActivated)
    );
    recover_on_error!(
        "recording the start checkpoint",
        advance_transaction(store, &mut tx, TransactionPhase::StartStarted)
    );
    if let Err(e) = tower.start() {
        // A control-channel transport failure here (a SIGKILLed guardian, a broken pipe) is never
        // the candidate's fault, and the candidate process never started. Restart for boot
        // recovery *without* recording a rejection (unlike `reject_then_recover`): recovery
        // restores the predecessor and rejects the candidate only if it actually ran and exited
        // (`boot::recover`'s service-exit check), so a healthy release is retried rather than
        // stranded a version behind. Return `RollbackPending` — the clean-exit-for-recovery path
        // (`AppOutcome::RestartForRecovery`) — NOT `Err`, whose `Fatal` branch abandons the update
        // and leaves the node with nothing running until a relaunch recovers it. Only a
        // genuine start failure (the guardian answered but refused) rejects. See
        // `GuardianError::Channel`.
        if e.kind() == io::ErrorKind::ConnectionReset {
            warn(&format!(
                "starting the new version could not reach the guardian ({e}); restarting for boot recovery"
            ));
            return Outcome::RollbackPending;
        }
        warn(&format!("starting the new version failed ({e})"));
        return reject_then_recover(store, &mut tx);
    }
    chaos.crossing(boundary::CANDIDATE_START_APPLIED);
    recover_on_error!(
        "recording the started checkpoint",
        advance_transaction(store, &mut tx, TransactionPhase::CandidateStarted)
    );

    recover_on_error!(
        "recording the health checkpoint",
        advance_transaction(store, &mut tx, TransactionPhase::HealthStarted)
    );
    if !became_healthy(tower, &tx.id, &candidate, &tx.previous_release).await {
        return reject_then_recover(store, &mut tx);
    }
    chaos.crossing(boundary::CANDIDATE_HEALTH_APPLIED);
    recover_on_error!(
        "recording the healthy checkpoint",
        advance_transaction(store, &mut tx, TransactionPhase::CandidateHealthy)
    );

    recover_on_error!(
        "recording the finalize checkpoint",
        advance_transaction(store, &mut tx, TransactionPhase::FinalizeStarted)
    );
    chaos.crossing(boundary::FINALIZE_APPLIED);
    recover_on_error!(
        "recording the finalized checkpoint",
        advance_transaction(store, &mut tx, TransactionPhase::Finalized)
    );

    // Commit atomically WITH the pending rollback intent: the update is unconfirmed until
    // it survives its window. Folding the rollback intent into one write means there is no
    // separate "arm" step to be interrupted — if a crash lands after this, the pending
    // record is already durable; if before, the journal reactivates the predecessor.
    //
    // The predecessor identity comes from the transaction, the same record boot recovery reads, so
    // the pending-driven rollback and the journal-driven one cannot describe different predecessors.
    // That includes the providers: the rollback restores the *predecessor*, so it must carry the
    // *predecessor's own* signed providers (app + providers are one signed unit), not the
    // candidate's. At the assigned head these are the same set; across a provider-set revision in
    // this update they differ, and reverting the old release with the new providers would
    // gate/watch it with the wrong hooks.
    let pending = Some(Pending {
        lifecycle_attempt_id: tx.id.clone(),
        previous_release: tx.previous_release.clone(),
        previous_archive_sha256: tx.previous_archive_sha256.clone(),
        previous_repository_lineage: tx.previous_repository_lineage.clone(),
        committed_at: now_unix(),
        lifecycle: tx.lifecycle.clone(),
    });
    recover_on_error!(
        "recording the commit checkpoint",
        advance_transaction(store, &mut tx, TransactionPhase::CommitStarted)
    );
    recover_on_error!(
        "committing the installed release",
        store.commit_installed(&InstalledState {
            repository_lineage: tx.candidate_repository_lineage.clone(),
            release: candidate.clone(),
            archive_sha256: tx.candidate_archive_sha256.clone(),
            // The candidate's own providers are now the installed release's providers; persist them so
            // the boot converge and the readiness gate can run them on the next boot. (This is the
            // candidate provider passed in — `tx.lifecycle` holds the *predecessor's*
            // now, for rollback.)
            lifecycle: Box::new(lifecycle),
            pending,
            // An update always has a proven predecessor: its failure recovery is this state machine's
            // rollback, never an ordered-fallback descent, so the new head commits already confirmed.
            confirmed: true,
        })
    );
    chaos.crossing(boundary::COMMIT_APPLIED);
    recover_on_error!(
        "recording the committed checkpoint",
        advance_transaction(store, &mut tx, TransactionPhase::Committed)
    );
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
    // Readiness is the last step and the update is already durable: a failure to flip the probe
    // back is not a failed update, and restarting for recovery here would roll back a committed,
    // healthy release. The next boot re-establishes readiness.
    if let Err(error) = tower.traffic_ready(true) {
        warn(&format!(
            "restoring readiness after a committed update failed ({error}); the release is \
             committed and the next probe cycle re-establishes it"
        ));
    }
    Outcome::Committed
}

/// Persist the rejection decision before applying it. If the process dies in the gap,
/// boot recovery replays the idempotent rejection from the transaction rather than
/// forgetting why rollback began and selecting the same bad archive again.
fn require_candidate_rejection(store: &mut dyn Store, tx: &mut Transaction) -> io::Result<()> {
    if !tx.candidate_rejection_required {
        tx.candidate_rejection_required = true;
        store.write_journal(tx)?;
    }
    store.reject(
        &tx.candidate_repository_lineage,
        &tx.candidate_archive_sha256,
    )
}

/// Reject the failed candidate and hand the rollback to the boot state machine — the single
/// rollback implementation. Every post-activation failure ends here: the candidate is activated
/// (and possibly still running) but failed, so this records the rejection and leaves the durable
/// journal for boot recovery to complete on the next supervisor start. A supervisor restart is
/// cheap; the guardian keeps the (failed) application alive across it, and the freshly-booted
/// supervisor stops the candidate and restores the predecessor with the predecessor's *own*
/// providers (carried in the transaction). Rolling back here in-process would be a second rollback
/// path to keep in lockstep with boot recovery — and, because a live supervisor runs the candidate's
/// tower, it would gate the restored predecessor with the *candidate's* reconciler. One path,
/// one set of providers, no divergence.
///
/// Recording the rejection is itself a durable write and can fail (ENOSPC, a read-only remount).
/// That failure must not escape: this runs with the application already drained, where an error
/// would hold the process alive with nothing serving. Boot recovery still restores the predecessor
/// from the journal — it only loses the rejection, which costs one more futile attempt at the same
/// candidate, not the node.
fn reject_then_recover(store: &mut dyn Store, tx: &mut Transaction) -> Outcome {
    if let Err(error) = require_candidate_rejection(store, tx) {
        warn(&format!(
            "recording the failed candidate's rejection after the application was drained \
             ({error}); restarting for boot recovery"
        ));
    }
    Outcome::RollbackPending
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

/// Invoke the single signed node reconciler with a stable operation and transaction identity.
/// The protocol is intentionally ordinary argv so an operator can implement it in Bash or
/// PowerShell without a JSON parser or SDK. A bounded wait prevents a wedged enterprise
/// integration from wedging the updater forever.
pub(crate) struct LifecycleInvocation<'a> {
    pub(crate) phase: Operation,
    pub(crate) reason: LifecycleReason,
    pub(crate) id: &'a str,
    pub(crate) pid: Option<u32>,
    pub(crate) candidate: &'a updated::bundle::ReleaseId,
    pub(crate) predecessor: &'a updated::bundle::ReleaseId,
}

pub(crate) fn run_lifecycle_command(
    lifecycle: &updated::state::ProviderRelease,
    opts: &Options,
    invocation: LifecycleInvocation<'_>,
) -> io::Result<()> {
    run_lifecycle_command_output(lifecycle, opts, invocation).map(|_| ())
}

fn run_lifecycle_command_output(
    lifecycle: &updated::state::ProviderRelease,
    opts: &Options,
    invocation: LifecycleInvocation<'_>,
) -> io::Result<ReconcilerOutput> {
    run_prepared_lifecycle_command(
        prepare_lifecycle_command(lifecycle, opts, invocation)?,
        None,
    )
}

struct PreparedLifecycleCommand {
    command: Command,
    phase: Operation,
    timeout: Duration,
}

fn prepare_lifecycle_command(
    lifecycle: &updated::state::ProviderRelease,
    opts: &Options,
    invocation: LifecycleInvocation<'_>,
) -> io::Result<PreparedLifecycleCommand> {
    let LifecycleInvocation {
        phase,
        reason,
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
    let timeout = lifecycle_timeout(phase, Duration::from_millis(lifecycle.timeout_millis));
    let phase_name = phase.as_str();
    let app_provider = updated::provider::BundleStore::for_app(&opts.paths);
    let candidate_dir = app_provider.location(candidate);
    let predecessor_dir = app_provider.location(predecessor);
    let state_dir = opts
        .paths
        .install_root
        .join("providers/state")
        .join(&lifecycle.product);
    std::fs::create_dir_all(&state_dir)?;
    let output_file = reconciler_output_path(&opts.paths.install_root, &candidate.manifest_sha256);
    if let Some(parent) = output_file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let input_file = state_dir.join("inputs.json");
    // Managed, not private: these are the deployment's own signed inputs, and the reconciler that
    // reads them may legitimately run as a different principal than the writer. A protected
    // owner-only DACL here would hand the operator's hook a file it cannot open.
    foundation::durable::atomic_write_managed(
        &input_file,
        ".inputs-",
        &serde_json::to_vec(&opts.application.inputs)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
    )?;
    let mut cmd = reconciler_command(&resolved.program)?;
    cmd.arg(phase_name)
        .arg("--protocol")
        .arg("1")
        .arg("--attempt-id")
        .arg(lifecycle_attempt_id)
        .arg("--reason")
        .arg(reason.name())
        .arg("--install-root")
        .arg(&opts.paths.install_root)
        .arg("--state-dir")
        .arg(&state_dir)
        .arg("--candidate")
        .arg(&candidate_dir)
        .arg("--candidate-version")
        .arg(&candidate.version)
        .arg("--output-file")
        .arg(&output_file)
        .arg("--input-file")
        .arg(&input_file)
        .arg("--predecessor")
        .arg(&predecessor_dir)
        .arg("--predecessor-version")
        .arg(&predecessor.version);
    if let Some(pid) = pid {
        cmd.arg("--managed-pid").arg(pid.to_string());
    }
    if !lifecycle.args.is_empty() {
        // Publisher-configured arguments are explicitly separated from the stable protocol.
        cmd.arg("--").args(&lifecycle.args);
    }
    cmd.current_dir(&resolved.cwd)
        .env_clear()
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    apply_reconciler_environment(&mut cmd);
    // A wrapper commonly waits on vendor CLIs, curl, or mount helpers. Run it as a
    // contained tree (Unix process group / Windows job object) so a timeout takes the
    // whole tree down, not just the shell — leaving the foreground operation orphaned.
    // The platform mechanism lives in `foundation::process`, not inlined here.
    // Linux also ties this transaction helper to this supervisor attempt. The managed
    // application is guardian-owned and deliberately has no such coupling.
    foundation::process::arrange_parent_death_signal(&mut cmd);
    Ok(PreparedLifecycleCommand {
        command: cmd,
        phase,
        timeout,
    })
}

/// Outputs are partitioned by immutable application archive. A failed candidate can leave its own
/// file behind without ever having those values attributed to the restored predecessor.
pub(crate) fn reconciler_output_path(
    install_root: &std::path::Path,
    archive_sha256: &str,
) -> std::path::PathBuf {
    install_root
        .join("providers")
        .join("outputs")
        .join(format!("{archive_sha256}.json"))
}

const FINGERPRINT_TIMEOUT: Duration = Duration::from_secs(5 * 60);

fn lifecycle_timeout(phase: Operation, configured: Duration) -> Duration {
    if phase == Operation::Inspect {
        configured.min(FINGERPRINT_TIMEOUT)
    } else {
        configured
    }
}

/// Run a blocking body without starving the async runtime.
///
/// Operator lifecycle hooks are external programs waited on synchronously, for up to their full
/// configured timeout. On a multi-threaded runtime that would otherwise pin a worker thread for the
/// entire hook — stalling telemetry, health probes, and the guardian channel on the same runtime.
/// Outside a runtime (the fingerprint observer runs on its own OS thread) the body simply runs.
fn without_blocking_the_runtime<T>(body: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current().map(|handle| handle.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(body),
        _ => body(),
    }
}

fn run_prepared_lifecycle_command(
    prepared: PreparedLifecycleCommand,
    cancelled: Option<&std::sync::atomic::AtomicBool>,
) -> io::Result<ReconcilerOutput> {
    without_blocking_the_runtime(move || {
        run_prepared_lifecycle_command_blocking(prepared, cancelled)
    })
}

fn run_prepared_lifecycle_command_blocking(
    prepared: PreparedLifecycleCommand,
    cancelled: Option<&std::sync::atomic::AtomicBool>,
) -> io::Result<ReconcilerOutput> {
    let PreparedLifecycleCommand {
        command,
        phase,
        timeout,
    } = prepared;
    let phase_name = phase.as_str();
    let mut child = foundation::process::ContainedChild::spawn(command)?;
    let stdout = capture_reconciler_output(
        child
            .take_stdout()
            .ok_or_else(|| io::Error::other("node reconciler stdout was not captured"))?,
    );
    let stderr = capture_reconciler_output(
        child
            .take_stderr()
            .ok_or_else(|| io::Error::other("node reconciler stderr was not captured"))?,
    );
    let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "lifecycle timeout is too large",
        )
    })?;
    loop {
        if let Some(status) = child.try_wait()? {
            // A wrapper may exit successfully while a background descendant retains the captured
            // pipes. Tear down the remainder of this disposable hook tree before joining the
            // readers; otherwise inherited stdout/stderr can bypass the lifecycle deadline.
            child.kill_tree()?;
            let output = report_reconciler_output(phase, stdout, stderr)?;
            return if status.success() {
                Ok(output)
            } else {
                Err(io::Error::other(format!(
                    "node reconciler {phase_name} exited with {status}"
                )))
            };
        }
        if cancelled.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Acquire)) {
            child.kill_tree()?;
            child.wait()?;
            report_reconciler_output(phase, stdout, stderr)?;
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                format!("node reconciler {phase_name} was cancelled for deployment reconciliation"),
            ));
        }
        if Instant::now() >= deadline {
            child.kill_tree()?;
            child.wait()?;
            report_reconciler_output(phase, stdout, stderr)?;
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "node reconciler {phase_name} exceeded its {}s timeout",
                    timeout.as_secs_f64()
                ),
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn apply_reconciler_environment(command: &mut Command) {
    #[cfg(unix)]
    command.env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");

    #[cfg(windows)]
    {
        let system_root = std::env::var_os("SystemRoot")
            .or_else(|| std::env::var_os("WINDIR"))
            .unwrap_or_else(|| std::ffi::OsString::from(r"C:\Windows"));
        let system32 = PathBuf::from(&system_root).join("System32");
        let powershell = system32.join("WindowsPowerShell/v1.0");
        command
            .env("SystemRoot", &system_root)
            .env("WINDIR", &system_root)
            .env(
                "PATH",
                std::env::join_paths([system32, powershell]).unwrap_or_default(),
            );
        for name in ["TEMP", "TMP"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
    }
}

const RECONCILER_OUTPUT_LIMIT: usize = 64 * 1024;

struct ReconcilerOutput {
    stdout: Vec<u8>,
    stdout_truncated: bool,
}

fn capture_reconciler_output(
    mut input: impl std::io::Read + Send + 'static,
) -> std::thread::JoinHandle<io::Result<(Vec<u8>, bool)>> {
    std::thread::spawn(move || {
        let mut captured = Vec::new();
        let mut truncated = false;
        let mut buffer = [0_u8; 8192];
        loop {
            let read = input.read(&mut buffer)?;
            if read == 0 {
                return Ok((captured, truncated));
            }
            let remaining = RECONCILER_OUTPUT_LIMIT.saturating_sub(captured.len());
            captured.extend_from_slice(&buffer[..read.min(remaining)]);
            truncated |= read > remaining;
        }
    })
}

fn report_reconciler_output(
    phase: Operation,
    stdout: std::thread::JoinHandle<io::Result<(Vec<u8>, bool)>>,
    stderr: std::thread::JoinHandle<io::Result<(Vec<u8>, bool)>>,
) -> io::Result<ReconcilerOutput> {
    let operation = phase.as_str();
    let mut stdout_result = None;
    for (stream, handle) in [("stdout", stdout), ("stderr", stderr)] {
        let (bytes, truncated) = handle
            .join()
            .map_err(|_| io::Error::other("node reconciler output reader panicked"))??;
        // Fingerprint stdout is opaque measured state, not diagnostics. It is hashed below and
        // must never be copied into logs; stderr remains the script's diagnostic channel.
        if !(bytes.is_empty() || phase == Operation::Inspect && stream == "stdout") {
            let suffix = if truncated { " [truncated]" } else { "" };
            log(&format!(
                "node reconciler {operation} {stream}{suffix}: {}",
                String::from_utf8_lossy(&bytes).trim_end()
            ));
        }
        if stream == "stdout" {
            stdout_result = Some((bytes, truncated));
        }
    }
    let (stdout, stdout_truncated) =
        stdout_result.ok_or_else(|| io::Error::other("node reconciler stdout result was lost"))?;
    Ok(ReconcilerOutput {
        stdout,
        stdout_truncated,
    })
}

fn reconciler_command(program: &Path) -> io::Result<Command> {
    #[cfg(target_os = "macos")]
    {
        // macOS has no native parent-death facility. Keep a watchdog in this reconciler's fresh
        // process group: it exits when the provider exits, but if this disposable supervisor
        // disappears first it kills only the transaction helper group. Positional parameters
        // preserve arbitrary program paths without interpolating them into shell source.
        const WATCHDOG: &str = r#"
supervisor=$1
shift
leader=$$
(
    while kill -0 "$supervisor" 2>/dev/null && kill -0 "$leader" 2>/dev/null; do
        sleep 0.05
    done
    if kill -0 "$leader" 2>/dev/null; then
        kill -KILL "-$leader"
    fi
) &
exec "$@"
"#;
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", WATCHDOG, "updated-reconciler-watchdog"])
            .arg(std::process::id().to_string())
            .arg(program);
        Ok(command)
    }
    #[cfg(not(target_os = "macos"))]
    {
        #[cfg(windows)]
        if program
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("ps1"))
        {
            let system_root = std::env::var_os("SystemRoot")
                .or_else(|| std::env::var_os("WINDIR"))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        "SystemRoot is unavailable for PowerShell reconciler",
                    )
                })?;
            let powershell =
                PathBuf::from(system_root).join("System32/WindowsPowerShell/v1.0/powershell.exe");
            let mut command = Command::new(powershell);
            command
                .args(["-NoLogo", "-NoProfile", "-NonInteractive", "-File"])
                .arg(program);
            return Ok(command);
        }
        Ok(Command::new(program))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_hashes_exact_stdout_bytes_without_text_normalization() {
        let exact = fingerprint_from_output(
            &"a".repeat(64),
            ReconcilerOutput {
                stdout: b"state\n".to_vec(),
                stdout_truncated: false,
            },
        )
        .unwrap();
        let without_newline = fingerprint_from_output(
            &"a".repeat(64),
            ReconcilerOutput {
                stdout: b"state".to_vec(),
                stdout_truncated: false,
            },
        )
        .unwrap();

        assert_ne!(exact.output_sha256, without_newline.output_sha256);
        assert_eq!(exact.definition_sha256, "a".repeat(64));
    }

    #[test]
    fn a_truncated_fingerprint_is_never_attested() {
        let error = fingerprint_from_output(
            &"a".repeat(64),
            ReconcilerOutput {
                stdout: vec![0; RECONCILER_OUTPUT_LIMIT],
                stdout_truncated: true,
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("output limit"));
    }

    #[test]
    fn an_empty_fingerprint_is_never_attested() {
        let error = fingerprint_from_output(
            &"a".repeat(64),
            ReconcilerOutput {
                stdout: Vec::new(),
                stdout_truncated: false,
            },
        )
        .unwrap_err();

        assert!(error.to_string().contains("no measured state"));
    }

    #[test]
    fn fingerprint_has_one_agent_owned_runtime_ceiling() {
        assert_eq!(
            lifecycle_timeout(Operation::Inspect, Duration::from_secs(86_400)),
            FINGERPRINT_TIMEOUT
        );
        assert_eq!(
            lifecycle_timeout(Operation::Inspect, Duration::from_secs(30)),
            Duration::from_secs(30)
        );
        assert_eq!(
            lifecycle_timeout(Operation::Healthcheck, Duration::from_secs(86_400)),
            Duration::from_secs(86_400)
        );
    }

    #[cfg(unix)]
    #[test]
    fn cancellation_kills_the_contained_fingerprint_process_tree() {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "sleep 30"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        foundation::process::arrange_parent_death_signal(&mut command);
        let prepared = PreparedLifecycleCommand {
            command,
            phase: Operation::Inspect,
            timeout: Duration::from_secs(30),
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&cancelled);
        let started = Instant::now();
        let handle =
            std::thread::spawn(move || run_prepared_lifecycle_command(prepared, Some(&signal)));
        std::thread::sleep(Duration::from_millis(100));
        cancelled.store(true, Ordering::Release);

        let error = match handle.join().unwrap() {
            Ok(_) => panic!("cancelled fingerprint unexpectedly completed"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_reconciler_watchdog_preserves_normal_exit() {
        let command = reconciler_command(Path::new("/usr/bin/true")).unwrap();
        let mut child = foundation::process::ContainedChild::spawn(command).unwrap();
        assert!(child.wait().unwrap().success());
    }

    fn release(version: &str, digest: &str) -> updated::bundle::ReleaseId {
        updated::bundle::ReleaseId {
            version: version.into(),
            manifest_sha256: digest.into(),
        }
    }

    fn reconciler_release() -> updated::state::ProviderRelease {
        updated::state::ProviderRelease {
            product: "reconciler".into(),
            release: release("1.0.0", "reconciler-manifest"),
            archive_sha256: "reconciler-archive".into(),
            args: Vec::new(),
            timeout_millis: 1_000,
        }
    }

    struct MemoryStore {
        installed: Installed,
        journal: Option<Transaction>,
        active: updated::bundle::ReleaseId,
        rejected: Vec<String>,
        /// Simulate a state directory that has gone unwritable (ENOSPC, a read-only remount).
        fail_reject: bool,
    }

    impl MemoryStore {
        fn new(previous: updated::bundle::ReleaseId) -> Self {
            Self {
                installed: Installed::Present(Box::new(InstalledState::confirmed(
                    test_lineage(),
                    previous.clone(),
                    "previous-archive".into(),
                    Box::new(reconciler_release()),
                ))),
                journal: None,
                active: previous,
                rejected: Vec::new(),
                fail_reject: false,
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
        fn install_journal(&self) -> io::Result<Option<updated::install::InstallTransaction>> {
            Ok(None)
        }
        fn active_release(&self) -> io::Result<Option<updated::bundle::ReleaseId>> {
            Ok(Some(self.active.clone()))
        }
        fn is_rejected(&self, _: &updated::state::RepositoryLineage, _: &str) -> bool {
            false
        }
        fn commit_installed(&mut self, state: &InstalledState) -> io::Result<()> {
            self.installed = Installed::Present(Box::new(state.clone()));
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
        fn write_install_journal(
            &mut self,
            _: &updated::install::InstallTransaction,
        ) -> io::Result<()> {
            Ok(())
        }
        fn clear_install_journal(&mut self) -> io::Result<()> {
            Ok(())
        }
        fn reject(
            &mut self,
            _: &updated::state::RepositoryLineage,
            digest: &str,
        ) -> io::Result<()> {
            if self.fail_reject {
                return Err(io::Error::other("injected rejection write failure"));
            }
            self.rejected.push(digest.into());
            Ok(())
        }
        fn clear_rejection(
            &mut self,
            _: &updated::state::RepositoryLineage,
            _: &str,
        ) -> io::Result<()> {
            Ok(())
        }
        fn verify_release(&self, _: &updated::bundle::ReleaseId) -> io::Result<()> {
            Ok(())
        }
        fn point_active(&mut self, release: &updated::bundle::ReleaseId) -> io::Result<()> {
            self.active = release.clone();
            Ok(())
        }
    }

    fn test_lineage() -> updated::state::RepositoryLineage {
        updated::state::RepositoryLineage::from_metadata_url("https://repo/metadata/")
    }

    #[derive(Default)]
    struct FakeTower {
        /// Every reconciler invocation, as the operation's wire spelling and its attempt id —
        /// the two halves of the argv contract a gate is required to honour.
        invocations: Vec<(&'static str, String)>,
        fail_rollback: bool,
        fail_first_healthcheck: bool,
        healthcheck_calls: usize,
        fail_first_activation: bool,
        fail_process_stop: bool,
        activations: usize,
    }

    impl DeploymentProvider for FakeTower {
        fn drain_hold(&self) -> DrainHold {
            DrainHold::None
        }
        fn traffic_ready(&mut self, _ready: bool) -> io::Result<()> {
            Ok(())
        }

        fn lifecycle(
            &mut self,
            phase: Operation,
            lifecycle_attempt_id: &str,
            _: &updated::bundle::ReleaseId,
            _: &updated::bundle::ReleaseId,
        ) -> io::Result<()> {
            self.invocations
                .push((phase.as_str(), lifecycle_attempt_id.to_string()));
            if matches!(phase, Operation::Healthcheck) {
                self.healthcheck_calls += 1;
            }
            if (matches!(phase, Operation::Rollback) && self.fail_rollback)
                || (matches!(phase, Operation::Healthcheck)
                    && self.fail_first_healthcheck
                    && self.healthcheck_calls == 1)
            {
                return Err(io::Error::other("injected lifecycle failure"));
            }
            Ok(())
        }
        fn stop(&mut self) -> io::Result<()> {
            if self.fail_process_stop {
                Err(io::Error::other("injected process stop failure"))
            } else {
                Ok(())
            }
        }
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
        fn verification_policy(&self) -> (Duration, u32, Duration) {
            (Duration::from_secs(1), 1, Duration::ZERO)
        }
    }

    /// The readiness gate is the reconciler's `healthcheck` operation — by that exact published
    /// spelling — under the reserved `boot` attempt identity. A reconciler answers argv, so a gate
    /// that asked for any other operation name would silently fall through the reconciler's
    /// dispatch and gate nothing.
    #[tokio::test]
    async fn the_boot_gate_is_the_published_healthcheck_operation() {
        let release = release("22.0.0", "current");
        let mut tower = FakeTower::default();

        assert!(became_healthy(&mut tower, attempt::BOOT, &release, &release).await);
        assert_eq!(tower.invocations, [("healthcheck", "boot".to_string())]);
        assert_eq!(tower.healthcheck_calls, 1);
    }

    /// The same one gate serves a transaction, carrying the transaction's own attempt id so the
    /// reconciler can rely on effects its earlier operations wrote — and still asking for exactly
    /// `healthcheck`.
    #[tokio::test]
    async fn the_transaction_gate_is_the_same_healthcheck_operation_under_the_attempt_id() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = MemoryStore::new(previous.clone());
        let mut tower = FakeTower::default();

        let outcome = apply_update(
            &mut tower,
            &mut store,
            &candidate,
            "archive-two",
            test_lineage(),
            reconciler_release(),
        )
        .await
        .unwrap();

        assert!(matches!(outcome, Outcome::Committed));
        let gates: Vec<&(&str, String)> = tower
            .invocations
            .iter()
            .filter(|(operation, _)| *operation == "healthcheck")
            .collect();
        let (_, attempt_id) = gates
            .first()
            .expect("a committed update is gated by the reconciler's healthcheck operation");
        assert_eq!(gates.len(), 1);
        assert!(
            !updated_contracts::reconciler::attempt::is_reserved(attempt_id),
            "a transaction gate carries its own attempt id, never a reserved observation identity"
        );
    }

    #[tokio::test]
    async fn failed_process_stop_preserves_recovery_evidence_and_never_activates() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = MemoryStore::new(previous.clone());
        let mut provider = FakeTower {
            fail_process_stop: true,
            ..Default::default()
        };

        let outcome = apply_update(
            &mut provider,
            &mut store,
            &candidate,
            "archive-two",
            test_lineage(),
            reconciler_release(),
        )
        .await
        .expect("a post-drain failure restarts for recovery rather than holding the node down");

        // Never `Err`: that maps to the fatal branch, which abandons the update with the
        // application drained. The single recovery path is a clean restart.
        assert!(matches!(outcome, Outcome::RollbackPending));
        assert_eq!(store.active, previous);
        assert_eq!(provider.activations, 0);
        assert!(
            store.journal.is_some(),
            "boot recovery needs the stop intent"
        );
    }

    #[tokio::test]
    async fn a_transient_healthcheck_failure_is_retried_by_the_agent() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = MemoryStore::new(previous);
        let mut provider = FakeTower {
            fail_first_healthcheck: true,
            ..Default::default()
        };

        let outcome = apply_update(
            &mut provider,
            &mut store,
            &candidate,
            "archive-two",
            test_lineage(),
            reconciler_release(),
        )
        .await
        .unwrap();

        assert!(matches!(outcome, Outcome::Committed));
        assert_eq!(provider.healthcheck_calls, 2);
        assert!(store.rejected.is_empty());
    }

    #[tokio::test]
    async fn a_failed_activation_records_the_rejection_before_deferring_to_recovery() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = MemoryStore::new(previous);
        let mut tower = FakeTower {
            fail_first_activation: true,
            ..Default::default()
        };

        let outcome = apply_update(
            &mut tower,
            &mut store,
            &candidate,
            "archive-two",
            test_lineage(),
            reconciler_release(),
        )
        .await
        .unwrap();

        // The candidate activated then failed: it is rejected and the rollback journal is durable
        // before we hand off to boot recovery. There is no in-process rollback to fail.
        assert!(matches!(outcome, Outcome::RollbackPending));
        assert_eq!(store.rejected, ["archive-two"]);
        assert!(
            store
                .journal
                .as_ref()
                .is_some_and(|tx| tx.candidate_rejection_required),
            "rollback evidence must retain the rejection decision"
        );
    }

    #[tokio::test]
    async fn an_unwritable_rejection_after_the_drain_still_restarts_for_recovery() {
        // The state directory goes unwritable exactly when the failed candidate's rejection is
        // recorded. The application is already stopped, so an `Err` here would map to
        // `AppOutcome::Fatal` and abandon the drained update instead of recovering in place —
        // the one outcome the post-drain half must be incapable of producing.
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = MemoryStore::new(previous.clone());
        store.fail_reject = true;
        let mut tower = FakeTower {
            fail_first_activation: true,
            ..Default::default()
        };

        let outcome = apply_update(
            &mut tower,
            &mut store,
            &candidate,
            "archive-two",
            test_lineage(),
            reconciler_release(),
        )
        .await
        .expect(
            "a failed durable write after the drain restarts rather than holding the node down",
        );

        assert!(matches!(outcome, Outcome::RollbackPending));
        assert!(store.rejected.is_empty());
        assert!(
            store
                .journal
                .as_ref()
                .is_some_and(|tx| tx.candidate_rejection_required),
            "the journal still carries the rollback and the rejection to replay"
        );
    }

    #[tokio::test]
    async fn reconciler_only_revision_uses_the_normal_transaction() {
        let application_release = release("1.0.0", "one");
        let mut store = MemoryStore::new(application_release.clone());
        let mut tower = FakeTower::default();
        let mut revised = reconciler_release();
        revised.release = release("2.0.0", "reconciler-two");
        revised.archive_sha256 = "reconciler-archive-two".into();

        let outcome = apply_update(
            &mut tower,
            &mut store,
            &application_release,
            "previous-archive",
            test_lineage(),
            revised.clone(),
        )
        .await
        .unwrap();

        assert!(matches!(outcome, Outcome::Committed));
        let Installed::Present(installed) = store.installed else {
            panic!("the reconciler revision must commit installed state");
        };
        assert_eq!(installed.release, application_release);
        assert_eq!(installed.lifecycle.as_ref(), &revised);
        let pending = installed
            .pending
            .expect("the reconciler revision must retain rollback intent");
        assert_ne!(pending.lifecycle.as_ref(), &revised);
    }

    #[test]
    fn chaos_catalog_is_unique_and_covers_every_supervised_durable_phase() {
        use std::collections::HashSet;

        let catalog: Vec<&str> = BOUNDARIES
            .iter()
            .chain(ROLLBACK_BOUNDARIES)
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
        ] {
            assert!(catalog.contains(&boundary::durable_phase(phase)));
        }
    }
}
