use super::*;

pub(crate) enum Outcome {
    Committed,
    /// A candidate failed *after* activation: it is rejected and the durable rollback journal is
    /// left in place, but the actual rollback is performed by the one rollback implementation — the
    /// boot state machine — after this disposable agent terminates and the launcher relaunches
    /// it. There is no in-process rollback path.
    RollbackPending,
}

/// Crashes at a configured transaction boundary, for the e2e's crash-recovery scenarios.
/// Compiled in only under the `chaos` feature (which the e2e enables); a production build
/// has no injection points, so a stray `UPDATED_CHAOS_POINT` can never crash it. One-shot:
/// after it fires it drops a sentinel, so the relaunched agent recovers instead of
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
            point: std::env::var(updated::env::CHAOS_POINT).ok(),
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
        eprintln!("agent: CHAOS: exiting at boundary {phase:?}");
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
    pub const ACTIVATE_STARTED: &str = "activate-started";
    pub const CANDIDATE_POINTER_APPLIED: &str = "candidate-pointer-applied";
    pub const CANDIDATE_LIFECYCLE_APPLIED: &str = "candidate-lifecycle-applied";
    pub const CANDIDATE_ACTIVATED: &str = "candidate-activated";
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
    pub const ROLLBACK_ACTIVATE_STARTED: &str = "rollback-activate-started";
    pub const PREDECESSOR_POINTER_APPLIED: &str = "predecessor-pointer-applied";
    pub const PREDECESSOR_LIFECYCLE_APPLIED: &str = "predecessor-lifecycle-applied";
    pub const PREDECESSOR_ACTIVATED: &str = "predecessor-activated";
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
            TransactionPhase::ActivateStarted => ACTIVATE_STARTED,
            TransactionPhase::CandidateActivated => CANDIDATE_ACTIVATED,
            TransactionPhase::HealthStarted => HEALTH_STARTED,
            TransactionPhase::CandidateHealthy => CANDIDATE_HEALTHY,
            TransactionPhase::FinalizeStarted => FINALIZE_STARTED,
            TransactionPhase::Finalized => FINALIZED,
            TransactionPhase::CommitStarted => COMMIT_STARTED,
            TransactionPhase::Committed => COMMITTED,
            TransactionPhase::RollbackStarted => ROLLBACK_STARTED,
            TransactionPhase::RollbackActivateStarted => ROLLBACK_ACTIVATE_STARTED,
            TransactionPhase::PredecessorActivated => PREDECESSOR_ACTIVATED,
            TransactionPhase::RollbackHealthStarted => ROLLBACK_HEALTH_STARTED,
            TransactionPhase::PredecessorHealthy => PREDECESSOR_HEALTHY,
            TransactionPhase::RollbackFinalizeStarted => ROLLBACK_FINALIZE_STARTED,
            TransactionPhase::RolledBack => ROLLED_BACK,
        }
    }
}

/// The ordered boundary list, emitted by `agent --list-chaos-boundaries` so the e2e
/// drives exactly these — one source of truth across the crate boundary (the e2e runs the
/// agent as a subprocess and cannot share a `const`).
#[cfg(any(feature = "chaos", test))]
pub(crate) const BOUNDARIES: &[&str] = &[
    boundary::PREFLIGHT_STARTED,
    boundary::PREFLIGHT_APPLIED,
    boundary::PREFLIGHT_COMPLETED,
    boundary::PREPARE_STARTED,
    boundary::PREPARE_APPLIED,
    boundary::PREPARED,
    boundary::ACTIVATE_STARTED,
    boundary::CANDIDATE_POINTER_APPLIED,
    boundary::CANDIDATE_LIFECYCLE_APPLIED,
    boundary::CANDIDATE_ACTIVATED,
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
    boundary::ROLLBACK_ACTIVATE_STARTED,
    boundary::PREDECESSOR_POINTER_APPLIED,
    boundary::PREDECESSOR_LIFECYCLE_APPLIED,
    boundary::PREDECESSOR_ACTIVATED,
    boundary::ROLLBACK_HEALTH_STARTED,
    boundary::PREDECESSOR_HEALTH_APPLIED,
    boundary::PREDECESSOR_HEALTHY,
    boundary::ROLLBACK_FINALIZE_STARTED,
    boundary::ROLLBACK_ADAPTER_APPLIED,
    boundary::ROLLED_BACK,
];

// ============================== the reconciler port ==============================
//
// What the transaction drives on the *live* side — the release's own reconciler hooks — behind a
// port, exactly as [`Store`] ports the durable side. The production [`ReleaseReconciler`] invokes
// the signed node reconciler that travels with the install; a test fake scripts operation outcomes
// and health, so every fault path of [`apply_update`] is provable without a subprocess.

/// Invoke the release's own reconciler — the single seam through which anything on this node
/// changes. The port the transaction drives.
///
/// A post-activation failure does not roll back in-process: the transaction rejects the candidate,
/// leaves a durable rollback journal, and the agent terminates so boot recovery performs the one
/// rollback path.
pub(crate) trait Reconciler {
    /// Invoke one operation of the release's signed node reconciler under `lifecycle_attempt_id`.
    fn invoke(
        &mut self,
        operation: Operation,
        lifecycle_attempt_id: &str,
        candidate: &updated::bundle::ReleaseId,
        predecessor: &updated::bundle::ReleaseId,
    ) -> io::Result<()>;
    /// Agent-owned retry policy for the reconciler's single-observation `healthcheck` operation.
    fn verification_policy(&self) -> (Duration, u32, Duration);
}

/// The production port: the signed node reconciler that travels with the install, invoked with
/// this agent's configured bounds.
pub(crate) struct ReleaseReconciler<'a> {
    opts: &'a Options,
    lifecycle: &'a updated::state::ProviderRelease,
    /// The `--reason` every probe this port makes carries. It is a property of the boot or the
    /// transaction the port serves, not of an individual probe, so it is fixed at construction:
    /// a boot gate observes the same kind of event the boot converge just performed.
    reason: Reason,
}

impl<'a> ReleaseReconciler<'a> {
    pub(crate) fn new(
        opts: &'a Options,
        lifecycle: &'a updated::state::ProviderRelease,
        reason: Reason,
    ) -> ReleaseReconciler<'a> {
        ReleaseReconciler {
            opts,
            lifecycle,
            reason,
        }
    }
}

impl Reconciler for ReleaseReconciler<'_> {
    fn invoke(
        &mut self,
        operation: Operation,
        lifecycle_attempt_id: &str,
        candidate: &updated::bundle::ReleaseId,
        predecessor: &updated::bundle::ReleaseId,
    ) -> io::Result<()> {
        run_lifecycle_command(
            self.lifecycle,
            self.opts,
            LifecycleInvocation {
                phase: operation,
                reason: self.reason,
                id: lifecycle_attempt_id,
                candidate,
                predecessor,
            },
        )
    }
    fn verification_policy(&self) -> (Duration, u32, Duration) {
        (
            self.opts.timeouts.health_grace,
            self.opts.timeouts.health_successes,
            self.opts.timeouts.health_interval,
        )
    }
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

/// THE environment converge: run the committed release's `apply` outside a release transaction,
/// so the reconciler sees the runtime the assignment names *now* — its resolved `inputs` above
/// all, which reach the reconciler only through `--input-file`.
///
/// Release placement already happened durably — in the install machine on a first boot, in the
/// update transaction on an upgrade — so this never places; it only asks the release's own
/// reconciler to converge the machine onto what is committed. The reconciler owns every workload
/// process, so this is also the only thing that starts, reloads, or restarts one: `--reason`
/// (`install`/`restart`) is what lets one script tell a first boot from a re-converge.
///
/// Fail-closed: the error propagates. Nothing is committed here, so a retry is the next boot or
/// the next reconcile of the same assignment.
pub(crate) fn converge_environment(
    opts: &Options,
    store: &dyn Store,
    reason: Reason,
) -> io::Result<()> {
    let updated::state::Installed::Present(installed) = store.installed() else {
        return Ok(());
    };
    let installed = *installed;
    let release = installed.release;
    let lifecycle = installed.lifecycle;
    run_lifecycle_command(
        lifecycle.as_ref(),
        opts,
        LifecycleInvocation {
            phase: Operation::Apply,
            reason,
            id: attempt::BOOT,
            candidate: &release,
            predecessor: &release,
        },
    )
}

/// Progress toward readiness: a run of `need` consecutive healthy probes, any failure resetting
/// the run. Pure — the async gate feeds it probe outcomes — so the consecutive-successes rule is
/// provable without invoking anything.
pub(crate) struct Readiness {
    need: u32,
    consecutive: u32,
}

impl Readiness {
    pub(crate) fn new(successes: u32) -> Self {
        Readiness {
            need: successes.max(1),
            consecutive: 0,
        }
    }

    /// Fold in one probe outcome; `true` once enough consecutive successes are seen.
    pub(crate) fn observe(&mut self, healthy: bool) -> bool {
        if healthy {
            self.consecutive += 1;
            self.consecutive >= self.need
        } else {
            self.consecutive = 0;
            false
        }
    }
}

/// THE readiness gate. Every readiness decision in this agent — the boot gate, a
/// candidate's transaction gate, a crash-recovered rollback's gate — is this one function, and
/// it can only ever ask the signed reconciler for [`Operation::Healthcheck`]: the operation is
/// not a parameter, so no caller can gate readiness on anything else.
///
/// It repeatedly invokes that one observation until the reconciler supplies the configured
/// consecutive-success evidence or the agent-owned deadline expires. The reconciler performs one
/// application-specific observation; the agent owns cadence, bounds, cancellation, and policy.
///
/// `lifecycle_attempt_id` is the transaction's own token whenever the gate is a step of a
/// transaction — the forward candidate's gate and a crash-recovered rollback's predecessor gate
/// alike — so the reconciler may rely on effects written by earlier operations of that exact
/// attempt. It is [`attempt::BOOT`] only for a gate that belongs to no transaction, which observes
/// durable steady state and never impersonates an attempt whose effects no longer exist.
pub(crate) async fn became_healthy<T: Reconciler>(
    reconciler: &mut T,
    lifecycle_attempt_id: &str,
    candidate: &updated::bundle::ReleaseId,
    predecessor: &updated::bundle::ReleaseId,
) -> Health {
    let (grace, successes, interval) = reconciler.verification_policy();
    let deadline = Instant::now() + grace;
    let mut readiness = Readiness::new(successes);
    let mut next = Instant::now();
    // The verdict is the state of the LAST probe, not a latch over the whole grace. The first probe
    // after an `apply` normally answers "not ready" while the workload is still starting, so a
    // latch saying "the reconciler answered at least once" would be set within ~100ms of every
    // switch-over and could never be unset — a state volume that fills at t=2s would then still be
    // reported as an unhealthy CANDIDATE and earn that release a permanent rejection. Whether the
    // probes could still reach the reconciler when the deadline arrived is the question that
    // actually distinguishes the two faults, so `unreached` is cleared by any answer and set by any
    // failure in front of the reconciler.
    let mut unreached: Option<io::Error> = None;
    while Instant::now() < deadline {
        if Instant::now() >= next {
            let ok = match reconciler.invoke(
                Operation::Healthcheck,
                lifecycle_attempt_id,
                candidate,
                predecessor,
            ) {
                Ok(()) => {
                    unreached = None;
                    true
                }
                Err(error) if reconciler_answered(&error) => {
                    unreached = None;
                    false
                }
                // The probe never reached the reconciler. It still counts as a failed observation
                // for cadence — readiness is consecutive evidence — but it is not a verdict.
                Err(error) => {
                    unreached = Some(error);
                    false
                }
            };
            if readiness.observe(ok) {
                return Health::Ready;
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
    match unreached {
        Some(error) => Health::Inconclusive(error),
        None => Health::Unhealthy,
    }
}

/// The verdict of a readiness gate.
///
/// The gate can only speak about the CANDIDATE when the reconciler actually ran and answered.
/// Preparing an invocation touches the node — it re-resolves (and re-hashes) the staged provider
/// bundle, creates the provider state directory, and writes the invocation's inputs — so a corrupt
/// or partially pruned provider tree, ENOSPC, EACCES or a read-only remount fails the probe before
/// the reconciler exists. That is evidence about this disk, not about the release, and answering it
/// with a durable, never-expiring rejection would strand the node a version behind the fleet over a
/// fault that says nothing about the candidate's bytes. Same split as `verify_release` vs.
/// `point_active`, and `LauncherError::Refused` vs. `Channel`.
pub(crate) enum Health {
    Ready,
    /// The grace expired with the reconciler still answering, and its last answer was not ready (a
    /// non-zero exit, or it wedged past its own timeout).
    Unhealthy,
    /// No verdict: when the grace expired the probes were no longer reaching the reconciler at all.
    /// Carries that failure for the log.
    Inconclusive(io::Error),
}

/// Whether a failed lifecycle invocation is the reconciler's own answer rather than a node-local
/// fault in front of it. The reconciler's answers are its non-zero exit ([`io::Error::other`]) and
/// its timeout; everything else — a bundle that will not resolve, a directory that cannot be
/// created, inputs that cannot be written, a program that will not spawn — happened before it ran.
fn reconciler_answered(error: &io::Error) -> bool {
    matches!(error.kind(), io::ErrorKind::Other | io::ErrorKind::TimedOut)
}

// ================================ the transaction ================================

/// Drive one application update through the durable transaction, over the [`Store`] and
/// [`Reconciler`] ports.
pub(crate) async fn apply_update<T: Reconciler>(
    reconciler: &mut T,
    store: &mut dyn Store,
    candidate: &updated::bundle::ReleaseId,
    candidate_archive_sha256: &str,
    candidate_repository_lineage: updated::state::RepositoryLineage,
    lifecycle: updated::state::ProviderRelease,
) -> io::Result<Outcome> {
    // Recovery belongs to the boot state machine. A live agent must never mutate recovery
    // evidence or move the active pointer outside a transaction. Any transaction error terminates
    // this disposable agent; the launcher relaunches it through the one recovery path.
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
                "an unreconciled update journal requires an agent restart",
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
        // runs the candidate through the `reconciler` port, never these fields; the candidate's
        // providers become the new head's at commit below. This keeps the journal-driven recovery
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

    // Everything up to here is side-effect free on the live node: the candidate is staged, nothing
    // is pointed at it, and a failure defers cleanly as `Err`. Past this line the pointer moves and
    // the release's `apply` runs, so no failure may surface as `Err` — that maps to
    // `AppOutcome::Fatal`, which abandons the update and ends the process with the node
    // half-switched until the launcher's backoff relaunches this agent. Recovering in place is
    // strictly better, so `switch_over` returns [`Outcome`] rather than `io::Result<Outcome>` — a
    // type error instead of a rule every future call site has to remember.
    Ok(switch_over(reconciler, store, tx, lifecycle).await)
}

/// The committing half of an update: the pointer moves and the candidate's `apply` runs, so every
/// failure from here on is answered by restarting into boot recovery, which resumes from the
/// journal's last durable phase (always a valid checkpoint). The infallible return type is the
/// enforcement: there is no way to propagate an error out of the switchover.
async fn switch_over<T: Reconciler>(
    reconciler: &mut T,
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
                        "{} failed after the switchover began ({error}); restarting for boot \
                         recovery",
                        $what
                    ));
                    return Outcome::RollbackPending;
                }
            }
        };
    }
    recover_on_error!(
        "recording the activation checkpoint",
        advance_transaction(store, &mut tx, TransactionPhase::ActivateStarted)
    );
    // Split the activation into its three failure classes. A re-verification failure means the
    // candidate's on-disk bytes are corrupt — genuinely its fault — so reject, as does an `apply`
    // that ran and failed. A pointer-write failure is pure infrastructure (ENOSPC, transient I/O),
    // never the candidate's fault: restart for boot recovery WITHOUT rejecting, so the healthy
    // release is retried instead of stranded a version behind.
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

    // The candidate's own `apply`: the release converges the machine onto itself — starting,
    // reloading or restarting whatever it owns. This agent touches no workload process, here or
    // anywhere.
    if let Err(e) = reconciler.invoke(Operation::Apply, &tx.id, &candidate, &tx.previous_release) {
        warn(&format!("activating the new version failed ({e})"));
        return reject_then_recover(store, &mut tx);
    }
    chaos.crossing(boundary::CANDIDATE_LIFECYCLE_APPLIED);
    recover_on_error!(
        "recording the activated checkpoint",
        advance_transaction(store, &mut tx, TransactionPhase::CandidateActivated)
    );

    recover_on_error!(
        "recording the health checkpoint",
        advance_transaction(store, &mut tx, TransactionPhase::HealthStarted)
    );
    match became_healthy(reconciler, &tx.id, &candidate, &tx.previous_release).await {
        Health::Ready => {}
        Health::Unhealthy => return reject_then_recover(store, &mut tx),
        // The gate never reached the reconciler, so it observed nothing about the candidate.
        // Restart for boot recovery *without* recording a rejection — the same fail-safe class as
        // the pointer-write case above — so the healthy release is retried once the node's own
        // fault clears, rather than excluded from this node forever.
        Health::Inconclusive(e) => {
            warn(&format!(
                "the readiness gate could not reach the node reconciler ({e}); restarting for boot recovery"
            ));
            return Outcome::RollbackPending;
        }
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
/// rollback implementation. Every post-activation failure ends here: the candidate is pointed at
/// and its `apply` has run, so this records the rejection and leaves the durable journal for boot
/// recovery to complete on the next agent start. An agent restart is cheap — it touches no workload
/// — and the freshly-booted agent restores the predecessor with the predecessor's *own* providers
/// (carried in the transaction). Rolling back here in-process would be a second rollback path to
/// keep in lockstep with boot recovery — and, because a live agent holds the candidate's
/// reconciler, it would compensate the restored predecessor with the *candidate's* hooks. One path,
/// one set of providers, no divergence.
///
/// Recording the rejection is itself a durable write and can fail (ENOSPC, a read-only remount).
/// That failure must not escape: this runs mid-switchover, where an error would hold the process
/// alive with the node half-converged. Boot recovery still restores the predecessor from the
/// journal — it only loses the rejection, which costs one more futile attempt at the same
/// candidate, not the node.
fn reject_then_recover(store: &mut dyn Store, tx: &mut Transaction) -> Outcome {
    if let Err(error) = require_candidate_rejection(store, tx) {
        warn(&format!(
            "recording the failed candidate's rejection mid-switchover ({error}); restarting for \
             boot recovery"
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
    pub(crate) reason: Reason,
    pub(crate) id: &'a str,
    pub(crate) candidate: &'a updated::bundle::ReleaseId,
    pub(crate) predecessor: &'a updated::bundle::ReleaseId,
}

pub(crate) fn run_lifecycle_command(
    lifecycle: &updated::state::ProviderRelease,
    opts: &Options,
    invocation: LifecycleInvocation<'_>,
) -> io::Result<()> {
    run_prepared_lifecycle_command(
        prepare_lifecycle_command(lifecycle, opts, invocation)?,
        None,
    )
    .map(|_| ())
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
    // The flag names come from the published grammar itself, positionally paired with their values,
    // so the agent cannot emit a flag the contract does not name — or stop emitting one a hook still
    // reads — without this failing to compile.
    let values: [&std::ffi::OsStr; updated_contracts::reconciler::FLAGS.len()] = [
        std::ffi::OsStr::new("1"),
        std::ffi::OsStr::new(lifecycle_attempt_id),
        std::ffi::OsStr::new(reason.as_str()),
        opts.paths.install_root.as_os_str(),
        state_dir.as_os_str(),
        candidate_dir.as_os_str(),
        std::ffi::OsStr::new(&candidate.version),
        output_file.as_os_str(),
        input_file.as_os_str(),
        predecessor_dir.as_os_str(),
        std::ffi::OsStr::new(&predecessor.version),
    ];
    let mut cmd = reconciler_command(&resolved.program)?;
    cmd.arg(phase_name);
    for (flag, value) in updated_contracts::reconciler::FLAGS.iter().zip(values) {
        cmd.arg(flag).arg(value);
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
    apply_reconciler_environment(&mut cmd, opts.secrets.values());
    // A wrapper commonly waits on vendor CLIs, curl, or mount helpers. Run it as a
    // contained tree (Unix process group / Windows job object) so a timeout takes the
    // whole tree down, not just the shell — leaving the foreground operation orphaned.
    // The platform mechanism lives in `foundation::process`, not inlined here. Linux also ties
    // the hook to this agent attempt — the workload the hook manages is the operator's init
    // system's, or the hook's own, and deliberately has no such coupling.
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

/// The agent-owned ceiling on a single `healthcheck`. The steady-state probe runs inline on the
/// control loop that emits the node's only report, so a wedged hook would spend the node's
/// freshness budget in silence and the healthproxy would drain a node whose workload is fine: the
/// ceiling must stay well inside `updated_contracts::telemetry::REPORT_FRESHNESS`. It is also what
/// makes [`became_healthy`]'s `health_grace` a real bound rather than an advisory one, since a
/// single probe could otherwise outlast the whole grace.
pub(crate) const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(20);

/// The agent's own runtime ceilings over the publisher-configured provider timeout. Exhaustive on
/// purpose: a new operation must state its bound rather than silently inherit "unbounded".
fn lifecycle_timeout(phase: Operation, configured: Duration) -> Duration {
    match phase {
        Operation::Inspect => configured.min(FINGERPRINT_TIMEOUT),
        Operation::Healthcheck => configured.min(HEALTHCHECK_TIMEOUT),
        // Deployment operations run under a transaction, not on the steady-state loop, and are
        // legitimately as slow as the publisher says they are.
        Operation::Apply | Operation::Rollback => configured,
    }
}

/// Run a blocking body without starving the async runtime.
///
/// Operator lifecycle hooks are external programs waited on synchronously, for up to their full
/// configured timeout. On a multi-threaded runtime that would otherwise pin a worker thread for the
/// entire hook — stalling telemetry, health probes, and the launcher channel on the same runtime.
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

/// THE environment every reconciler invocation runs with: a cleared environment, the minimum a
/// script needs to find an interpreter, and the deployment's resolved secret values named by
/// `SecretReference.environment`.
///
/// One chokepoint, so a secret cannot reach a hook by any other route and cannot be missing from
/// one. Values go in the environment and never in argv — argv is world-readable in `ps` on every
/// platform this runs on — and they are applied last so a secret always wins over an ambient name.
fn apply_reconciler_environment(
    command: &mut Command,
    secrets: &std::collections::BTreeMap<String, String>,
) {
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

    for (name, value) in secrets {
        command.env(name, value);
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
        // process group: it exits when the provider exits, but if this disposable agent
        // disappears first it kills only the transaction helper group. Positional parameters
        // preserve arbitrary program paths without interpolating them into shell source.
        const WATCHDOG: &str = r#"
agent=$1
shift
leader=$$
(
    while kill -0 "$agent" 2>/dev/null && kill -0 "$leader" 2>/dev/null; do
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
    fn steady_state_operations_have_agent_owned_runtime_ceilings() {
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
            HEALTHCHECK_TIMEOUT
        );
        assert_eq!(
            lifecycle_timeout(Operation::Healthcheck, Duration::from_secs(5)),
            Duration::from_secs(5)
        );
        // Deployment operations run under a transaction, never on the report loop, so they keep the
        // publisher's own bound.
        assert_eq!(
            lifecycle_timeout(Operation::Apply, Duration::from_secs(86_400)),
            Duration::from_secs(86_400)
        );
    }

    #[test]
    fn a_healthcheck_cannot_stall_the_loop_into_a_health_drain() {
        // The periodic `healthcheck` runs inline on the loop that emits the node's only report, so
        // its ceiling is a health property: a probe near REPORT_FRESHNESS drains a healthy node out
        // of rotation for a reason no reader can see.
        assert!(
            HEALTHCHECK_TIMEOUT * 2 < updated_contracts::telemetry::REPORT_FRESHNESS,
            "a healthcheck ceiling of {HEALTHCHECK_TIMEOUT:?} is not well inside the {:?} freshness \
             window the healthproxy drains on",
            updated_contracts::telemetry::REPORT_FRESHNESS
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

    #[cfg(unix)]
    #[test]
    fn successful_hook_kills_its_undetached_tree_but_not_a_detached_workload() {
        // The published contract, executable: an invocation's tree is torn down when the hook
        // returns — on SUCCESS as much as on timeout — so a workload started inside it is killed by
        // its own successful `apply`, and a hook that wants the workload to belong to the release
        // must move it out of the tree first. Both halves are asserted, because a "fix" that spares
        // the tree on success would let a wrapper's inherited pipes outlive the deadline.
        fn run(script: &str) -> (io::Result<ReconcilerOutput>, PathBuf) {
            let dir = std::env::temp_dir().join(format!(
                "hook-detach-{}-{}",
                std::process::id(),
                updated::rand::token().unwrap()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let pidfile = dir.join("workload.pid");
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", script])
                .env("PIDFILE", &pidfile)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            foundation::process::arrange_parent_death_signal(&mut command);
            let outcome = run_prepared_lifecycle_command(
                PreparedLifecycleCommand {
                    command,
                    phase: Operation::Apply,
                    timeout: Duration::from_secs(30),
                },
                None,
            );
            (outcome, pidfile)
        }
        fn recorded_pid(pidfile: &std::path::Path) -> u32 {
            std::fs::read_to_string(pidfile)
                .unwrap()
                .trim()
                .parse()
                .unwrap()
        }
        fn alive(pid: u32) -> bool {
            unsafe { libc::kill(pid as i32, 0) == 0 }
        }
        fn settle(pid: u32, want: bool) -> bool {
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                if alive(pid) == want {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            alive(pid) == want
        }

        let (outcome, pidfile) = run("sleep 60 & echo $! > \"$PIDFILE\"; exit 0");
        outcome.expect("the hook succeeded");
        let undetached = recorded_pid(&pidfile);
        assert!(
            settle(undetached, false),
            "a workload left inside the invocation's tree must not survive the hook's return"
        );

        // The other half needs a shell-reachable way to leave the session. Where there is none
        // (macOS ships no `setsid`), the undetached half above is the whole assertion this platform
        // can make; the reference hook's own `detach()` covers it in the e2e.
        if !Command::new("sh")
            .args(["-c", "command -v setsid"])
            .stdout(std::process::Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
        {
            return;
        }
        let (outcome, pidfile) = run(
            "setsid sh -c 'echo $$ > \"$PIDFILE\"; exec sleep 60' </dev/null >/dev/null 2>&1 &\n\
             while [ ! -s \"$PIDFILE\" ]; do sleep 0.05; done; exit 0",
        );
        outcome.expect("the hook succeeded");
        let detached = recorded_pid(&pidfile);
        std::thread::sleep(Duration::from_millis(300));
        let survived = alive(detached);
        unsafe { libc::kill(detached as i32, libc::SIGKILL) };
        assert!(
            survived,
            "a workload the hook detached belongs to the release and must outlive the invocation"
        );
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

    /// A store holding `previous` as the confirmed installed release, which is what every
    /// transaction test starts from.
    fn store_with(previous: updated::bundle::ReleaseId) -> MemStore {
        MemStore {
            installed: Some(InstalledState::confirmed(
                test_lineage(),
                previous.clone(),
                "previous-archive".into(),
                Box::new(reconciler_release()),
            )),
            active: Some(previous),
            ..MemStore::default()
        }
    }

    fn test_lineage() -> updated::state::RepositoryLineage {
        updated::state::RepositoryLineage::from_metadata_url("https://repo/metadata/")
    }

    /// A scripted stand-in for the release's reconciler: it records every invocation and can be
    /// made to fail any operation, so each fault path of [`apply_update`] is provable without a
    /// subprocess.
    #[derive(Default)]
    struct FakeReconciler {
        /// Every invocation, as the operation's wire spelling and its attempt id — the two halves
        /// of the argv contract a gate is required to honour.
        invocations: Vec<(&'static str, String)>,
        fail_first_healthcheck: bool,
        /// Fail EVERY healthcheck with this kind — a node-local fault in front of the reconciler
        /// (`StorageFull`, `InvalidData`) as opposed to the reconciler's own answer (`Other`).
        healthcheck_failure: Option<io::ErrorKind>,
        /// The 1-based probe at which `healthcheck_failure` starts (0 and 1 both mean the first),
        /// so a fault can be made to arrive PART WAY THROUGH a grace period.
        healthcheck_failure_from: usize,
        healthcheck_calls: usize,
        fail_first_apply: bool,
        applies: usize,
    }

    impl FakeReconciler {
        fn operations(&self) -> Vec<&str> {
            self.invocations
                .iter()
                .map(|(operation, _)| *operation)
                .collect()
        }
    }

    impl Reconciler for FakeReconciler {
        fn invoke(
            &mut self,
            operation: Operation,
            lifecycle_attempt_id: &str,
            _: &updated::bundle::ReleaseId,
            _: &updated::bundle::ReleaseId,
        ) -> io::Result<()> {
            self.invocations
                .push((operation.as_str(), lifecycle_attempt_id.to_string()));
            match operation {
                Operation::Healthcheck => {
                    self.healthcheck_calls += 1;
                    if let Some(kind) = self.healthcheck_failure {
                        if self.healthcheck_calls >= self.healthcheck_failure_from.max(1) {
                            return Err(io::Error::new(kind, "injected healthcheck failure"));
                        }
                    }
                    if self.fail_first_healthcheck && self.healthcheck_calls == 1 {
                        return Err(io::Error::other("injected healthcheck failure"));
                    }
                }
                Operation::Apply => {
                    self.applies += 1;
                    if self.fail_first_apply && self.applies == 1 {
                        return Err(io::Error::other("injected apply failure"));
                    }
                }
                Operation::Rollback | Operation::Inspect => {}
            }
            Ok(())
        }
        fn verification_policy(&self) -> (Duration, u32, Duration) {
            (Duration::from_secs(1), 1, Duration::ZERO)
        }
    }

    #[test]
    fn readiness_needs_consecutive_successes_and_a_failure_resets_the_run() {
        let mut r = Readiness::new(3);
        assert!(!r.observe(true)); // 1
        assert!(!r.observe(true)); // 2
        assert!(!r.observe(false), "a failure resets the run");
        assert!(!r.observe(true)); // 1 again
        assert!(!r.observe(true)); // 2
        assert!(r.observe(true), "the third consecutive success is ready");
    }

    #[test]
    fn a_single_required_success_is_ready_at_once() {
        let mut r = Readiness::new(1);
        assert!(!r.observe(false));
        assert!(r.observe(true));
    }

    #[test]
    fn zero_successes_is_treated_as_one() {
        // `successes` is clamped to at least 1 so a misconfig never declares readiness on
        // no evidence.
        let mut r = Readiness::new(0);
        assert!(r.observe(true));
    }

    /// The readiness gate is the reconciler's `healthcheck` operation — by that exact published
    /// spelling — under the reserved `boot` attempt identity. A reconciler answers argv, so a gate
    /// that asked for any other operation name would silently fall through the reconciler's
    /// dispatch and gate nothing.
    #[tokio::test]
    async fn the_boot_gate_is_the_published_healthcheck_operation() {
        let release = release("22.0.0", "current");
        let mut reconciler = FakeReconciler::default();

        assert!(matches!(
            became_healthy(&mut reconciler, attempt::BOOT, &release, &release).await,
            Health::Ready
        ));
        assert_eq!(
            reconciler.invocations,
            [("healthcheck", "boot".to_string())]
        );
        assert_eq!(reconciler.healthcheck_calls, 1);
    }

    /// The same one gate serves a transaction, carrying the transaction's own attempt id so the
    /// reconciler can rely on effects its earlier operations wrote — and still asking for exactly
    /// `healthcheck`.
    #[tokio::test]
    async fn the_transaction_gate_is_the_same_healthcheck_operation_under_the_attempt_id() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = store_with(previous.clone());
        let mut reconciler = FakeReconciler::default();

        let outcome = apply_update(
            &mut reconciler,
            &mut store,
            &candidate,
            "archive-two",
            test_lineage(),
            reconciler_release(),
        )
        .await
        .unwrap();

        assert!(matches!(outcome, Outcome::Committed));
        let gates: Vec<&(&str, String)> = reconciler
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

    /// The whole forward transaction, as the release sees it: exactly one `apply` (the switchover)
    /// and then the healthcheck gate, in that order, under one attempt identity. The agent starts
    /// and stops nothing itself, so an `apply` that is missing, doubled, or ordered after the gate
    /// is a node that never converged onto the candidate it just committed.
    #[tokio::test]
    async fn a_committed_update_is_one_apply_then_the_health_gate() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = store_with(previous);
        let mut reconciler = FakeReconciler::default();

        let outcome = apply_update(
            &mut reconciler,
            &mut store,
            &candidate,
            "archive-two",
            test_lineage(),
            reconciler_release(),
        )
        .await
        .unwrap();

        assert!(matches!(outcome, Outcome::Committed));
        assert_eq!(reconciler.operations(), ["apply", "healthcheck"]);
        assert_eq!(store.active.as_ref(), Some(&candidate));
        let attempts: std::collections::HashSet<&str> = reconciler
            .invocations
            .iter()
            .map(|(_, id)| id.as_str())
            .collect();
        assert_eq!(attempts.len(), 1, "one transaction, one attempt identity");
    }

    #[tokio::test]
    async fn a_transient_healthcheck_failure_is_retried_by_the_agent() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = store_with(previous);
        let mut reconciler = FakeReconciler {
            fail_first_healthcheck: true,
            ..Default::default()
        };

        let outcome = apply_update(
            &mut reconciler,
            &mut store,
            &candidate,
            "archive-two",
            test_lineage(),
            reconciler_release(),
        )
        .await
        .unwrap();

        assert!(matches!(outcome, Outcome::Committed));
        assert_eq!(reconciler.healthcheck_calls, 2);
        assert!(store.rejected.is_empty());
    }

    /// A probe that fails before the reconciler runs — a corrupt provider tree, ENOSPC writing the
    /// invocation's inputs — observed nothing about the candidate, so the gate is INCONCLUSIVE. A
    /// reconciler that ran and answered badly is unhealthy. The two must not collapse together:
    /// only the second is evidence about the release.
    #[tokio::test]
    async fn a_gate_that_never_reaches_the_reconciler_is_inconclusive_not_unhealthy() {
        let candidate = release("2.0.0", "two");

        let mut unreachable = FakeReconciler {
            healthcheck_failure: Some(io::ErrorKind::StorageFull),
            ..Default::default()
        };
        assert!(matches!(
            became_healthy(&mut unreachable, attempt::BOOT, &candidate, &candidate).await,
            Health::Inconclusive(_)
        ));

        let mut answered = FakeReconciler {
            healthcheck_failure: Some(io::ErrorKind::Other),
            ..Default::default()
        };
        assert!(matches!(
            became_healthy(&mut answered, attempt::BOOT, &candidate, &candidate).await,
            Health::Unhealthy
        ));
    }

    /// The verdict follows the LAST probe, not "did the reconciler ever answer". After a
    /// switch-over the first probe almost always answers "not ready" (the application is still
    /// starting), so a latch on that first answer would make every later node-local fault look like
    /// an unhealthy candidate. A disk that fills part way through the grace must still be
    /// inconclusive.
    #[tokio::test]
    async fn a_fault_arriving_after_the_first_answer_is_still_inconclusive() {
        let candidate = release("2.0.0", "two");
        let mut reconciler = FakeReconciler {
            // Probe 1 reaches the reconciler and it answers "not ready"; from probe 2 on, the state
            // volume is full and no probe reaches it again.
            fail_first_healthcheck: true,
            healthcheck_failure: Some(io::ErrorKind::StorageFull),
            healthcheck_failure_from: 2,
            ..Default::default()
        };

        assert!(
            matches!(
                became_healthy(&mut reconciler, attempt::BOOT, &candidate, &candidate).await,
                Health::Inconclusive(_)
            ),
            "one early answer must not latch the gate into judging the release"
        );
        assert!(reconciler.healthcheck_calls > 1, "the grace kept probing");
    }

    /// The harshest consequence in the system — a durable, never-expiring rejection — must never be
    /// spent on a node-local fault. A gate that could not reach the reconciler restarts for boot
    /// recovery with the candidate's bytes still installable, so the node converges forward again
    /// once its disk is repaired instead of being stranded a release behind the fleet.
    #[tokio::test]
    async fn a_gate_that_never_reaches_the_reconciler_rolls_back_without_rejecting() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = store_with(previous);
        let mut reconciler = FakeReconciler {
            healthcheck_failure: Some(io::ErrorKind::StorageFull),
            ..Default::default()
        };

        let outcome = apply_update(
            &mut reconciler,
            &mut store,
            &candidate,
            "archive-two",
            test_lineage(),
            reconciler_release(),
        )
        .await
        .expect("an unreachable reconciler restarts for recovery rather than failing fatally");

        assert!(matches!(outcome, Outcome::RollbackPending));
        assert!(
            store.rejected.is_empty(),
            "a node-local fault is not evidence about the candidate's bytes"
        );
        assert!(
            store.journal.is_some(),
            "boot recovery needs the rollback intent"
        );
    }

    #[tokio::test]
    async fn a_failed_activation_records_the_rejection_before_deferring_to_recovery() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = store_with(previous);
        let mut reconciler = FakeReconciler {
            fail_first_apply: true,
            ..Default::default()
        };

        let outcome = apply_update(
            &mut reconciler,
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
        assert_eq!(
            store.rejected,
            std::collections::HashSet::from([test_lineage().rejection_key("archive-two")])
        );
        assert_eq!(
            reconciler.operations(),
            ["apply"],
            "a failed apply is never followed by a health gate on the candidate"
        );
        assert!(
            store
                .journal
                .as_ref()
                .is_some_and(|tx| tx.candidate_rejection_required),
            "rollback evidence must retain the rejection decision"
        );
    }

    #[tokio::test]
    async fn an_unwritable_rejection_mid_switchover_still_restarts_for_recovery() {
        // The state directory goes unwritable exactly when the failed candidate's rejection is
        // recorded. The pointer has already moved, so an `Err` here would map to
        // `AppOutcome::Fatal` and abandon the half-switched update instead of recovering in place —
        // the one outcome the switching half must be incapable of producing.
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = store_with(previous.clone());
        store.fail_reject = true;
        let mut reconciler = FakeReconciler {
            fail_first_apply: true,
            ..Default::default()
        };

        let outcome = apply_update(
            &mut reconciler,
            &mut store,
            &candidate,
            "archive-two",
            test_lineage(),
            reconciler_release(),
        )
        .await
        .expect("a failed durable write mid-switchover restarts rather than holding the node down");

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
        let mut store = store_with(application_release.clone());
        let mut reconciler = FakeReconciler::default();
        let mut revised = reconciler_release();
        revised.release = release("2.0.0", "reconciler-two");
        revised.archive_sha256 = "reconciler-archive-two".into();

        let outcome = apply_update(
            &mut reconciler,
            &mut store,
            &application_release,
            "previous-archive",
            test_lineage(),
            revised.clone(),
        )
        .await
        .unwrap();

        assert!(matches!(outcome, Outcome::Committed));
        let Some(installed) = store.installed else {
            panic!("the reconciler revision must commit installed state");
        };
        assert_eq!(installed.release, application_release);
        assert_eq!(installed.lifecycle.as_ref(), &revised);
        let pending = installed
            .pending
            .expect("the reconciler revision must retain rollback intent");
        assert_ne!(pending.lifecycle.as_ref(), &revised);
    }

    /// The one route a secret takes to the release: the environment of a reconciler invocation,
    /// applied at the single chokepoint every hook goes through. Two properties matter and both are
    /// asserted here — the values ARRIVE (a hook that cannot see them converges the machine onto
    /// credentials it does not have), and they arrive in the ENVIRONMENT rather than argv, which is
    /// world-readable in `ps` on every platform this runs on.
    #[test]
    fn secret_values_reach_a_reconciler_invocation_by_environment_and_never_by_argv() {
        let secrets = std::collections::BTreeMap::from([
            ("DATABASE_PASSWORD".to_string(), "assigned".to_string()),
            ("API_TOKEN".to_string(), "token".to_string()),
        ]);
        let mut command = Command::new("/bin/true");
        command.env_clear();
        // An ambient name a hook might otherwise pick up; the assignment's value must win.
        command.env("DATABASE_PASSWORD", "ambient");
        apply_reconciler_environment(&mut command, &secrets);

        let environment: std::collections::BTreeMap<String, String> = command
            .get_envs()
            .filter_map(|(name, value)| {
                Some((name.to_str()?.to_string(), value?.to_str()?.to_string()))
            })
            .collect();
        assert_eq!(
            environment.get("DATABASE_PASSWORD").map(String::as_str),
            Some("assigned"),
            "an assigned secret outranks an ambient variable of the same name"
        );
        assert_eq!(
            environment.get("API_TOKEN").map(String::as_str),
            Some("token")
        );
        assert!(
            command.get_args().next().is_none(),
            "the chokepoint contributes no arguments, so no secret can land in argv"
        );

        // And the chokepoint is the only one: the invocation builder hands the manager's values to
        // exactly this function and reads them nowhere else, so there is no second route for a
        // secret to reach a hook — or to be missing from one.
        // Spelled in halves so these assertions do not count themselves.
        let source = include_str!("update.rs");
        assert_eq!(
            source.matches(concat!("secrets", ".values()")).count(),
            1,
            "resolved secret values have exactly one reader"
        );
        assert!(source.contains(concat!(
            "apply_reconciler_environment(&mut cmd, opts.secrets.",
            "values());"
        )));
    }

    #[test]
    fn the_chokepoint_sets_exactly_the_names_a_secret_may_never_claim() {
        // Secret values are applied last so a deployment's own value wins over an ambient one,
        // which means every ambient name this chokepoint sets is shadowable — unless the contract
        // refuses to let an assignment claim it. Coupling the two here is what stops a future
        // ambient variable from being added on one side only.
        let mut command = Command::new("hook");
        apply_reconciler_environment(&mut command, &std::collections::BTreeMap::new());
        let mut set: Vec<String> = command
            .get_envs()
            .filter_map(|(name, _)| Some(name.to_str()?.to_uppercase()))
            .collect();
        set.sort();
        set.dedup();
        let mut expected: Vec<String> =
            updated_contracts::assignment::RECONCILER_AMBIENT_ENVIRONMENT
                .iter()
                .map(|name| (*name).to_owned())
                .collect();
        // TEMP/TMP are forwarded only when this machine has them; the contract blocks them either
        // way, so the chokepoint's set is a subset of the reserved one and never exceeds it.
        expected.sort();
        for name in &set {
            assert!(
                expected.contains(name),
                "{name} is set on every hook but no assignment is stopped from shadowing it"
            );
        }
        assert!(set.contains(&"PATH".to_owned()));
    }

    #[test]
    fn chaos_catalog_is_unique_and_covers_every_durable_phase() {
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
            TransactionPhase::ActivateStarted,
            TransactionPhase::CandidateActivated,
            TransactionPhase::HealthStarted,
            TransactionPhase::CandidateHealthy,
            TransactionPhase::FinalizeStarted,
            TransactionPhase::Finalized,
            TransactionPhase::CommitStarted,
            TransactionPhase::Committed,
            TransactionPhase::RollbackStarted,
            TransactionPhase::RollbackActivateStarted,
            TransactionPhase::PredecessorActivated,
            TransactionPhase::RollbackHealthStarted,
            TransactionPhase::PredecessorHealthy,
            TransactionPhase::RollbackFinalizeStarted,
            TransactionPhase::RolledBack,
        ] {
            assert!(catalog.contains(&boundary::durable_phase(phase)));
        }
    }
}
