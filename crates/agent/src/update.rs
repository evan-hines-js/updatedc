use super::*;

pub(crate) enum Outcome {
    Committed {
        host_action: updated_contracts::reconciler::HostAction,
    },
    /// A candidate failed *after* activation: it is rejected and the durable rollback journal is
    /// left in place, but the actual rollback is performed by the one rollback implementation — the
    /// boot state machine — after this disposable agent terminates and the platform service restarts
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
            sentinel: std::env::var(updated::env::STATE_DIR)
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
/// in [`execute_update`] and the `BOUNDARIES` list the e2e enumerates both reference these,
/// so the two cannot drift — a crossing and its list entry are the *same* string.
pub(crate) mod boundary {
    use crate::domain::TransactionPhase;

    pub const PREPARED: &str = "prepared";
    pub const ACTIVATED: &str = "activated";
    pub const CANDIDATE_POINTER_MOVED: &str = "candidate-pointer-moved";
    pub const CANDIDATE_CONVERGE_FINISHED: &str = "candidate-converge-finished";
    pub const CANDIDATE_HEALTH_PASSED: &str = "candidate-health-passed";
    pub const CONVERGED: &str = "converged";
    pub const VERIFIED: &str = "verified";
    pub const COMMITTED: &str = "committed";
    pub const INSTALLED_STATE_COMMITTED: &str = "installed-state-committed";
    pub const ROLLBACK_PLANNED: &str = "rollback-planned";
    pub const CANDIDATE_COMPENSATED: &str = "candidate-compensated";
    pub const PREDECESSOR_POINTER_MOVED: &str = "predecessor-pointer-moved";
    pub const PREDECESSOR_CONVERGE_FINISHED: &str = "predecessor-converge-finished";
    pub const RESTORED: &str = "restored";
    pub const PREDECESSOR_HEALTH_PASSED: &str = "predecessor-health-passed";
    pub const ROLLBACK_VERIFIED: &str = "rollback-verified";
    pub const CANDIDATE_ROLLBACK_FINISHED: &str = "candidate-rollback-finished";
    pub const ROLLED_BACK: &str = "rolled-back";

    pub fn durable_phase(phase: TransactionPhase) -> &'static str {
        match phase {
            TransactionPhase::Prepared => PREPARED,
            TransactionPhase::Activated => ACTIVATED,
            TransactionPhase::Converged => CONVERGED,
            TransactionPhase::Verified => VERIFIED,
            TransactionPhase::Committed => COMMITTED,
            TransactionPhase::RollbackPlanned => ROLLBACK_PLANNED,
            TransactionPhase::CandidateCompensated => CANDIDATE_COMPENSATED,
            TransactionPhase::Restored => RESTORED,
            TransactionPhase::RollbackVerified => ROLLBACK_VERIFIED,
            TransactionPhase::RolledBack => ROLLED_BACK,
        }
    }
}

/// The ordered boundary list, emitted by `agent --list-chaos-boundaries` so the e2e
/// drives exactly these — one source of truth across the crate boundary (the e2e runs the
/// agent as a subprocess and cannot share a `const`).
#[cfg(any(feature = "chaos", test))]
pub(crate) const BOUNDARIES: &[&str] = &[
    boundary::PREPARED,
    boundary::CANDIDATE_POINTER_MOVED,
    boundary::ACTIVATED,
    boundary::CANDIDATE_CONVERGE_FINISHED,
    boundary::CONVERGED,
    boundary::CANDIDATE_HEALTH_PASSED,
    boundary::VERIFIED,
    boundary::INSTALLED_STATE_COMMITTED,
    boundary::COMMITTED,
];

#[cfg(any(feature = "chaos", test))]
pub(crate) const ROLLBACK_BOUNDARIES: &[&str] = &[
    boundary::ROLLBACK_PLANNED,
    boundary::CANDIDATE_ROLLBACK_FINISHED,
    boundary::CANDIDATE_COMPENSATED,
    boundary::PREDECESSOR_POINTER_MOVED,
    boundary::PREDECESSOR_CONVERGE_FINISHED,
    boundary::RESTORED,
    boundary::PREDECESSOR_HEALTH_PASSED,
    boundary::ROLLBACK_VERIFIED,
    boundary::ROLLED_BACK,
];

// ============================== the reconciler port ==============================
//
// What the transaction drives on the *live* side — the release's own reconciler hooks — behind a
// port, exactly as [`Store`] ports the durable side. The production [`ReleaseReconciler`] invokes
// the signed node reconciler that travels with the install; a test fake scripts operation outcomes
// and health, so every fault path of [`execute_update`] is provable without a subprocess.

/// The only two meanings a reconciler failure can have.
///
/// `ReleaseFault` is evidence about the release: its reconciler returned a non-zero status, wrote
/// an invalid semantic answer, or ran past its signed timeout. `Inconclusive` means the platform
/// has no safe release verdict: resolving the provider, preparing its file exchange,
/// spawning/waiting for the process, or publishing its outputs failed, or the reconciler explicitly
/// requested retries through the bounded attempt budget. Keeping the policy in the type prevents
/// process mechanics or an `io::ErrorKind` chosen by an unrelated primitive from becoming a
/// permanent release rejection.
#[derive(Debug)]
pub(crate) enum InvocationFailure {
    ReleaseFault(io::Error),
    Inconclusive(io::Error),
}

#[derive(Debug)]
struct ContextualIoError {
    context: String,
    source: io::Error,
}

impl std::fmt::Display for ContextualIoError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.context, self.source)
    }
}

impl std::error::Error for ContextualIoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Add the operation and path without erasing the source `io::Error`. The transient-fault
/// classifier walks this chain to retain Windows sharing/lock codes, while the outer message makes
/// a service log identify the exact durable boundary that failed.
fn io_error_with_context(error: io::Error, context: impl Into<String>) -> io::Error {
    io::Error::new(
        error.kind(),
        ContextualIoError {
            context: context.into(),
            source: error,
        },
    )
}

#[derive(Clone, Copy)]
pub(crate) struct ReleaseTarget<'a> {
    pub(crate) release: &'a updated::bundle::ReleaseId,
    pub(crate) archive_sha256: &'a str,
}

impl ReleaseTarget<'_> {
    fn audit_identity(self) -> Result<updated_contracts::reconciler::ReconciledRelease, String> {
        updated_contracts::reconciler::ReconciledRelease::new(
            self.release.version.clone(),
            self.release.manifest_sha256.clone(),
            self.archive_sha256.to_string(),
        )
    }
}

impl InvocationFailure {
    #[cfg(all(test, unix))]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn kind(&self) -> io::ErrorKind {
        match self {
            Self::ReleaseFault(error) | Self::Inconclusive(error) => error.kind(),
        }
    }

    fn into_io_error(self) -> io::Error {
        match self {
            Self::ReleaseFault(error) | Self::Inconclusive(error) => error,
        }
    }
}

fn invalid_reconciliation_context(error: String) -> InvocationFailure {
    InvocationFailure::Inconclusive(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("invalid platform reconciliation context: {error}"),
    ))
}

/// Invoke the release's own reconciler — the single seam through which anything on this node
/// changes. The port the transaction drives.
///
/// A post-activation failure does not roll back in-process: the transaction rejects the candidate,
/// leaves a durable rollback journal, and the agent terminates so boot recovery performs the one
/// rollback path.
pub(crate) trait Reconciler {
    /// Persist recovery prerequisites before the journal authorizes activation.
    fn prepare_update(&mut self, _attempt_id: &str) -> io::Result<()> {
        Ok(())
    }

    fn mutate(
        &mut self,
        operation: MutationOperation,
        attempt_id: &str,
        candidate: ReleaseTarget<'_>,
        predecessor: ReleaseTarget<'_>,
    ) -> Result<updated_contracts::reconciler::SuccessfulMutation, InvocationFailure>;
    fn observe(
        &mut self,
        operation: ObservationOperation,
        timeout: Duration,
        attempt_id: &str,
        candidate: ReleaseTarget<'_>,
        predecessor: ReleaseTarget<'_>,
    ) -> Result<(), InvocationFailure>;
    /// Agent-owned retry policy for the reconciler's single-observation `healthcheck` operation.
    fn verification_policy(&self) -> (Duration, u32, Duration);
}

/// The production port: the signed node reconciler that travels with the install, invoked with
/// this agent's configured bounds.
pub(crate) struct ReleaseReconciler<'a> {
    opts: &'a Options,
    reconciler: &'a updated::state::ReconcilerRelease,
    /// The `--reason` every probe this port makes carries. It is a property of the boot or the
    /// transaction the port serves, not of an individual probe, so it is fixed at construction:
    /// a boot gate observes the same kind of event the boot converge just performed.
    reason: Reason,
}

impl<'a> ReleaseReconciler<'a> {
    pub(crate) fn new(
        opts: &'a Options,
        reconciler: &'a updated::state::ReconcilerRelease,
        reason: Reason,
    ) -> ReleaseReconciler<'a> {
        ReleaseReconciler {
            opts,
            reconciler,
            reason,
        }
    }
}

impl Reconciler for ReleaseReconciler<'_> {
    fn prepare_update(&mut self, attempt_id: &str) -> io::Result<()> {
        if self.opts.runtime_data.selection() != &self.opts.application.input_selection
            || self.opts.runtime_data.inputs() != &self.opts.inputs
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "update inputs are not authenticated",
            ));
        }
        self.opts
            .runtime_data
            .pin(&self.opts.paths.recovery_inputs, attempt_id)
    }

    fn mutate(
        &mut self,
        operation: MutationOperation,
        attempt_id: &str,
        candidate: ReleaseTarget<'_>,
        predecessor: ReleaseTarget<'_>,
    ) -> Result<updated_contracts::reconciler::SuccessfulMutation, InvocationFailure> {
        invoke_reconciler_mutation(
            self.reconciler,
            self.opts,
            operation,
            ReconcilerInvocation {
                reason: self.reason,
                id: attempt_id,
                candidate,
                predecessor,
            },
            None,
        )
    }
    fn observe(
        &mut self,
        operation: ObservationOperation,
        timeout: Duration,
        attempt_id: &str,
        candidate: ReleaseTarget<'_>,
        predecessor: ReleaseTarget<'_>,
    ) -> Result<(), InvocationFailure> {
        invoke_reconciler_observation(
            self.reconciler,
            self.opts,
            operation,
            timeout,
            ReconcilerInvocation {
                reason: self.reason,
                id: attempt_id,
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
    command: PreparedReconcilerCommand,
    definition_sha256: String,
}

impl FingerprintJob {
    pub(crate) fn run(
        self,
        cancelled: &std::sync::atomic::AtomicBool,
    ) -> io::Result<updated_contracts::telemetry::Fingerprint> {
        let output = run_prepared_reconciler_command(self.command, Some(cancelled))
            .map_err(InvocationFailure::into_io_error)?;
        fingerprint_from_output(&self.definition_sha256, output)
    }
}

pub(crate) fn prepare_fingerprint_job(
    release: &updated::state::ReconcilerRelease,
    opts: &Options,
    invocation: ReconcilerInvocation<'_>,
) -> io::Result<FingerprintJob> {
    Ok(FingerprintJob {
        command: prepare_reconciler_command(release, opts, Operation::Inspect, None, invocation)?,
        definition_sha256: release.execution_digest(),
    })
}

fn fingerprint_from_output(
    definition_sha256: &str,
    output: ReconcilerOutput,
) -> io::Result<updated_contracts::telemetry::Fingerprint> {
    let updated::reconciler::InvocationResult::Observation = output.result else {
        unreachable!("fingerprint preparation permits only inspect observations")
    };
    if output.capture.stdout_truncated {
        return Err(io::Error::other(format!(
            "node fingerprint exceeded the {}-byte output limit",
            updated::reconciler::OUTPUT_LIMIT
        )));
    }
    if output.capture.stdout.is_empty() {
        return Err(io::Error::other(
            "node fingerprint produced no measured state on stdout",
        ));
    }
    updated_contracts::telemetry::Fingerprint::from_output(
        definition_sha256,
        &output.capture.stdout,
    )
    .map_err(io::Error::other)
}

/// THE environment converge: run the committed release's `converge` outside a release transaction,
/// so the reconciler sees the runtime the assignment names *now* — its resolved `inputs` above
/// all, which reach the reconciler only through `--input-dir`.
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
    store: &Store,
    reason: Reason,
    attempt_id: &str,
    runtime_ceiling: Option<Duration>,
) -> io::Result<updated_contracts::reconciler::SuccessfulMutation> {
    let updated::state::Installed::Present(installed) = store.installed()? else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a verified installed release is required for convergence",
        ));
    };
    let installed = *installed;
    let release = installed.release;
    let archive_sha256 = installed.archive_sha256;
    let reconciler = installed.reconciler;
    run_reconciler_mutation(
        reconciler.as_ref(),
        opts,
        MutationOperation::Converge,
        ReconcilerInvocation {
            reason,
            id: attempt_id,
            candidate: ReleaseTarget {
                release: &release,
                archive_sha256: &archive_sha256,
            },
            predecessor: ReleaseTarget {
                release: &release,
                archive_sha256: &archive_sha256,
            },
        },
        runtime_ceiling,
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
/// `attempt_id` is the transaction's own token whenever the gate is a step of a
/// transaction — the forward candidate's gate and a crash-recovered rollback's predecessor gate
/// alike — so the reconciler may rely on effects written by earlier operations of that exact
/// attempt. It is [`attempt::BOOT`] only for a gate that belongs to no transaction, which observes
/// durable steady state and never impersonates an attempt whose effects no longer exist.
pub(crate) async fn became_healthy<T: Reconciler>(
    reconciler: &mut T,
    attempt_id: &str,
    candidate: ReleaseTarget<'_>,
    predecessor: ReleaseTarget<'_>,
) -> Health {
    let (grace, successes, interval) = reconciler.verification_policy();
    let deadline = Instant::now() + grace;
    let mut readiness = Readiness::new(successes);
    let mut next = Instant::now();
    // The verdict is the state of the LAST probe, not a latch over the whole grace. The first probe
    // after a `converge` normally answers "not ready" while the workload is still starting, so a
    // latch saying "the reconciler answered at least once" would be set within ~100ms of every
    // switch-over and could never be unset — a state volume that fills at t=2s would then still be
    // reported as an unhealthy CANDIDATE and earn that release a permanent rejection. Whether the
    // probes could still reach the reconciler when the deadline arrived is the question that
    // actually distinguishes the two faults, so the final invocation failure is retained exactly.
    let mut last_probe: Option<Result<(), InvocationFailure>> = None;
    while Instant::now() < deadline {
        if Instant::now() >= next {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            let probe = reconciler.observe(
                ObservationOperation::Healthcheck,
                remaining,
                attempt_id,
                candidate,
                predecessor,
            );
            // Both failure classes reset consecutive readiness. Their distinction matters only if
            // this remains the final probe, so retain the result intact for the gate verdict.
            let ok = probe.is_ok();
            last_probe = Some(probe);
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
    match last_probe {
        Some(Err(InvocationFailure::ReleaseFault(error))) => Health::Unhealthy(error),
        Some(Err(InvocationFailure::Inconclusive(error))) => Health::Inconclusive(error),
        Some(Ok(())) => Health::Unhealthy(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "the readiness grace expired before {successes} consecutive successful healthchecks"
            ),
        )),
        None => Health::Inconclusive(io::Error::new(
            io::ErrorKind::TimedOut,
            "the readiness grace expired before any healthcheck completed",
        )),
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
    Unhealthy(io::Error),
    /// No verdict: when the grace expired the probes were no longer reaching the reconciler at all.
    /// Carries that failure for the log.
    Inconclusive(io::Error),
}

// ================================ the transaction ================================

/// Drive one application update through the durable transaction, over the [`Store`] and
/// [`Reconciler`] ports.
pub(crate) async fn execute_update<T: Reconciler>(
    reconciler: &mut T,
    store: &mut Store,
    candidate: &updated::bundle::ReleaseId,
    candidate_archive_sha256: &str,
    candidate_repository_lineage: updated::state::RepositoryLineage,
    candidate_reconciler: updated::state::ReconcilerRelease,
) -> io::Result<Outcome> {
    // Recovery belongs to the boot state machine. A live agent must never mutate recovery
    // evidence or move the active pointer outside a transaction. Any transaction error terminates
    // this disposable agent; the platform service restarts it through the one recovery path.
    match store.journal()? {
        None => {}
        // A journal that can no longer drive a rollback is SPENT — its transaction already reached
        // its end state and everything durable is written. The only reason one is still here is
        // that the delete after commit failed (a read-only remount, an EIO). Retrying that delete
        // is not recovery: there is nothing left to reconcile, and treating it as fatal instead
        // ends every boot on a transient filesystem error — a relaunch loop that re-derives the
        // same spent journal and gets no further.
        //
        // The question goes to the phase machine (via the recovery driver's own
        // `boot::drives_rollback`) rather than to a list of terminal phases written out here: this
        // is the site that DELETES the journal, and the enumerate-the-phases version of the test is
        // exactly what once let `RolledBack` through.
        Some(journal) if !crate::boot::drives_rollback(&journal) => {
            store.clear_journal()?;
            log("removed a spent update journal left behind by a failed post-commit cleanup");
        }
        Some(_) => {
            return Err(io::Error::other(
                "an unreconciled update journal requires an agent restart",
            ));
        }
    }

    let installed = match store.installed()? {
        Installed::Present(state) => state,
        _ => return Err(io::Error::other("a verified installed release is required")),
    };
    for release in [&candidate_reconciler, installed.reconciler.as_ref()] {
        release.check_supported().map_err(io::Error::other)?;
    }
    let Some(candidate_rejection_sha256) = updated::state::candidate_rejection_sha256(
        &installed.release,
        &installed.archive_sha256,
        candidate,
        candidate_archive_sha256,
    ) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "an update must change the payload or reconciler",
        ));
    };
    let tx = Transaction {
        id: updated::rand::token()?,
        previous_release: installed.release.clone(),
        previous_archive_sha256: installed.archive_sha256.clone(),
        previous_repository_lineage: installed.repository_lineage.clone(),
        candidate_release: candidate.clone(),
        candidate_archive_sha256: candidate_archive_sha256.to_string(),
        candidate_rejection_sha256,
        candidate_repository_lineage: candidate_repository_lineage.clone(),
        candidate_rejection_required: false,
        // These fields drive ROLLBACK recovery (restoring the predecessor), so they carry the
        // PREDECESSOR's own signed providers — app and providers are one signed unit, and a revert
        // must gate/watch the old release with the old hooks, not the candidate's. The forward path
        // runs the candidate through the `reconciler` port, never these fields; the candidate's
        // providers become the new head's at commit below. This keeps the journal-driven recovery
        // (an in-process rollback that crashed) consistent with the pending-driven one, which
        // already carries the predecessor's providers.
        previous_reconciler: installed.reconciler.clone(),
        candidate_reconciler: Box::new(candidate_reconciler),
        rollback_health_failures: 0,
        phase: TransactionPhase::Prepared,
    };
    reconciler.prepare_update(&tx.id)?;
    persist_transaction(store, &tx)?;

    // Everything up to here is side-effect free on the live node: the candidate is staged, nothing
    // is pointed at it, and a failure defers cleanly as `Err`. Past this line the pointer moves and
    // the release's `converge` runs, so no failure may surface as `Err` — that maps to
    // `AppOutcome::Fatal`, which abandons the update and ends the process with the node
    // half-switched until the platform service restarts this agent. Recovering in place is
    // strictly better, so `switch_over` returns [`Outcome`] rather than `io::Result<Outcome>` — a
    // type error instead of a rule every future call site has to remember.
    Ok(switch_over(reconciler, store, tx).await)
}

/// The committing half of an update: the pointer moves and the candidate's `converge` runs, so every
/// failure from here on is answered by restarting into boot recovery, which resumes from the
/// journal's last durable phase (always a valid checkpoint). The infallible return type is the
/// enforcement: there is no way to propagate an error out of the switchover.
async fn switch_over<T: Reconciler>(
    reconciler: &mut T,
    store: &mut Store,
    mut tx: Transaction,
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
    // Activation itself owns verify-before-point. Staging already separated reproducible archive
    // faults from local storage faults before publishing the tree, so neither a later integrity
    // failure nor pointer I/O is evidence that may poison the durable rejection set.
    recover_on_error!(
        "verifying and writing the active-release pointer",
        store.activate(&candidate)
    );
    chaos.crossing(boundary::CANDIDATE_POINTER_MOVED);
    recover_on_error!(
        "recording the completed activation",
        advance_transaction(store, &mut tx, TransactionPhase::Activated)
    );

    // The candidate's own `converge`: the release converges the machine onto itself — starting,
    // reloading or restarting whatever it owns. This agent touches no workload process, here or
    // anywhere.
    let converge_result = match reconciler.mutate(
        MutationOperation::Converge,
        &tx.id,
        ReleaseTarget {
            release: &candidate,
            archive_sha256: &tx.candidate_archive_sha256,
        },
        ReleaseTarget {
            release: &tx.previous_release,
            archive_sha256: &tx.previous_archive_sha256,
        },
    ) {
        Ok(result) => result,
        Err(InvocationFailure::ReleaseFault(error)) => {
            warn(&format!("activating the new version failed ({error})"));
            return reject_then_recover(store, &mut tx);
        }
        Err(InvocationFailure::Inconclusive(error)) => {
            warn(&format!(
                "the candidate's reconciler could not be invoked ({error}); restarting for boot \
                 recovery without rejecting the release"
            ));
            return Outcome::RollbackPending;
        }
    };
    chaos.crossing(boundary::CANDIDATE_CONVERGE_FINISHED);
    recover_on_error!(
        "recording the completed candidate convergence",
        advance_transaction(store, &mut tx, TransactionPhase::Converged)
    );
    if converge_result.host_action() != updated_contracts::reconciler::HostAction::Reboot {
        match became_healthy(
            reconciler,
            &tx.id,
            ReleaseTarget {
                release: &candidate,
                archive_sha256: &tx.candidate_archive_sha256,
            },
            ReleaseTarget {
                release: &tx.previous_release,
                archive_sha256: &tx.previous_archive_sha256,
            },
        )
        .await
        {
            Health::Ready => {}
            Health::Unhealthy(error) => {
                warn(&format!(
                    "the candidate failed its readiness gate ({error})"
                ));
                return reject_then_recover(store, &mut tx);
            }
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
        chaos.crossing(boundary::CANDIDATE_HEALTH_PASSED);
        recover_on_error!(
            "recording the successful candidate health gate",
            advance_transaction(store, &mut tx, TransactionPhase::Verified)
        );
    }

    // Commit atomically WITH the pending rollback intent: the update is unconfirmed until
    // it survives its window. Folding the rollback intent into one write means there is no
    // separate "arm" step to be interrupted — if a crash lands after this, the pending
    // record is already durable; if before, the journal reactivates the predecessor.
    //
    // The predecessor identity comes from the transaction, the same record boot recovery reads, so
    // the pending-driven rollback and the journal-driven one cannot describe different predecessors.
    // Recovery retains the predecessor package's own execution definition.
    let pending = Some(RollbackGuard {
        attempt_id: tx.id.clone(),
        candidate_rejection_sha256: tx.candidate_rejection_sha256.clone(),
        previous_release: tx.previous_release.clone(),
        previous_archive_sha256: tx.previous_archive_sha256.clone(),
        previous_repository_lineage: tx.previous_repository_lineage.clone(),
        committed_at: now_unix(),
        reconciler: tx.previous_reconciler.clone(),
    });
    recover_on_error!(
        "committing the installed release",
        store.commit_installed(&InstalledState {
            repository_lineage: tx.candidate_repository_lineage.clone(),
            release: candidate.clone(),
            archive_sha256: tx.candidate_archive_sha256.clone(),
            // The candidate's own providers are part of the durable transaction identity, so the
            // commit gate proves the whole deployed unit rather than trusting an adjacent
            // in-memory argument.
            reconciler: tx.candidate_reconciler.clone(),
            rollback_guard: pending,
            // An update always has a proven predecessor: its failure recovery is this state machine's
            // rollback to a proven predecessor, so the restored head commits already confirmed.
            maturity: Maturity::Proven,
        })
    );
    chaos.crossing(boundary::INSTALLED_STATE_COMMITTED);
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
    Outcome::Committed {
        host_action: converge_result.host_action(),
    }
}

/// Persist the rejection decision before applying it. If the process dies in the gap,
/// boot recovery replays the idempotent rejection from the transaction rather than
/// forgetting why rollback began and selecting the same failed deployment again.
fn require_candidate_rejection(store: &mut Store, tx: &mut Transaction) -> io::Result<()> {
    if !tx.candidate_rejection_required {
        tx.candidate_rejection_required = true;
        store.write_journal(tx)?;
    }
    store.reject_deployment(
        &tx.candidate_repository_lineage,
        &tx.candidate_archive_sha256,
    )
}

/// Reject the failed candidate and hand the rollback to the boot state machine — the single
/// rollback implementation. Every post-activation failure ends here: the candidate is pointed at
/// and its `converge` has run, so this records the rejection and leaves the durable journal for boot
/// recovery to complete on the next agent start. An agent restart is cheap — it touches no workload
/// — and the freshly booted agent first compensates with the candidate's reconciler, then restores
/// and converges with the predecessor's reconciler. Rolling back here in-process would be a second
/// path to keep in lockstep with boot recovery. One path, one explicit reconciler per operation.
///
/// Recording the rejection is itself a durable write and can fail (ENOSPC, a read-only remount).
/// That failure must not escape: this runs mid-switchover, where an error would hold the process
/// alive with the node half-converged. Boot recovery still restores the predecessor from the
/// journal — it only loses the rejection, which costs one more futile attempt at the same
/// candidate, not the node.
fn reject_then_recover(store: &mut Store, tx: &mut Transaction) -> Outcome {
    if let Err(error) = require_candidate_rejection(store, tx) {
        warn(&format!(
            "recording the failed candidate's rejection mid-switchover ({error}); restarting for \
             boot recovery"
        ));
    }
    Outcome::RollbackPending
}

pub(crate) fn advance_transaction(
    store: &mut Store,
    tx: &mut Transaction,
    phase: TransactionPhase,
) -> io::Result<()> {
    tx.advance(phase)?;
    persist_transaction(store, tx)
}

pub(crate) fn persist_transaction(store: &mut Store, tx: &Transaction) -> io::Result<()> {
    store.write_journal(tx)?;
    Chaos::from_env().crossing(boundary::durable_phase(tx.phase));
    Ok(())
}

/// Invoke the single signed node reconciler with a stable operation and transaction identity.
/// The protocol is intentionally ordinary argv so an operator can implement it in Bash or
/// PowerShell without a JSON parser or SDK. A bounded wait prevents a wedged enterprise
/// integration from wedging the updater forever.
#[derive(Clone, Copy)]
pub(crate) struct ReconcilerInvocation<'a> {
    pub(crate) reason: Reason,
    pub(crate) id: &'a str,
    pub(crate) candidate: ReleaseTarget<'a>,
    pub(crate) predecessor: ReleaseTarget<'a>,
}

pub(crate) fn run_reconciler_mutation(
    reconciler: &updated::state::ReconcilerRelease,
    opts: &Options,
    operation: MutationOperation,
    invocation: ReconcilerInvocation<'_>,
    runtime_ceiling: Option<Duration>,
) -> io::Result<updated_contracts::reconciler::SuccessfulMutation> {
    invoke_reconciler_mutation(reconciler, opts, operation, invocation, runtime_ceiling)
        .map_err(InvocationFailure::into_io_error)
}

pub(crate) fn run_reconciler_observation(
    reconciler: &updated::state::ReconcilerRelease,
    opts: &Options,
    operation: ObservationOperation,
    invocation: ReconcilerInvocation<'_>,
) -> io::Result<()> {
    invoke_reconciler_observation(reconciler, opts, operation, HEALTHCHECK_TIMEOUT, invocation)
        .map_err(InvocationFailure::into_io_error)
}

fn invoke_reconciler_mutation(
    reconciler: &updated::state::ReconcilerRelease,
    opts: &Options,
    operation: MutationOperation,
    invocation: ReconcilerInvocation<'_>,
    runtime_ceiling: Option<Duration>,
) -> Result<updated_contracts::reconciler::SuccessfulMutation, InvocationFailure> {
    if let Some(hold) = updated::command_adapter::read_attention(&opts.paths.install_root)
        .map_err(InvocationFailure::Inconclusive)?
    {
        return Err(InvocationFailure::Inconclusive(io::Error::other(format!(
            "operator attention required: {}",
            hold.message
        ))));
    }
    let phase = operation.operation();
    let max_attempts = updated_contracts::reconciler::MAX_MUTATION_ATTEMPTS;
    let deadline = runtime_ceiling
        .map(|ceiling| {
            Instant::now().checked_add(ceiling).ok_or_else(|| {
                InvocationFailure::Inconclusive(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "reconciler runtime ceiling is too large",
                ))
            })
        })
        .transpose()?;

    for attempt in 1..=max_attempts {
        let remaining = mutation_runtime_remaining(deadline, phase)?;
        let prepared = prepare_reconciler_command(reconciler, opts, phase, remaining, invocation)
            .map_err(InvocationFailure::Inconclusive)?;
        let output = run_prepared_reconciler_command(prepared, None)?;
        let updated::reconciler::InvocationResult::Mutation(resolution) = output.result else {
            unreachable!("a mutation invocation is validated before it reaches this boundary")
        };
        match resolution {
            updated_contracts::reconciler::MutationResolution::NeedsAttention(message) => {
                let root = updated::bundle_store::BundleStore::for_app(&opts.paths)
                    .location(invocation.candidate.release);
                let hold = updated_contracts::attention::Attention {
                    product: reconciler.product.clone(),
                    receipt: updated::command_adapter::receipt_id(&root)
                        .map_err(InvocationFailure::Inconclusive)?,
                    operation,
                    attempt: invocation.id.into(),
                    version: invocation.candidate.release.version.clone(),
                    message,
                };
                updated::command_adapter::write_attention(&opts.paths.install_root, &hold)
                    .map_err(InvocationFailure::Inconclusive)?;
                return Err(InvocationFailure::Inconclusive(io::Error::other(format!(
                    "operator attention required: {}",
                    hold.message
                ))));
            }
            updated_contracts::reconciler::MutationResolution::Succeeded(result) => {
                let transition = updated_contracts::reconciler::ReconciliationTransition::new(
                    invocation
                        .candidate
                        .audit_identity()
                        .map_err(invalid_reconciliation_context)?,
                    invocation
                        .predecessor
                        .audit_identity()
                        .map_err(invalid_reconciliation_context)?,
                );

                let reconciler = updated_contracts::reconciler::ReconcilerIdentity::new(
                    reconciler.definition_sha256.clone(),
                    reconciler.product.clone(),
                    reconciler.api,
                )
                .map_err(invalid_reconciliation_context)?;
                let record = updated_contracts::reconciler::LastReconciliation::new(
                    operation,
                    invocation.reason,
                    invocation.id.to_string(),
                    transition,
                    reconciler,
                    result,
                    updated_contracts::telemetry::now_ms(),
                )
                .map_err(invalid_reconciliation_context)?;
                updated::reconciler::write_last_reconciliation(
                    &opts.paths.last_reconciliation,
                    &record,
                )
                .map_err(|error| {
                    InvocationFailure::Inconclusive(io_error_with_context(
                        error,
                        format!(
                            "reconciler {phase} succeeded, but persisting its audit record to {} failed",
                            opts.paths.last_reconciliation.display()
                        ),
                    ))
                })?;
                if let Some(message) = record.result().message() {
                    log(&format!("reconciler {phase}: {message}"));
                }
                return Ok(record.into_result());
            }
            updated_contracts::reconciler::MutationResolution::Retry(retry) => {
                let delay = Duration::from_secs(retry.after_seconds());
                let message = retry.message().unwrap_or("temporary condition");
                if attempt == max_attempts {
                    return Err(InvocationFailure::Inconclusive(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        format!(
                            "reconciler {phase} requested another retry after {max_attempts} attempts: {message}"
                        ),
                    )));
                }
                warn(&format!(
                    "reconciler {phase} requested retry {attempt} of {max_attempts} in {}s: {message}",
                    delay.as_secs()
                ));
                if mutation_runtime_remaining(deadline, phase)?.is_some_and(|left| delay >= left) {
                    return Err(mutation_runtime_exhausted(phase));
                }
                without_blocking_the_runtime(|| std::thread::sleep(delay));
            }
        }
    }
    unreachable!("the retry loop always returns on its final attempt")
}

fn mutation_runtime_remaining(
    deadline: Option<Instant>,
    phase: Operation,
) -> Result<Option<Duration>, InvocationFailure> {
    let Some(deadline) = deadline else {
        return Ok(None);
    };
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(mutation_runtime_exhausted(phase))
    } else {
        Ok(Some(remaining))
    }
}

fn mutation_runtime_exhausted(phase: Operation) -> InvocationFailure {
    InvocationFailure::Inconclusive(io::Error::new(
        io::ErrorKind::TimedOut,
        format!("agent-owned runtime budget for reconciler {phase} was exhausted"),
    ))
}

fn invoke_reconciler_observation(
    reconciler: &updated::state::ReconcilerRelease,
    opts: &Options,
    operation: ObservationOperation,
    runtime_ceiling: Duration,
    invocation: ReconcilerInvocation<'_>,
) -> Result<(), InvocationFailure> {
    let prepared = prepare_reconciler_command(
        reconciler,
        opts,
        operation.operation(),
        Some(runtime_ceiling),
        invocation,
    )
    .map_err(InvocationFailure::Inconclusive)?;
    let output = run_prepared_reconciler_command(prepared, None)?;
    match output.result {
        updated::reconciler::InvocationResult::Observation => Ok(()),
        updated::reconciler::InvocationResult::Mutation(_) => {
            unreachable!("an observation invocation is validated before it reaches this boundary")
        }
    }
}

struct PreparedReconcilerCommand {
    command: Command,
    phase: Operation,
    timeout: Duration,
    invocation_data: InvocationData,
    pending_reboot: PathBuf,
}

/// Private, per-invocation file exchange. The reconciler sees ordinary files; JSON/base64 is only
/// the internal storage boundary between the agent and S3.
struct InvocationData {
    root: PathBuf,
    input_dir: PathBuf,
    output_dir: PathBuf,
    result_file: PathBuf,
    output_snapshot: PathBuf,
}

impl InvocationData {
    fn create(
        state_dir: &Path,
        inputs: &updated_contracts::dataflow::FileSnapshot,
        output_snapshot: PathBuf,
    ) -> io::Result<Self> {
        inputs
            .validate()
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
        let exchanges = state_dir.join("invocations");
        std::fs::create_dir_all(&exchanges)?;
        let root = exchanges.join(updated::rand::token()?);
        foundation::durable::create_private_directory(&root)?;
        let input_dir = root.join("inputs");
        let output_dir = root.join("outputs");
        let result_file = root.join("result.json");
        foundation::durable::create_private_directory(&input_dir)?;
        foundation::durable::create_private_directory(&output_dir)?;
        for (name, value) in &inputs.files {
            let bytes = value
                .bytes()
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            let path = input_dir.join(name);
            let mut file = foundation::durable::create_private_new(&path)?;
            std::io::Write::write_all(&mut file, &bytes)?;
            file.sync_all()?;
        }
        foundation::durable::sync_dir(&input_dir)?;
        Ok(Self {
            root,
            input_dir,
            output_dir,
            result_file,
            output_snapshot,
        })
    }

    fn publish_outputs(&self) -> io::Result<()> {
        let snapshot = updated::reconciler::snapshot_directory(&self.output_dir)?;
        if let Some(parent) = self.output_snapshot.parent() {
            std::fs::create_dir_all(parent)?;
        }
        foundation::durable::atomic_write(
            &self.output_snapshot,
            ".outputs-",
            &serde_json::to_vec(&snapshot)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
        )
    }

    fn take_result(&self, phase: Operation) -> io::Result<updated::reconciler::InvocationResult> {
        updated::reconciler::take_result(&self.result_file, phase)
    }
}

impl Drop for InvocationData {
    fn drop(&mut self) {
        if let Err(error) = foundation::durable::remove_path(&self.root) {
            crate::warn(&format!(
                "removing reconciler file exchange {} failed: {error}",
                self.root.display()
            ));
        }
    }
}

/// Remove every plaintext file exchange an interrupted agent could have left behind.
///
/// The caller holds the installation's instance lock, so every `invocations` tree is stale. Product
/// state itself is durable reconciler-owned data and is deliberately preserved; only the one
/// agent-owned ephemeral child is removed.
pub(crate) fn clear_stale_invocation_data(paths: &updated::config::Paths) -> io::Result<()> {
    let products = match std::fs::read_dir(&paths.execution_state_root) {
        Ok(products) => products,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(io_error_with_context(
                error,
                format!(
                    "reading reconciler state root {}",
                    paths.execution_state_root.display()
                ),
            ));
        }
    };
    for product in products {
        let product = product.map_err(|error| {
            io_error_with_context(
                error,
                format!(
                    "enumerating reconciler state root {}",
                    paths.execution_state_root.display()
                ),
            )
        })?;
        let product_path = product.path();
        if product
            .file_type()
            .map_err(|error| {
                io_error_with_context(
                    error,
                    format!("reading reconciler state entry {}", product_path.display()),
                )
            })?
            .is_dir()
        {
            let invocations = product_path.join("invocations");
            foundation::durable::remove_path(&invocations).map_err(|error| {
                io_error_with_context(
                    error,
                    format!(
                        "removing stale plaintext reconciler exchanges {}",
                        invocations.display()
                    ),
                )
            })?;
        }
    }
    Ok(())
}

fn prepare_reconciler_command(
    reconciler: &updated::state::ReconcilerRelease,
    opts: &Options,
    operation: Operation,
    runtime_ceiling: Option<Duration>,
    invocation: ReconcilerInvocation<'_>,
) -> io::Result<PreparedReconcilerCommand> {
    let ReconcilerInvocation {
        reason,
        id: attempt_id,
        candidate,
        predecessor: _,
    } = invocation;
    reconciler.check_supported().map_err(io::Error::other)?;
    let mut timeout =
        reconciler_timeout(operation, Duration::from_millis(reconciler.timeout_millis));
    if let Some(runtime_ceiling) = runtime_ceiling {
        timeout = timeout.min(runtime_ceiling);
    }
    let phase_name = operation.as_str();
    let app_provider = updated::bundle_store::BundleStore::for_app(&opts.paths);
    let candidate_dir = app_provider.location(candidate.release);
    // Both durable hook directories come from the one layout definition (`Paths`), never from a
    // string join here: the conformance harness derives them from the same place, so a hook is
    // never certified against a layout no node uses.
    let state_dir = opts.paths.reconciler_state_dir(&reconciler.product);
    std::fs::create_dir_all(&state_dir)?;
    let output_snapshot = opts
        .paths
        .reconciler_output_snapshot(&candidate.release.manifest_sha256);
    let invocation_data = InvocationData::create(&state_dir, &opts.inputs, output_snapshot)?;
    // Each value is named for the flag it belongs to, and the published grammar itself binds the
    // two: the agent cannot emit a flag the contract does not name, stop emitting one a hook still
    // reads, or hand a value to the flag beside it.
    let arguments = updated_contracts::reconciler::Arguments {
        protocol: std::ffi::OsStr::new(updated_contracts::reconciler::PROTOCOL),
        attempt_id: std::ffi::OsStr::new(attempt_id),
        reason,
        install_root: opts.paths.install_root.as_os_str(),
        state_dir: state_dir.as_os_str(),
        payload_root: candidate_dir.as_os_str(),
        payload_version: std::ffi::OsStr::new(&candidate.release.version),
        output_dir: invocation_data.output_dir.as_os_str(),
        result_file: invocation_data.result_file.as_os_str(),
        input_dir: invocation_data.input_dir.as_os_str(),
    };
    let mut cmd = Command::new(&opts.helper_executable);
    cmd.arg(phase_name);
    for (flag, value) in arguments.argv() {
        cmd.arg(flag).arg(value);
    }
    cmd.current_dir(&candidate_dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    // THE invocation environment, shared with `updatectl check` so the harness cannot be
    // stricter or looser than a real node. It clears the environment itself.
    updated::reconciler::configure_environment(&mut cmd);
    updated::helper::configure(&mut cmd, &opts.helper_executable, operation, &arguments)?;
    cmd.env(
        updated::command_adapter::EXPECTED_DEFINITION_ENV,
        &reconciler.definition_sha256,
    );
    // A wrapper commonly waits on vendor CLIs, curl, or mount helpers. Run it as a
    // contained tree (Unix process group / Windows job object) so a timeout takes the
    // whole tree down, not just the shell — leaving the foreground operation orphaned.
    // The platform mechanism and parent-death guarantee are one primitive in
    // `foundation::process`, not call-site configuration.
    Ok(PreparedReconcilerCommand {
        command: cmd,
        phase: operation,
        timeout,
        invocation_data,
        pending_reboot: opts.paths.pending_reboot.clone(),
    })
}

const FINGERPRINT_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// The agent-owned ceiling on a single `healthcheck`. The steady-state probe runs inline on the
/// control loop that emits the node's only report, so a wedged hook would spend the node's
/// freshness budget in silence and the healthproxy would drain a node whose workload is fine: the
/// ceiling must stay well inside `updated_contracts::telemetry::REPORT_FRESHNESS`. It is also what
/// makes [`became_healthy`]'s `health_grace` a real bound rather than an advisory one, since a
/// single probe could otherwise outlast the whole grace.
pub(crate) const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(20);

/// A non-transactional `converge` runs inline on the report loop. Boot and update transactions keep
/// the publisher's full signed timeout; only this recurring steady-state invocation is bounded so
/// retries or a wedged hook cannot age the last healthy report past the reader freshness window.
pub(crate) const STEADY_STATE_CONVERGE_TIMEOUT: Duration = Duration::from_secs(20);

/// The agent's own runtime ceilings over the publisher-configured provider timeout. Exhaustive on
/// purpose: a new operation must state its bound rather than silently inherit "unbounded".
fn reconciler_timeout(phase: Operation, configured: Duration) -> Duration {
    match phase {
        Operation::Inspect => configured.min(FINGERPRINT_TIMEOUT),
        Operation::Healthcheck => configured.min(HEALTHCHECK_TIMEOUT),
        // The ordinary deployment paths are boot and transactions, where these operations are
        // legitimately as slow as the publisher says they are. The report loop supplies its
        // separate runtime ceiling when it invokes a recurring `converge`.
        Operation::Converge | Operation::Rollback => configured,
    }
}

/// Run a blocking body without starving the async runtime.
///
/// Operator reconciler hooks are external programs waited on synchronously, for up to their full
/// configured timeout. On a multi-threaded runtime that would otherwise pin a worker thread for the
/// entire hook — stalling telemetry and health probes on the same runtime.
/// Outside a runtime (the fingerprint observer runs on its own OS thread) the body simply runs.
fn without_blocking_the_runtime<T>(body: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current().map(|handle| handle.runtime_flavor()) {
        Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(body),
        _ => body(),
    }
}

fn run_prepared_reconciler_command(
    prepared: PreparedReconcilerCommand,
    cancelled: Option<&std::sync::atomic::AtomicBool>,
) -> Result<ReconcilerOutput, InvocationFailure> {
    without_blocking_the_runtime(move || {
        run_prepared_reconciler_command_blocking(prepared, cancelled)
    })
}

fn run_prepared_reconciler_command_blocking(
    prepared: PreparedReconcilerCommand,
    cancelled: Option<&std::sync::atomic::AtomicBool>,
) -> Result<ReconcilerOutput, InvocationFailure> {
    let PreparedReconcilerCommand {
        command,
        phase,
        timeout,
        invocation_data,
        pending_reboot,
    } = prepared;
    let phase_name = phase.as_str();
    let mut child = foundation::process::ContainedChild::spawn(command)
        .map_err(InvocationFailure::Inconclusive)?;
    let stdout = updated::reconciler::capture_output(
        child
            .take_stdout()
            .ok_or_else(|| io::Error::other("node reconciler stdout was not captured"))
            .map_err(InvocationFailure::Inconclusive)?,
    );
    let stderr = updated::reconciler::capture_output(
        child
            .take_stderr()
            .ok_or_else(|| io::Error::other("node reconciler stderr was not captured"))
            .map_err(InvocationFailure::Inconclusive)?,
    );
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "reconciler timeout is too large",
            )
        })
        .map_err(InvocationFailure::Inconclusive)?;
    // How this invocation ended. Nothing below returns early: the two capture threads are blocked
    // on the hook's pipes and `report_reconciler_output` is the only place they are joined, so a
    // `?` between spawning them and joining would leak both threads and their pipe fds, and drop
    // `child` unreaped — `ContainedChild` has no Unix `Drop`, so the hook tree would also keep
    // running outside any containment while the caller is told it timed out. A teardown that did
    // not finish — a kill that really failed (EPERM against a hook that escalated privilege), or a
    // leader still unreaped when the kill headroom expired — is folded into the reported error
    // instead of replacing the reason we are here.
    enum Ending {
        Exited(std::process::ExitStatus),
        Unwaitable(io::Error),
        Cancelled,
        TimedOut,
    }
    // Kill the tree and reap the leader — under a bound, and reaping even when the kill failed so a
    // leader that exits anyway does not become a zombie. `stop` is the workspace's one stop
    // sequence (ask, kill, then give the reap `KILL_HEADROOM`); the bound is the point. An
    // unbounded `wait()` here waits on a leader the kill may never have reached — EPERM against a
    // hook that setuid'd away from this unprivileged agent, or one wedged in uninterruptible I/O —
    // and this is the converge/rollback path, so that wait is the whole deployment loop stopping
    // forever rather than failing the operation with a reason.
    let kill_and_reap = |child: &mut foundation::process::ContainedChild| {
        match child.stop(Duration::ZERO) {
            foundation::process::Stopped::Gracefully | foundation::process::Stopped::Killed => {
                Ok(())
            }
            // Reported, not waited on. What follows still joins the capture threads, which the
            // survivor may hold open by keeping the inherited pipes — the hook obligation
            // `updatectl check` exists to catch before a release ships.
            foundation::process::Stopped::Surviving => Err(io::Error::other(format!(
                "its leader was still unreaped {:?} after the kill",
                foundation::process::KILL_HEADROOM
            ))),
        }
    };
    let (ending, teardown) = loop {
        match child.try_wait() {
            // `ContainedChild::try_wait` tears down undetached descendants before it reaps and
            // returns the root status. Keeping that invariant in the process primitive means an
            // ordinary successful exit cannot leave a pipe-holding helper behind either.
            Ok(Some(status)) => break (Ending::Exited(status), Ok(())),
            Ok(None) => {}
            Err(error) => break (Ending::Unwaitable(error), kill_and_reap(&mut child)),
        }
        if cancelled.is_some_and(|flag| flag.load(std::sync::atomic::Ordering::Acquire)) {
            break (Ending::Cancelled, kill_and_reap(&mut child));
        }
        if Instant::now() >= deadline {
            break (Ending::TimedOut, kill_and_reap(&mut child));
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let capture =
        report_reconciler_output(phase, stdout, stderr).map_err(InvocationFailure::Inconclusive)?;
    let also = match &teardown {
        Ok(()) => String::new(),
        Err(error) => format!(" (tearing down its process tree also failed: {error})"),
    };
    match ending {
        Ending::Exited(status) if status.success() => match teardown {
            Ok(()) => {
                let result = invocation_data.take_result(phase).map_err(|error| {
                    if error.kind() == io::ErrorKind::InvalidData {
                        InvocationFailure::ReleaseFault(error)
                    } else {
                        InvocationFailure::Inconclusive(error)
                    }
                })?;
                if matches!(&result, updated::reconciler::InvocationResult::Mutation(
                    updated_contracts::reconciler::MutationResolution::Succeeded(result)
                ) if result.host_action() == HostAction::Reboot)
                {
                    host::record_reboot(&pending_reboot)
                        .map_err(InvocationFailure::Inconclusive)?;
                }
                if phase.publishes_outputs()
                    && matches!(
                        &result,
                        updated::reconciler::InvocationResult::Mutation(
                            updated_contracts::reconciler::MutationResolution::Succeeded(_)
                        )
                    )
                {
                    invocation_data
                        .publish_outputs()
                        .map_err(InvocationFailure::Inconclusive)?;
                }
                Ok(ReconcilerOutput { capture, result })
            }
            Err(error) => Err(InvocationFailure::Inconclusive(error)),
        },
        Ending::Exited(status) => Err(InvocationFailure::ReleaseFault(io::Error::other(format!(
            "node reconciler {phase_name} exited with {status}{also}"
        )))),
        Ending::Unwaitable(error) => Err(InvocationFailure::Inconclusive(io::Error::other(
            format!("waiting on node reconciler {phase_name} failed: {error}{also}"),
        ))),
        Ending::Cancelled => Err(InvocationFailure::Inconclusive(io::Error::new(
            io::ErrorKind::Interrupted,
            format!(
                "node reconciler {phase_name} was cancelled for deployment \
                 reconciliation{also}"
            ),
        ))),
        Ending::TimedOut => Err(InvocationFailure::ReleaseFault(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "node reconciler {phase_name} exceeded its {}s timeout{also}",
                timeout.as_secs_f64()
            ),
        ))),
    }
}

struct ReconcilerOutput {
    capture: CapturedOutput,
    result: updated::reconciler::InvocationResult,
}

struct CapturedOutput {
    stdout: Vec<u8>,
    stdout_truncated: bool,
}

/// How long a captured pipe is given to reach EOF once the invocation is over and its tree has been
/// torn down.
///
/// In every conforming invocation EOF has already happened and this waits for nothing: the hook and
/// everything in its tree are gone, so their descriptors are closed. A pipe still open past it means
/// a descendant escaped the tree entirely — detached with `setsid` while keeping the inherited
/// stdout/stderr, which `docs/node-reconciler-protocol.md` forbids and `updatectl check`
/// fails a hook for. Reading that pipe is a wait no kill can end, on the converge/rollback path: the
/// node's whole deployment loop stopped forever by one stray descendant. So the read is abandoned
/// and the operation answered with what arrived, which for an `inspect` means no fingerprint is
/// published rather than no report at all.
const READER_GRACE: Duration = Duration::from_secs(5);

fn report_reconciler_output(
    phase: Operation,
    stdout: std::sync::mpsc::Receiver<io::Result<(Vec<u8>, bool)>>,
    stderr: std::sync::mpsc::Receiver<io::Result<(Vec<u8>, bool)>>,
) -> io::Result<CapturedOutput> {
    let operation = phase.as_str();
    let mut stdout_result = None;
    for (stream, reader) in [("stdout", stdout), ("stderr", stderr)] {
        let (bytes, truncated) = match reader.recv_timeout(READER_GRACE) {
            Ok(result) => result?,
            // Abandoned, not waited on: see `READER_GRACE`. Reported, because a hook that leaves a
            // descendant holding these pipes has broken a published obligation and the operator
            // needs the name of the hook that did it.
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                warn(&format!(
                    "node reconciler {operation} {stream} was still open {READER_GRACE:?} after its                      process tree was torn down; a descendant escaped the tree holding it.                      Abandoning the read"
                ));
                (Vec::new(), true)
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err(io::Error::other("node reconciler output reader panicked"))
            }
        };
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
    Ok(CapturedOutput {
        stdout,
        stdout_truncated,
    })
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::test_support::{deployment_rejection, digest, release};

    #[cfg(unix)]
    fn test_invocation_data() -> InvocationData {
        let state_dir = std::env::temp_dir().join(format!(
            "updated-agent-invocation-test-{}-{}",
            std::process::id(),
            updated::rand::token().unwrap()
        ));
        InvocationData::create(
            &state_dir,
            &updated_contracts::dataflow::FileSnapshot::default(),
            state_dir.join("outputs.json"),
        )
        .unwrap()
    }

    fn observation_output(stdout: Vec<u8>, stdout_truncated: bool) -> ReconcilerOutput {
        ReconcilerOutput {
            capture: CapturedOutput {
                stdout,
                stdout_truncated,
            },
            result: updated::reconciler::InvocationResult::Observation,
        }
    }

    fn successful_no_change_result() -> updated_contracts::reconciler::SuccessfulMutation {
        updated_contracts::reconciler::SuccessfulMutation::new(
            false,
            updated_contracts::reconciler::HostAction::None,
            None,
        )
        .unwrap()
    }

    fn target(release: &updated::bundle::ReleaseId) -> ReleaseTarget<'_> {
        ReleaseTarget {
            release,
            archive_sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        }
    }

    #[test]
    fn boot_cleanup_removes_crashed_plaintext_exchanges_and_only_those_exchanges() {
        let root = tempfile::tempdir().unwrap();
        let paths = updated::config::Paths::resolve(root.path(), &root.path().join("enrollment"));
        let product_state = paths.reconciler_state_dir("database");
        let stale = product_state.join("invocations/abandoned/inputs/password");
        std::fs::create_dir_all(stale.parent().unwrap()).unwrap();
        std::fs::write(&stale, b"plaintext secret").unwrap();
        let durable = product_state.join("database.state");
        std::fs::write(&durable, b"keep").unwrap();

        clear_stale_invocation_data(&paths).unwrap();

        assert!(!product_state.join("invocations").exists());
        assert_eq!(std::fs::read(&durable).unwrap(), b"keep");
        clear_stale_invocation_data(&paths).unwrap();
    }

    #[test]
    fn fingerprint_hashes_exact_stdout_bytes_without_text_normalization() {
        let exact = fingerprint_from_output(
            &"a".repeat(64),
            observation_output(b"state\n".to_vec(), false),
        )
        .unwrap();
        let without_newline = fingerprint_from_output(
            &"a".repeat(64),
            observation_output(b"state".to_vec(), false),
        )
        .unwrap();

        assert_ne!(exact.output_sha256, without_newline.output_sha256);
        assert_eq!(exact.definition_sha256, "a".repeat(64));
    }

    #[test]
    fn a_truncated_fingerprint_is_never_attested() {
        let error = fingerprint_from_output(
            &"a".repeat(64),
            observation_output(vec![0; updated::reconciler::OUTPUT_LIMIT], true),
        )
        .unwrap_err();

        assert!(error.to_string().contains("output limit"));
    }

    #[test]
    fn an_empty_fingerprint_is_never_attested() {
        let error = fingerprint_from_output(&"a".repeat(64), observation_output(Vec::new(), false))
            .unwrap_err();

        assert!(error.to_string().contains("no measured state"));
    }

    #[test]
    fn steady_state_operations_have_agent_owned_runtime_ceilings() {
        assert_eq!(
            reconciler_timeout(Operation::Inspect, Duration::from_secs(86_400)),
            FINGERPRINT_TIMEOUT
        );
        assert_eq!(
            reconciler_timeout(Operation::Inspect, Duration::from_secs(30)),
            Duration::from_secs(30)
        );
        assert_eq!(
            reconciler_timeout(Operation::Healthcheck, Duration::from_secs(86_400)),
            HEALTHCHECK_TIMEOUT
        );
        assert_eq!(
            reconciler_timeout(Operation::Healthcheck, Duration::from_secs(5)),
            Duration::from_secs(5)
        );
        // Boot and transactional deployment operations keep the publisher's own bound. The
        // recurring report-loop converge supplies a separate shrinking budget to command
        // preparation on every attempt.
        assert_eq!(
            reconciler_timeout(Operation::Converge, Duration::from_secs(86_400)),
            Duration::from_secs(86_400)
        );
        let remaining = mutation_runtime_remaining(
            Some(Instant::now() + STEADY_STATE_CONVERGE_TIMEOUT),
            Operation::Converge,
        )
        .unwrap()
        .unwrap();
        assert!(remaining <= STEADY_STATE_CONVERGE_TIMEOUT);
        assert_eq!(
            reconciler_timeout(Operation::Converge, Duration::from_secs(86_400)).min(remaining),
            remaining
        );
        assert!(matches!(
            mutation_runtime_remaining(Some(Instant::now()), Operation::Converge),
            Err(InvocationFailure::Inconclusive(ref error))
                if error.kind() == io::ErrorKind::TimedOut
        ));
    }

    #[test]
    fn a_steady_state_converge_cannot_stall_the_loop_into_a_health_drain() {
        // Even the pathological timeout teardown (kill headroom plus two escaped pipe readers)
        // leaves room to publish the now-unready heartbeat before readers age out the prior one.
        assert!(
            STEADY_STATE_CONVERGE_TIMEOUT + foundation::process::KILL_HEADROOM + READER_GRACE * 2
                < updated_contracts::telemetry::REPORT_FRESHNESS
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
        let prepared = PreparedReconcilerCommand {
            command,
            phase: Operation::Inspect,
            timeout: Duration::from_secs(30),
            invocation_data: test_invocation_data(),
            pending_reboot: crate::test_support::nonexistent_root().join("pending-reboot"),
        };
        let cancelled = Arc::new(AtomicBool::new(false));
        let signal = Arc::clone(&cancelled);
        let started = Instant::now();
        let handle =
            std::thread::spawn(move || run_prepared_reconciler_command(prepared, Some(&signal)));
        std::thread::sleep(Duration::from_millis(100));
        cancelled.store(true, Ordering::Release);

        let error = match handle.join().unwrap() {
            Ok(_) => panic!("cancelled fingerprint unexpectedly completed"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    /// Every wait on this path is bounded, because this path is the deployment loop. The tree is
    /// gone by the time the pipes are read, so a pipe that never reaches EOF is a descendant that
    /// escaped the tree still holding the inherited stdout/stderr — detached with `setsid` but
    /// never redirected, which the protocol forbids and `updatectl check` fails a hook
    /// for. Joining that reader stopped converge, rollback, and every probe on the node forever, for a
    /// hook that had already exited zero. Now the read is abandoned and the operation answers.
    #[test]
    fn a_pipe_that_never_reaches_eof_is_abandoned_instead_of_stalling_the_invocation() {
        struct NeverEof;
        impl std::io::Read for NeverEof {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                std::thread::sleep(Duration::from_secs(3600));
                Ok(0)
            }
        }
        let started = Instant::now();
        let output = report_reconciler_output(
            Operation::Converge,
            updated::reconciler::capture_output(NeverEof),
            updated::reconciler::capture_output(std::io::empty()),
        )
        .expect("an abandoned read still answers the invocation");
        assert!(output.stdout.is_empty());
        assert!(
            output.stdout_truncated,
            "output that was never collected must not pass as complete"
        );
        assert!(
            started.elapsed() < READER_GRACE * 3,
            "the read is abandoned on a deadline, not joined"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_retry_result_cannot_publish_candidate_outputs() {
        let invocation_data = test_invocation_data();
        let output_snapshot = invocation_data.output_snapshot.clone();
        let mut command = Command::new("/bin/sh");
        command
            .args([
                "-c",
                "printf secret >\"$OUTPUT_DIR/value\"; \
                 printf '%s' '{\"schema\":1,\"status\":\"retry\",\"retryAfterSeconds\":1,\"message\":null}' >\"$RESULT_FILE\"",
            ])
            .env("OUTPUT_DIR", &invocation_data.output_dir)
            .env("RESULT_FILE", &invocation_data.result_file)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let output = run_prepared_reconciler_command(
            PreparedReconcilerCommand {
                command,
                phase: Operation::Converge,
                timeout: Duration::from_secs(5),
                invocation_data,
                pending_reboot: crate::test_support::nonexistent_root().join("pending-reboot"),
            },
            None,
        )
        .unwrap();

        assert!(matches!(
            output.result,
            updated::reconciler::InvocationResult::Mutation(
                updated_contracts::reconciler::MutationResolution::Retry(_)
            )
        ));
        assert!(
            !output_snapshot.exists(),
            "only a succeeded result may replace the durable output snapshot"
        );
    }

    #[cfg(unix)]
    #[test]
    fn successful_hook_kills_its_undetached_tree_but_not_a_detached_workload() {
        // The published contract, executable: an invocation's tree is torn down when the hook
        // returns — on SUCCESS as much as on timeout — so a workload started inside it is killed by
        // its own successful `converge`, and a hook that wants the workload to belong to the release
        // must move it out of the tree first. Both halves are asserted, because a "fix" that spares
        // the tree on success would let a wrapper's inherited pipes outlive the deadline.
        fn run(script: &str) -> (Result<ReconcilerOutput, InvocationFailure>, PathBuf) {
            let dir = std::env::temp_dir().join(format!(
                "hook-detach-{}-{}",
                std::process::id(),
                updated::rand::token().unwrap()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let pidfile = dir.join("workload.pid");
            let invocation_data = test_invocation_data();
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", script])
                .env("PIDFILE", &pidfile)
                .env("RESULT_FILE", &invocation_data.result_file)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            let outcome = run_prepared_reconciler_command(
                PreparedReconcilerCommand {
                    command,
                    phase: Operation::Converge,
                    timeout: Duration::from_secs(30),
                    invocation_data,
                    pending_reboot: crate::test_support::nonexistent_root().join("pending-reboot"),
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

        let (outcome, pidfile) = run(
            "sleep 60 & echo $! > \"$PIDFILE\"; \
             printf '%s' '{\"schema\":1,\"status\":\"succeeded\",\"changed\":true,\"hostAction\":\"none\",\"message\":null}' >\"$RESULT_FILE\"",
        );
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
             while [ ! -s \"$PIDFILE\" ]; do sleep 0.05; done; \
             printf '%s' '{\"schema\":1,\"status\":\"succeeded\",\"changed\":true,\"hostAction\":\"none\",\"message\":null}' >\"$RESULT_FILE\"",
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

    fn reconciler_release() -> updated::state::ReconcilerRelease {
        *crate::test_support::provider()
    }

    /// A store holding `previous` as the confirmed installed release, which is what every
    /// transaction test starts from.
    fn store_with(previous: updated::bundle::ReleaseId) -> Store {
        Store::memory(MemoryBackend {
            installed: Some(InstalledState::proven(
                test_lineage(),
                previous.clone(),
                digest("previous-archive"),
                Box::new(reconciler_release()),
            )),
            active: Some(previous),
            ..MemoryBackend::default()
        })
    }

    fn test_lineage() -> updated::state::RepositoryLineage {
        updated::state::RepositoryLineage::from_metadata_url("https://repo/metadata/")
            .expect("fixture metadata URL is valid")
    }

    /// A scripted stand-in for the release's reconciler: it records every invocation and can be
    /// made to fail any operation, so each fault path of [`execute_update`] is provable without a
    /// subprocess.
    #[derive(Clone, Copy)]
    enum FakeFailure {
        ReleaseFault,
        Inconclusive(io::ErrorKind),
    }

    impl FakeFailure {
        fn error(self, operation: &str) -> InvocationFailure {
            match self {
                Self::ReleaseFault => InvocationFailure::ReleaseFault(io::Error::other(format!(
                    "injected {operation} answer"
                ))),
                Self::Inconclusive(kind) => InvocationFailure::Inconclusive(io::Error::new(
                    kind,
                    format!("injected {operation} invocation failure"),
                )),
            }
        }
    }

    #[derive(Default)]
    struct FakeReconciler {
        /// Every invocation, as the operation's wire spelling and its attempt id — the two halves
        /// of the argv contract a gate is required to honour.
        invocations: Vec<(&'static str, String)>,
        fail_first_healthcheck: bool,
        /// Fail every healthcheck either before the reconciler or with its own answer.
        healthcheck_failure: Option<FakeFailure>,
        /// The 1-based probe at which `healthcheck_failure` starts (0 and 1 both mean the first),
        /// so a fault can be made to arrive PART WAY THROUGH a grace period.
        healthcheck_failure_from: usize,
        healthcheck_calls: usize,
        healthcheck_timeouts: Vec<Duration>,
        health_successes: u32,
        health_interval: Duration,
        fail_first_converge: bool,
        unreach_first_converge: bool,
        converges: usize,
        host_action: updated_contracts::reconciler::HostAction,
        preparation_fails: bool,
    }

    impl FakeReconciler {
        fn operations(&self) -> Vec<&str> {
            self.invocations
                .iter()
                .map(|(operation, _)| *operation)
                .collect()
        }

        fn invoke_operation(
            &mut self,
            operation: Operation,
            attempt_id: &str,
        ) -> Result<(), InvocationFailure> {
            self.invocations
                .push((operation.as_str(), attempt_id.to_string()));
            match operation {
                Operation::Healthcheck => {
                    self.healthcheck_calls += 1;
                    if let Some(failure) = self.healthcheck_failure {
                        if self.healthcheck_calls >= self.healthcheck_failure_from.max(1) {
                            return Err(failure.error("healthcheck"));
                        }
                    }
                    if self.fail_first_healthcheck && self.healthcheck_calls == 1 {
                        return Err(FakeFailure::ReleaseFault.error("healthcheck"));
                    }
                }
                Operation::Converge => {
                    self.converges += 1;
                    if self.unreach_first_converge && self.converges == 1 {
                        return Err(
                            FakeFailure::Inconclusive(io::ErrorKind::StorageFull).error("converge")
                        );
                    }
                    if self.fail_first_converge && self.converges == 1 {
                        return Err(FakeFailure::ReleaseFault.error("converge"));
                    }
                }
                Operation::Rollback | Operation::Inspect => {}
            }
            Ok(())
        }
    }

    impl Reconciler for FakeReconciler {
        fn prepare_update(&mut self, _: &str) -> io::Result<()> {
            if self.preparation_fails {
                Err(io::Error::from(io::ErrorKind::StorageFull))
            } else {
                Ok(())
            }
        }
        fn mutate(
            &mut self,
            operation: MutationOperation,
            attempt_id: &str,
            _: ReleaseTarget<'_>,
            _: ReleaseTarget<'_>,
        ) -> Result<updated_contracts::reconciler::SuccessfulMutation, InvocationFailure> {
            self.invoke_operation(operation.operation(), attempt_id)?;
            let result = successful_no_change_result();
            Ok(updated_contracts::reconciler::SuccessfulMutation::new(
                result.changed(),
                self.host_action,
                result.message().map(str::to_owned),
            )
            .unwrap())
        }
        fn observe(
            &mut self,
            operation: ObservationOperation,
            timeout: Duration,
            attempt_id: &str,
            _: ReleaseTarget<'_>,
            _: ReleaseTarget<'_>,
        ) -> Result<(), InvocationFailure> {
            if operation == ObservationOperation::Healthcheck {
                self.healthcheck_timeouts.push(timeout);
            }
            self.invoke_operation(operation.operation(), attempt_id)
        }
        fn verification_policy(&self) -> (Duration, u32, Duration) {
            (
                Duration::from_secs(1),
                self.health_successes.max(1),
                self.health_interval,
            )
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
            became_healthy(
                &mut reconciler,
                attempt::BOOT,
                target(&release),
                target(&release)
            )
            .await,
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

        let outcome = execute_update(
            &mut reconciler,
            &mut store,
            &candidate,
            &digest("archive-two"),
            test_lineage(),
            reconciler_release(),
        )
        .await
        .unwrap();

        assert!(matches!(outcome, Outcome::Committed { .. }));
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
            "a transaction gate carries its own attempt id, never a reserved non-transaction identity"
        );
    }

    /// The whole forward transaction, as the release sees it: exactly one `converge` (the switchover)
    /// and then the healthcheck gate, in that order, under one attempt identity. The agent starts
    /// and stops nothing itself, so a `converge` that is missing, doubled, or ordered after the gate
    /// is a node that never converged onto the candidate it just committed.
    #[tokio::test]
    async fn a_committed_update_is_one_converge_then_the_health_gate() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = store_with(previous);
        let mut reconciler = FakeReconciler::default();

        let outcome = execute_update(
            &mut reconciler,
            &mut store,
            &candidate,
            &digest("archive-two"),
            test_lineage(),
            reconciler_release(),
        )
        .await
        .unwrap();

        assert!(matches!(outcome, Outcome::Committed { .. }));
        assert_eq!(reconciler.operations(), ["converge", "healthcheck"]);
        assert_eq!(store.memory_backend().active.as_ref(), Some(&candidate));
        let attempts: std::collections::HashSet<&str> = reconciler
            .invocations
            .iter()
            .map(|(_, id)| id.as_str())
            .collect();
        assert_eq!(attempts.len(), 1, "one transaction, one attempt identity");
    }

    #[tokio::test]
    async fn an_unpersistable_input_pin_prevents_activation_and_hooks() {
        let previous = release("1.0.0", "one");
        let mut store = store_with(previous.clone());
        let mut reconciler = FakeReconciler {
            preparation_fails: true,
            ..Default::default()
        };
        let error = execute_update(
            &mut reconciler,
            &mut store,
            &release("2.0.0", "two"),
            &digest("archive-two"),
            test_lineage(),
            reconciler_release(),
        )
        .await
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::StorageFull);
        assert_eq!(store.memory_backend().active.as_ref(), Some(&previous));
        assert!(store.journal().unwrap().is_none());
        assert!(reconciler.operations().is_empty());
    }

    #[tokio::test]
    async fn unavailable_execution_api_prevents_activation_without_rejecting_bytes() {
        let previous = release("1.0.0", "one");
        let mut store = store_with(previous.clone());
        let mut reconciler = FakeReconciler::default();
        let mut candidate = reconciler_release();
        candidate.api = 99;
        let result = execute_update(
            &mut reconciler,
            &mut store,
            &release("2.0.0", "two"),
            &digest("archive-two"),
            test_lineage(),
            candidate,
        )
        .await;
        assert!(result.is_err());
        assert_eq!(store.memory_backend().active.as_ref(), Some(&previous));
        assert!(store.journal().unwrap().is_none());
        assert!(reconciler.operations().is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn a_reboot_result_is_durable_even_if_publishing_outputs_fails() {
        let directory = tempfile::tempdir().unwrap();
        let pending = directory.path().join("pending-reboot");
        let mut data = test_invocation_data();
        // Force a post-result publication failure without touching the reboot record's directory.
        let blocker = directory.path().join("not-a-directory");
        std::fs::write(&blocker, b"blocker").unwrap();
        data.output_snapshot = blocker.join("outputs");
        let mut command = Command::new("/bin/sh");
        command.args(["-c", r#"printf '%s' '{"schema":1,"status":"succeeded","changed":true,"hostAction":"reboot","message":null}' >"$RESULT_FILE""#])
            .env("RESULT_FILE", &data.result_file)
            .stdin(std::process::Stdio::null()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped());
        let outcome = run_prepared_reconciler_command(
            PreparedReconcilerCommand {
                command,
                phase: Operation::Rollback,
                timeout: Duration::from_secs(5),
                invocation_data: data,
                pending_reboot: pending.clone(),
            },
            None,
        );
        assert!(matches!(outcome, Err(InvocationFailure::Inconclusive(_))));
        assert!(host::reboot_pending(&pending).unwrap());
        // Repeated process restarts have no authority to turn this into a completed reboot.
        assert!(host::reboot_pending(&pending).unwrap());
    }

    #[tokio::test]
    async fn a_reboot_request_is_committed_without_a_pre_reboot_health_verdict() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = store_with(previous);
        let mut reconciler = FakeReconciler {
            host_action: updated_contracts::reconciler::HostAction::Reboot,
            ..Default::default()
        };

        let outcome = execute_update(
            &mut reconciler,
            &mut store,
            &candidate,
            &digest("archive-two"),
            test_lineage(),
            reconciler_release(),
        )
        .await
        .unwrap();

        assert!(matches!(
            outcome,
            Outcome::Committed {
                host_action: updated_contracts::reconciler::HostAction::Reboot
            }
        ));
        assert_eq!(
            reconciler.operations(),
            ["converge"],
            "health is judged only after the host has crossed the requested reboot boundary"
        );
        assert_eq!(store.memory_backend().active.as_ref(), Some(&candidate));
        assert!(
            store
                .memory_backend()
                .installed
                .as_ref()
                .and_then(|installed| installed.rollback_guard.as_ref())
                .is_some(),
            "the predecessor remains available until post-reboot confirmation"
        );
        store
            .memory_backend_mut()
            .installed
            .as_mut()
            .unwrap()
            .rollback_guard
            .as_mut()
            .unwrap()
            .committed_at = 1;
        let situation = gather_situation(&store).unwrap();
        let plan = plan_boot(&situation);
        let Installed::Present(installed) = &situation.installed else {
            panic!("installed candidate")
        };
        assert!(window_passed(
            installed.rollback_guard.as_ref().unwrap(),
            Duration::from_secs(120),
            now_unix()
        ));
        execute_boot_plan(&plan, &mut store, false, None).unwrap();
        let Installed::Present(installed) = store.installed().unwrap() else {
            panic!("installed candidate")
        };
        assert_eq!(boot::plan_gate_failure(&installed), GateFailure::Revert);
        assert!(
            plan.commit.is_none(),
            "elapsed downtime cannot confirm an unverified reboot"
        );
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

        let outcome = execute_update(
            &mut reconciler,
            &mut store,
            &candidate,
            &digest("archive-two"),
            test_lineage(),
            reconciler_release(),
        )
        .await
        .unwrap();

        assert!(matches!(outcome, Outcome::Committed { .. }));
        assert_eq!(reconciler.healthcheck_calls, 2);
        assert!(store.memory_backend().rejected.is_empty());
    }

    /// A probe that fails before the reconciler runs — a corrupt provider tree, ENOSPC writing the
    /// invocation's inputs — observed nothing about the candidate, so the gate is INCONCLUSIVE. A
    /// reconciler that ran and answered badly is unhealthy. The two must not collapse together:
    /// only the second is evidence about the release.
    #[tokio::test]
    async fn a_gate_that_never_reaches_the_reconciler_is_inconclusive_not_unhealthy() {
        let candidate = release("2.0.0", "two");

        let mut unreachable = FakeReconciler {
            healthcheck_failure: Some(FakeFailure::Inconclusive(io::ErrorKind::StorageFull)),
            ..Default::default()
        };
        assert!(matches!(
            became_healthy(
                &mut unreachable,
                attempt::BOOT,
                target(&candidate),
                target(&candidate),
            )
            .await,
            Health::Inconclusive(_)
        ));

        let mut answered = FakeReconciler {
            healthcheck_failure: Some(FakeFailure::ReleaseFault),
            ..Default::default()
        };
        match became_healthy(
            &mut answered,
            attempt::BOOT,
            target(&candidate),
            target(&candidate),
        )
        .await
        {
            Health::Unhealthy(error) => assert!(
                error.to_string().contains("injected healthcheck answer"),
                "the release verdict must retain the reconciler's exact failure: {error}"
            ),
            _ => panic!("a reconciler answer must produce an unhealthy release verdict"),
        }
        assert!(
            answered
                .healthcheck_timeouts
                .iter()
                .all(|timeout| *timeout <= Duration::from_secs(1)),
            "no probe may outlive the gate's remaining grace"
        );
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
            healthcheck_failure: Some(FakeFailure::Inconclusive(io::ErrorKind::StorageFull)),
            healthcheck_failure_from: 2,
            ..Default::default()
        };

        assert!(
            matches!(
                became_healthy(
                    &mut reconciler,
                    attempt::BOOT,
                    target(&candidate),
                    target(&candidate),
                )
                .await,
                Health::Inconclusive(_)
            ),
            "one early answer must not latch the gate into judging the release"
        );
        assert!(reconciler.healthcheck_calls > 1, "the grace kept probing");
    }

    #[tokio::test]
    async fn an_incomplete_success_run_is_unhealthy_not_inconclusive() {
        let candidate = release("2.0.0", "two");
        let mut reconciler = FakeReconciler {
            health_successes: 2,
            health_interval: Duration::from_secs(2),
            ..Default::default()
        };

        match became_healthy(
            &mut reconciler,
            attempt::BOOT,
            target(&candidate),
            target(&candidate),
        )
        .await
        {
            Health::Unhealthy(error) => assert!(error
                .to_string()
                .contains("before 2 consecutive successful healthchecks")),
            _ => panic!("one success cannot satisfy a two-success readiness policy"),
        }
        assert_eq!(reconciler.healthcheck_calls, 1);
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
            healthcheck_failure: Some(FakeFailure::Inconclusive(io::ErrorKind::StorageFull)),
            ..Default::default()
        };

        let outcome = execute_update(
            &mut reconciler,
            &mut store,
            &candidate,
            &digest("archive-two"),
            test_lineage(),
            reconciler_release(),
        )
        .await
        .expect("an unreachable reconciler restarts for recovery rather than failing fatally");

        assert!(matches!(outcome, Outcome::RollbackPending));
        assert!(
            store.memory_backend().rejected.is_empty(),
            "a node-local fault is not evidence about the candidate's bytes"
        );
        assert!(
            store.memory_backend().journal.is_some(),
            "boot recovery needs the rollback intent"
        );
    }

    #[tokio::test]
    async fn a_candidate_converge_failure_records_the_rejection_before_deferring_to_recovery() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = store_with(previous);
        let mut reconciler = FakeReconciler {
            fail_first_converge: true,
            ..Default::default()
        };

        let outcome = execute_update(
            &mut reconciler,
            &mut store,
            &candidate,
            &digest("archive-two"),
            test_lineage(),
            reconciler_release(),
        )
        .await
        .unwrap();

        // The candidate activated then failed: it is rejected and the rollback journal is durable
        // before we hand off to boot recovery. There is no in-process rollback to fail.
        assert!(matches!(outcome, Outcome::RollbackPending));
        let rejection = deployment_rejection(&digest("archive-two"));
        assert_eq!(
            store.memory_backend().rejected,
            std::collections::HashSet::from([test_lineage().rejection_key(&rejection)])
        );
        assert!(!store.is_rejected(&test_lineage(), &digest("archive-two")));
        assert_eq!(
            reconciler.operations(),
            ["converge"],
            "a failed converge is never followed by a health gate on the candidate"
        );
        assert!(
            store
                .memory_backend()
                .journal
                .as_ref()
                .is_some_and(|tx| tx.candidate_rejection_required),
            "rollback evidence must retain the rejection decision"
        );
    }

    /// The stage operation already proved the archive and classified every reproducible defect as
    /// rejectable. A later tree mismatch is therefore local drift or device failure: recovery may
    /// retry it, but it must not turn that node-local observation into a permanent archive verdict.
    #[tokio::test]
    async fn a_pre_activation_integrity_failure_never_rejects_the_release() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = store_with(previous.clone());
        store.memory_backend_mut().fail_verify_release = true;
        let mut reconciler = FakeReconciler::default();

        let outcome = execute_update(
            &mut reconciler,
            &mut store,
            &candidate,
            &digest("archive-two"),
            test_lineage(),
            reconciler_release(),
        )
        .await
        .unwrap();

        assert!(matches!(outcome, Outcome::RollbackPending));
        assert_eq!(
            store.memory_backend().active,
            Some(previous),
            "the pointer never moved"
        );
        assert!(
            store.memory_backend().rejected.is_empty(),
            "local drift is not archive evidence"
        );
        assert!(
            reconciler.invocations.is_empty(),
            "unverified bytes never run"
        );
        assert!(
            store
                .memory_backend()
                .journal
                .as_ref()
                .is_some_and(|tx| !tx.candidate_rejection_required),
            "boot recovery retains intent without inventing a release verdict"
        );
    }

    /// Pointer persistence is platform I/O after the bytes have verified. It follows the exact same
    /// recovery-only policy as an integrity read failure and cannot reject the candidate either.
    #[tokio::test]
    async fn an_active_pointer_write_failure_never_rejects_the_release() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = store_with(previous.clone());
        store.memory_backend_mut().fail_point_active = true;
        let mut reconciler = FakeReconciler::default();

        let outcome = execute_update(
            &mut reconciler,
            &mut store,
            &candidate,
            &digest("archive-two"),
            test_lineage(),
            reconciler_release(),
        )
        .await
        .unwrap();

        assert!(matches!(outcome, Outcome::RollbackPending));
        assert_eq!(
            store.memory_backend().active,
            Some(previous),
            "the failed write is atomic"
        );
        assert!(
            store.memory_backend().rejected.is_empty(),
            "pointer I/O is not archive evidence"
        );
        assert!(
            reconciler.invocations.is_empty(),
            "inactive bytes never run"
        );
        assert!(store
            .memory_backend()
            .journal
            .as_ref()
            .is_some_and(|tx| !tx.candidate_rejection_required));
    }

    /// Preparing and spawning the hook are node-local work. If they fail after the application
    /// pointer moved, recovery must restore the predecessor, but the candidate's authenticated
    /// bytes remain eligible: the release never got a chance to answer.
    #[tokio::test]
    async fn a_converge_that_never_reaches_the_reconciler_rolls_back_without_rejecting() {
        let previous = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut store = store_with(previous);
        let mut reconciler = FakeReconciler {
            unreach_first_converge: true,
            ..Default::default()
        };

        let outcome = execute_update(
            &mut reconciler,
            &mut store,
            &candidate,
            &digest("archive-two"),
            test_lineage(),
            reconciler_release(),
        )
        .await
        .unwrap();

        assert!(matches!(outcome, Outcome::RollbackPending));
        assert!(
            store.memory_backend().rejected.is_empty(),
            "a failure before the hook starts is not a verdict on the release"
        );
        assert!(
            store
                .memory_backend()
                .journal
                .as_ref()
                .is_some_and(|tx| !tx.candidate_rejection_required),
            "recovery is retained without inventing rejection evidence"
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
        store.memory_backend_mut().fail_reject = true;
        let mut reconciler = FakeReconciler {
            fail_first_converge: true,
            ..Default::default()
        };

        let outcome = execute_update(
            &mut reconciler,
            &mut store,
            &candidate,
            &digest("archive-two"),
            test_lineage(),
            reconciler_release(),
        )
        .await
        .expect("a failed durable write mid-switchover restarts rather than holding the node down");

        assert!(matches!(outcome, Outcome::RollbackPending));
        assert_eq!(
            store.memory_backend().rejected.len(),
            1,
            "persistence failure cannot erase the live process's rejection evidence"
        );
        assert!(
            store
                .memory_backend()
                .journal
                .as_ref()
                .is_some_and(|tx| tx.candidate_rejection_required),
            "the journal still carries the rollback and the rejection to replay"
        );
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
        for phase in TransactionPhase::ALL {
            assert!(catalog.contains(&boundary::durable_phase(phase)));
        }
    }
}
