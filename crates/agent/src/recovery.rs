//! Bringing an interrupted transaction to a definite end at boot: what the journal says was in
//! flight is either confirmed, rolled back, or reverted, and a rollback that cannot pass its own
//! health gate is bounded rather than retried forever.

use crate::*;

/// Reject the bytes of a *provisional* (never-health-proven) cold-installed head so the next
/// boot's cold install descends via ordered fallback past it.
///
/// Called only for a head [`boot::plan_gate_failure`] has already classified provisional: a head
/// with a predecessor to revert to takes the revert path instead, and a confirmed head is never
/// rejected for ill health at all.
pub(crate) fn reject_provisional_head(
    store: &mut FileStore,
    state: &updated::state::InstalledState,
) -> std::io::Result<()> {
    store.reject(&state.repository_lineage, &state.archive_sha256)?;
    warn(&format!(
        "provisional head {} never passed a health gate; rejected its bytes so the next cold \
         install descends via ordered fallback",
        state.release.version
    ));
    Ok(())
}

/// How many consecutive boots may fail to health-gate a crash-recovered rollback's predecessor
/// before the agent stops retrying it and descends via ordered fallback. More than one so a
/// merely slow-to-start predecessor is not abandoned on its first miss; small so a genuinely broken
/// predecessor cannot keep the node down for long.
pub(crate) const MAX_ROLLBACK_HEALTH_ATTEMPTS: u32 = 3;

/// What a boot does after a crash-recovered rollback's predecessor fails its health gate.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RollbackHealthOutcome {
    /// Still under the bound: the incremented counter is persisted and the same predecessor is
    /// retried on the next boot. Carries the attempt number for the log.
    Retry(u32),
    /// The bound was reached: the failed candidate's `rollback` compensation is run first, then the
    /// predecessor's bytes are rejected, it is recorded as a provisional (now-rejected) head, and
    /// the rollback journal is cleared, so the next boot's [`ensure_installed`] descends via ordered
    /// fallback past it exactly as a cold install does.
    Descend,
}

/// Bound rollback-target health failures so a predecessor whose bytes can no longer pass the gate
/// cannot crash-loop the node forever. The failure count rides the journal (the very thing that
/// re-derives the rollback on each boot, so it survives the launcher relaunch). Once it reaches
/// [`MAX_ROLLBACK_HEALTH_ATTEMPTS`], this compensates the failed candidate through the release's
/// own `rollback` — the agent promises reconciler authors that every `apply` it drives is
/// compensated, and abandoning the transaction here would break that promise with the journal
/// destroyed — and then rejects the predecessor, records it provisional, and drops the journal, so
/// the next boot descends via the cold-install ordered-fallback path instead of relaunching the
/// same broken predecessor.
///
/// The compensation is journaled before it is attempted, and the failure tally is the durable
/// marker that makes it one shot rather than a relaunch loop: the boot that reaches the bound
/// persists the count at exactly [`MAX_ROLLBACK_HEALTH_ATTEMPTS`] before invoking the hook, so a
/// boot that finds the count already past the bound knows the previous attempt did not complete and
/// descends uncompensated instead of relaunching into it forever. Worst case, two boots.
///
/// The phase is deliberately not advanced across this: the predecessor never became healthy, and
/// [`Transaction::advance`] admits only the true rollback edges.
pub(crate) fn bound_unhealthy_rollback(
    store: &mut dyn Store,
    tx: &mut Transaction,
    compensate: &mut dyn FnMut(&Transaction) -> io::Result<()>,
) -> io::Result<RollbackHealthOutcome> {
    let failures = tx.record_rollback_health_failure()?;
    if failures >= MAX_ROLLBACK_HEALTH_ATTEMPTS {
        if failures == MAX_ROLLBACK_HEALTH_ATTEMPTS {
            // Journal the intent first, so a compensation that dies mid-flight is not re-attempted
            // forever by the boots that follow.
            persist_transaction(store, tx)?;
            compensate(tx)?;
            Chaos::from_env().crossing(update::boundary::ROLLBACK_ADAPTER_APPLIED);
        } else {
            warn(
                "the failed candidate's rollback compensation was already attempted and did not \
                 complete; descending uncompensated rather than relaunching into it forever",
            );
            // Record the observation as its own state transition before moving the phase. Keeping
            // one durable mutation per write lets the storage boundary reject skipped history
            // without needing a special compound-transition escape hatch.
            persist_transaction(store, tx)?;
        }
        // Conclude the rollback only after the compensation completed or its one durable attempt
        // was consumed. There is no metadata-only finalize phase.
        if tx.recovery_pending(TransactionPhase::RolledBack) {
            update::advance_transaction(store, tx, TransactionPhase::RolledBack)?;
        }
        store.reject(&tx.previous_repository_lineage, &tx.previous_archive_sha256)?;
        store.commit_installed(&updated::state::InstalledState::provisional(
            tx.previous_repository_lineage.clone(),
            tx.previous_release.clone(),
            tx.previous_archive_sha256.clone(),
            tx.lifecycle.clone(),
        ))?;
        store.clear_journal()?;
        Ok(RollbackHealthOutcome::Descend)
    } else {
        // Persist the incremented count (phase unchanged) so the next boot resumes the tally.
        persist_transaction(store, tx)?;
        Ok(RollbackHealthOutcome::Retry(failures))
    }
}

pub(crate) fn recovery_transaction(situation: &Situation) -> Option<Transaction> {
    if let Some(tx) = &situation.journal {
        let committed = match &situation.installed {
            Installed::Present(state) => Some(&state.release),
            Installed::Missing | Installed::Invalid => None,
        };
        return match boot::journal_recovery(tx, situation.active.as_ref(), committed) {
            // The predecessor must actually be restored: this journal IS the recovery, and it is
            // resumed from its own recorded phase.
            updated::transaction::Recovery::RestorePredecessor => Some(tx.clone()),
            // The update's commit landed, so this journal has nothing left to undo — it is merely
            // spent (a tolerated `clear_journal` failure, or a crash between the commit and the
            // journal's terminal write) — including when the active pointer has since moved off the
            // candidate, which [`boot::journal_recovery`] resolves rather than mistaking a spent
            // journal for a rollback it can never drive. What matters now is the same thing with no
            // journal at all: the boot plan treats the committed record's `pending` as
            // authoritative, so this boot may still be a confirmation-window revert. Derive that
            // rollback from `pending` exactly as the journal-less path does — the candidate's
            // machine-state changes are owed a compensating `rollback` either way, and a spent
            // file on disk must not be what decides whether they are undone.
            updated::transaction::Recovery::Committed => confirmation_window_rollback(situation),
            // Nothing was ever displaced (a pre-activation crash), or the rollback already ran to
            // completion. `reconcile_transaction` clears the journal and, for a finished rollback,
            // commits the predecessor with zero lifecycle calls; synthesizing anything here would
            // re-run an already-completed rollback machine and double-invoke every hook.
            updated::transaction::Recovery::NeverSwapped => None,
        };
    }
    confirmation_window_rollback(situation)
}

/// The rollback owed by the committed record itself, when a previous boot already moved the active
/// pointer back to `pending.previous_release` but died before the compensating `rollback` and the
/// final commit. It is the revert [`boot::plan_boot`] completes off `pending`, and it must replay
/// the operator's `rollback` for the candidate's machine-state changes.
///
/// The rejection is NOT re-derived here: the boot that judged the candidate recorded it durably
/// (see [`revert_unconfirmed_head`]) before the pointer ever moved.
pub(crate) fn confirmation_window_rollback(situation: &Situation) -> Option<Transaction> {
    let Installed::Present(installed) = &situation.installed else {
        return None;
    };
    let pending = installed.pending.as_ref()?;
    if situation.active.as_ref() != Some(&pending.previous_release) {
        return None;
    }
    Some(rollback_of_unconfirmed(installed, pending, false))
}

/// The rollback transaction that reverts `installed` to the predecessor its `pending` names — the
/// one shape both the boot gate's revert and the resumption of an interrupted one produce, so a
/// revert that is decided in one boot and driven by the next cannot describe two different things.
pub(crate) fn rollback_of_unconfirmed(
    installed: &updated::state::InstalledState,
    pending: &Pending,
    reject_candidate: bool,
) -> Transaction {
    Transaction {
        id: pending.lifecycle_attempt_id.clone(),
        previous_release: pending.previous_release.clone(),
        previous_archive_sha256: pending.previous_archive_sha256.clone(),
        previous_repository_lineage: pending.previous_repository_lineage.clone(),
        candidate_release: installed.release.clone(),
        candidate_archive_sha256: installed.archive_sha256.clone(),
        candidate_rejection_sha256: pending.candidate_rejection_sha256.clone(),
        candidate_repository_lineage: installed.repository_lineage.clone(),
        candidate_rejection_required: reject_candidate,
        lifecycle: pending.lifecycle.clone(),
        rollback_health_failures: 0,
        phase: TransactionPhase::RollbackActivating,
    }
}

/// Record the revert an unconfirmed release earned by failing its boot health gate: a durable
/// rollback journal, and the candidate's rejection.
///
/// Only the intent is written here — the rollback itself is boot recovery's, the single
/// implementation — so this agent exits and the next boot restores the predecessor's pointer, runs
/// its `apply`, gates it, and replays the compensating `rollback` from exactly this journal.
///
/// `bytes_repaired` is the one thing that withholds the rejection. It is permanent and keyed by
/// archive hash, so it may never be charged to bytes this same boot re-downloaded and re-verified:
/// the gate then failed on a tree that no longer exists. The revert is owed either way — it is
/// reversible — and a release that fails the gate again on the next boot, which finds the tree
/// intact, is charged for it, so the descent still terminates.
pub(crate) fn revert_unconfirmed_head(
    store: &mut dyn Store,
    installed: &updated::state::InstalledState,
    bytes_repaired: bool,
) -> io::Result<()> {
    let pending = installed
        .pending
        .as_ref()
        .expect("an unconfirmed head has a pending record");
    let tx = rollback_of_unconfirmed(installed, pending, !bytes_repaired);
    warn(&format!(
        "release {} failed its boot health gate inside its confirmation window; reverting to {}",
        installed.release.version, pending.previous_release.version
    ));
    persist_transaction(store, &tx)?;
    if tx.candidate_rejection_required {
        store.reject(
            &installed.repository_lineage,
            &tx.candidate_rejection_sha256,
        )?;
    }
    Ok(())
}

/// Converge the machine onto the restored predecessor during a rollback recovery.
///
/// The boot converge is the committed release's `apply` and never runs during recovery, so this is
/// the only thing that starts the predecessor's workload. An incomplete rollback owes a converged
/// predecessor until it reaches `RolledBack` — not merely one historical `apply` — because a machine
/// reboot (rather than an agent kill) at any later rollback phase leaves the predecessor's workload
/// stopped and the boot gate would then fail a perfectly healthy release. The `apply` is idempotent
/// by the Execution contract, so replaying it on every resume boot is exactly the right semantics.
///
/// It runs under the transaction's compensating attempt identity, never the forward one: the
/// forward switchover already invoked `apply` under `tx.id` with the *candidate* as `--candidate`,
/// and a reconciler that keys completion on the attempt id would otherwise skip this one.
pub(crate) fn complete_recovery_activation(
    opts: &Options,
    store: &mut dyn Store,
    recovery: Option<&mut Transaction>,
) -> io::Result<updated_contracts::reconciler::HostAction> {
    let Some(tx) = recovery else {
        return Ok(updated_contracts::reconciler::HostAction::None);
    };
    if !tx.recovery_pending(TransactionPhase::RolledBack) {
        return Ok(updated_contracts::reconciler::HostAction::None);
    }
    // Restore the predecessor's machine state through the same reconciler operation used for the
    // candidate — the predecessor's own `apply`, which is what re-converges whatever it owns.
    let result = run_lifecycle_mutation(
        tx.lifecycle.as_ref(),
        opts,
        MutationOperation::Apply,
        LifecycleInvocation {
            reason: Reason::Update,
            id: &tx.rollback_attempt_id(),
            candidate: ReleaseTarget {
                release: &tx.previous_release,
                archive_sha256: &tx.previous_archive_sha256,
            },
            predecessor: ReleaseTarget {
                release: &tx.candidate_release,
                archive_sha256: &tx.candidate_archive_sha256,
            },
        },
    )?;
    if result.host_action == updated_contracts::reconciler::HostAction::Reboot {
        return Ok(result.host_action);
    }
    Chaos::from_env().crossing(update::boundary::PREDECESSOR_LIFECYCLE_APPLIED);
    if tx.recovery_pending(TransactionPhase::RollbackApplied) {
        advance_transaction(store, tx, TransactionPhase::RollbackApplied)?;
    }
    Ok(updated_contracts::reconciler::HostAction::None)
}

// ============================== boot: gather + execute ==============================

/// Read the whole world the boot planner needs — durable state via the [`Store`] and the
/// launcher's rejection marker, already claimed into [`launcher::Evidence`] — into one
/// [`Situation`]. The shell's single point of input gathering. Reading evidence leaves it on disk;
/// the boot path clears the claim only once the intent it implies is durable.
pub(crate) fn gather_situation(
    opts: &Options,
    store: &dyn Store,
    evidence: &launcher::Evidence,
) -> io::Result<Situation> {
    let active = store.active_release()?;
    let installed = store.installed();
    let journal = store.journal()?;
    Ok(Situation {
        installed,
        active,
        journal,
        bad_agent: evidence.rejected_agent().map(PathBuf::from),
        confirm_window: opts.timeouts.confirmation_window,
        now: now_unix(),
    })
}

/// Perform a boot [`Plan`]'s durable reconciliation and return the still-unconfirmed
/// update (if any) for the loop to watch.
pub(crate) fn execute_boot_plan(
    plan: &Plan,
    store: &mut dyn Store,
    self_update: &mut SelfUpdateState,
    defer_commit: bool,
    recovery: Option<&mut Transaction>,
    evidence: &mut launcher::Evidence,
) -> io::Result<Option<Pending>> {
    let activate_release = recovery
        .as_ref()
        .is_none_or(|tx| tx.recovery_pending(TransactionPhase::RollbackApplied));
    apply_store_plan(plan, store, defer_commit, activate_release)?;
    if activate_release && !matches!(plan.release, ReleaseFix::None) {
        Chaos::from_env().crossing(update::boundary::PREDECESSOR_POINTER_APPLIED);
    }
    if let Some(path) = &plan.reject_agent {
        // Fallible on purpose, and cleared only here: a rejection that failed to reach disk must
        // not be mistaken for a durable one. If the write fails this boot fails with the marker
        // intact, so the next boot rejects the same candidate instead of re-staging it forever.
        //
        // With one exception, which is the marker module's own stated invariant: bytes that are not
        // a content-addressed `agents/<hash>/<binary>` path — a stray write, a truncated or
        // partially restored file — name no hash to suppress and are not evidence about any
        // candidate. Failing the boot on them would fail identically on every subsequent boot (the
        // marker is only ever cleared here), leaving the node permanently unbootable, so they are
        // discarded with a warning and the marker is cleared.
        //
        // The shape is decided HERE, before the write is attempted, and `reject_candidate` takes
        // the extracted hash rather than re-deriving it: a failing write reports `InvalidInput`
        // for a bad key too, so classifying the error afterwards would make "malformed marker"
        // and "the rejection did not reach disk" the same test.
        if let Some(hash) = rejected_agent_hash(path) {
            self_update.reject_candidate(hash)?;
        } else {
            warn(&format!(
                "discarding an unusable rejected-agent marker: {} is not a content-addressed \
                 agents/<hash>/<binary> path and names no candidate to suppress",
                path.display()
            ));
        }
        evidence.clear_rejected_agent()?;
    }
    Ok(installed_pending(store))
}

/// Apply the durable half of a boot [`Plan`] to the [`Store`].
pub(crate) fn apply_store_plan(
    plan: &Plan,
    store: &mut dyn Store,
    defer_commit: bool,
    activate_release: bool,
) -> io::Result<()> {
    // Commit the intended state before activation; immutable predecessor releases remain
    // available if a crash interrupts pointer reconciliation.
    if !defer_commit {
        if let Some(state) = &plan.commit {
            store.commit_installed(state)?;
        }
    }
    if activate_release {
        match &plan.release {
            ReleaseFix::None => {}
            ReleaseFix::Activate(release) => store.activate(release)?,
        }
    }
    for (lineage, hash) in &plan.reject_app {
        store.reject(lineage, hash)?;
    }
    Ok(())
}

/// The candidate hash a rejected-agent marker names, or `None` when the marker's bytes are
/// not a content-addressed `agents/<hash>/<binary>` path.
///
/// The one place that extraction happens; the hash it yields is what `reject_candidate` records.
/// It applies the very predicate `Rejections::reject` validates with — [`updated::reject::is_rejection_key`],
/// called rather than restated — so this accepts exactly the markers that path would accept
/// however that grammar moves. Every marker it turns down would have failed there with no hash
/// recorded anyway.
pub(crate) fn rejected_agent_hash(path: &std::path::Path) -> Option<&str> {
    let hash = path.parent()?.file_name()?.to_str()?;
    updated::reject::is_rejection_key(hash).then_some(hash)
}

/// The unconfirmed update recorded in the installed state, if any.
pub(crate) fn installed_pending(store: &dyn Store) -> Option<Pending> {
    match store.installed() {
        Installed::Present(s) => s.pending,
        _ => None,
    }
}

/// The application, provider-set and manifest digests of the committed head, for the heartbeat.
/// Read from the store at report time rather than tracked alongside the running version: the
/// version is a local carried across four separate commit paths, and a digest that drifted out of
/// step with it would name bytes that are not running — worse than naming none. Empty when nothing
/// is committed (no install yet, or an unreadable record), reported as "running no known bytes".
pub(crate) fn installed_release_identity(store: &dyn Store) -> (String, String, String) {
    match store.installed() {
        Installed::Present(state) => (
            state.archive_sha256,
            state.lifecycle.provider_set_sha256.clone(),
            state.release.manifest_sha256,
        ),
        _ => (String::new(), String::new(), String::new()),
    }
}

/// Run one steady-state probe against the committed release and the lifecycle provider that must
/// invoke it, read together from the one installed record.
///
/// The record is read here, inside the call, and `probe` only ever *borrows* what it names — so a
/// caller cannot hold a target across ticks without deliberately cloning one, and the shape the
/// loop used to have (resolve once at boot, reuse forever) does not compile. That matters because
/// `garbage_collect` protects exactly the provider release this record names, so any second copy of
/// it is a release the collector is free to prune: an in-loop repair commits a different provider
/// (its own `stage_providers` result), the boot-time copy then named a provider bundle that was
/// about to disappear, and every periodic probe after it failed to resolve — so a node whose
/// release was serving perfectly well reported itself unready and was drained out of rotation.
pub(crate) fn probe_steady_target<T>(
    store: &dyn Store,
    probe: impl FnOnce(&updated::bundle::ReleaseId, &str, &updated::state::ProviderRelease) -> T,
) -> io::Result<T> {
    match store.installed() {
        Installed::Present(state) => Ok(probe(
            &state.release,
            &state.archive_sha256,
            &state.lifecycle,
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "a verified installed release is required",
        )),
    }
}

/// Confirm the current update by clearing its pending record.
/// Returns `true` only once the confirmation is durable, so callers must keep their
/// in-memory pending intent (and continue suppressing updates) after a write failure.
pub(crate) fn confirm_update(store: &mut dyn Store) -> bool {
    if let Installed::Present(mut st) = store.installed() {
        st.pending = None;
        if let Err(e) = store.commit_installed(&st) {
            // Could not durably clear the pending intent; retry on the next tick or boot.
            warn(&format!(
                "could not durably confirm the update ({e}); will retry"
            ));
            return false;
        }
    }
    true
}
