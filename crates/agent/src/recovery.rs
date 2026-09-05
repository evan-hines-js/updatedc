//! Bringing an interrupted transaction to a definite end at boot: what the journal says was in
//! flight is either confirmed, rolled back, or reverted, and a rollback that cannot pass its own
//! health gate is bounded rather than retried forever.

use crate::*;

/// Reject the exact deployed unit of a *provisional* (never-health-proven) cold-installed head so
/// the next boot's cold install descends via cold-install fallback past that exact signed package.
///
/// Called only for a head [`boot::plan_gate_failure`] has already classified provisional: a head
/// with a predecessor to revert to takes the revert path instead, and a confirmed head is never
/// rejected for ill health at all.
pub(crate) fn reject_provisional_head(
    store: &mut Store,
    state: &updated::state::InstalledState,
) -> std::io::Result<()> {
    store.reject_deployment(&state.repository_lineage, &state.archive_sha256)?;
    warn(&format!(
        "provisional head {} never passed a health gate; rejected its exact deployment so the \
         next cold install descends via cold-install fallback",
        state.release.version
    ));
    Ok(())
}

/// How many consecutive boots may fail to health-gate a crash-recovered rollback's predecessor
/// before the agent settles on that exact predecessor and reports it unhealthy. More than one so a
/// merely slow-to-start predecessor is not abandoned on its first miss; small so a genuinely broken
/// predecessor cannot keep the node in a service restart loop.
pub(crate) const MAX_ROLLBACK_HEALTH_ATTEMPTS: u32 = 3;

/// What a boot does after a crash-recovered rollback's predecessor fails its health gate.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RollbackHealthOutcome {
    /// Still under the bound: the incremented counter is persisted and the same predecessor is
    /// retried on the next boot. Carries the attempt number for the log.
    Retry(u32),
    /// The bound was reached: the failed candidate's `rollback` compensation has been consumed and
    /// the transaction is terminal. The caller must finish the ordinary recovery commit, retaining
    /// the exact previously confirmed predecessor and reporting its current health as unhealthy.
    SettledUnhealthy,
}

/// Bound rollback-target health failures so a predecessor deployment that can no longer pass the gate
/// cannot crash-loop the node forever. The failure count rides the journal (the very thing that
/// re-derives the rollback on each boot, so it survives the service restart). Once it reaches
/// [`MAX_ROLLBACK_HEALTH_ATTEMPTS`], it marks the rollback terminal. Candidate compensation is an
/// earlier durable barrier and is never coupled to predecessor health. The exact previously
/// confirmed predecessor remains selected; its current health is reported as unhealthy. Recovery
/// never turns a failed direct update into an inferred walk through repository history.
///
/// Settlement advances only across the ordinary `Restored -> RolledBack` edge. It does not
/// manufacture a success verdict; the caller carries the failed health gate into telemetry.
pub(crate) fn bound_unhealthy_rollback(
    store: &mut Store,
    tx: &mut Transaction,
) -> io::Result<RollbackHealthOutcome> {
    let failures = tx.record_rollback_health_failure()?;
    if failures >= MAX_ROLLBACK_HEALTH_ATTEMPTS {
        persist_transaction(store, tx)?;
        if tx.recovery_pending(TransactionPhase::RolledBack) {
            update::advance_transaction(store, tx, TransactionPhase::RolledBack)?;
        }
        Ok(RollbackHealthOutcome::SettledUnhealthy)
    } else {
        // Persist the incremented count (phase unchanged) so the next boot resumes the tally.
        persist_transaction(store, tx)?;
        Ok(RollbackHealthOutcome::Retry(failures))
    }
}

pub(crate) fn recovery_transaction(situation: &Situation) -> Option<Transaction> {
    if let Some(tx) = &situation.journal {
        let committed = match &situation.installed {
            Installed::Present(state) => Some(state.as_ref()),
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
            // commits the predecessor with zero reconciler calls; synthesizing anything here would
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
/// (see [`revert_guarded_head`]) before the pointer ever moved.
pub(crate) fn confirmation_window_rollback(situation: &Situation) -> Option<Transaction> {
    if !situation.predecessor_is_active() {
        return None;
    }
    let Installed::Present(installed) = &situation.installed else {
        return None;
    };
    let pending = installed.rollback_guard.as_ref()?;
    Some(rollback_of_guarded(installed, pending, false))
}

/// The rollback transaction that reverts `installed` to the predecessor its `pending` names — the
/// one shape both the boot gate's revert and the resumption of an interrupted one produce, so a
/// revert that is decided in one boot and driven by the next cannot describe two different things.
pub(crate) fn rollback_of_guarded(
    installed: &updated::state::InstalledState,
    rollback_guard: &RollbackGuard,
    reject_candidate: bool,
) -> Transaction {
    Transaction {
        id: rollback_guard.attempt_id.clone(),
        previous_release: rollback_guard.previous_release.clone(),
        previous_archive_sha256: rollback_guard.previous_archive_sha256.clone(),
        previous_repository_lineage: rollback_guard.previous_repository_lineage.clone(),
        candidate_release: installed.release.clone(),
        candidate_archive_sha256: installed.archive_sha256.clone(),
        candidate_rejection_sha256: rollback_guard.candidate_rejection_sha256.clone(),
        candidate_repository_lineage: installed.repository_lineage.clone(),
        candidate_rejection_required: reject_candidate,
        previous_reconciler: rollback_guard.reconciler.clone(),
        candidate_reconciler: installed.reconciler.clone(),
        rollback_health_failures: 0,
        phase: TransactionPhase::RollbackPlanned,
    }
}

/// Record the revert an unconfirmed release earned by failing its boot health gate: a durable
/// rollback journal, and the candidate's rejection.
///
/// Only the intent is written here — the rollback itself is boot recovery's, the single
/// implementation — so this agent exits and the next boot compensates the failed candidate, then
/// restores, converges, and health-gates the predecessor from exactly this journal.
///
/// `bytes_repaired` is the one thing that withholds the rejection. It is permanent and keyed by
/// archive hash, so it may never be charged to bytes this same boot re-downloaded and re-verified:
/// the gate then failed on a tree that no longer exists. The revert is owed either way — it is
/// reversible — and a release that fails the gate again on the next boot, which finds the tree
/// intact, is charged for it, so the descent still terminates.
pub(crate) fn revert_guarded_head(
    store: &mut Store,
    installed: &updated::state::InstalledState,
    bytes_repaired: bool,
) -> io::Result<()> {
    let pending = installed
        .rollback_guard
        .as_ref()
        .expect("a guarded head has a rollback guard");
    let tx = rollback_of_guarded(installed, pending, !bytes_repaired);
    // A completed forward journal may survive cleanup. Retire that spent record before
    // starting the guard's rollback; its terminal phase cannot be rewritten backwards.
    if let Some(journal) = store.journal()? {
        if boot::journal_recovery(&journal, store.active_release()?.as_ref(), Some(installed))
            == updated::transaction::Recovery::Committed
        {
            store.clear_journal()?;
        }
    }
    warn(&format!(
        "release {} failed its boot health gate inside its confirmation window; reverting to {}",
        installed.release.version, pending.previous_release.version
    ));
    persist_transaction(store, &tx)?;
    if tx.candidate_rejection_required {
        store.reject_deployment(
            &tx.candidate_repository_lineage,
            &tx.candidate_archive_sha256,
        )?;
    }
    Ok(())
}

/// Compensate the failed candidate before any predecessor state is restored. The operation is
/// bound to the candidate's own reconciler and payload; once this barrier is durable, recovery
/// never invokes it again and can safely move on to predecessor convergence.
pub(crate) fn complete_candidate_compensation(
    opts: &Options,
    store: &mut Store,
    recovery: Option<&mut Transaction>,
) -> io::Result<updated_contracts::reconciler::HostAction> {
    let Some(tx) = recovery else {
        return Ok(updated_contracts::reconciler::HostAction::None);
    };
    if !tx.recovery_pending(TransactionPhase::CandidateCompensated) {
        return Ok(updated_contracts::reconciler::HostAction::None);
    }
    let result = run_reconciler_mutation(
        tx.candidate_reconciler.as_ref(),
        opts,
        MutationOperation::Rollback,
        ReconcilerInvocation {
            reason: Reason::Update,
            id: &tx.rollback_attempt_id(),
            candidate: ReleaseTarget {
                release: &tx.candidate_release,
                archive_sha256: &tx.candidate_archive_sha256,
            },
            predecessor: ReleaseTarget {
                release: &tx.previous_release,
                archive_sha256: &tx.previous_archive_sha256,
            },
        },
        None,
    )?;
    Chaos::from_env().crossing(update::boundary::CANDIDATE_ROLLBACK_FINISHED);
    advance_transaction(store, tx, TransactionPhase::CandidateCompensated)?;
    Ok(result.host_action())
}

/// Verify the restored predecessor and replay its output evidence during rollback recovery.
///
/// The compensating attempt tells the native runtime to check actual predecessor health without
/// rerunning its deployment command. The candidate's explicit recovery procedure owns restoration;
/// lost health after a machine reboot requires attention rather than an implicit migration replay.
pub(crate) fn complete_recovery_activation(
    opts: &Options,
    store: &mut Store,
    recovery: Option<&mut Transaction>,
) -> io::Result<updated_contracts::reconciler::HostAction> {
    let Some(tx) = recovery else {
        return Ok(updated_contracts::reconciler::HostAction::None);
    };
    if !tx.recovery_pending(TransactionPhase::RolledBack) {
        return Ok(updated_contracts::reconciler::HostAction::None);
    }
    // The native runtime interprets this compensating converge as predecessor verification.
    let result = run_reconciler_mutation(
        tx.previous_reconciler.as_ref(),
        opts,
        MutationOperation::Converge,
        ReconcilerInvocation {
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
        None,
    )?;
    Chaos::from_env().crossing(update::boundary::PREDECESSOR_CONVERGE_FINISHED);
    if tx.recovery_pending(TransactionPhase::Restored) {
        advance_transaction(store, tx, TransactionPhase::Restored)?;
    }
    Ok(result.host_action())
}

// ============================== boot: gather + execute ==============================

/// Read the durable state the boot planner needs into one [`Situation`].
pub(crate) fn gather_situation(store: &Store) -> io::Result<Situation> {
    let active = store.active_release()?;
    let installed = store.installed()?;
    let journal = store.journal()?;
    Ok(Situation {
        installed,
        active,
        journal,
    })
}

/// Perform a boot [`Plan`]'s durable reconciliation and return the still-unconfirmed
/// update (if any) for the loop to watch.
pub(crate) fn execute_boot_plan(
    plan: &Plan,
    store: &mut Store,
    defer_commit: bool,
    recovery: Option<&mut Transaction>,
) -> io::Result<Option<RollbackGuard>> {
    let activate_release = recovery.as_ref().is_none_or(|tx| {
        !tx.recovery_pending(TransactionPhase::CandidateCompensated)
            && tx.recovery_pending(TransactionPhase::Restored)
    });
    execute_store_plan(plan, store, defer_commit, activate_release)?;
    if activate_release && !matches!(plan.release, ReleaseFix::None) {
        Chaos::from_env().crossing(update::boundary::PREDECESSOR_POINTER_MOVED);
    }
    installed_rollback_guard(store)
}

/// Converge the durable half of a boot [`Plan`] to the [`Store`].
pub(crate) fn execute_store_plan(
    plan: &Plan,
    store: &mut Store,
    defer_commit: bool,
    activate_release: bool,
) -> io::Result<()> {
    // One ordering everywhere: verify/activate the release, then commit metadata that names it.
    // The Store enforces the same relationship, so a future caller cannot accidentally make the
    // installed record authoritative for bytes the active pointer does not run. Immutable releases
    // remain available across either crash boundary; the journal/pending record re-derives the
    // same idempotent plan on the next boot.
    if activate_release {
        match &plan.release {
            ReleaseFix::None => {}
            ReleaseFix::Activate(release) => store.activate(release)?,
        }
    }
    if !defer_commit {
        if let Some(state) = &plan.commit {
            store.commit_installed(state)?;
        }
    }
    for (lineage, hash) in &plan.reject_candidate {
        store.reject_artifact(lineage, hash)?;
    }
    Ok(())
}

/// The unconfirmed update recorded in the installed state, if any.
pub(crate) fn installed_rollback_guard(store: &Store) -> io::Result<Option<RollbackGuard>> {
    Ok(match store.installed()? {
        Installed::Present(s) => s.rollback_guard,
        Installed::Missing | Installed::Invalid => None,
    })
}

/// Run one steady-state probe against the committed release and the reconciler that must
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
    store: &Store,
    probe: impl FnOnce(&updated::bundle::ReleaseId, &str, &updated::state::ReconcilerRelease) -> T,
) -> io::Result<T> {
    match store.installed()? {
        Installed::Present(state) => Ok(probe(
            &state.release,
            &state.archive_sha256,
            &state.reconciler,
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
pub(crate) fn disarm_update_rollback(store: &mut Store) -> bool {
    match store.installed() {
        Ok(Installed::Present(mut st)) => {
            if !st.disarm_rollback() {
                return true;
            }
            if let Err(e) = store.commit_installed(&st) {
                // Could not durably clear the pending intent; retry on the next tick or boot.
                warn(&format!(
                    "could not durably confirm the update ({e}); will retry"
                ));
                return false;
            }
            true
        }
        Ok(Installed::Missing | Installed::Invalid) => {
            // In-memory pending intent must not be cleared when its authoritative durable record
            // disappeared or became corrupt. Keep reporting the update in flight and let the next
            // boot fail closed on the same state.
            warn("could not durably confirm the update: installed state is missing or invalid");
            false
        }
        Err(error) => {
            warn(&format!(
                "could not read installed state while confirming the update ({error}); will retry"
            ));
            false
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod confirmation_tests {
    use super::*;
    use crate::test_support::{deployment_rejection, digest, lineage, provider, release};

    fn unconfirmed_update() -> updated::state::InstalledState {
        updated::state::InstalledState {
            repository_lineage: lineage(),
            release: release("2.0.0", "candidate"),
            archive_sha256: digest("candidate-archive"),
            reconciler: provider(),
            rollback_guard: Some(updated::state::RollbackGuard {
                attempt_id: digest("attempt"),
                candidate_rejection_sha256: deployment_rejection(&digest("candidate-archive")),
                previous_release: release("1.0.0", "predecessor"),
                previous_archive_sha256: digest("predecessor-archive"),
                previous_repository_lineage: lineage(),
                reconciler: provider(),
                committed_at: 1,
            }),
            maturity: Maturity::Proven,
        }
    }

    #[test]
    fn confirmation_clears_memory_only_after_the_durable_transition() {
        let candidate = unconfirmed_update();
        let mut store = Store::memory(MemoryBackend {
            active: Some(candidate.release.clone()),
            installed: Some(candidate),
            ..Default::default()
        });

        assert!(disarm_update_rollback(&mut store));
        assert!(matches!(
            store.installed().unwrap(),
            Installed::Present(state) if state.rollback_guard.is_none()
        ));

        store.memory_backend_mut().installed = None;
        assert!(!disarm_update_rollback(&mut store));

        let mut corrupt = unconfirmed_update();
        corrupt.archive_sha256 = "not-a-digest".into();
        store.memory_backend_mut().installed = Some(corrupt);
        assert!(!disarm_update_rollback(&mut store));
    }
}
