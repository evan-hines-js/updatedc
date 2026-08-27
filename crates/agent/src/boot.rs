//! Pure boot reconciliation for immutable application releases.

use crate::domain::*;
use updated::transaction::{self, Recovery};

pub(crate) fn plan_boot(s: &Situation) -> Plan {
    let mut plan = Plan::default();
    let state = match &s.installed {
        Installed::Present(state) => state.clone(),
        Installed::Missing => {
            plan.fail_closed = Some(
                "installed state is missing; seed a verified initial bundle before launch".into(),
            );
            return plan;
        }
        Installed::Invalid => {
            plan.fail_closed = Some("installed state present but INVALID (corrupt)".into());
            return plan;
        }
    };
    plan.current = Some(state.release.version.clone());

    let pending_revert_in_progress = state
        .pending
        .as_ref()
        .is_some_and(|pending| s.active.as_ref() == Some(&pending.previous_release));
    // A journal that still has recovery work to drive owns this boot's release reconciliation. A
    // journal that is merely SPENT (see [`journal_recovery`]) is cleared and otherwise says nothing:
    // the committed record decides, exactly as it does when no journal is on disk at all. Letting a
    // spent file take the wheel is what left a boot planning a reconciliation whose every resume
    // gate was closed — and then deleting the only evidence of it.
    let carries_recovery = match &s.journal {
        Some(tx) => reconcile_transaction(&mut plan, s, tx, &state) != Recovery::Committed,
        None => false,
    };
    let pending_authoritative = if carries_recovery {
        false
    } else if pending_revert_in_progress {
        complete_pending_rollback(&mut plan, &state);
        false
    } else {
        enforce_installed(&mut plan, s, &state);
        if plan.fail_closed.is_some() {
            return plan;
        }
        true
    };

    if pending_authoritative {
        if let Some(pending) = &state.pending {
            confirm_if_window_passed(&mut plan, s, &state, pending);
        }
    }

    plan.reject_agent = s.bad_agent.clone();
    plan
}

/// What a boot owes when its health gate does not pass — the only local revert path left, and the
/// reason it is bounded to the confirmation window.
///
/// The `healthcheck` hook is the single health source, so a gate failure is the one piece of
/// evidence this node has about the release it is running. Inside the confirmation window that is
/// worth a local revert: the predecessor is still on disk, the rollback intent is already recorded,
/// and the fleet has nothing better to offer. Past it — a CONFIRMED release that has proven itself
/// once — it is not: the hook may converge later, and a node that reverts itself on every unhealthy
/// window would fight the reconciler it is supposed to obey. Ill health there is reported and
/// nothing else (`health.last_ready = false` in the node's report), leaving the decision to the
/// control plane.
pub(crate) fn plan_gate_failure(installed: &InstalledState) -> GateFailure {
    if installed.pending.is_some() {
        GateFailure::Revert
    } else if !installed.confirmed {
        GateFailure::RejectProvisional
    } else {
        GateFailure::Report
    }
}

/// The three answers to a failed boot health gate. See [`plan_gate_failure`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GateFailure {
    /// An update is still inside its confirmation window: revert to the predecessor its `pending`
    /// record names and reject the candidate's bytes.
    Revert,
    /// A provisional head that has never proven healthy: reject its bytes so the next boot's cold
    /// install descends via ordered fallback past it.
    RejectProvisional,
    /// A confirmed release: report it unhealthy and keep running. Never reverted locally.
    Report,
}

/// A prior agent restored the predecessor pointer but crashed before the external rollback and
/// the final state commit. Preserve that direction: never "repair" the pointer back to the failed
/// candidate, and record the predecessor as what this node is running.
fn complete_pending_rollback(plan: &mut Plan, state: &InstalledState) {
    let pending = state
        .pending
        .as_ref()
        .expect("a rollback in progress has a pending record");
    plan.release = ReleaseFix::Activate(pending.previous_release.clone());
    // Carry the predecessor's providers (the operator set `pending` holds for exactly this
    // rollback) onto the restored record.
    plan.commit = Some(InstalledState::confirmed(
        pending.previous_repository_lineage.clone(),
        pending.previous_release.clone(),
        pending.previous_archive_sha256.clone(),
        pending.lifecycle.clone(),
    ));
    plan.current = Some(pending.previous_release.version.clone());
    plan.warn(format!(
        "recovery: completing rollback from {} to {}",
        state.release.version, pending.previous_release.version
    ));
}

/// Whether a journal can still *drive* a rollback, asked of the phase machine itself rather than of
/// a list of phases: the recovery driver's own two steps, replayed on a throwaway copy.
///
/// A journal off the rollback path is first moved onto it (`advance` to `RollbackActivating`), which
/// the phase machine refuses from a terminal phase; a journal already on the path has work left
/// exactly while a resume gate is open, which is what `recovery_pending` up to the final phase
/// answers. Deriving it this way means a change to the phase machine moves this with it — the
/// enumerate-one-phase version of this test is precisely what let `RolledBack` through.
///
/// Its negation is the single definition of a SPENT journal — one whose transaction reached its end
/// state, so nothing is left to reconcile — which is why [`crate::update::apply_update`] asks this
/// too before deleting one rather than naming the terminal phases a second time.
pub(crate) fn drives_rollback(tx: &Transaction) -> bool {
    let mut probe = tx.clone();
    if !probe.is_rollback() && probe.advance(TransactionPhase::RollbackActivating).is_err() {
        return false;
    }
    probe.recovery_pending(TransactionPhase::RolledBack)
}

/// The recovery a journal on disk can actually *drive*.
///
/// [`transaction::classify_recovery`] reports what the world looks like. This adds the one fact only
/// the recovery driver knows: a journal in a TERMINAL phase — `Committed`, whose forward commit
/// landed, or `RolledBack`, whose rollback ran to the end — is SPENT. The phase machine refuses to
/// (re)start a rollback from either (`Transaction::advance`), and every resume gate reads
/// `rollback_rank`, which for a terminal phase leaves nothing pending. See [`drives_rollback`],
/// which asks the machine instead of naming the phases.
///
/// Such a journal outlives its transaction whenever `clear_journal` fails (tolerated, with a
/// warning, by the update's switch-over and by the rollback's finalize), and it stops classifying
/// benignly the moment the active pointer moves off the release it names — an in-loop repair
/// falling back to the predecessor, or a restored backup. Classified `RestorePredecessor` it
/// produced a boot that planned an
/// activation and a commit, ran neither (every gate closed), and cleared the journal anyway:
/// the node ran one release while the installed record — and every heartbeat derived from it —
/// named another. It is spent, so the committed record decides instead.
pub(crate) fn journal_recovery(
    tx: &Transaction,
    active: Option<&updated::bundle::ReleaseId>,
    committed: Option<&InstalledState>,
) -> Recovery {
    match transaction::classify_recovery(tx, active, committed) {
        Recovery::RestorePredecessor if !drives_rollback(tx) => Recovery::Committed,
        recovery => recovery,
    }
}

fn reconcile_transaction(
    plan: &mut Plan,
    situation: &Situation,
    tx: &Transaction,
    installed: &InstalledState,
) -> Recovery {
    plan.clear_journal = true;
    let recovery = journal_recovery(tx, situation.active.as_ref(), Some(installed));
    if tx.candidate_rejection_required {
        plan.reject_candidate.push((
            tx.candidate_repository_lineage.clone(),
            tx.candidate_rejection_sha256.clone(),
        ));
        plan.warn(format!(
            "recovery: rejected {} after failed activation",
            tx.candidate_release.version
        ));
    }
    match recovery {
        // Spent: nothing left to drive, so the journal contributes nothing but its own removal (and
        // any rejection it recorded above). In particular it must NOT commit a release record — the
        // committed record, reconciled below, is what names what this node runs.
        Recovery::Committed => {
            plan.info(format!(
                "recovery: journal for {} is spent at phase {:?}",
                tx.candidate_release.version, tx.phase
            ));
            return recovery;
        }
        Recovery::NeverSwapped => plan.info(format!(
            "recovery: activation of {} never landed",
            tx.candidate_release.version
        )),
        Recovery::RestorePredecessor => {
            // Restore the pointer the interrupted activation displaced. The candidate is rejected
            // only when the journal says so (`candidate_rejection_required`, written by the
            // transaction that judged it): an interrupted activation is evidence about this
            // process, never about the candidate's bytes.
            plan.release = ReleaseFix::Activate(tx.previous_release.clone());
            plan.warn(format!(
                "recovery: restoring predecessor {} after interrupted activation of {}",
                tx.previous_release.version, tx.candidate_release.version
            ));
        }
    }
    if tx.is_rollback() {
        // Restore the predecessor *with* the operator providers the transaction staged, so a
        // crash-recovered rollback health-gates and crash-watches the predecessor identically to
        // an in-process one rather than committing a provider-less record.
        plan.commit = Some(InstalledState::confirmed(
            tx.previous_repository_lineage.clone(),
            tx.previous_release.clone(),
            tx.previous_archive_sha256.clone(),
            tx.previous_lifecycle.clone(),
        ));
        plan.current = Some(tx.previous_release.version.clone());
    }
    recovery
}

fn enforce_installed(plan: &mut Plan, situation: &Situation, installed: &InstalledState) {
    if situation.active.as_ref() == Some(&installed.release) {
        return;
    }
    // The installed release is immutable and remains the authoritative recovery target.
    // The executor re-verifies it at the activation/commit moment before changing
    // active-release; the steady-state pointer match above is trusted without a re-hash.
    plan.release = ReleaseFix::Activate(installed.release.clone());
    plan.warn(format!(
        "active release drifted; restoring committed {}",
        installed.release.version
    ));
}

/// An update that ran its whole confirmation window is settled: clear its rollback intent so the
/// predecessor can be collected. A window that is still open is left alone — the boot health gate
/// below decides it, and a failing gate reverts through [`plan_gate_failure`].
fn confirm_if_window_passed(
    plan: &mut Plan,
    situation: &Situation,
    installed: &InstalledState,
    pending: &Pending,
) {
    if window_passed(pending, situation.confirm_window, situation.now) {
        // The value owns the one settlement transition. Cloning then settling preserves every
        // other authenticated identity field instead of reconstructing a lookalike record here.
        let mut settled = installed.clone();
        let changed = settled.settle_update();
        debug_assert!(changed, "this branch is entered with a pending update");
        plan.commit = Some(settled);
        plan.info(format!("release {} confirmed", installed.release.version));
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::test_support::{deployment_rejection, digest, lineage, provider, release};
    use std::time::Duration;
    use updated::bundle::ReleaseId;

    fn steady() -> Situation {
        let current = release("1.0.0", "one");
        let installed = InstalledState::confirmed(
            lineage(),
            current.clone(),
            digest("archive-one"),
            provider(),
        );
        installed.validate().expect("nominal fixture is durable");
        Situation {
            installed: Installed::Present(Box::new(installed)),
            active: Some(current),
            journal: None,
            bad_agent: None,
            confirm_window: Duration::from_secs(60),
            now: 100,
        }
    }

    fn transaction(
        predecessor: ReleaseId,
        candidate: ReleaseId,
        phase: TransactionPhase,
        candidate_rejection_required: bool,
    ) -> Transaction {
        let tx = Transaction {
            id: digest("attempt"),
            previous_release: predecessor,
            previous_archive_sha256: digest("archive-one"),
            previous_repository_lineage: lineage(),
            candidate_release: candidate,
            candidate_archive_sha256: digest("archive-two"),
            candidate_rejection_sha256: deployment_rejection(
                &digest("archive-two"),
                &provider().provider_set_sha256,
            ),
            candidate_repository_lineage: lineage(),
            candidate_rejection_required,
            previous_lifecycle: provider(),
            candidate_lifecycle: provider(),
            rollback_health_failures: 0,
            phase,
        };
        tx.validate().expect("nominal fixture is durable");
        tx
    }

    fn update_head(predecessor: ReleaseId, candidate: ReleaseId) -> InstalledState {
        let tx = transaction(predecessor, candidate, TransactionPhase::Committed, false);
        let state = InstalledState {
            repository_lineage: tx.candidate_repository_lineage,
            release: tx.candidate_release,
            archive_sha256: tx.candidate_archive_sha256,
            lifecycle: tx.candidate_lifecycle,
            pending: Some(Pending {
                lifecycle_attempt_id: tx.id,
                candidate_rejection_sha256: tx.candidate_rejection_sha256,
                previous_release: tx.previous_release,
                previous_archive_sha256: tx.previous_archive_sha256,
                previous_repository_lineage: tx.previous_repository_lineage,
                committed_at: 100,
                lifecycle: tx.previous_lifecycle,
            }),
            confirmed: true,
        };
        state.validate().expect("nominal fixture is durable");
        state
    }

    #[test]
    fn steady_release_is_unchanged() {
        let plan = plan_boot(&steady());
        assert_eq!(plan.release, ReleaseFix::None);
        assert_eq!(plan.current.as_deref(), Some("1.0.0"));
    }

    #[test]
    fn interrupted_activation_restores_the_predecessor() {
        let mut situation = steady();
        let candidate = release("2.0.0", "two");
        situation.active = Some(candidate.clone());
        situation.journal = Some(transaction(
            release("1.0.0", "one"),
            candidate,
            TransactionPhase::Activating,
            true,
        ));
        let plan = plan_boot(&situation);
        assert_eq!(plan.release, ReleaseFix::Activate(release("1.0.0", "one")));
        assert_eq!(
            plan.reject_candidate,
            vec![(
                lineage(),
                deployment_rejection(&digest("archive-two"), &provider().provider_set_sha256)
            )]
        );
        assert!(plan
            .notes
            .iter()
            .any(|note| note.msg == "recovery: rejected 2.0.0 after failed activation"));
    }

    #[test]
    fn agent_crash_during_activation_does_not_poison_the_release() {
        let mut situation = steady();
        let candidate = release("2.0.0", "two");
        situation.active = Some(candidate.clone());
        situation.journal = Some(transaction(
            release("1.0.0", "one"),
            candidate,
            TransactionPhase::Activating,
            false,
        ));
        let plan = plan_boot(&situation);
        assert!(plan.reject_candidate.is_empty());
    }

    #[test]
    fn a_journaled_rejection_is_replayed_on_the_rollback_path() {
        let predecessor = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut situation = steady();
        situation.active = Some(predecessor.clone());
        situation.installed = Installed::Present(Box::new(InstalledState {
            repository_lineage: lineage(),
            release: candidate.clone(),
            archive_sha256: digest("archive-two"),
            lifecycle: provider(),
            pending: None,
            confirmed: true,
        }));
        situation.journal = Some(transaction(
            predecessor,
            candidate,
            TransactionPhase::RollbackActivating,
            true,
        ));

        let plan = plan_boot(&situation);

        assert_eq!(
            plan.reject_candidate,
            vec![(
                lineage(),
                deployment_rejection(&digest("archive-two"), &provider().provider_set_sha256)
            )]
        );
    }

    #[test]
    fn journaled_rejection_is_replayed_when_activation_failed_before_pointer_move() {
        let predecessor = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut situation = steady();
        situation.journal = Some(transaction(
            predecessor.clone(),
            candidate,
            // Activation intent is durable before the Store re-verifies and moves the pointer.
            // A verification failure can therefore reject the candidate while the pointer still
            // names the predecessor, but a Prepared journal cannot carry that verdict.
            TransactionPhase::Activating,
            true,
        ));

        let plan = plan_boot(&situation);

        assert_eq!(plan.release, ReleaseFix::Activate(predecessor));
        assert_eq!(
            plan.reject_candidate,
            vec![(
                lineage(),
                deployment_rejection(&digest("archive-two"), &provider().provider_set_sha256)
            )]
        );
        assert!(plan.clear_journal);
    }

    /// The record as it looks when an update committed but its rollback was interrupted: the
    /// installed candidate still holds the `pending` naming the predecessor it displaced.
    fn candidate_with_pending(predecessor: &ReleaseId, candidate: ReleaseId) -> Installed {
        Installed::Present(Box::new(update_head(predecessor.clone(), candidate)))
    }

    fn spent_journal(
        predecessor: ReleaseId,
        candidate: ReleaseId,
        phase: TransactionPhase,
    ) -> Transaction {
        transaction(predecessor, candidate, phase, false)
    }

    fn spent_committed_journal(predecessor: ReleaseId, candidate: ReleaseId) -> Transaction {
        spent_journal(predecessor, candidate, TransactionPhase::Committed)
    }

    #[test]
    fn every_terminal_journal_phase_is_spent_and_no_other_phase_is() {
        // The property the neutralisation rests on, asked of the phase machine rather than of a
        // list: a journal is spent exactly when it can neither begin a rollback nor advance along
        // one. Enumerating a single phase here is what let `RolledBack` drive a boot it could not
        // execute, so assert the whole phase space instead.
        let predecessor = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        for phase in TransactionPhase::ALL {
            let tx = spent_journal(predecessor.clone(), candidate.clone(), phase);
            let spent = !drives_rollback(&tx);
            assert_eq!(
                spent,
                matches!(
                    phase,
                    TransactionPhase::Committed | TransactionPhase::RolledBack
                ),
                "{phase:?} classified spent={spent}"
            );
            // A spent journal must never be handed a recovery its resume gates cannot run.
            if spent {
                let committed = InstalledState::confirmed(
                    tx.candidate_repository_lineage.clone(),
                    tx.candidate_release.clone(),
                    tx.candidate_archive_sha256.clone(),
                    tx.candidate_lifecycle.clone(),
                );
                assert_eq!(
                    journal_recovery(&tx, Some(&release("3.0.0", "three")), Some(&committed)),
                    Recovery::Committed,
                    "{phase:?} cannot drive a rollback, so it must not claim one"
                );
            }
        }
    }

    #[test]
    fn a_spent_rolled_back_journal_never_commits_its_predecessor_over_a_third_release() {
        // A rollback finished, wrote `RolledBack`, committed the predecessor — and then
        // `clear_journal` failed (tolerated), so the journal survived. A later boot found that
        // committed bundle corrupt and `repair_from_assignment` installed and activated the
        // assigned release 3.0.0 *before* the journal was read. `classify_recovery` then reads
        // `RestorePredecessor` (active != previous_release), but `RolledBack` is terminal: every
        // resume gate is closed, so the planned activation cannot run. Committing the
        // predecessor record anyway left the node running 3.0.0 while `installed.json` — and every
        // heartbeat off it — named 1.0.0, and the next boot's drift enforcement stopped the healthy
        // application to re-activate the corrupt predecessor.
        let predecessor = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let repaired = release("3.0.0", "three");
        let mut situation = steady();
        situation.active = Some(repaired.clone());
        situation.installed = Installed::Present(Box::new(InstalledState::confirmed(
            lineage(),
            repaired.clone(),
            digest("archive-three"),
            provider(),
        )));
        situation.journal = Some(spent_journal(
            predecessor,
            candidate,
            TransactionPhase::RolledBack,
        ));

        let plan = plan_boot(&situation);

        assert_eq!(
            plan.release,
            ReleaseFix::None,
            "the repaired release is both active and committed; nothing to reconcile"
        );
        assert_eq!(
            plan.commit, None,
            "a journal that cannot run its rollback must not commit that rollback's record"
        );
        assert_eq!(plan.current.as_deref(), Some("3.0.0"));
        assert!(plan.clear_journal, "the spent journal is removed");
    }

    #[test]
    fn a_spent_committed_journal_does_not_suppress_the_rollback_it_left_half_done() {
        // The update committed, `clear_journal` failed (tolerated), and a later in-loop repair fell
        // back to the predecessor's pointer but died before `commit_installed`. The spent
        // `Committed` journal then classifies `RestorePredecessor`, and taking it as the recovery
        // produced a transaction with no rollback rank: the executor's resume gates closed, so the
        // planned activation never ran while the journal was cleared anyway — leaving
        // the node running the predecessor with the record, and every heartbeat off it, naming the
        // candidate.
        let predecessor = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut situation = steady();
        situation.active = Some(predecessor.clone());
        situation.installed = candidate_with_pending(&predecessor, candidate.clone());
        situation.journal = Some(spent_committed_journal(predecessor.clone(), candidate));

        let plan = plan_boot(&situation);

        assert_eq!(
            plan.release,
            ReleaseFix::Activate(predecessor.clone()),
            "the predecessor the pointer already names is the release this boot reconciles"
        );
        assert_eq!(
            plan.commit,
            Some(InstalledState::confirmed(
                lineage(),
                predecessor,
                digest("archive-one"),
                provider(),
            )),
            "the record must name the release that is actually running"
        );
        assert_eq!(plan.current.as_deref(), Some("1.0.0"));
        assert!(plan.clear_journal);
    }

    #[test]
    fn a_committed_journal_that_still_agrees_with_the_pointer_confirms_its_update() {
        // Guard the scope: an ordinary spent journal whose candidate is both active and installed
        // is still the committed head, so the confirmation window — not a rollback — governs.
        let predecessor = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut situation = steady();
        situation.active = Some(candidate.clone());
        situation.installed = candidate_with_pending(&predecessor, candidate.clone());
        situation.journal = Some(spent_committed_journal(predecessor, candidate.clone()));
        situation.now = 1_000;

        let plan = plan_boot(&situation);

        assert_eq!(plan.release, ReleaseFix::None);
        assert_eq!(plan.current.as_deref(), Some("2.0.0"));
        assert_eq!(
            plan.commit,
            Some(InstalledState::confirmed(
                lineage(),
                candidate,
                digest("archive-two"),
                provider(),
            )),
            "the passed window confirms the candidate and clears its pending record"
        );
    }

    /// The record of an update that committed over `1.0.0` and is still inside its confirmation
    /// window: the head, plus the `pending` naming the predecessor it displaced.
    fn unconfirmed_head() -> InstalledState {
        update_head(release("1.0.0", "one"), release("2.0.0", "two"))
    }

    #[test]
    fn a_failed_gate_reverts_only_inside_the_confirmation_window() {
        // The whole local-revert policy in one place. An unconfirmed update whose healthcheck hook
        // will not pass its boot gate is reverted to the predecessor `pending` names and its bytes
        // are rejected — the node has a proven release on disk and nothing better to wait for. The
        // same failing gate against a CONFIRMED release is reported and nothing else: the hook owns
        // the workload and may converge later, and a node that reverted itself here would fight the
        // reconciler it exists to obey (and, past the window, has no predecessor image left).
        assert_eq!(plan_gate_failure(&unconfirmed_head()), GateFailure::Revert);

        let confirmed = InstalledState::confirmed(
            lineage(),
            release("2.0.0", "two"),
            digest("archive-two"),
            provider(),
        );
        assert_eq!(plan_gate_failure(&confirmed), GateFailure::Report);
    }

    #[test]
    fn a_provisional_head_that_never_gets_healthy_is_rejected_so_the_next_boot_descends() {
        // A cold-installed head has never proven anything, and there is no predecessor to revert
        // to: rejecting its bytes is what lets the next boot's ordered fallback descend past it
        // instead of relaunching a release that cannot serve.
        let provisional = InstalledState::provisional(
            lineage(),
            release("2.0.0", "two"),
            digest("archive-two"),
            provider(),
        );
        assert_eq!(
            plan_gate_failure(&provisional),
            GateFailure::RejectProvisional
        );
    }

    #[test]
    fn a_passed_window_confirms_rather_than_reverting() {
        // The confirm side of the same record: once the window is spent the update is settled and
        // its rollback intent is dropped, so no later gate failure can revert it.
        let mut situation = steady();
        situation.active = Some(release("2.0.0", "two"));
        situation.installed = Installed::Present(Box::new(unconfirmed_head()));
        situation.now = 10_000;

        let plan = plan_boot(&situation);

        assert_eq!(plan.release, ReleaseFix::None);
        assert!(plan.reject_candidate.is_empty());
        assert_eq!(
            plan.commit,
            Some(InstalledState::confirmed(
                lineage(),
                release("2.0.0", "two"),
                digest("archive-two"),
                provider(),
            ))
        );
    }

    #[test]
    fn recovery_replays_the_rejection_the_journal_itself_recorded() {
        // `candidate_rejection_required` is a durable fact recorded by the transaction that judged
        // the candidate, and recovery replays it whatever else this boot decides.
        let predecessor = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut situation = steady();
        situation.active = Some(candidate.clone());
        situation.installed = Installed::Present(Box::new(InstalledState {
            repository_lineage: lineage(),
            release: candidate.clone(),
            archive_sha256: digest("archive-two"),
            lifecycle: provider(),
            pending: None,
            confirmed: true,
        }));
        situation.journal = Some(transaction(
            predecessor,
            candidate,
            TransactionPhase::RollbackActivating,
            true,
        ));

        let plan = plan_boot(&situation);

        assert_eq!(
            plan.reject_candidate,
            vec![(
                lineage(),
                deployment_rejection(&digest("archive-two"), &provider().provider_set_sha256)
            )]
        );
    }

    #[test]
    fn pending_rollback_already_pointing_at_predecessor_never_reactivates_candidate() {
        let predecessor = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut situation = steady();
        situation.active = Some(predecessor.clone());
        situation.installed =
            Installed::Present(Box::new(update_head(predecessor.clone(), candidate)));

        let plan = plan_boot(&situation);

        assert_eq!(plan.release, ReleaseFix::Activate(predecessor.clone()));
        assert_eq!(plan.current.as_deref(), Some("1.0.0"));
        assert_eq!(
            plan.commit,
            Some(InstalledState::confirmed(
                lineage(),
                predecessor,
                digest("archive-one"),
                provider(),
            ))
        );
    }
}
