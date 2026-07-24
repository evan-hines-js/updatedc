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
    plan.updates_enabled = true;
    plan.current = Some(state.release.version.clone());

    let pending_revert_in_progress = state
        .pending
        .as_ref()
        .is_some_and(|pending| s.active.as_ref() == Some(&pending.previous_release));
    let pending_authoritative = if let Some(tx) = &s.journal {
        reconcile_transaction(&mut plan, s, tx, &state) == Recovery::Committed
    } else if pending_revert_in_progress {
        // A prior supervisor restored the predecessor pointer but crashed before the
        // external rollback and final state commit. Preserve that direction: never
        // "repair" the pointer back to the failed candidate.
        let pending = state.pending.as_ref().expect("checked above");
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
            confirm_or_revert(&mut plan, s, &state, pending);
        }
    }

    // A boot that (re)installed this cycle changed the active bytes. Any process the guardian kept
    // alive is the *previous* release — e.g. a wedged head the cold-install descent just stepped
    // past — so it must be stopped and the freshly-installed bytes launched. Adopting it would
    // health-gate the stale process and then reject the release we just installed as if it were the
    // one that failed, stranding a node on an exhausted descent even though a healthy release was
    // available. (A crashed head leaves no running process, so this only bites the wedge path.)
    if s.first_install && s.app_running.is_some() {
        plan.quiesce = true;
    }
    plan.acquire = match s.app_running {
        Some(pid) if !plan.quiesce => Acquire::Adopt(pid),
        _ => Acquire::Launch,
    };
    plan.reject_supervisor = s.bad_supervisor.clone();
    plan
}

fn reconcile_transaction(
    plan: &mut Plan,
    situation: &Situation,
    tx: &Transaction,
    installed: &InstalledState,
) -> Recovery {
    plan.clear_journal = true;
    let recovery =
        transaction::classify_recovery(tx, situation.active.as_ref(), Some(&installed.release));
    if tx.candidate_rejection_required {
        plan.reject_app.push((
            tx.candidate_repository_lineage.clone(),
            tx.candidate_archive_sha256.clone(),
        ));
        plan.warn(format!(
            "recovery: rejected {} after failed activation",
            tx.candidate_release.version
        ));
    }
    match recovery {
        Recovery::Committed => plan.info(format!(
            "recovery: release {} was already committed",
            tx.candidate_release.version
        )),
        Recovery::NeverSwapped => plan.info(format!(
            "recovery: activation of {} never landed",
            tx.candidate_release.version
        )),
        Recovery::RestorePredecessor => {
            // A reload deployment keeps its process across a failed candidate reload, so adopt the
            // running predecessor rather than stop-starting it (no downtime). A restart deployment
            // stops the uncommitted candidate and relaunches the predecessor.
            plan.quiesce = situation.app_running.is_some();
            plan.release = ReleaseFix::Activate(tx.previous_release.clone());
            if situation.service_exited && !tx.candidate_rejection_required {
                plan.reject_app.push((
                    tx.candidate_repository_lineage.clone(),
                    tx.candidate_archive_sha256.clone(),
                ));
                plan.warn(format!(
                    "recovery: rejected {} after failed activation",
                    tx.candidate_release.version
                ));
            }
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
            tx.lifecycle.clone(),
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
    plan.quiesce = situation.app_running.is_some();
    plan.release = ReleaseFix::Activate(installed.release.clone());
    plan.warn(format!(
        "active release drifted; restoring committed {}",
        installed.release.version
    ));
}

fn confirm_or_revert(
    plan: &mut Plan,
    situation: &Situation,
    installed: &InstalledState,
    pending: &Pending,
) {
    if situation.service_exited {
        // Reload deployments adopt the still-running predecessor; restart deployments stop-start it.
        plan.quiesce = situation.app_running.is_some();
        plan.release = ReleaseFix::Activate(pending.previous_release.clone());
        plan.reject_app.push((
            installed.repository_lineage.clone(),
            installed.archive_sha256.clone(),
        ));
        // Revert to the predecessor carrying its providers (held in `pending`) so the restored
        // release keeps its crash-watch, provider health, and pre-start hook — see the confirm
        // branch below, which carries the same three for the forward case.
        plan.commit = Some(InstalledState::confirmed(
            pending.previous_repository_lineage.clone(),
            pending.previous_release.clone(),
            pending.previous_archive_sha256.clone(),
            pending.lifecycle.clone(),
        ));
        plan.current = Some(pending.previous_release.version.clone());
        plan.warn(format!(
            "release {} exited within its confirmation window; reverting to {}",
            installed.release.version, pending.previous_release.version
        ));
    } else if window_passed(pending, situation.confirm_window, situation.now) {
        // Confirming the current install: carry its providers forward unchanged.
        plan.commit = Some(InstalledState::confirmed(
            installed.repository_lineage.clone(),
            installed.release.clone(),
            installed.archive_sha256.clone(),
            installed.lifecycle.clone(),
        ));
        plan.info(format!("release {} confirmed", installed.release.version));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use updated::bundle::ReleaseId;

    fn release(version: &str, digest: &str) -> ReleaseId {
        ReleaseId {
            version: version.into(),
            manifest_sha256: digest.into(),
        }
    }

    fn lineage() -> updated::state::RepositoryLineage {
        updated::state::RepositoryLineage::from_metadata_url("https://repo/metadata/")
    }

    fn provider() -> Box<updated::state::ProviderRelease> {
        Box::new(updated::state::ProviderRelease {
            product: "reconciler".into(),
            release: release("1.0.0", "reconciler-manifest"),
            archive_sha256: "reconciler-archive".into(),
            args: Vec::new(),
            timeout_millis: 1_000,
        })
    }

    fn steady() -> Situation {
        let current = release("1.0.0", "one");
        Situation {
            installed: Installed::Present(Box::new(InstalledState::confirmed(
                lineage(),
                current.clone(),
                "archive-one".into(),
                provider(),
            ))),
            active: Some(current),
            journal: None,
            service_exited: false,
            app_running: None,
            first_install: false,
            bad_supervisor: None,
            confirm_window: Duration::from_secs(60),
            now: 100,
        }
    }

    #[test]
    fn a_reinstall_launches_fresh_and_stops_a_kept_alive_stale_process() {
        // The cold-install descent re-installs a lower release while the guardian is still holding
        // the wedged head it stepped past. The planner must stop that stale process and launch the
        // freshly-installed bytes — never adopt it (which would health-gate the wrong version and
        // reject the release just installed).
        let mut situation = steady();
        situation.first_install = true;
        situation.app_running = Some(4321);

        let plan = plan_boot(&situation);

        assert!(
            plan.quiesce,
            "a re-install with a kept-alive process must stop it"
        );
        assert_eq!(
            plan.acquire,
            Acquire::Launch,
            "a re-install must launch the freshly-installed bytes, not adopt the stale process"
        );
    }

    #[test]
    fn a_plain_restart_still_adopts_the_running_process() {
        // Guard the fix's scope: an ordinary supervisor restart (no re-install this boot) must
        // still adopt the app the guardian legitimately keeps running.
        let mut situation = steady();
        situation.app_running = Some(4321);

        let plan = plan_boot(&situation);

        assert!(!plan.quiesce);
        assert_eq!(plan.acquire, Acquire::Adopt(4321));
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
        situation.service_exited = true;
        situation.journal = Some(Transaction {
            id: "attempt".into(),
            previous_release: release("1.0.0", "one"),
            previous_archive_sha256: "archive-one".into(),
            previous_repository_lineage: lineage(),
            candidate_release: candidate,
            candidate_archive_sha256: "archive-two".into(),
            candidate_repository_lineage: lineage(),
            candidate_rejection_required: false,
            lifecycle: provider(),
            rollback_health_failures: 0,
            phase: TransactionPhase::CandidateActivated,
        });
        let plan = plan_boot(&situation);
        assert_eq!(plan.release, ReleaseFix::Activate(release("1.0.0", "one")));
        assert_eq!(plan.reject_app, vec![(lineage(), "archive-two".into())]);
        assert!(plan
            .notes
            .iter()
            .any(|note| note.msg == "recovery: rejected 2.0.0 after failed activation"));
    }

    #[test]
    fn supervisor_crash_during_activation_does_not_poison_the_release() {
        let mut situation = steady();
        let candidate = release("2.0.0", "two");
        situation.active = Some(candidate.clone());
        situation.journal = Some(Transaction {
            id: "attempt".into(),
            previous_release: release("1.0.0", "one"),
            previous_archive_sha256: "archive-one".into(),
            previous_repository_lineage: lineage(),
            candidate_release: candidate,
            candidate_archive_sha256: "archive-two".into(),
            candidate_repository_lineage: lineage(),
            candidate_rejection_required: false,
            lifecycle: provider(),
            rollback_health_failures: 0,
            phase: TransactionPhase::CandidateActivated,
        });
        let plan = plan_boot(&situation);
        assert!(plan.reject_app.is_empty());
    }

    #[test]
    fn journaled_rejection_survives_consuming_the_crash_marker() {
        let predecessor = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut situation = steady();
        situation.active = Some(predecessor.clone());
        situation.installed = Installed::Present(Box::new(InstalledState {
            repository_lineage: lineage(),
            release: candidate.clone(),
            archive_sha256: "archive-two".into(),
            lifecycle: provider(),
            pending: None,
            confirmed: true,
        }));
        situation.service_exited = false;
        situation.journal = Some(Transaction {
            id: "attempt".into(),
            previous_release: predecessor,
            previous_archive_sha256: "archive-one".into(),
            previous_repository_lineage: lineage(),
            candidate_release: candidate,
            candidate_archive_sha256: "archive-two".into(),
            candidate_repository_lineage: lineage(),
            candidate_rejection_required: true,
            lifecycle: provider(),
            rollback_health_failures: 0,
            phase: TransactionPhase::RollbackStarted,
        });

        let plan = plan_boot(&situation);

        assert_eq!(plan.reject_app, vec![(lineage(), "archive-two".into())]);
    }

    #[test]
    fn journaled_rejection_is_replayed_when_activation_never_started() {
        let predecessor = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut situation = steady();
        situation.journal = Some(Transaction {
            id: "attempt".into(),
            previous_release: predecessor,
            previous_archive_sha256: "archive-one".into(),
            previous_repository_lineage: lineage(),
            candidate_release: candidate,
            candidate_archive_sha256: "archive-two".into(),
            candidate_repository_lineage: lineage(),
            candidate_rejection_required: true,
            lifecycle: provider(),
            rollback_health_failures: 0,
            phase: TransactionPhase::PreflightStarted,
        });

        let plan = plan_boot(&situation);

        assert_eq!(plan.release, ReleaseFix::None);
        assert_eq!(plan.reject_app, vec![(lineage(), "archive-two".into())]);
        assert!(plan.clear_journal);
    }

    #[test]
    fn pending_rollback_already_pointing_at_predecessor_never_reactivates_candidate() {
        let predecessor = release("1.0.0", "one");
        let candidate = release("2.0.0", "two");
        let mut situation = steady();
        situation.active = Some(predecessor.clone());
        situation.installed = Installed::Present(Box::new(InstalledState {
            repository_lineage: lineage(),
            release: candidate,
            archive_sha256: "archive-two".into(),
            lifecycle: provider(),
            pending: Some(Pending {
                lifecycle_attempt_id: "attempt".into(),
                previous_release: predecessor.clone(),
                previous_archive_sha256: "archive-one".into(),
                previous_repository_lineage: lineage(),
                committed_at: 100,
                lifecycle: provider(),
            }),
            confirmed: true,
        }));

        let plan = plan_boot(&situation);

        assert_eq!(plan.release, ReleaseFix::Activate(predecessor.clone()));
        assert_eq!(plan.current.as_deref(), Some("1.0.0"));
        assert_eq!(
            plan.commit,
            Some(InstalledState::confirmed(
                lineage(),
                predecessor,
                "archive-one".into(),
                provider(),
            ))
        );
    }
}
