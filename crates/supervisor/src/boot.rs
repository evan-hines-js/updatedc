//! The boot state machine: `plan_boot(&Situation) -> Plan`.
//!
//! One pure function decides everything the supervisor does before it enters its update
//! loop: reconcile an interrupted update, enforce the committed binary against drift,
//! reject a release whose application crashed before it committed, resolve a committed
//! update that is still unconfirmed (confirm it, or — one strike — revert it if its
//! application crashed), and choose whether to adopt the running application or launch a
//! fresh one. No I/O — the shell performs the returned [`Plan`].

use crate::domain::*;
use updated::transaction::{self, BinaryAction, Recovery};

/// Decide the whole boot sequence from the gathered [`Situation`].
pub(crate) fn plan_boot(s: &Situation) -> Plan {
    let mut plan = Plan::default();

    // 1. Installed state → current version, updates-enabled, committed hash, pending update.
    let (committed_sha, pending) = match &s.installed {
        Installed::Present(st) => {
            plan.updates_enabled = true;
            plan.current = Some(st.version.clone());
            (Some(st.sha256.clone()), st.pending.clone())
        }
        Installed::Missing => match &s.baseline {
            Some(state) => {
                let Some(actual) = s.disk_sha.as_deref() else {
                    plan.fail_closed = Some("installer baseline binary cannot be hashed".into());
                    return plan;
                };
                let state = match updated::state::verified_baseline(
                    actual,
                    &state.version,
                    &state.sha256,
                ) {
                    Ok(state) => state,
                    Err(e) => {
                        plan.fail_closed = Some(e.to_string());
                        return plan;
                    }
                };
                plan.updates_enabled = true;
                plan.current = Some(state.version.clone());
                plan.info(format!(
                    "no installed state; provisioning installer baseline {}",
                    state.version
                ));
                plan.commit = Some(state);
                (None, None)
            }
            None => {
                plan.fail_closed =
                    Some("no installed state and no installer-provisioned application.current_version/application.current_sha256 baseline".into());
                return plan;
            }
        },
        Installed::Invalid => {
            plan.fail_closed = Some("installed state present but INVALID (corrupt)".into());
            return plan;
        }
    };

    // 2. Reconcile the on-disk binary: an in-flight transaction takes priority; otherwise
    //    enforce the committed hash (drift). On first install the boot plan has already
    //    matched the on-disk bytes to the installer-provisioned baseline digest and will
    //    commit that same digest before launch.
    // A journal that reconciled as *committed* left the binary alone: its update is durable
    // and its pending record is authoritative, so the unconfirmed-update rules below still
    // govern it. Any other journal outcome spoke for the binary itself.
    let pending_is_authoritative = match (&s.journal, &committed_sha) {
        (Some(tx), _) => reconcile_transaction(&mut plan, s, tx) == Recovery::Committed,
        (None, Some(sha)) => {
            enforce_committed(&mut plan, s, sha);
            if plan.fail_closed.is_some() {
                return plan;
            }
            true
        }
        (None, None) => true,
    };

    // 3. Resolve an unconfirmed committed update. This must run whenever the pending record
    //    is live, journal or not: `gather_situation` consumes the crash marker to build this
    //    Situation, so skipping the check *destroys* the evidence rather than deferring it —
    //    the crash would be silently forgiven and the bad release confirmed on the next pass,
    //    with its rollback image dropped and nothing left to revert to.
    if pending_is_authoritative {
        if let (Some(p), Some(sha)) = (&pending, &committed_sha) {
            confirm_or_revert(&mut plan, s, p, sha);
        }
    }

    // 4. Acquire: adopt the running application unless we are stopping it, else launch.
    plan.acquire = match s.app_running {
        Some(pid) if !plan.quiesce => Acquire::Adopt(pid),
        _ => Acquire::Launch,
    };

    // 5. A candidate supervisor the guardian rolled back is rejected by hash.
    plan.reject_supervisor = s.bad_supervisor.clone();

    plan
}

/// Reconcile an interrupted update transaction against the on-disk binary. Whatever the
/// outcome, the journal is spent and must be removed once the reconciliation is performed.
/// Returns how it classified, so the caller knows whether the binary was left as committed.
fn reconcile_transaction(plan: &mut Plan, s: &Situation, tx: &Transaction) -> Recovery {
    plan.clear_journal = true;
    let disk = s.disk_sha.as_deref().unwrap_or_default();
    let recovery = transaction::classify_recovery(tx, disk, plan.current.as_deref());
    match &recovery {
        Recovery::Committed => {
            // The commit wrote its pending record atomically; only the journal removal was
            // left. There is nothing to reconcile — the loop confirms the update later.
            plan.info(format!("recovery: update {} committed", tx.to_version));
        }
        Recovery::NeverSwapped => {
            plan.binary = BinaryFix::DropRollback;
            plan.info("recovery: update never swapped; keeping the current version");
        }
        Recovery::RestorePredecessor => {
            plan.binary = BinaryFix::RestoreCommitted {
                sha: tx.old_sha256.clone(),
            };
            plan.info(format!(
                "recovery: rolling an uncommitted update {} back to the committed binary",
                tx.to_version
            ));
            // The guardian may still be running the uncommitted candidate — stop it
            // before its binary is swapped out from under it.
            if s.app_running.is_some() {
                plan.quiesce = true;
            }
            // If that candidate's application crashed before committing, reject its bytes
            // so recovery does not immediately re-apply it (a crash-loop).
            if s.app_crashed {
                plan.reject_app.push(tx.new_sha256.clone());
                plan.warn(format!(
                    "update {} crashed before commit; rejecting it",
                    tx.to_version
                ));
            }
        }
    }
    recovery
}

/// Enforce that the on-disk binary matches the committed hash before running it.
fn enforce_committed(plan: &mut Plan, s: &Situation, committed_sha: &str) {
    match transaction::classify_binary(s.disk_sha.as_deref(), s.old_sha.as_deref(), committed_sha) {
        BinaryAction::Ready => {}
        BinaryAction::RestoreRollback => {
            plan.binary = BinaryFix::RestoreCommitted {
                sha: committed_sha.to_string(),
            };
            plan.warn(
                "on-disk binary drifted from committed state; restoring it from the rollback image",
            );
        }
        BinaryAction::FailClosed => {
            plan.fail_closed =
                Some("refusing to run drifted bytes; reinstall the committed version".into());
        }
    }
}

/// Resolve a committed-but-unconfirmed update: one strike — a crash within its window
/// reverts to the predecessor and rejects the bad release; surviving the window confirms
/// it and drops the rollback image; otherwise leave it pending for the loop to confirm.
fn confirm_or_revert(plan: &mut Plan, s: &Situation, p: &Pending, committed_sha: &str) {
    let current = plan.current.clone().unwrap_or_default();
    if s.app_crashed {
        // The rollback image is the retained `<binary>.old`; restoring it reverts the binary.
        plan.binary = BinaryFix::RestoreCommitted {
            sha: p.previous_sha256.clone(),
        };
        plan.commit = Some(InstalledState::confirmed(
            p.previous_version.clone(),
            p.previous_sha256.clone(),
        ));
        plan.reject_app.push(committed_sha.to_string());
        plan.current = Some(p.previous_version.clone());
        // A crash means the application already died, but stay defensive: if the guardian
        // somehow still holds it, stop it before its binary is replaced.
        if s.app_running.is_some() {
            plan.quiesce = true;
        }
        plan.warn(format!(
            "update {current} crashed within its confirmation window; reverting to {} and rejecting it",
            p.previous_version
        ));
    } else if window_passed(p, s.confirm_window, s.now) {
        plan.commit = Some(InstalledState::confirmed(
            current.clone(),
            committed_sha.to_string(),
        ));
        plan.drop_rollback = true;
        plan.info(format!(
            "update {current} confirmed; confirmation window passed"
        ));
    }
    // else: still within the window and no crash — leave it pending; the loop confirms it.
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const WINDOW: Duration = Duration::from_secs(120);

    /// A minimal steady-state situation: committed `version`/`sha`, matching on-disk
    /// bytes, nothing in flight. Individual tests mutate the field under test.
    fn steady(version: &str, sha: &str) -> Situation {
        Situation {
            installed: Installed::Present(InstalledState::confirmed(version.into(), sha.into())),
            baseline: None,
            disk_sha: Some(sha.into()),
            old_sha: None,
            journal: None,
            app_crashed: false,
            app_running: None,
            bad_supervisor: None,
            confirm_window: WINDOW,
            now: 1_000_000,
        }
    }

    fn tx(from: &str, to: &str) -> Transaction {
        Transaction {
            old_sha256: "oldsha".into(),
            new_sha256: "newsha".into(),
            to_version: to.into(),
            from_version: Some(from.into()),
        }
    }

    /// A committed install of `version`/`sha` still pending confirmation, reverting to
    /// `prev`/`prev_sha`, committed `age` seconds before the situation's `now`.
    fn pending(
        version: &str,
        sha: &str,
        prev: &str,
        prev_sha: &str,
        committed_at: u64,
    ) -> Situation {
        let mut s = steady(version, sha);
        s.installed = Installed::Present(InstalledState {
            version: version.into(),
            sha256: sha.into(),
            pending: Some(Pending {
                previous_version: prev.into(),
                previous_sha256: prev_sha.into(),
                committed_at,
            }),
        });
        s
    }

    #[test]
    fn steady_state_adopts_a_running_healthy_app() {
        let mut s = steady("2.0.0", "sha2");
        s.app_running = Some(4242);
        let plan = plan_boot(&s);
        assert_eq!(plan.acquire, Acquire::Adopt(4242));
        assert_eq!(plan.binary, BinaryFix::None);
        assert!(plan.updates_enabled);
        assert_eq!(plan.current.as_deref(), Some("2.0.0"));
    }

    #[test]
    fn steady_state_launches_when_no_app_is_running() {
        assert_eq!(plan_boot(&steady("2.0.0", "sha2")).acquire, Acquire::Launch);
    }

    #[test]
    fn first_install_verifies_baseline_and_launches() {
        let mut s = steady("1.0.0", "sha1");
        s.installed = Installed::Missing;
        s.baseline = Some(InstalledState::confirmed("1.0.0".into(), "sha1".into()));
        s.disk_sha = Some("sha1".into());
        let plan = plan_boot(&s);
        assert!(plan.updates_enabled);
        assert_eq!(
            plan.commit.as_ref().map(|s| s.version.as_str()),
            Some("1.0.0")
        );
        assert_eq!(plan.binary, BinaryFix::None);
        assert_eq!(plan.acquire, Acquire::Launch);
    }

    #[test]
    fn first_install_with_wrong_installer_digest_fails_closed() {
        let mut s = steady("1.0.0", "sha1");
        s.installed = Installed::Missing;
        s.baseline = Some(InstalledState::confirmed("1.0.0".into(), "expected".into()));
        s.disk_sha = Some("tampered".into());
        assert!(plan_boot(&s).fail_closed.is_some());
    }

    #[test]
    fn missing_state_and_no_baseline_fails_closed() {
        let mut s = steady("1.0.0", "sha1");
        s.installed = Installed::Missing;
        s.baseline = None;
        assert!(plan_boot(&s).fail_closed.is_some());
    }

    #[test]
    fn invalid_state_fails_closed() {
        let mut s = steady("1.0.0", "sha1");
        s.installed = Installed::Invalid;
        assert!(plan_boot(&s).fail_closed.is_some());
    }

    #[test]
    fn drift_without_a_rollback_image_fails_closed() {
        let mut s = steady("2.0.0", "committed");
        s.disk_sha = Some("drifted".into());
        s.old_sha = None;
        assert!(plan_boot(&s).fail_closed.is_some());
    }

    #[test]
    fn drift_restores_from_the_rollback_image() {
        let mut s = steady("2.0.0", "committed");
        s.disk_sha = Some("drifted".into());
        s.old_sha = Some("committed".into());
        let plan = plan_boot(&s);
        assert_eq!(
            plan.binary,
            BinaryFix::RestoreCommitted {
                sha: "committed".into()
            }
        );
        assert!(plan.fail_closed.is_none());
    }

    #[test]
    fn interrupted_committed_update_only_clears_the_journal() {
        // The commit wrote its pending record atomically; recovery just clears the journal.
        let mut s = pending("2.0.0", "newsha", "1.0.0", "oldsha", 1_000_000);
        s.journal = Some(tx("1.0.0", "2.0.0"));
        s.disk_sha = Some("newsha".into());
        let plan = plan_boot(&s);
        assert_eq!(plan.binary, BinaryFix::None);
        assert!(plan.clear_journal);
        assert!(
            plan.commit.is_none(),
            "no re-commit needed; pending already recorded"
        );
    }

    #[test]
    fn interrupted_uncommitted_update_rolls_back() {
        let mut s = steady("1.0.0", "oldsha");
        s.journal = Some(tx("1.0.0", "2.0.0"));
        s.disk_sha = Some("newsha".into()); // swapped but not committed
        let plan = plan_boot(&s);
        assert_eq!(
            plan.binary,
            BinaryFix::RestoreCommitted {
                sha: "oldsha".into()
            }
        );
        assert!(plan.reject_app.is_empty(), "no crash ⇒ no rejection");
    }

    #[test]
    fn uncommitted_update_that_crashed_is_rejected() {
        let mut s = steady("1.0.0", "oldsha");
        s.journal = Some(tx("1.0.0", "2.0.0"));
        s.disk_sha = Some("newsha".into());
        s.app_crashed = true;
        let plan = plan_boot(&s);
        assert_eq!(plan.reject_app, vec!["newsha".to_string()]);
        assert!(matches!(plan.binary, BinaryFix::RestoreCommitted { .. }));
    }

    #[test]
    fn interrupted_update_that_never_swapped_drops_the_copy() {
        let mut s = steady("1.0.0", "oldsha");
        s.journal = Some(tx("1.0.0", "2.0.0"));
        s.disk_sha = Some("oldsha".into());
        assert_eq!(plan_boot(&s).binary, BinaryFix::DropRollback);
    }

    #[test]
    fn rolling_back_a_running_uncommitted_candidate_quiesces_it() {
        let mut s = steady("1.0.0", "oldsha");
        s.journal = Some(tx("1.0.0", "2.0.0"));
        s.disk_sha = Some("newsha".into());
        s.app_running = Some(99);
        let plan = plan_boot(&s);
        assert!(plan.quiesce);
        assert_eq!(
            plan.acquire,
            Acquire::Launch,
            "quiesced ⇒ relaunch, not adopt"
        );
    }

    #[test]
    fn pending_within_window_and_no_crash_is_left_alone() {
        let s = pending("2.0.0", "newsha", "1.0.0", "oldsha", 1_000_000); // just committed
        let plan = plan_boot(&s);
        assert_eq!(plan.binary, BinaryFix::None);
        assert!(plan.commit.is_none());
        assert!(!plan.drop_rollback);
    }

    #[test]
    fn pending_past_window_is_confirmed() {
        let s = pending("2.0.0", "newsha", "1.0.0", "oldsha", 1_000_000 - 200); // window elapsed
        let plan = plan_boot(&s);
        assert_eq!(
            plan.commit,
            Some(InstalledState::confirmed("2.0.0".into(), "newsha".into()))
        );
        assert!(plan.drop_rollback, "confirmation drops the rollback image");
    }

    #[test]
    fn pending_update_that_crashes_reverts_and_rejects_one_strike() {
        let mut s = pending("2.0.0", "newsha", "1.0.0", "oldsha", 1_000_000);
        s.app_crashed = true; // a single crash within the window
        let plan = plan_boot(&s);
        assert_eq!(
            plan.binary,
            BinaryFix::RestoreCommitted {
                sha: "oldsha".into()
            }
        );
        assert_eq!(
            plan.current.as_deref(),
            Some("1.0.0"),
            "reverted to predecessor"
        );
        assert_eq!(plan.reject_app, vec!["newsha".to_string()]);
        assert_eq!(
            plan.commit,
            Some(InstalledState::confirmed("1.0.0".into(), "oldsha".into()))
        );
    }

    #[test]
    fn a_surviving_journal_does_not_forgive_a_crash_inside_the_window() {
        // `update.rs` deliberately tolerates a failed journal delete after a commit ("the
        // next boot's recovery will remove it"), and a kill in the commit→clear window
        // leaves the same state: a spent journal beside a live pending record. The crash
        // marker is consumed to build this Situation, so if the one-strike rule is skipped
        // here the evidence is destroyed, not deferred — the crash-looping release would be
        // confirmed on the next pass and its rollback image dropped.
        let mut s = pending("2.0.0", "newsha", "1.0.0", "oldsha", 1_000_000);
        s.journal = Some(tx("1.0.0", "2.0.0"));
        s.disk_sha = Some("newsha".into()); // the swap landed: classify_recovery => Committed
        s.app_crashed = true;

        let plan = plan_boot(&s);
        assert!(plan.clear_journal, "the spent journal is still removed");
        assert_eq!(
            plan.binary,
            BinaryFix::RestoreCommitted {
                sha: "oldsha".into()
            },
            "the crash must revert the binary exactly as it does without a journal"
        );
        assert_eq!(plan.reject_app, vec!["newsha".to_string()]);
        assert_eq!(plan.current.as_deref(), Some("1.0.0"));
        assert!(
            !plan.drop_rollback,
            "a reverting boot must keep the image it just restored from"
        );
    }

    #[test]
    fn a_surviving_journal_still_confirms_a_healthy_update_past_its_window() {
        let mut s = pending("2.0.0", "newsha", "1.0.0", "oldsha", 1);
        s.journal = Some(tx("1.0.0", "2.0.0"));
        s.disk_sha = Some("newsha".into());
        let plan = plan_boot(&s);
        assert!(plan.clear_journal);
        assert_eq!(
            plan.commit,
            Some(InstalledState::confirmed("2.0.0".into(), "newsha".into())),
            "a survived window confirms whether or not a spent journal is present"
        );
        assert!(plan.drop_rollback);
    }

    #[test]
    fn an_uncommitted_journal_still_owns_the_binary_decision() {
        // Guard the other side of the fix: when the transaction did NOT commit, its own
        // reconciliation decides the binary — the pending path must not also weigh in.
        let mut s = pending("2.0.0", "newsha", "1.0.0", "oldsha", 1_000_000);
        s.journal = Some(tx("1.0.0", "2.0.0"));
        s.disk_sha = Some("oldsha".into()); // never swapped
        s.app_crashed = true;
        let plan = plan_boot(&s);
        assert_eq!(
            plan.binary,
            BinaryFix::DropRollback,
            "the never-swapped recovery still owns the binary"
        );
    }

    #[test]
    fn rolled_back_supervisor_candidate_is_rejected() {
        let mut s = steady("2.0.0", "newsha");
        s.bad_supervisor = Some("/state/supervisors/deadbeef/supervisor".into());
        let plan = plan_boot(&s);
        assert_eq!(
            plan.reject_supervisor.as_deref(),
            Some(std::path::Path::new(
                "/state/supervisors/deadbeef/supervisor"
            ))
        );
    }
}
