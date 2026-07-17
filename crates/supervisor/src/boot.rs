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

    let pending_authoritative = if let Some(tx) = &s.journal {
        reconcile_transaction(&mut plan, s, tx, &state) == Recovery::Committed
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
            plan.quiesce = situation.app_running.is_some();
            plan.release = ReleaseFix::Activate(tx.previous_release.clone());
            if situation.app_crashed {
                plan.reject_app.push(tx.candidate_archive_sha256.clone());
            }
            plan.warn(format!(
                "recovery: restoring predecessor {} after interrupted activation of {}",
                tx.previous_release.version, tx.candidate_release.version
            ));
        }
    }
    recovery
}

fn enforce_installed(plan: &mut Plan, situation: &Situation, installed: &InstalledState) {
    if situation.active.as_ref() == Some(&installed.release) && situation.active_verified {
        return;
    }
    // The installed release is immutable and remains the authoritative recovery target.
    // The executor re-verifies it before changing active-release.
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
    if situation.app_crashed {
        plan.quiesce = situation.app_running.is_some();
        plan.release = ReleaseFix::Activate(pending.previous_release.clone());
        plan.reject_app.push(installed.archive_sha256.clone());
        plan.commit = Some(InstalledState::confirmed(
            pending.previous_release.clone(),
            pending.previous_archive_sha256.clone(),
        ));
        plan.current = Some(pending.previous_release.version.clone());
        plan.warn(format!(
            "release {} crashed within its confirmation window; reverting to {}",
            installed.release.version, pending.previous_release.version
        ));
    } else if window_passed(pending, situation.confirm_window, situation.now) {
        plan.commit = Some(InstalledState::confirmed(
            installed.release.clone(),
            installed.archive_sha256.clone(),
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

    fn steady() -> Situation {
        let current = release("1.0.0", "one");
        Situation {
            installed: Installed::Present(InstalledState::confirmed(
                current.clone(),
                "archive-one".into(),
            )),
            active: Some(current),
            active_verified: true,
            journal: None,
            app_crashed: false,
            app_running: None,
            bad_supervisor: None,
            confirm_window: Duration::from_secs(60),
            now: 100,
        }
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
        situation.app_crashed = true;
        situation.journal = Some(Transaction {
            previous_release: release("1.0.0", "one"),
            candidate_release: candidate,
            candidate_archive_sha256: "archive-two".into(),
        });
        let plan = plan_boot(&situation);
        assert_eq!(plan.release, ReleaseFix::Activate(release("1.0.0", "one")));
        assert_eq!(plan.reject_app, vec!["archive-two"]);
    }

    #[test]
    fn supervisor_crash_during_activation_does_not_poison_the_release() {
        let mut situation = steady();
        let candidate = release("2.0.0", "two");
        situation.active = Some(candidate.clone());
        situation.journal = Some(Transaction {
            previous_release: release("1.0.0", "one"),
            candidate_release: candidate,
            candidate_archive_sha256: "archive-two".into(),
        });
        let plan = plan_boot(&situation);
        assert!(plan.reject_app.is_empty());
    }
}
