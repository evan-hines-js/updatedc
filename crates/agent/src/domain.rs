//! The agent's pure domain: data in, data out.
//!
//! Nothing here touches the filesystem, the network, the clock, or a process. The
//! decision logic is a state machine over durable state; the shell gathers the inputs (a
//! [`Situation`]), calls a planner, and
//! performs the returned plan through its adapters. Because the core is pure, every
//! branch is provable in a unit test with hand-built data — no real time, files, or
//! subprocesses.

use std::time::Duration;

use updated::bundle::ReleaseId;
use updated::config::Timeouts;
pub(crate) use updated::state::{Installed, InstalledState, Maturity, RollbackGuard};
pub(crate) use updated::transaction::{Phase as TransactionPhase, Transaction};
use updated_contracts::reconciler::Reason;

/// Whether a [`RollbackGuard`] update's confirmation window has passed as of `now` (unix secs).
pub(crate) fn window_passed(rollback_guard: &RollbackGuard, window: Duration, now: u64) -> bool {
    now >= rollback_guard.committed_at.saturating_add(window.as_secs())
}

/// Wall-clock time left in a [`RollbackGuard`] update's window as of `now`, so the loop can
/// wake to confirm even when the update interval is longer.
pub(crate) fn window_remaining(
    rollback_guard: &RollbackGuard,
    window: Duration,
    now: u64,
) -> Duration {
    let ends_at = rollback_guard.committed_at.saturating_add(window.as_secs());
    // Clamped to the window itself: more than that is never a legitimate answer, and a
    // `committed_at` in the future — a backward clock step across a reboot, or a corrupt
    // record, the installed state being plain JSON with no integrity check — would otherwise
    // return a near-`u64::MAX` duration that panics `Instant + Duration` in the loop's sleep,
    // turning a bad timestamp into a diagnostic-free crash loop on every boot.
    Duration::from_secs(ends_at.saturating_sub(now)).min(window)
}

/// The longest wall-clock wait the agent will ever schedule. Every timeout it holds is a
/// deadline (`Instant + Duration`) or a sleep, and both PANIC on overflow — a near-`u64::MAX`
/// duration turns into a diagnostic-free crash on every boot, before any rejection or rollback can
/// be recorded.
///
/// The ceiling itself is not this crate's to pick: it is the same rule
/// [`MAX_INTERVAL_SECONDS`](updated_contracts::assignment::MAX_INTERVAL_SECONDS) applies when a
/// signed assignment is ingested, so it is *referenced* here rather than restated. A second
/// literal could drift from the one publishers are validated against, and then a value that
/// passed ingest would be silently rewritten here (or, worse, a value this crate accepted would
/// exceed what the fleet contract promised).
const MAX_WAIT: Duration = Duration::from_secs(updated_contracts::assignment::MAX_INTERVAL_SECONDS);

/// The agent's timeouts, with every wall-clock wait clamped to [`MAX_WAIT`].
///
/// Ingest already rejects anything above the ceiling, so this clamp is the belt to that
/// suspenders: it also covers the durations that reach an agent without passing
/// `ManagedRuntime::validate` — the node-local config and this crate's own defaults —
/// and it is structural, since `new` is the only constructor and a `Timeouts` cannot reach a
/// deadline or a sleep any other way. `Deref` keeps every read site unchanged.
#[derive(Clone)]
pub(crate) struct BoundedTimeouts(Timeouts);

impl BoundedTimeouts {
    pub(crate) fn new(timeouts: Timeouts) -> Self {
        BoundedTimeouts(Timeouts {
            check_interval: timeouts.check_interval.min(MAX_WAIT),
            health_grace: timeouts.health_grace.min(MAX_WAIT),
            health_successes: timeouts.health_successes,
            health_interval: timeouts.health_interval.min(MAX_WAIT),
            refresh_retry: timeouts.refresh_retry.min(MAX_WAIT),
            confirmation_window: timeouts.confirmation_window.min(MAX_WAIT),
        })
    }
}

impl std::ops::Deref for BoundedTimeouts {
    type Target = Timeouts;

    fn deref(&self) -> &Timeouts {
        &self.0
    }
}

/// The whole identity of the boot health gate's invocation: which attempt it belongs to, which
/// payload it observes, which payload that one displaced, and the reconciler it must observe with.
///
/// These are one signed unit and must always be resolved together. During a crash-recovered
/// rollback the predecessor's commit is deferred until *after* the gate, so the installed record
/// still names the CANDIDATE while the restored PREDECESSOR is what the node is running: taking
/// the providers from the transaction but the identity from the record would gate 1.0.0 with
/// `--payload-version 2.0.0`, and a reconciler that honours the documented argv contract reports
/// unhealthy — eventually rejecting a perfectly good release and writing its outputs under the
/// candidate's hash, where telemetry never looks.
pub(crate) struct GateTarget {
    /// The attempt this observation belongs to: the rollback transaction's own compensating token
    /// when the gate is that transaction's health step, and the reserved boot identity otherwise.
    pub attempt: String,
    /// The semantic event this observation belongs to. Recovery is an update even though it runs
    /// during process boot; ordinary gates retain the boot's install/restart reason.
    pub reason: Reason,
    pub candidate: ReleaseId,
    pub candidate_archive_sha256: String,
    pub predecessor: ReleaseId,
    pub predecessor_archive_sha256: String,
    pub reconciler: Box<updated::state::ReconcilerRelease>,
}

/// Resolve the boot gate's whole invocation identity from one source.
///
/// A crash-recovered rollback's boot gate IS that transaction's health step — its verdict advances
/// `Restored` -> `RollbackVerified` and bounds the rollback — so it carries the same
/// compensating attempt identity as the transaction's predecessor `converge` and its `rollback`, and
/// names the failed candidate as the predecessor. Every other boot gate belongs to no transaction
/// and is a reserved-identity observation of the installed release.
pub(crate) fn boot_gate_target(
    recovery: Option<&Transaction>,
    installed: &InstalledState,
    boot_reason: Reason,
) -> GateTarget {
    match recovery {
        Some(tx) if tx.is_rollback() => GateTarget {
            attempt: tx.rollback_attempt_id(),
            reason: Reason::Update,
            candidate: tx.previous_release.clone(),
            candidate_archive_sha256: tx.previous_archive_sha256.clone(),
            predecessor: tx.candidate_release.clone(),
            predecessor_archive_sha256: tx.candidate_archive_sha256.clone(),
            reconciler: tx.previous_reconciler.clone(),
        },
        _ => GateTarget {
            attempt: updated_contracts::reconciler::attempt::BOOT.to_string(),
            reason: boot_reason,
            candidate: installed.release.clone(),
            candidate_archive_sha256: installed.archive_sha256.clone(),
            predecessor: installed.release.clone(),
            predecessor_archive_sha256: installed.archive_sha256.clone(),
            reconciler: installed.reconciler.clone(),
        },
    }
}

// ============================== boot state machine ==============================

/// Everything the boot planner reads about the world, gathered by the shell.
pub(crate) struct Situation {
    /// The committed installed-state slot — version, authorizing hash, and any pending
    /// (unconfirmed) update — or missing/invalid.
    pub installed: Installed,
    /// The release named by the durable active-release record.
    pub active: Option<ReleaseId>,
    /// The in-flight update transaction, if a journal is present.
    pub journal: Option<Transaction>,
}

impl Situation {
    /// A payload pointer proves an interrupted revert only if it moved away from the
    /// installed payload. Reconciler-only updates share that pointer with their predecessor;
    /// their rollback direction must come from an explicit transaction journal.
    pub(crate) fn predecessor_is_active(&self) -> bool {
        let Installed::Present(installed) = &self.installed else {
            return false;
        };
        installed.rollback_guard.as_ref().is_some_and(|guard| {
            guard.previous_release != installed.release
                && self.active.as_ref() == Some(&guard.previous_release)
        })
    }
}

/// The boot planner's decision — a pure description the executor performs in order.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Plan {
    /// Refuse to run (invalid/missing state, drift with no rollback image). When set,
    /// no other field is acted on.
    pub fail_closed: Option<String>,
    pub current: Option<String>,
    pub release: ReleaseFix,
    /// Remove the transaction journal after reconciling it (an in-flight update was
    /// resolved). Never set for a plain drift/steady-state boot, which has no journal.
    pub clear_journal: bool,
    /// Candidate verdict identities to add to the rejected set.
    pub reject_candidate: Vec<(updated::state::RepositoryLineage, String)>,
    /// Installed-state to (re)write when committing the predecessor on a revert.
    pub commit: Option<InstalledState>,
    pub notes: Vec<Note>,
}

impl Plan {
    pub(crate) fn info(&mut self, msg: impl Into<String>) {
        self.notes.push(Note {
            level: Level::Info,
            msg: msg.into(),
        });
    }
    pub(crate) fn warn(&mut self, msg: impl Into<String>) {
        self.notes.push(Note {
            level: Level::Warn,
            msg: msg.into(),
        });
    }
}

/// How to make active-release match committed state before running it.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) enum ReleaseFix {
    #[default]
    None,
    Activate(ReleaseId),
}

/// A human-facing note the executor emits at the recorded level.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Note {
    pub level: Level,
    pub msg: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Level {
    Info,
    Warn,
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::test_support::{deployment_rejection, digest, lineage, provider, release};

    fn rollback_guard() -> RollbackGuard {
        RollbackGuard {
            attempt_id: digest("attempt"),
            candidate_rejection_sha256: deployment_rejection(&digest("candidate-archive")),
            previous_release: release("1.0.0", "one"),
            previous_archive_sha256: digest("archive-one"),
            previous_repository_lineage: lineage(),
            reconciler: provider(),
            committed_at: 1000,
        }
    }

    #[test]
    fn window_remaining_and_passed_track_the_confirmation_deadline() {
        let window = Duration::from_secs(120); // deadline at committed_at + 120 = 1120
        assert_eq!(
            window_remaining(&rollback_guard(), window, 1000),
            Duration::from_secs(120)
        );
        assert_eq!(
            window_remaining(&rollback_guard(), window, 1100),
            Duration::from_secs(20)
        );
        assert!(!window_passed(&rollback_guard(), window, 1119));
        // A `committed_at` in the future must not produce a duration that panics the
        // loop's `Instant + Duration`; at most one window of waiting is ever correct.
        let future = RollbackGuard {
            attempt_id: digest("attempt"),
            committed_at: u64::MAX - 1,
            ..rollback_guard()
        };
        assert_eq!(window_remaining(&future, window, 1000), window);
        let _ = std::time::Instant::now() + window_remaining(&future, window, 1000);
        // At and past the deadline: no time remains, and it counts as passed.
        assert_eq!(
            window_remaining(&rollback_guard(), window, 1120),
            Duration::ZERO
        );
        assert_eq!(
            window_remaining(&rollback_guard(), window, 5000),
            Duration::ZERO
        );
        assert!(window_passed(&rollback_guard(), window, 1120));
    }

    /// The installed record as it looks mid-rollback: the CANDIDATE, because its predecessor's
    /// commit is deferred until after the boot health gate.
    fn deferred_candidate_record() -> InstalledState {
        InstalledState::proven(
            lineage(),
            release("2.0.0", "two"),
            digest("archive-two"),
            provider(),
        )
    }

    fn rollback_of(predecessor: ReleaseId) -> Transaction {
        let mut predecessor_provider = provider();
        predecessor_provider.definition_sha256 = digest("predecessor-execution");
        Transaction {
            id: digest("attempt"),
            previous_release: predecessor,
            previous_archive_sha256: digest("archive-one"),
            previous_repository_lineage: lineage(),
            candidate_release: release("2.0.0", "two"),
            candidate_archive_sha256: digest("archive-two"),
            candidate_rejection_sha256: deployment_rejection(&digest("archive-two")),
            candidate_repository_lineage: lineage(),
            candidate_rejection_required: true,
            previous_reconciler: predecessor_provider,
            candidate_reconciler: provider(),
            rollback_health_failures: 0,
            phase: TransactionPhase::RollbackPlanned,
        }
    }

    #[test]
    fn the_boot_gate_targets_the_release_that_is_actually_running() {
        // A crash-recovered rollback restored 1.0.0 but the installed record still names the
        // candidate. Both the identity AND the providers must come from the transaction: gating
        // 1.0.0 with `--payload-version 2.0.0` makes a conforming reconciler report unhealthy.
        let predecessor = release("1.0.0", "one");
        let tx = rollback_of(predecessor.clone());
        let record = deferred_candidate_record();

        let target = boot_gate_target(Some(&tx), &record, Reason::Restart);
        assert_eq!(target.candidate, predecessor);
        assert_eq!(target.reconciler, tx.previous_reconciler);
        // The gate is this rollback's health step, so it carries the transaction's own compensating
        // identity and names the failed candidate as the predecessor — the same three arguments its
        // predecessor `converge` and its `rollback` carry.
        assert_eq!(target.attempt, tx.rollback_attempt_id());
        assert_eq!(target.reason, Reason::Update);
        assert_eq!(target.predecessor, tx.candidate_release);
        assert!(
            !updated_contracts::reconciler::attempt::is_reserved(&target.attempt),
            "a transaction's gate never borrows a reserved non-transaction identity"
        );

        // An ordinary boot has no rollback, so the committed record is the running release and the
        // gate belongs to no transaction.
        let target = boot_gate_target(None, &record, Reason::Restart);
        assert_eq!(target.candidate, record.release);
        assert_eq!(target.predecessor, record.release);
        assert_eq!(target.reconciler, record.reconciler);
        assert_eq!(target.attempt, updated_contracts::reconciler::attempt::BOOT);
        assert_eq!(target.reason, Reason::Restart);

        // A forward transaction is not a rollback: nothing was restored, the record still governs
        // and the gate is still a reserved-identity observation.
        let mut forward = rollback_of(release("1.0.0", "one"));
        forward.phase = TransactionPhase::Activated;
        let target = boot_gate_target(Some(&forward), &record, Reason::Install);
        assert_eq!(target.candidate, record.release);
        assert_eq!(target.predecessor, record.release);
        assert_eq!(target.attempt, updated_contracts::reconciler::attempt::BOOT);
        assert_eq!(target.reason, Reason::Install);
    }

    #[test]
    fn timeouts_from_a_signed_assignment_can_never_overflow_a_deadline() {
        // The assignment bounds these from below only, so an absurd (or hostile) value must not
        // reach `Instant + Duration`, which panics on overflow — a crash loop no rollback can break.
        let bounded = BoundedTimeouts::new(Timeouts {
            check_interval: Duration::MAX,
            health_grace: Duration::from_secs(u64::MAX),
            health_interval: Duration::MAX,
            refresh_retry: Duration::MAX,
            confirmation_window: Duration::MAX,
            ..Timeouts::default()
        });
        let now = std::time::Instant::now();
        for wait in [
            bounded.check_interval,
            bounded.health_grace,
            bounded.health_interval,
            bounded.refresh_retry,
            bounded.confirmation_window,
        ] {
            assert_eq!(wait, MAX_WAIT);
            let _ = now + wait;
        }
        // Ordinary values pass through untouched.
        let sane = BoundedTimeouts::new(Timeouts::default());
        assert_eq!(sane.health_grace, Timeouts::default().health_grace);
        assert_eq!(sane.check_interval, Timeouts::default().check_interval);
    }

    #[test]
    fn plan_notes_record_their_level_and_message_in_order() {
        let mut plan = Plan::default();
        plan.info("started");
        plan.warn("degraded");
        assert_eq!(
            plan.notes,
            vec![
                Note {
                    level: Level::Info,
                    msg: "started".into()
                },
                Note {
                    level: Level::Warn,
                    msg: "degraded".into()
                },
            ]
        );
    }
}
