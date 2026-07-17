//! The supervisor's pure domain: data in, data out.
//!
//! Nothing here touches the filesystem, the network, the clock, or a process. The
//! decision logic is a state machine over durable state and the guardian's recovery
//! markers; the shell gathers the inputs (a [`Situation`]), calls a planner, and
//! performs the returned plan through its adapters. Because the core is pure, every
//! branch is provable in a unit test with hand-built data — no real time, files, or
//! subprocesses.

use std::path::PathBuf;
use std::time::Duration;

pub(crate) use updated::state::{Installed, InstalledState, Pending};
pub(crate) use updated::transaction::Transaction;

/// Whether a [`Pending`] update's confirmation window has passed as of `now` (unix secs).
pub(crate) fn window_passed(pending: &Pending, window: Duration, now: u64) -> bool {
    now >= pending.committed_at.saturating_add(window.as_secs())
}

/// Wall-clock time left in a [`Pending`] update's window as of `now`, so the loop can
/// wake to confirm even when the update interval is longer.
pub(crate) fn window_remaining(pending: &Pending, window: Duration, now: u64) -> Duration {
    let ends_at = pending.committed_at.saturating_add(window.as_secs());
    // Clamped to the window itself: more than that is never a legitimate answer, and a
    // `committed_at` in the future — a backward clock step across a reboot, or a corrupt
    // record, the installed state being plain JSON with no integrity check — would otherwise
    // return a near-`u64::MAX` duration that panics `Instant + Duration` in the loop's sleep,
    // turning a bad timestamp into a diagnostic-free crash loop on every boot.
    Duration::from_secs(ends_at.saturating_sub(now)).min(window)
}

// ============================== boot state machine ==============================

/// Everything the boot planner reads about the world, gathered by the shell.
pub(crate) struct Situation {
    /// The committed installed-state slot — version, authorizing hash, and any pending
    /// (unconfirmed) update — or missing/invalid.
    pub installed: Installed,
    /// First-install baseline from config (`application.current_version`).
    pub baseline: Option<InstalledState>,
    /// Hash of the on-disk application binary (`None` if unreadable / absent).
    pub disk_sha: Option<String>,
    /// Hash of the retained `<binary>.old` rollback copy, if present.
    pub old_sha: Option<String>,
    /// The in-flight update transaction, if a journal is present.
    pub journal: Option<Transaction>,
    /// The guardian's crash marker: the last application exit was a crash.
    pub app_crashed: bool,
    /// The PID of an application the guardian is already running (adopt, do not relaunch).
    pub app_running: Option<u32>,
    /// A candidate supervisor the guardian rolled back (reject its content hash).
    pub bad_supervisor: Option<PathBuf>,
    /// How long a committed update stays unconfirmed.
    pub confirm_window: Duration,
    /// Unix seconds now (the only clock input; kept explicit so the planner stays pure).
    pub now: u64,
}

/// The boot planner's decision — a pure description the executor performs in order.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Plan {
    /// Refuse to run (invalid/missing state, drift with no rollback image). When set,
    /// no other field is acted on.
    pub fail_closed: Option<String>,
    pub updates_enabled: bool,
    pub current: Option<String>,
    /// Stop the running (uncommitted) application before reconciling its binary.
    pub quiesce: bool,
    pub binary: BinaryFix,
    /// Remove the transaction journal after reconciling it (an in-flight update was
    /// resolved). Never set for a plain drift/steady-state boot, which has no journal.
    pub clear_journal: bool,
    /// Application release hashes to add to the rejected set.
    pub reject_app: Vec<String>,
    /// A rolled-back candidate supervisor to reject, by its content-addressed path.
    pub reject_supervisor: Option<PathBuf>,
    /// Installed-state to (re)write — set to confirm an update (clear pending) or to
    /// commit the predecessor on a revert.
    pub commit: Option<InstalledState>,
    /// Drop the `<binary>.old` rollback image (an update was confirmed, or a first
    /// install has nothing to revert to).
    pub drop_rollback: bool,
    pub acquire: Acquire,
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

/// How to make the on-disk application binary match committed state before running it.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) enum BinaryFix {
    /// The binary already matches committed state; leave it.
    #[default]
    None,
    /// Roll `<binary>.old` back over the binary and verify it hashes to `sha`. Used both
    /// to reverse an uncommitted swap and to revert a confirmed-then-crashing update.
    RestoreCommitted { sha: String },
    /// Drop the `<binary>.old` rollback copy (an update that never swapped).
    DropRollback,
}

/// How the shell takes charge of the application after reconciling state.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) enum Acquire {
    /// Ask the guardian to launch a fresh application from the committed binary.
    #[default]
    Launch,
    /// Adopt the application the guardian is already running (no restart).
    Adopt(u32),
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
mod tests {
    use super::*;

    fn pending() -> Pending {
        Pending {
            previous_version: "1.0.0".into(),
            previous_sha256: "aa".into(),
            committed_at: 1000,
        }
    }

    #[test]
    fn window_remaining_and_passed_track_the_confirmation_deadline() {
        let window = Duration::from_secs(120); // deadline at committed_at + 120 = 1120
        assert_eq!(
            window_remaining(&pending(), window, 1000),
            Duration::from_secs(120)
        );
        assert_eq!(
            window_remaining(&pending(), window, 1100),
            Duration::from_secs(20)
        );
        assert!(!window_passed(&pending(), window, 1119));
        // A `committed_at` in the future must not produce a duration that panics the
        // loop's `Instant + Duration`; at most one window of waiting is ever correct.
        let future = Pending {
            committed_at: u64::MAX - 1,
            ..pending()
        };
        assert_eq!(window_remaining(&future, window, 1000), window);
        let _ = std::time::Instant::now() + window_remaining(&future, window, 1000);
        // At and past the deadline: no time remains, and it counts as passed.
        assert_eq!(window_remaining(&pending(), window, 1120), Duration::ZERO);
        assert_eq!(window_remaining(&pending(), window, 5000), Duration::ZERO);
        assert!(window_passed(&pending(), window, 1120));
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
