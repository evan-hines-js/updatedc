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

use updated::bundle::ReleaseId;
use updated::config::Timeouts;
pub(crate) use updated::state::{Installed, InstalledState, Pending};
pub(crate) use updated::transaction::{Phase as TransactionPhase, Transaction};

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

/// The longest wall-clock wait the supervisor will ever schedule. Every timeout it holds is a
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

/// The supervisor's timeouts, with every wall-clock wait clamped to [`MAX_WAIT`].
///
/// Ingest already rejects anything above the ceiling, so this clamp is the belt to that
/// suspenders: it also covers the durations that reach a supervisor without passing
/// `ManagedRuntime::validate` — the node-local bootstrap config and this crate's own defaults —
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
            retry_after: timeouts.retry_after.min(MAX_WAIT),
            refresh_retry: timeouts.refresh_retry.min(MAX_WAIT),
            confirmation_window: timeouts.confirmation_window.min(MAX_WAIT),
            supervisor_check_interval: timeouts.supervisor_check_interval.min(MAX_WAIT),
            drain_hold: timeouts.drain_hold.map(|hold| hold.min(MAX_WAIT)),
        })
    }
}

impl std::ops::Deref for BoundedTimeouts {
    type Target = Timeouts;

    fn deref(&self) -> &Timeouts {
        &self.0
    }
}

/// The release the boot health gate must observe, and the providers it must observe it with.
///
/// These are one signed unit and must always be resolved together. During a crash-recovered
/// rollback the predecessor's commit is deferred until *after* the gate, so the installed record
/// still names the CANDIDATE while the restored PREDECESSOR is the process that is running: taking
/// the providers from the transaction but the identity from the record would gate 1.0.0 with
/// `--candidate 2.0.0`, and a reconciler that honours the documented argv contract reports
/// unhealthy — eventually rejecting a perfectly good release and writing its outputs under the
/// candidate's hash, where telemetry never looks.
pub(crate) fn boot_gate_target(
    recovery: Option<&Transaction>,
    installed: &InstalledState,
) -> (ReleaseId, Box<updated::state::ProviderRelease>) {
    match recovery {
        Some(tx) if tx.is_rollback() => (tx.previous_release.clone(), tx.lifecycle.clone()),
        _ => (installed.release.clone(), installed.lifecycle.clone()),
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
    /// The guardian's marker that the managed service exited spontaneously.
    /// The managed service exited spontaneously. Exit zero is included: service policy
    /// requires a continuously running process, so the exact code affects outer restart
    /// behavior but not whether an unconfirmed release must be reconsidered.
    pub service_exited: bool,
    /// This boot found the committed release DAMAGED on disk and repaired it before planning.
    ///
    /// The exit recorded against that release is then evidence about this disk, not about the
    /// release: the bytes charged with the crash are not the bytes about to run. So the exit still
    /// drives every *recoverable* consequence — the revert to `pending.previous_release`, the
    /// descent past a provisional head — but nothing PERMANENT: see
    /// [`Situation::charge_crash_to_release`].
    pub bytes_repaired: bool,
    /// The PID of an application the guardian is already running (adopt, do not relaunch).
    pub app_running: Option<u32>,
    /// This boot performed a (re)install — [`ensure_installed`](crate::install::ensure_installed)
    /// changed the active bytes. Any process the guardian kept alive is therefore the *previous*
    /// release (e.g. a wedged head we just descended past), so the planner must stop it and launch
    /// the freshly-installed bytes rather than adopt a stale process and health-gate the wrong one.
    pub first_install: bool,
    /// A candidate supervisor the guardian rolled back (reject its content hash).
    pub bad_supervisor: Option<PathBuf>,
    /// How long a committed update stays unconfirmed.
    pub confirm_window: Duration,
    /// Unix seconds now (the only clock input; kept explicit so the planner stays pure).
    pub now: u64,
}

impl Situation {
    /// Whether the service exit on disk may be charged to the committed release's BYTES — the one
    /// question every permanent, hash-keyed rejection turns on.
    ///
    /// A rejection never expires and is keyed by archive hash, so charging it to the wrong bytes
    /// blacklists a good release on this node forever and walks its ordered fallback downward. A
    /// boot that repaired a damaged tree ([`Situation::bytes_repaired`]) re-downloaded and
    /// re-verified that very archive, so the exit it is about to read describes bytes that no
    /// longer exist. Every other consequence of the exit — reverting to the predecessor, descending
    /// past a provisional head, relaunching rather than adopting — stays on: they are reversible,
    /// and a release that genuinely crashes is caught by the next boot, which finds the tree intact
    /// and therefore charges the crash to it.
    pub fn charge_crash_to_release(&self) -> bool {
        self.service_exited && !self.bytes_repaired
    }
}

/// The boot planner's decision — a pure description the executor performs in order.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Plan {
    /// Refuse to run (invalid/missing state, drift with no rollback image). When set,
    /// no other field is acted on.
    pub fail_closed: Option<String>,
    pub current: Option<String>,
    /// Stop the running application before changing its active release.
    pub quiesce: bool,
    pub release: ReleaseFix,
    /// Remove the transaction journal after reconciling it (an in-flight update was
    /// resolved). Never set for a plain drift/steady-state boot, which has no journal.
    pub clear_journal: bool,
    /// Application release hashes to add to the rejected set.
    pub reject_app: Vec<(updated::state::RepositoryLineage, String)>,
    /// A rolled-back candidate supervisor to reject, by its content-addressed path.
    pub reject_supervisor: Option<PathBuf>,
    /// Installed-state to (re)write — set to confirm an update (clear pending) or to
    /// commit the predecessor on a revert.
    pub commit: Option<InstalledState>,
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

/// How to make active-release match committed state before running it.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) enum ReleaseFix {
    #[default]
    None,
    Activate(ReleaseId),
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

    fn provider() -> Box<updated::state::ProviderRelease> {
        Box::new(updated::state::ProviderRelease {
            product: "reconciler".into(),
            release: updated::bundle::ReleaseId {
                version: "1.0.0".into(),
                manifest_sha256: "manifest".into(),
            },
            archive_sha256: "archive".into(),
            args: Vec::new(),
            timeout_millis: 1_000,
        })
    }

    fn pending() -> Pending {
        Pending {
            lifecycle_attempt_id: "attempt".into(),
            previous_release: updated::bundle::ReleaseId {
                version: "1.0.0".into(),
                manifest_sha256: "aa".into(),
            },
            previous_archive_sha256: "archive-aa".into(),
            previous_repository_lineage: updated::state::RepositoryLineage::from_metadata_url(
                "https://repo/metadata/",
            ),
            lifecycle: provider(),
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
            lifecycle_attempt_id: "attempt".into(),
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

    fn release(version: &str) -> ReleaseId {
        ReleaseId {
            version: version.into(),
            manifest_sha256: format!("{version}-manifest"),
        }
    }

    fn lineage() -> updated::state::RepositoryLineage {
        updated::state::RepositoryLineage::from_metadata_url("https://repo/metadata/")
    }

    /// The installed record as it looks mid-rollback: the CANDIDATE, because its predecessor's
    /// commit is deferred until after the boot health gate.
    fn deferred_candidate_record() -> InstalledState {
        InstalledState::confirmed(
            lineage(),
            release("2.0.0"),
            "archive-two".into(),
            provider(),
        )
    }

    fn rollback_of(predecessor: ReleaseId) -> Transaction {
        let mut predecessor_provider = provider();
        predecessor_provider.release = release("0.9.0");
        Transaction {
            id: "attempt".into(),
            previous_release: predecessor,
            previous_archive_sha256: "archive-one".into(),
            previous_repository_lineage: lineage(),
            candidate_release: release("2.0.0"),
            candidate_archive_sha256: "archive-two".into(),
            candidate_repository_lineage: lineage(),
            candidate_rejection_required: true,
            lifecycle: predecessor_provider,
            rollback_health_failures: 0,
            phase: TransactionPhase::RollbackStarted,
        }
    }

    #[test]
    fn the_boot_gate_targets_the_release_that_is_actually_running() {
        // A crash-recovered rollback restored 1.0.0 but the installed record still names the
        // candidate. Both the identity AND the providers must come from the transaction: gating
        // 1.0.0 with `--candidate 2.0.0` makes a conforming reconciler report unhealthy.
        let predecessor = release("1.0.0");
        let tx = rollback_of(predecessor.clone());
        let record = deferred_candidate_record();

        let (target, lifecycle) = boot_gate_target(Some(&tx), &record);
        assert_eq!(target, predecessor);
        assert_eq!(lifecycle, tx.lifecycle);

        // An ordinary boot has no rollback, so the committed record is the running release.
        let (target, lifecycle) = boot_gate_target(None, &record);
        assert_eq!(target, record.release);
        assert_eq!(lifecycle, record.lifecycle);

        // A forward transaction is not a rollback: nothing was restored, the record still governs.
        let mut forward = rollback_of(release("1.0.0"));
        forward.phase = TransactionPhase::CandidateStarted;
        let (target, _) = boot_gate_target(Some(&forward), &record);
        assert_eq!(target, record.release);
    }

    #[test]
    fn timeouts_from_a_signed_assignment_can_never_overflow_a_deadline() {
        // The assignment bounds these from below only, so an absurd (or hostile) value must not
        // reach `Instant + Duration`, which panics on overflow — a crash loop no rollback can break.
        let bounded = BoundedTimeouts::new(Timeouts {
            check_interval: Duration::MAX,
            health_grace: Duration::from_secs(u64::MAX),
            health_interval: Duration::MAX,
            retry_after: Duration::MAX,
            refresh_retry: Duration::MAX,
            confirmation_window: Duration::MAX,
            supervisor_check_interval: Duration::MAX,
            drain_hold: Some(Duration::MAX),
            ..Timeouts::default()
        });
        let now = std::time::Instant::now();
        for wait in [
            bounded.check_interval,
            bounded.health_grace,
            bounded.health_interval,
            bounded.retry_after,
            bounded.refresh_retry,
            bounded.confirmation_window,
            bounded.supervisor_check_interval,
            bounded.drain_hold.unwrap(),
        ] {
            assert_eq!(wait, MAX_WAIT);
            let _ = now + wait;
        }
        // Ordinary values pass through untouched.
        let sane = BoundedTimeouts::new(Timeouts::default());
        assert_eq!(sane.health_grace, Timeouts::default().health_grace);
        assert_eq!(sane.drain_hold, Timeouts::default().drain_hold);
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
