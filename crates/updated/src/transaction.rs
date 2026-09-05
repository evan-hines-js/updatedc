//! Shared durable update transaction and binary-state decisions.
//!
//! The node agent uses this journal format and recovery classifier.

use serde::{Deserialize, Serialize};
use std::io;

use crate::bundle::ReleaseId;
use crate::state::{
    candidate_rejection_sha256, InstalledState, ReconcilerRelease, RepositoryLineage, RollbackGuard,
};

/// Durable intent for an in-flight executable replacement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    /// Fresh identity for this attempt. Stable across crash recovery, different for a
    /// later retry of the same candidate/predecessor pair.
    pub id: String,
    pub previous_release: ReleaseId,
    pub previous_archive_sha256: String,
    pub previous_repository_lineage: RepositoryLineage,
    pub candidate_release: ReleaseId,
    pub candidate_archive_sha256: String,
    /// Domain-separated runtime rejection identity of the exact candidate package.
    pub candidate_rejection_sha256: String,
    pub candidate_repository_lineage: RepositoryLineage,
    /// Recovery must durably reject the candidate before this transaction may be
    /// cleared. This records the verdict of whatever judged the candidate — a failed activation, a
    /// failed health gate — so a later recovery boot, which has no way to re-derive it, still
    /// enforces it. Node-local activation failures carry no candidate verdict.
    pub candidate_rejection_required: bool,
    /// The predecessor's reconciler. Recovery replays this exact artifact while
    /// restoring the predecessor; it is part of the deployed unit being compensated back to.
    pub previous_reconciler: Box<ReconcilerRelease>,
    /// The candidate's reconciler. The commit gate binds this durable identity together
    /// with the candidate application bytes, so a caller cannot commit a different reconciler than
    /// the one the update transaction authorized.
    pub candidate_reconciler: Box<ReconcilerRelease>,
    /// How many consecutive boots have failed to health-gate the restored predecessor during a
    /// crash-recovered rollback. The agent's boot health gate bounds this: once it reaches its
    /// limit, the rollback settles on that exact historically confirmed predecessor and reports
    /// its current health as unhealthy. Zero for a forward update; only the rollback recovery path
    /// increments it. It survives the agent relaunch precisely because it rides the journal, which
    /// is what re-derives the rollback on each boot.
    pub rollback_health_failures: u32,
    /// Last state-machine operation known to have completed durably. Recovery replays
    /// the next operation; adapters are idempotent across the action/journal-write gap.
    pub phase: Phase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    /// Candidate payload and reconciler bytes are staged; live state is untouched.
    Prepared,
    /// Candidate bytes were re-verified and the active pointer now names them.
    Activated,
    /// The candidate reconciler completed `converge`.
    Converged,
    /// The candidate passed its immediate health gate.
    Verified,
    /// Candidate installed state (including its rollback guard) was committed.
    Committed,
    /// Durable intent to compensate the failed candidate and restore the exact predecessor.
    RollbackPlanned,
    /// The failed candidate's reconciler completed `rollback`.
    CandidateCompensated,
    /// The predecessor pointer was restored and its reconciler completed `converge`.
    Restored,
    /// The restored predecessor passed its health gate.
    RollbackVerified,
    /// Predecessor installed state was committed.
    RolledBack,
}

impl Phase {
    pub const ALL: [Self; 10] = [
        Self::Prepared,
        Self::Activated,
        Self::Converged,
        Self::Verified,
        Self::Committed,
        Self::RollbackPlanned,
        Self::CandidateCompensated,
        Self::Restored,
        Self::RollbackVerified,
        Self::RolledBack,
    ];
}

impl Transaction {
    pub fn validate(&self) -> io::Result<()> {
        if !crate::rand::is_token(&self.id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "transaction id is invalid",
            ));
        }
        self.previous_release.validate()?;
        self.candidate_release.validate()?;
        if !updated_contracts::is_canonical_sha256(&self.previous_archive_sha256)
            || !updated_contracts::is_canonical_sha256(&self.candidate_archive_sha256)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "transaction archive identity is invalid",
            ));
        }
        if !self.previous_repository_lineage.validate()
            || !self.candidate_repository_lineage.validate()
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "transaction repository lineage is invalid",
            ));
        }
        let Some(expected_rejection) = candidate_rejection_sha256(
            &self.previous_release,
            &self.previous_archive_sha256,
            &self.candidate_release,
            &self.candidate_archive_sha256,
        ) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "update transaction must change the package",
            ));
        };
        if !updated_contracts::is_canonical_sha256(&self.candidate_rejection_sha256)
            || self.candidate_rejection_sha256 != expected_rejection
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "transaction rejection identity does not match the executable replacement",
            ));
        }
        if !self.previous_reconciler.is_valid() || !self.candidate_reconciler.is_valid() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "transaction reconciler identity is invalid",
            ));
        }
        if !self.phase_evidence_is_valid() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "transaction phase contradicts its durable evidence",
            ));
        }
        Ok(())
    }

    /// Whether the evidence carried by this record could have been observed at its phase.
    ///
    /// This is deliberately a value invariant, not only a Store transition check: journals are
    /// unauthenticated JSON and recovery reads them before it has any prior in-memory state with
    /// which to replay their history. A candidate verdict can first be learned during activation
    /// and must immediately take the rollback branch; rollback health cannot be observed until the
    /// predecessor converge has completed. Deserialization, ordinary writes, and phase advancement
    /// all consume this one rule.
    fn phase_evidence_is_valid(&self) -> bool {
        let rejection_is_possible = !self.candidate_rejection_required
            || matches!(
                self.phase,
                Phase::Activated
                    | Phase::Converged
                    | Phase::RollbackPlanned
                    | Phase::CandidateCompensated
                    | Phase::Restored
                    | Phase::RollbackVerified
                    | Phase::RolledBack
            );
        let rollback_health_is_possible = self.rollback_health_failures == 0
            || matches!(
                self.phase,
                Phase::Restored | Phase::RollbackVerified | Phase::RolledBack
            );
        rejection_is_possible && rollback_health_is_possible
    }

    /// Whether `state` is the exact deployed predecessor this transaction names.
    ///
    /// Payload bytes and their reconciler are one deployed unit. Keeping this full
    /// comparison on the transaction prevents commit, rollback, and journal-start gates from
    /// growing subtly different notions of "the predecessor".
    pub fn matches_previous(&self, state: &InstalledState) -> bool {
        self.previous_repository_lineage == state.repository_lineage
            && self.previous_release == state.release
            && self.previous_archive_sha256 == state.archive_sha256
            && self.previous_reconciler == state.reconciler
    }

    /// Whether `state` is the exact deployed candidate this transaction names.
    pub fn matches_candidate(&self, state: &InstalledState) -> bool {
        self.candidate_repository_lineage == state.repository_lineage
            && self.candidate_release == state.release
            && self.candidate_archive_sha256 == state.archive_sha256
            && self.candidate_reconciler == state.reconciler
    }

    /// Whether a committed candidate's rollback intent is the predecessor half of this exact
    /// transaction. Candidate identity is checked separately with [`Self::matches_candidate`].
    pub fn matches_rollback_guard(&self, rollback_guard: &RollbackGuard) -> bool {
        self.id == rollback_guard.attempt_id
            && self.candidate_rejection_sha256 == rollback_guard.candidate_rejection_sha256
            && self.previous_repository_lineage == rollback_guard.previous_repository_lineage
            && self.previous_release == rollback_guard.previous_release
            && self.previous_archive_sha256 == rollback_guard.previous_archive_sha256
            && self.previous_reconciler == rollback_guard.reconciler
    }

    /// The attempt identity every compensating operation of this transaction carries — the
    /// predecessor's `converge` and the `rollback` alike. It is a different attempt from the forward
    /// direction (whose identity is [`id`](Self::id)) because the two invoke the same operation
    /// with different arguments, and a reconciler that keys idempotence on the attempt id must be
    /// able to tell them apart. Derived rather than stored, so every boot and every replay of the
    /// same transaction produces the identical string. The suffix is dashless: an attempt id is
    /// dashless hex, and the reference reconciler splits its per-attempt effect names on the first
    /// `-`.
    pub fn rollback_attempt_id(&self) -> String {
        format!("{}r", self.id)
    }

    pub fn is_rollback(&self) -> bool {
        matches!(
            self.phase,
            Phase::RollbackPlanned
                | Phase::CandidateCompensated
                | Phase::Restored
                | Phase::RollbackVerified
                | Phase::RolledBack
        )
    }

    /// The recovery rank of a phase — its position on the recovery path (0 = activation pending,
    /// 4 = fully rolled back), or `None` for a phase that is not on that path. The single mapping
    /// every resume gate reads, so the ordering lives in one place; it stays private because
    /// [`recovery_pending`](Self::recovery_pending) is the only way call sites are meant to consume
    /// it — a bare rank integer outside this module would be a second ordering-aware gate.
    fn rollback_rank_of(phase: Phase) -> Option<u8> {
        match phase {
            Phase::RollbackPlanned => Some(0),
            Phase::CandidateCompensated => Some(1),
            Phase::Restored => Some(2),
            Phase::RollbackVerified => Some(3),
            Phase::RolledBack => Some(4),
            // The forward path, named rather than left to `_`. A phase added to the ROLLBACK path
            // and silently ranked `None` here would read as "not rolling back at all": the resume
            // gate would skip the step that phase exists to re-run, and a rollback would resume by
            // stepping over its own unfinished work.
            Phase::Prepared
            | Phase::Activated
            | Phase::Converged
            | Phase::Verified
            | Phase::Committed => None,
        }
    }

    /// True when this transaction is on the rollback path and has not yet advanced *into* `target` —
    /// so the recovery step that records `target` is still pending and must be (re)run on resume.
    /// Off the rollback path (or when `target` is not a rollback phase) it is false: nothing to
    /// replay. This is the single home of the "resume until the target phase is reached" convention,
    /// so recovery call sites name the phase they drive toward instead of a bare rank integer —
    /// reorder [`rollback_rank_of`](Self::rollback_rank_of) and every gate moves with it, by
    /// construction rather than by matching literals.
    pub fn recovery_pending(&self, target: Phase) -> bool {
        matches!(
            (
                Self::rollback_rank_of(self.phase),
                Self::rollback_rank_of(target),
            ),
            (Some(current), Some(boundary)) if current < boundary
        )
    }

    pub fn advance(&mut self, next: Phase) -> io::Result<()> {
        let forward = matches!(
            (self.phase, next),
            (Phase::Prepared, Phase::Activated)
                | (Phase::Activated, Phase::Converged)
                | (Phase::Converged, Phase::Verified)
                | (Phase::Verified, Phase::Committed)
                // A successful converge may require a reboot before health can be meaningful.
                // The committed rollback guard makes the next boot's gate authoritative.
                | (Phase::Converged, Phase::Committed)
        );
        let begin_rollback = matches!(
            (self.phase, next),
            (
                Phase::Prepared | Phase::Activated | Phase::Converged | Phase::Verified,
                Phase::RollbackPlanned
            )
        );
        let rollback = matches!(
            (self.phase, next),
            (Phase::RollbackPlanned, Phase::CandidateCompensated)
                | (Phase::CandidateCompensated, Phase::Restored)
                | (Phase::Restored, Phase::RollbackVerified)
                | (Phase::RollbackVerified, Phase::RolledBack)
                // A bounded unhealthy rollback compensates once and settles on the exact
                // historically confirmed predecessor without claiming it passed this boot's gate.
                | (Phase::Restored, Phase::RolledBack)
        );
        if !(forward || begin_rollback || rollback) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid transaction phase {:?} -> {next:?}", self.phase),
            ));
        }
        let previous = self.phase;
        self.phase = next;
        if !self.phase_evidence_is_valid() {
            self.phase = previous;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("transaction evidence cannot advance from {previous:?} to {next:?}"),
            ));
        }
        Ok(())
    }

    /// Record one failed authoritative boot gate while a rollback is waiting to settle.
    ///
    /// A reboot can repeat that gate after any durable point from `Restored`
    /// through `RollbackVerified`: a later phase records what a previous process completed,
    /// not that the predecessor is healthy in this process. This is the only mutation path for the
    /// durable tally, and [`permits_replacement`](Self::permits_replacement) replays it when
    /// validating a journal write, so execution and persistence cannot acquire different phase or
    /// overflow rules.
    pub fn record_rollback_health_failure(&mut self) -> io::Result<u32> {
        let boot_gate_is_active =
            !self.recovery_pending(Phase::Restored) && self.recovery_pending(Phase::RolledBack);
        if !boot_gate_is_active {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "cannot record a rollback health failure at phase {:?}",
                    self.phase
                ),
            ));
        }
        self.rollback_health_failures =
            self.rollback_health_failures
                .checked_add(1)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "rollback health failure count overflow",
                    )
                })?;
        Ok(self.rollback_health_failures)
    }

    /// Whether `next` is a legitimate durable rewrite of this transaction.
    ///
    /// The immutable identity is compared as a whole after normalizing only the three fields the
    /// machine is allowed to change. This is intentionally fail-closed for future fields. A valid
    /// rewrite is exactly one of: an identical replay, one state-machine edge, the one-way
    /// candidate-rejection verdict, or one failed rollback-health observation.
    pub fn permits_replacement(&self, next: &Self) -> bool {
        let mut identity = next.clone();
        identity.phase = self.phase;
        identity.candidate_rejection_required = self.candidate_rejection_required;
        identity.rollback_health_failures = self.rollback_health_failures;
        if identity != *self {
            return false;
        }
        if self == next {
            return true;
        }

        if self.phase != next.phase {
            // A failed confirmation-window gate can already have moved the pointer back while the
            // original update's spent Committed journal survived cleanup. Recovery materializes
            // the rollback from the committed record's RollbackGuard intent under the same lifecycle
            // attempt id. This is the only terminal same-id restart; RolledBack has no remaining
            // obligation and cannot be repurposed.
            let resumes_committed_pending = self.phase == Phase::Committed
                && next.phase == Phase::RollbackPlanned
                && self.candidate_rejection_required == next.candidate_rejection_required
                && self.rollback_health_failures == next.rollback_health_failures;
            if resumes_committed_pending {
                return true;
            }
            let mut advanced = self.clone();
            return advanced.advance(next.phase).is_ok() && advanced == *next;
        }

        // A permanent verdict is meaningful only after candidate bytes were re-verified at the
        // activation boundary or its reconciler answered during activation/health. Earlier phases
        // have observed no candidate behavior, and later phases already proved it healthy.
        let may_record_rejection = matches!(self.phase, Phase::Activated | Phase::Converged);
        let records_rejection = may_record_rejection
            && !self.candidate_rejection_required
            && next.candidate_rejection_required
            && self.rollback_health_failures == next.rollback_health_failures;
        let mut failed_rollback_health = self.clone();
        let records_failed_rollback_health = self.candidate_rejection_required
            == next.candidate_rejection_required
            && failed_rollback_health
                .record_rollback_health_failure()
                .is_ok()
            && failed_rollback_health == *next;
        records_rejection || records_failed_rollback_health
    }
}

/// The recovery action implied by a journal, the live binary, and committed state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recovery {
    /// New bytes and committed version agree; only journal/rollback cleanup remains.
    Committed,
    /// The live binary is still the predecessor; the swap never landed.
    NeverSwapped,
    /// The swap landed without its state commit, or disk is otherwise inconsistent.
    RestorePredecessor,
}

pub fn classify_recovery(
    tx: &Transaction,
    active: Option<&ReleaseId>,
    committed: Option<&InstalledState>,
) -> Recovery {
    // The commit may have landed without its journal write: the swap and the state commit are two
    // steps, and a crash between them leaves a node fully updated but journalled as mid-flight.
    if matches!(
        tx.phase,
        Phase::Converged | Phase::Verified | Phase::Committed
    ) && active == Some(&tx.candidate_release)
        && committed.is_some_and(|state| tx.matches_candidate(state))
    {
        return Recovery::Committed;
    }
    match tx.phase {
        Phase::Prepared if active == Some(&tx.previous_release) => Recovery::NeverSwapped,
        Phase::RolledBack if active == Some(&tx.previous_release) => Recovery::NeverSwapped,
        // Everything else restores the predecessor, spelled out rather than left to `_`.
        //
        // Restoring is the safe default only for a phase that precedes the commit. A phase added
        // AFTER the commit would inherit it silently and undo a finished update on the next boot —
        // the one outcome recovery must never produce — and a wildcard is what makes that a quiet
        // behaviour change instead of a compile error. Naming every phase means a new one cannot
        // join without someone deciding, here, which side of the commit it falls on.
        Phase::Prepared
        | Phase::Activated
        | Phase::Converged
        | Phase::Verified
        | Phase::Committed
        | Phase::RollbackPlanned
        | Phase::CandidateCompensated
        | Phase::Restored
        | Phase::RollbackVerified
        | Phase::RolledBack => Recovery::RestorePredecessor,
    }
}

/// Persisted through [`crate::journal`], which owns the read/write/clear the first-install
/// transaction needs in exactly the same shape.
impl crate::journal::Journaled for Transaction {
    const STAGING_PREFIX: &'static str = ".transaction-";

    fn validate(&self) -> io::Result<()> {
        Transaction::validate(self)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::testing::update_transaction as tx;

    fn previous_state(tx: &Transaction) -> InstalledState {
        InstalledState::proven(
            tx.previous_repository_lineage.clone(),
            tx.previous_release.clone(),
            tx.previous_archive_sha256.clone(),
            tx.previous_reconciler.clone(),
        )
    }

    fn candidate_state(tx: &Transaction) -> InstalledState {
        InstalledState::proven(
            tx.candidate_repository_lineage.clone(),
            tx.candidate_release.clone(),
            tx.candidate_archive_sha256.clone(),
            tx.candidate_reconciler.clone(),
        )
    }

    #[test]
    fn recovery_is_derived_from_active_pointer_and_commit() {
        let mut tx = tx();
        let previous = previous_state(&tx);
        let candidate = candidate_state(&tx);
        tx.phase = Phase::Committed;
        assert_eq!(
            classify_recovery(&tx, Some(&tx.candidate_release), Some(&candidate)),
            Recovery::Committed
        );
        tx.phase = Phase::Activated;
        assert_eq!(
            classify_recovery(&tx, Some(&tx.candidate_release), Some(&previous)),
            Recovery::RestorePredecessor
        );
        tx.phase = Phase::Prepared;
        assert_eq!(
            classify_recovery(&tx, Some(&tx.previous_release), Some(&previous)),
            Recovery::NeverSwapped
        );
        assert_eq!(
            classify_recovery(&tx, None, Some(&previous)),
            Recovery::RestorePredecessor
        );

        tx.phase = Phase::Verified;
        assert_eq!(
            classify_recovery(&tx, Some(&tx.candidate_release), Some(&candidate)),
            Recovery::Committed,
            "a crash after installed-state commit but before its phase write is committed"
        );

        let mut substituted = candidate;
        substituted.reconciler.definition_sha256 = "1".repeat(64);
        assert_eq!(
            classify_recovery(&tx, Some(&tx.candidate_release), Some(&substituted)),
            Recovery::RestorePredecessor,
            "matching application bytes with another reconciler are not a committed deployed unit"
        );
    }

    #[test]
    fn durable_update_identity_is_fully_validated() {
        let valid = tx();
        valid.validate().unwrap();
        for invalid in [
            {
                let mut value = valid.clone();
                value.id = "attempt".into();
                value
            },
            {
                let mut value = valid.clone();
                value.previous_release.manifest_sha256 = "bad".into();
                value
            },
            {
                let mut value = valid.clone();
                value.candidate_archive_sha256 = "bad".into();
                value
            },
            {
                let mut value = valid.clone();
                value.previous_archive_sha256 = "bad".into();
                value
            },
            {
                let mut value = valid.clone();
                value.candidate_rejection_sha256 = "0".repeat(64);
                value
            },
            {
                let mut value = valid.clone();
                value.candidate_release = value.previous_release.clone();
                value.candidate_archive_sha256 = value.previous_archive_sha256.clone();
                value.candidate_reconciler = value.previous_reconciler.clone();
                value.candidate_rejection_sha256 = value.candidate_archive_sha256.clone();
                value
            },
        ] {
            assert_eq!(
                invalid.validate().unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }

        let mut provider_only = valid.clone();
        provider_only.candidate_release = provider_only.previous_release.clone();
        provider_only.candidate_archive_sha256 = provider_only.previous_archive_sha256.clone();
        provider_only.candidate_reconciler.definition_sha256 = "e".repeat(64);
        provider_only.candidate_rejection_sha256 =
            updated_contracts::digest::deployment_rejection_sha256(
                &provider_only.candidate_archive_sha256,
            )
            .unwrap();
        assert!(provider_only.validate().is_err());
        provider_only.candidate_rejection_sha256 = "e".repeat(64);
        assert_eq!(
            provider_only.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "a reconciler-only runtime failure cannot poison the reconciler artifact globally"
        );

        let mut combined = valid;
        combined.candidate_reconciler.definition_sha256 = "e".repeat(64);
        combined.candidate_rejection_sha256 =
            updated_contracts::digest::deployment_rejection_sha256(
                &combined.candidate_archive_sha256,
            )
            .unwrap();
        combined.validate().unwrap();
        combined.candidate_rejection_sha256 = combined.candidate_archive_sha256.clone();
        assert_eq!(
            combined.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "a combined replacement must reject its exact deployed pair"
        );
    }

    #[test]
    fn transaction_accepts_only_its_explicit_path() {
        let mut supervised = tx();
        for phase in [
            Phase::Activated,
            Phase::Converged,
            Phase::Verified,
            Phase::Committed,
        ] {
            supervised.advance(phase).unwrap();
        }
        assert!(supervised.advance(Phase::RollbackPlanned).is_err());

        let mut rejected = tx();
        rejected.advance(Phase::Activated).unwrap();
        rejected.advance(Phase::Converged).unwrap();
        rejected.candidate_rejection_required = true;
        assert!(rejected.advance(Phase::Verified).is_err());
        assert_eq!(rejected.phase, Phase::Converged);
    }

    #[test]
    fn durable_evidence_is_valid_only_after_its_observation_boundary() {
        let mut premature_rejection = tx();
        premature_rejection.candidate_rejection_required = true;
        assert_eq!(
            premature_rejection.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut rejected_forward_commit = tx();
        rejected_forward_commit.phase = Phase::Verified;
        rejected_forward_commit.candidate_rejection_required = true;
        assert_eq!(
            rejected_forward_commit.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let mut premature_health = tx();
        premature_health.phase = Phase::RollbackPlanned;
        premature_health.rollback_health_failures = 1;
        assert_eq!(
            premature_health.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        premature_health.phase = Phase::Restored;
        premature_health.validate().unwrap();
    }

    #[test]
    fn every_phase_edge_is_explicit_and_monotonic() {
        for from in Phase::ALL {
            for to in Phase::ALL {
                let expected = matches!(
                    (from, to),
                    (Phase::Prepared, Phase::Activated)
                        | (Phase::Activated, Phase::Converged)
                        | (Phase::Converged, Phase::Verified | Phase::Committed)
                        | (Phase::Verified, Phase::Committed)
                        | (
                            Phase::Prepared | Phase::Activated | Phase::Converged | Phase::Verified,
                            Phase::RollbackPlanned
                        )
                        | (Phase::RollbackPlanned, Phase::CandidateCompensated)
                        | (Phase::CandidateCompensated, Phase::Restored)
                        | (Phase::Restored, Phase::RollbackVerified | Phase::RolledBack)
                        | (Phase::RollbackVerified, Phase::RolledBack)
                );
                let mut transaction = tx();
                transaction.phase = from;
                assert_eq!(
                    transaction.advance(to).is_ok(),
                    expected,
                    "unexpected transition {from:?} -> {to:?}"
                );
            }
        }
    }

    #[test]
    fn journal_replacement_cannot_rewrite_identity_or_history() {
        let started = tx();
        assert!(started.permits_replacement(&started));

        let mut activation = started.clone();
        activation.advance(Phase::Activated).unwrap();
        assert!(started.permits_replacement(&activation));
        assert!(!activation.permits_replacement(&started));
        let mut rejected = activation.clone();
        rejected.candidate_rejection_required = true;
        assert!(activation.permits_replacement(&rejected));
        assert!(!rejected.permits_replacement(&activation));
        let mut premature_rejection = started.clone();
        premature_rejection.candidate_rejection_required = true;
        assert!(
            !started.permits_replacement(&premature_rejection),
            "prepared state has no evidence with which to reject the candidate"
        );

        let mut rollback = started.clone();
        rollback.advance(Phase::RollbackPlanned).unwrap();
        let mut too_early = rollback.clone();
        too_early.rollback_health_failures = 1;
        assert!(!rollback.permits_replacement(&too_early));
        rollback.advance(Phase::CandidateCompensated).unwrap();
        rollback.advance(Phase::Restored).unwrap();
        for phase in [Phase::Restored, Phase::RollbackVerified] {
            rollback.phase = phase;
            let mut failed_once = rollback.clone();
            failed_once.rollback_health_failures = 1;
            assert!(
                rollback.permits_replacement(&failed_once),
                "a reboot can observe a failed rollback boot gate at {phase:?}"
            );
            let mut skipped = rollback.clone();
            skipped.rollback_health_failures = 2;
            assert!(!rollback.permits_replacement(&skipped));
        }
        rollback.phase = Phase::RolledBack;
        let mut too_late = rollback.clone();
        too_late.rollback_health_failures = 1;
        assert!(!rollback.permits_replacement(&too_late));

        let mut mutated = activation.clone();
        mutated.candidate_archive_sha256 = "f".repeat(64);
        assert!(
            !started.permits_replacement(&mutated),
            "an id cannot make different update evidence the same transaction"
        );

        let mut committed = activation;
        committed.advance(Phase::Converged).unwrap();
        committed.advance(Phase::Verified).unwrap();
        committed.advance(Phase::Committed).unwrap();
        let mut pending_rollback = committed.clone();
        pending_rollback.phase = Phase::RollbackPlanned;
        assert!(committed.permits_replacement(&pending_rollback));
        let mut repurposed = pending_rollback.clone();
        repurposed.candidate_archive_sha256 = "0".repeat(64);
        assert!(!committed.permits_replacement(&repurposed));
        let mut rolled_back = committed;
        rolled_back.phase = Phase::RolledBack;
        assert!(!rolled_back.permits_replacement(&pending_rollback));
    }

    /// An abandoned health gate concludes through the same terminal edges as a passed one: the
    /// bounded-unhealthy descend must be able to reach `RolledBack` (where the journal becomes
    /// discardable) without lying about `RollbackVerified`.
    #[test]
    fn an_abandoned_health_gate_still_reaches_the_rollback_terminal() {
        let mut transaction = tx();
        transaction.phase = Phase::Restored;
        transaction.advance(Phase::RolledBack).unwrap();
        assert_eq!(transaction.phase, Phase::RolledBack);
    }

    #[test]
    fn rollback_records_every_completed_recovery_operation() {
        let mut transaction = tx();
        transaction.phase = Phase::Activated;
        for (phase, rank) in [
            (Phase::RollbackPlanned, 0),
            (Phase::CandidateCompensated, 1),
            (Phase::Restored, 2),
            (Phase::RollbackVerified, 3),
            (Phase::RolledBack, 4),
        ] {
            transaction.advance(phase).unwrap();
            assert_eq!(Transaction::rollback_rank_of(transaction.phase), Some(rank));
        }
        assert!(transaction.advance(Phase::Restored).is_err());
    }

    #[test]
    fn recovery_pending_is_true_only_for_phases_not_yet_reached() {
        // Sit the transaction at Restored. Every rollback phase strictly ahead
        // is pending; the current phase and everything behind it are not — the exact resume gate the
        // agent drives, expressed without a single rank literal.
        let mut transaction = tx();
        transaction.phase = Phase::Activated;
        transaction.advance(Phase::RollbackPlanned).unwrap();
        transaction.advance(Phase::CandidateCompensated).unwrap();
        transaction.advance(Phase::Restored).unwrap();

        // Behind / at the current phase: nothing to replay.
        for done in [
            Phase::RollbackPlanned,
            Phase::CandidateCompensated,
            Phase::Restored,
        ] {
            assert!(!transaction.recovery_pending(done), "{done:?} already done");
        }
        // Ahead on the rollback path: still pending.
        for pending in [Phase::RollbackVerified, Phase::RolledBack] {
            assert!(
                transaction.recovery_pending(pending),
                "{pending:?} still pending"
            );
        }
        // A phase that is not on the rollback path is never "pending".
        assert!(!transaction.recovery_pending(Phase::Committed));

        // A transaction that is not rolling back has nothing pending at all.
        let forward = tx();
        assert!(!forward.recovery_pending(Phase::RolledBack));
    }

    #[test]
    fn obsolete_or_unknown_journal_shapes_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("update.tx");
        std::fs::write(
            &path,
            br#"{"previous_release":{"version":"1","manifest_sha256":"a"},"candidate_release":{"version":"2","manifest_sha256":"b"},"candidate_archive_sha256":"c","legacy":true}"#,
        )
        .unwrap();
        assert!(
            crate::journal::read::<Transaction>(&path).is_err(),
            "unknown fields are not a second schema"
        );
    }
}
