//! Shared durable update transaction and binary-state decisions.
//!
//! The node agent uses this journal format and recovery classifier.

use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;

use crate::bundle::ReleaseId;
use crate::state::{ProviderRelease, RepositoryLineage};

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
    pub candidate_repository_lineage: RepositoryLineage,
    /// Recovery must durably reject the candidate before this transaction may be
    /// cleared. This records the verdict of whatever judged the candidate — a failed activation, a
    /// failed health gate — so a later recovery boot, which has no way to re-derive it, still
    /// applies it.
    pub candidate_rejection_required: bool,
    /// Recovery must replay the operator lifecycle provider before clearing this intent.
    pub lifecycle: Box<ProviderRelease>,
    /// How many consecutive boots have failed to health-gate the restored predecessor during a
    /// crash-recovered rollback. The agent's boot health gate bounds this: once it reaches its
    /// limit, a predecessor whose bytes can no longer pass the gate stops looping the node and
    /// instead descends via ordered fallback past it. Zero for a forward update; only the rollback
    /// recovery path increments it. It survives the agent relaunch precisely because it rides the
    /// journal, which is what re-derives the rollback on each boot.
    pub rollback_health_failures: u32,
    /// Last state-machine operation known to have completed durably. Recovery replays
    /// the next operation; adapters are idempotent across the action/journal-write gap.
    pub phase: Phase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    PreflightStarted,
    PreflightCompleted,
    PrepareStarted,
    Prepared,
    ActivateStarted,
    CandidateActivated,
    HealthStarted,
    CandidateHealthy,
    FinalizeStarted,
    Finalized,
    CommitStarted,
    Committed,
    RollbackStarted,
    RollbackActivateStarted,
    PredecessorActivated,
    RollbackHealthStarted,
    PredecessorHealthy,
    RollbackFinalizeStarted,
    RolledBack,
}

impl Transaction {
    pub fn validate(&self) -> io::Result<()> {
        if self.id.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "transaction id must not be empty",
            ));
        }
        if !updated_contracts::is_sha256_hex(self.previous_repository_lineage.as_str())
            || !updated_contracts::is_sha256_hex(self.candidate_repository_lineage.as_str())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "transaction repository lineage is invalid",
            ));
        }
        if self.lifecycle.product.is_empty() || self.lifecycle.timeout_millis == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "transaction provider identity is invalid",
            ));
        }
        Ok(())
    }

    pub fn is_rollback(&self) -> bool {
        matches!(
            self.phase,
            Phase::RollbackStarted
                | Phase::RollbackActivateStarted
                | Phase::PredecessorActivated
                | Phase::RollbackHealthStarted
                | Phase::PredecessorHealthy
                | Phase::RollbackFinalizeStarted
                | Phase::RolledBack
        )
    }

    /// Position in the recovery path (0 = rollback just began, 6 = fully rolled back), or `None`
    /// when the transaction is not on the rollback path at all. This lets a fresh agent resume
    /// after the last durable boundary without re-running an operation already recorded complete.
    pub fn rollback_rank(&self) -> Option<u8> {
        Self::rollback_rank_of(self.phase)
    }

    /// The recovery rank of a phase — its position on the rollback path, or `None` for a phase that
    /// is not on that path. The single mapping every resume gate reads, so the ordering lives in one
    /// place; [`recovery_pending`](Self::recovery_pending) is how the driver consumes it.
    fn rollback_rank_of(phase: Phase) -> Option<u8> {
        match phase {
            Phase::RollbackStarted => Some(0),
            Phase::RollbackActivateStarted => Some(1),
            Phase::PredecessorActivated => Some(2),
            Phase::RollbackHealthStarted => Some(3),
            Phase::PredecessorHealthy => Some(4),
            Phase::RollbackFinalizeStarted => Some(5),
            Phase::RolledBack => Some(6),
            _ => None,
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
            (self.rollback_rank(), Self::rollback_rank_of(target)),
            (Some(current), Some(boundary)) if current < boundary
        )
    }

    pub fn advance(&mut self, next: Phase) -> io::Result<()> {
        let forward = matches!(
            (self.phase, next),
            (Phase::PreflightStarted, Phase::PreflightCompleted)
                | (Phase::PreflightCompleted, Phase::PrepareStarted)
                | (Phase::PrepareStarted, Phase::Prepared)
                | (Phase::Prepared, Phase::ActivateStarted)
                | (Phase::ActivateStarted, Phase::CandidateActivated)
                | (Phase::CandidateActivated, Phase::HealthStarted)
                | (Phase::HealthStarted, Phase::CandidateHealthy)
                | (Phase::CandidateHealthy, Phase::FinalizeStarted)
                | (Phase::FinalizeStarted, Phase::Finalized)
                | (Phase::Finalized, Phase::CommitStarted)
                | (Phase::CommitStarted, Phase::Committed)
        );
        let begin_rollback = next == Phase::RollbackStarted
            && !matches!(self.phase, Phase::Committed | Phase::RolledBack);
        let rollback = matches!(
            (self.phase, next),
            (Phase::RollbackStarted, Phase::RollbackActivateStarted)
                | (Phase::RollbackActivateStarted, Phase::PredecessorActivated)
                | (Phase::PredecessorActivated, Phase::RollbackHealthStarted)
                | (Phase::RollbackHealthStarted, Phase::PredecessorHealthy)
                | (Phase::PredecessorHealthy, Phase::RollbackFinalizeStarted)
                | (Phase::RollbackFinalizeStarted, Phase::RolledBack)
        );
        if !(forward || begin_rollback || rollback) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid transaction phase {:?} -> {next:?}", self.phase),
            ));
        }
        self.phase = next;
        Ok(())
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
    committed: Option<&ReleaseId>,
) -> Recovery {
    let commit_may_have_landed = matches!(tx.phase, Phase::CommitStarted | Phase::Committed);
    match tx.phase {
        _ if commit_may_have_landed
            && active == Some(&tx.candidate_release)
            && committed == Some(&tx.candidate_release) =>
        {
            Recovery::Committed
        }
        Phase::PreflightStarted
        | Phase::PreflightCompleted
        | Phase::PrepareStarted
        | Phase::Prepared
            if active == Some(&tx.previous_release) =>
        {
            Recovery::NeverSwapped
        }
        Phase::RolledBack if active == Some(&tx.previous_release) => Recovery::NeverSwapped,
        _ => Recovery::RestorePredecessor,
    }
}

pub fn read(path: &Path) -> io::Result<Option<Transaction>> {
    match std::fs::read(path) {
        Ok(raw) => {
            let transaction: Transaction = serde_json::from_slice(&raw)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            transaction.validate()?;
            Ok(Some(transaction))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn write(path: &Path, tx: &Transaction) -> io::Result<()> {
    tx.validate()?;
    foundation::durable::atomic_write_managed(
        path,
        ".transaction-",
        &serde_json::to_vec(tx).map_err(io::Error::other)?,
    )
}

pub fn clear(path: &Path) -> io::Result<()> {
    foundation::durable::remove_file(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{provider, release};

    fn tx() -> Transaction {
        Transaction {
            id: "transaction-id".into(),
            previous_release: release("1.0.0", "old"),
            previous_archive_sha256: "previous-archive".into(),
            previous_repository_lineage: crate::state::RepositoryLineage::from_metadata_url(
                "https://old/metadata/",
            ),
            candidate_release: release("2.0.0", "new"),
            candidate_archive_sha256: "archive".into(),
            candidate_repository_lineage: crate::state::RepositoryLineage::from_metadata_url(
                "https://new/metadata/",
            ),
            candidate_rejection_required: false,
            lifecycle: provider(),
            rollback_health_failures: 0,
            phase: Phase::PreflightStarted,
        }
    }

    #[test]
    fn recovery_is_derived_from_active_pointer_and_commit() {
        let mut tx = tx();
        tx.phase = Phase::Committed;
        assert_eq!(
            classify_recovery(
                &tx,
                Some(&tx.candidate_release),
                Some(&tx.candidate_release)
            ),
            Recovery::Committed
        );
        tx.phase = Phase::CandidateActivated;
        assert_eq!(
            classify_recovery(&tx, Some(&tx.candidate_release), Some(&tx.previous_release)),
            Recovery::RestorePredecessor
        );
        tx.phase = Phase::PreflightCompleted;
        assert_eq!(
            classify_recovery(&tx, Some(&tx.previous_release), Some(&tx.previous_release)),
            Recovery::NeverSwapped
        );
        assert_eq!(
            classify_recovery(&tx, None, Some(&tx.previous_release)),
            Recovery::RestorePredecessor
        );

        tx.phase = Phase::CommitStarted;
        assert_eq!(
            classify_recovery(
                &tx,
                Some(&tx.candidate_release),
                Some(&tx.candidate_release)
            ),
            Recovery::Committed,
            "a crash after installed-state commit but before its phase write is committed"
        );
    }

    #[test]
    fn transaction_accepts_only_its_explicit_path() {
        let mut supervised = tx();
        for phase in [
            Phase::PreflightCompleted,
            Phase::PrepareStarted,
            Phase::Prepared,
            Phase::ActivateStarted,
            Phase::CandidateActivated,
            Phase::HealthStarted,
            Phase::CandidateHealthy,
            Phase::FinalizeStarted,
            Phase::Finalized,
            Phase::CommitStarted,
            Phase::Committed,
        ] {
            supervised.advance(phase).unwrap();
        }
        assert!(supervised.advance(Phase::RollbackStarted).is_err());
    }

    #[test]
    fn rollback_records_every_completed_recovery_operation() {
        let mut transaction = tx();
        transaction.phase = Phase::CandidateHealthy;
        for (phase, rank) in [
            (Phase::RollbackStarted, 0),
            (Phase::RollbackActivateStarted, 1),
            (Phase::PredecessorActivated, 2),
            (Phase::RollbackHealthStarted, 3),
            (Phase::PredecessorHealthy, 4),
            (Phase::RollbackFinalizeStarted, 5),
            (Phase::RolledBack, 6),
        ] {
            transaction.advance(phase).unwrap();
            assert_eq!(transaction.rollback_rank(), Some(rank));
        }
        assert!(transaction.advance(Phase::PredecessorActivated).is_err());
    }

    #[test]
    fn recovery_pending_is_true_only_for_phases_not_yet_reached() {
        // Sit the transaction at PredecessorActivated (rank 2). Every rollback phase strictly ahead
        // is pending; the current phase and everything behind it are not — the exact resume gate the
        // agent drives, expressed without a single rank literal.
        let mut transaction = tx();
        transaction.phase = Phase::CandidateHealthy;
        transaction.advance(Phase::RollbackStarted).unwrap();
        transaction.advance(Phase::RollbackActivateStarted).unwrap();
        transaction.advance(Phase::PredecessorActivated).unwrap();

        // Behind / at the current phase: nothing to replay.
        for done in [
            Phase::RollbackStarted,
            Phase::RollbackActivateStarted,
            Phase::PredecessorActivated,
        ] {
            assert!(!transaction.recovery_pending(done), "{done:?} already done");
        }
        // Ahead on the rollback path: still pending.
        for pending in [
            Phase::RollbackHealthStarted,
            Phase::PredecessorHealthy,
            Phase::RollbackFinalizeStarted,
            Phase::RolledBack,
        ] {
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

    fn tmp(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join(name);
        std::fs::create_dir_all(&d).unwrap();
        let path = d.join("update.tx");
        (dir, path)
    }

    #[test]
    fn journal_round_trips_and_absent_is_none() {
        let (_dir, path) = tmp("journal");
        assert_eq!(read(&path).unwrap(), None, "absent journal reads as None");

        write(&path, &tx()).unwrap();
        assert_eq!(
            read(&path).unwrap(),
            Some(tx()),
            "written journal reads back"
        );

        clear(&path).unwrap();
        assert_eq!(read(&path).unwrap(), None, "cleared journal reads as None");
    }

    #[test]
    fn obsolete_or_unknown_journal_shapes_are_rejected() {
        let (_dir, path) = tmp("strict-schema");
        std::fs::write(
            &path,
            br#"{"previous_release":{"version":"1","manifest_sha256":"a"},"candidate_release":{"version":"2","manifest_sha256":"b"},"candidate_archive_sha256":"c","legacy":true}"#,
        )
        .unwrap();
        assert!(
            read(&path).is_err(),
            "unknown fields are not a second schema"
        );
    }

    #[test]
    fn unreadable_journal_is_an_error_not_absent() {
        // A read error that is *not* NotFound (here, the path is a directory) must
        // propagate, never be mistaken for an absent journal.
        let d = tempfile::tempdir().unwrap();
        assert!(read(d.path()).is_err());
    }
}
