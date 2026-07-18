//! Shared durable update transaction and binary-state decisions.
//!
//! Both the continuously supervised updater and the one-shot launcher use this exact
//! journal format and recovery classifier. Process control and health policy remain in
//! their shells; deciding what durable state means lives here once.

use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;

use crate::apply;
use crate::bundle::ReleaseId;
use crate::state::LifecycleProviderRelease;

/// Durable intent for an in-flight executable replacement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    /// Fresh identity for this attempt. Stable across crash recovery, different for a
    /// later retry of the same candidate/predecessor pair.
    pub id: String,
    pub kind: Kind,
    pub previous_release: ReleaseId,
    pub previous_archive_sha256: String,
    pub candidate_release: ReleaseId,
    pub candidate_archive_sha256: String,
    /// Recovery must durably reject the candidate before this transaction may be
    /// cleared. This records policy intent that cannot safely be reconstructed from
    /// one-shot process-exit markers on a later recovery boot.
    pub candidate_rejection_required: bool,
    /// Recovery must replay the operator lifecycle provider before clearing this intent.
    #[serde(deserialize_with = "crate::required_option")]
    pub lifecycle: Option<Box<LifecycleProviderRelease>>,
    /// Last state-machine operation known to have completed durably. Recovery replays
    /// the next operation; adapters are idempotent across the action/journal-write gap.
    pub phase: Phase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    Started,
    PreflightStarted,
    PreflightCompleted,
    PrepareStarted,
    Prepared,
    DrainStarted,
    Drained,
    StopStarted,
    Stopped,
    ActivateStarted,
    CandidateActivated,
    CandidateVerified,
    StartStarted,
    CandidateStarted,
    HealthStarted,
    CandidateHealthy,
    FinalizeStarted,
    Finalized,
    CommitStarted,
    Committed,
    RollbackStarted,
    RollbackStopStarted,
    RollbackStopped,
    RollbackActivateStarted,
    PredecessorActivated,
    RollbackStartStarted,
    PredecessorStarted,
    RollbackHealthStarted,
    PredecessorHealthy,
    RollbackFinalizeStarted,
    RolledBack,
    Aborted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Supervised,
    OnLaunch,
}

impl Transaction {
    pub fn validate(&self) -> io::Result<()> {
        if self.id.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "transaction id must not be empty",
            ));
        }
        if self.kind == Kind::OnLaunch && self.candidate_rejection_required {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "on-launch transactions cannot require supervised candidate rejection",
            ));
        }
        if let Some(lifecycle) = &self.lifecycle {
            if lifecycle.product.is_empty() || lifecycle.timeout_millis == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "transaction lifecycle identity is invalid",
                ));
            }
        }
        let valid = match self.kind {
            Kind::Supervised => self.phase != Phase::Started,
            Kind::OnLaunch => matches!(
                self.phase,
                Phase::Started
                    | Phase::CandidateActivated
                    | Phase::CandidateVerified
                    | Phase::Committed
            ),
        };
        if valid {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "transaction kind {:?} cannot have phase {:?}",
                    self.kind, self.phase
                ),
            ))
        }
    }

    pub fn is_rollback(&self) -> bool {
        matches!(
            self.phase,
            Phase::RollbackStarted
                | Phase::RollbackStopStarted
                | Phase::RollbackStopped
                | Phase::RollbackActivateStarted
                | Phase::PredecessorActivated
                | Phase::RollbackStartStarted
                | Phase::PredecessorStarted
                | Phase::RollbackHealthStarted
                | Phase::PredecessorHealthy
                | Phase::RollbackFinalizeStarted
                | Phase::RolledBack
                | Phase::Aborted
        )
    }

    /// Position in the recovery path. This lets a fresh supervisor resume after the
    /// last durable boundary without re-running an operation already recorded complete.
    pub fn rollback_rank(&self) -> Option<u8> {
        match self.phase {
            Phase::RollbackStarted => Some(0),
            Phase::RollbackStopStarted => Some(1),
            Phase::RollbackStopped => Some(2),
            Phase::RollbackActivateStarted => Some(3),
            Phase::PredecessorActivated => Some(4),
            Phase::RollbackStartStarted => Some(5),
            Phase::PredecessorStarted => Some(6),
            Phase::RollbackHealthStarted => Some(7),
            Phase::PredecessorHealthy => Some(8),
            Phase::RollbackFinalizeStarted => Some(9),
            Phase::RolledBack | Phase::Aborted => Some(10),
            _ => None,
        }
    }

    pub fn advance(&mut self, next: Phase) -> io::Result<()> {
        let supervised_forward = self.kind == Kind::Supervised
            && matches!(
                (self.phase, next),
                (Phase::PreflightStarted, Phase::PreflightCompleted)
                    | (Phase::PreflightCompleted, Phase::PrepareStarted)
                    | (Phase::PrepareStarted, Phase::Prepared)
                    | (Phase::Prepared, Phase::DrainStarted)
                    | (Phase::DrainStarted, Phase::Drained)
                    | (Phase::Drained, Phase::StopStarted)
                    | (Phase::StopStarted, Phase::Stopped)
                    | (Phase::Stopped, Phase::ActivateStarted)
                    | (Phase::ActivateStarted, Phase::CandidateActivated)
                    | (Phase::CandidateActivated, Phase::StartStarted)
                    | (Phase::StartStarted, Phase::CandidateStarted)
                    | (Phase::CandidateStarted, Phase::HealthStarted)
                    | (Phase::HealthStarted, Phase::CandidateHealthy)
                    | (Phase::CandidateHealthy, Phase::FinalizeStarted)
                    | (Phase::FinalizeStarted, Phase::Finalized)
                    | (Phase::Finalized, Phase::CommitStarted)
                    | (Phase::CommitStarted, Phase::Committed)
            );
        let on_launch_forward = self.kind == Kind::OnLaunch
            && matches!(
                (self.phase, next),
                (Phase::Started, Phase::CandidateActivated)
                    | (Phase::CandidateActivated, Phase::CandidateVerified)
                    | (Phase::CandidateVerified, Phase::Committed)
            );
        let begin_rollback = next == Phase::RollbackStarted
            && !matches!(self.phase, Phase::Committed | Phase::RolledBack);
        let rollback = matches!(
            (self.phase, next),
            (Phase::RollbackStarted, Phase::RollbackStopStarted)
                | (Phase::RollbackStopStarted, Phase::RollbackStopped)
                | (Phase::RollbackStopped, Phase::RollbackActivateStarted)
                | (Phase::RollbackActivateStarted, Phase::PredecessorActivated)
                | (Phase::PredecessorActivated, Phase::RollbackStartStarted)
                | (Phase::RollbackStartStarted, Phase::PredecessorStarted)
                | (Phase::PredecessorStarted, Phase::RollbackHealthStarted)
                | (Phase::RollbackHealthStarted, Phase::PredecessorHealthy)
                | (Phase::PredecessorHealthy, Phase::RollbackFinalizeStarted)
                | (Phase::RollbackFinalizeStarted, Phase::RolledBack)
                | (Phase::RollbackStarted, Phase::Aborted)
        );
        if !(supervised_forward || on_launch_forward || begin_rollback || rollback) {
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
    let commit_may_have_landed = match tx.kind {
        Kind::Supervised => matches!(tx.phase, Phase::CommitStarted | Phase::Committed),
        Kind::OnLaunch => matches!(tx.phase, Phase::CandidateVerified | Phase::Committed),
    };
    match tx.phase {
        _ if commit_may_have_landed
            && active == Some(&tx.candidate_release)
            && committed == Some(&tx.candidate_release) =>
        {
            Recovery::Committed
        }
        Phase::Started
        | Phase::PreflightStarted
        | Phase::PreflightCompleted
        | Phase::PrepareStarted
        | Phase::Prepared
        | Phase::DrainStarted
        | Phase::Drained
        | Phase::StopStarted
        | Phase::Stopped
            if active == Some(&tx.previous_release) =>
        {
            Recovery::NeverSwapped
        }
        Phase::RolledBack | Phase::Aborted if active == Some(&tx.previous_release) => {
            Recovery::NeverSwapped
        }
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
    apply::atomic_write(path, &serde_json::to_vec(tx).map_err(io::Error::other)?)
}

pub fn clear(path: &Path) -> io::Result<()> {
    apply::remove_file_durable(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn release(version: &str, digest: &str) -> ReleaseId {
        ReleaseId {
            version: version.into(),
            manifest_sha256: digest.into(),
        }
    }

    fn tx() -> Transaction {
        Transaction {
            id: "transaction-id".into(),
            kind: Kind::Supervised,
            previous_release: release("1.0.0", "old"),
            previous_archive_sha256: "previous-archive".into(),
            candidate_release: release("2.0.0", "new"),
            candidate_archive_sha256: "archive".into(),
            candidate_rejection_required: false,
            lifecycle: None,
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

        tx.kind = Kind::OnLaunch;
        tx.phase = Phase::CandidateVerified;
        assert_eq!(
            classify_recovery(
                &tx,
                Some(&tx.candidate_release),
                Some(&tx.candidate_release)
            ),
            Recovery::Committed
        );
    }

    #[test]
    fn each_transaction_kind_accepts_only_its_explicit_path() {
        let mut supervised = tx();
        for phase in [
            Phase::PreflightCompleted,
            Phase::PrepareStarted,
            Phase::Prepared,
            Phase::DrainStarted,
            Phase::Drained,
            Phase::StopStarted,
            Phase::Stopped,
            Phase::ActivateStarted,
            Phase::CandidateActivated,
            Phase::StartStarted,
            Phase::CandidateStarted,
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

        let mut on_launch = tx();
        on_launch.kind = Kind::OnLaunch;
        on_launch.phase = Phase::Started;
        assert!(on_launch.advance(Phase::CandidateActivated).is_ok());
        assert!(on_launch.advance(Phase::CandidateVerified).is_ok());
        assert!(on_launch.advance(Phase::Committed).is_ok());
        assert!(on_launch.advance(Phase::Finalized).is_err());
    }

    #[test]
    fn rollback_records_every_completed_recovery_operation() {
        let mut transaction = tx();
        transaction.phase = Phase::CandidateHealthy;
        for (phase, rank) in [
            (Phase::RollbackStarted, 0),
            (Phase::RollbackStopStarted, 1),
            (Phase::RollbackStopped, 2),
            (Phase::RollbackActivateStarted, 3),
            (Phase::PredecessorActivated, 4),
            (Phase::RollbackStartStarted, 5),
            (Phase::PredecessorStarted, 6),
            (Phase::RollbackHealthStarted, 7),
            (Phase::PredecessorHealthy, 8),
            (Phase::RollbackFinalizeStarted, 9),
            (Phase::RolledBack, 10),
        ] {
            transaction.advance(phase).unwrap();
            assert_eq!(transaction.rollback_rank(), Some(rank));
        }
        assert!(transaction.advance(Phase::PredecessorStarted).is_err());
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("tx-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("update.tx")
    }

    #[test]
    fn journal_round_trips_and_absent_is_none() {
        let path = tmp("journal");
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
        let path = tmp("strict-schema");
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
    fn phase_must_belong_to_the_declared_transaction_kind() {
        let path = tmp("kind-phase");
        let mut invalid = tx();
        invalid.phase = Phase::Started;
        assert!(write(&path, &invalid).is_err());

        invalid.kind = Kind::OnLaunch;
        invalid.phase = Phase::Drained;
        assert!(write(&path, &invalid).is_err());
    }

    #[test]
    fn on_launch_cannot_carry_supervised_rejection_policy() {
        let mut invalid = tx();
        invalid.kind = Kind::OnLaunch;
        invalid.phase = Phase::Started;
        invalid.candidate_rejection_required = true;

        assert_eq!(
            invalid.validate().unwrap_err().to_string(),
            "on-launch transactions cannot require supervised candidate rejection"
        );
    }

    #[test]
    fn unreadable_journal_is_an_error_not_absent() {
        // A read error that is *not* NotFound (here, the path is a directory) must
        // propagate, never be mistaken for an absent journal.
        let d = std::env::temp_dir().join(format!("tx-{}-isdir", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        assert!(read(&d).is_err());
    }
}
