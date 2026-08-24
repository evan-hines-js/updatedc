//! Durable first-install transaction and its recovery classifier.
//!
//! Cold install is a first-class operation with a *different meaning* than an update: there
//! is no predecessor to roll back to. It is `prepare -> place -> commit`,
//! and a failure fails closed (nothing to restore — the node simply retries the install on
//! the next boot). This module owns that record and its phases — the same shape and spirit as the
//! update [`crate::transaction`], but without any predecessor or rollback machinery. Persisting it
//! is [`crate::journal`]: the record differs, "write the intent before acting and read it back
//! after a crash" does not.
//!
//! The journal is written before any durable install step, so a crash mid-install always
//! leaves evidence the next boot can complete idempotently — closing the window where an
//! interrupted install could consume enrollment yet leave no installed record.

use serde::{Deserialize, Serialize};
use std::io;

use crate::bundle::ReleaseId;
use crate::state::{ProviderRelease, RepositoryLineage};

/// Durable intent for an in-flight first install of a single release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstallTransaction {
    /// Fresh identity for this attempt. Stable across crash recovery.
    pub id: String,
    /// The release being installed. Recorded so recovery can `place` and `commit` from the
    /// already-staged bytes without re-resolving the assignment.
    pub release: ReleaseId,
    pub archive_sha256: String,
    pub repository_lineage: RepositoryLineage,
    /// The operator lifecycle provider staged with the install, persisted so the committed
    /// record can reference it and so recovery replays placement with the same provider.
    pub lifecycle: Box<ProviderRelease>,
    /// Last install step known to have completed durably. Recovery replays the next step;
    /// every step is idempotent across the action/journal-write gap.
    pub phase: InstallPhase,
}

/// Forward-only steps of a first install. No rollback: a first install has no predecessor,
/// so a failure before [`InstallPhase::Committed`] is retried from the top, not reverted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum InstallPhase {
    /// Intent is durable; the release is chosen but nothing on disk has changed yet.
    Started,
    /// The application bundle is fetched and staged into the versioned store.
    Prepared,
    /// The active pointer references the release and the provider's placement hook has run.
    Placed,
    /// Enrollment and the installed record are written; the install is durable and complete.
    Committed,
}

impl InstallTransaction {
    pub fn validate(&self) -> io::Result<()> {
        if !crate::rand::is_token(&self.id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "install transaction id is invalid",
            ));
        }
        self.release.validate()?;
        if !updated_contracts::is_canonical_sha256(&self.archive_sha256) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "install transaction archive identity is invalid",
            ));
        }
        if !updated_contracts::is_canonical_sha256(self.repository_lineage.as_str()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "install transaction repository lineage is invalid",
            ));
        }
        if !self.lifecycle.is_valid() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "install transaction provider identity is invalid",
            ));
        }
        Ok(())
    }

    pub fn advance(&mut self, next: InstallPhase) -> io::Result<()> {
        let forward = matches!(
            (self.phase, next),
            (InstallPhase::Started, InstallPhase::Prepared)
                | (InstallPhase::Prepared, InstallPhase::Placed)
                | (InstallPhase::Placed, InstallPhase::Committed)
        );
        if !forward {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("invalid install phase {:?} -> {next:?}", self.phase),
            ));
        }
        self.phase = next;
        Ok(())
    }

    /// Whether `next` is a legitimate durable rewrite of this same install attempt.
    ///
    /// A journal may be replayed byte-for-byte or advance exactly one state-machine edge. Using
    /// whole-record equality after [`InstallTransaction::advance`] makes every other field
    /// immutable by default: adding a field to the transaction cannot accidentally make it
    /// mutable unless this rule is deliberately changed too.
    pub fn permits_replacement(&self, next: &Self) -> bool {
        if self == next {
            return true;
        }
        let mut advanced = self.clone();
        advanced.advance(next.phase).is_ok() && advanced == *next
    }
}

/// The recovery action implied by an install journal and the committed installed record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstallRecovery {
    /// The installed record is committed at the journal's release; only cleanup remains.
    Committed,
    /// The install did not durably complete; drive it forward from its recorded phase.
    Resume,
}

pub fn classify_install_recovery(
    tx: &InstallTransaction,
    installed: Option<&ReleaseId>,
) -> InstallRecovery {
    if installed == Some(&tx.release) {
        InstallRecovery::Committed
    } else {
        InstallRecovery::Resume
    }
}

/// Persisted through [`crate::journal`], which owns the read/write/clear the update transaction
/// needs in exactly the same shape.
impl crate::journal::Journaled for InstallTransaction {
    const STAGING_PREFIX: &'static str = ".install-";

    fn validate(&self) -> io::Result<()> {
        InstallTransaction::validate(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::install_transaction as tx;
    use crate::testing::release;

    #[test]
    fn advance_is_forward_only() {
        let mut t = tx();
        t.advance(InstallPhase::Prepared).unwrap();
        t.advance(InstallPhase::Placed).unwrap();
        t.advance(InstallPhase::Committed).unwrap();
        assert!(t.advance(InstallPhase::Started).is_err());
        assert!(tx().advance(InstallPhase::Placed).is_err());
    }

    #[test]
    fn journal_replacement_is_replay_or_one_exact_forward_step() {
        let started = tx();
        assert!(started.permits_replacement(&started));

        let mut prepared = started.clone();
        prepared.advance(InstallPhase::Prepared).unwrap();
        assert!(started.permits_replacement(&prepared));
        assert!(!prepared.permits_replacement(&started));

        let mut mutated = prepared.clone();
        mutated.archive_sha256 = "f".repeat(64);
        assert!(
            !started.permits_replacement(&mutated),
            "an id cannot make different install evidence the same attempt"
        );
    }

    #[test]
    fn recovery_is_committed_only_when_installed_matches() {
        let t = tx();
        assert_eq!(
            classify_install_recovery(&t, Some(&t.release)),
            InstallRecovery::Committed
        );
        assert_eq!(classify_install_recovery(&t, None), InstallRecovery::Resume);
        assert_eq!(
            classify_install_recovery(&t, Some(&release("9.9.9", "other"))),
            InstallRecovery::Resume
        );
    }

    #[test]
    fn durable_install_identity_is_fully_validated() {
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
                value.release.manifest_sha256 = "bad".into();
                value
            },
            {
                let mut value = valid;
                value.archive_sha256 = "bad".into();
                value
            },
        ] {
            assert_eq!(
                invalid.validate().unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn unknown_journal_shapes_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("install.json");
        std::fs::write(
            &path,
            br#"{"id":"x","release":{"version":"1","manifest_sha256":"a"},"legacy":true}"#,
        )
        .unwrap();
        assert!(
            crate::journal::read::<InstallTransaction>(&path).is_err(),
            "unknown fields are not a second schema"
        );
    }
}
