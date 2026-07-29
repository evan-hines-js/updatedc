//! Durable first-install transaction and its recovery classifier.
//!
//! Cold install is a first-class operation with a *different meaning* than an update: there
//! is no predecessor to drain, stop, or roll back to. It is `prepare -> place -> commit`,
//! and a failure fails closed (nothing to restore — the node simply retries the install on
//! the next boot). This module owns that journal in the same shape and spirit as the update
//! [`crate::transaction`], but without any predecessor or rollback machinery.
//!
//! The journal is written before any durable install step, so a crash mid-install always
//! leaves evidence the next boot can complete idempotently — closing the window where an
//! interrupted install could consume enrollment yet leave no installed record.

use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;

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
        if self.id.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "install transaction id must not be empty",
            ));
        }
        if !updated_contracts::is_sha256_hex(self.repository_lineage.as_str()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "install transaction repository lineage is invalid",
            ));
        }
        if self.lifecycle.product.is_empty() || self.lifecycle.timeout_millis == 0 {
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

pub fn read(path: &Path) -> io::Result<Option<InstallTransaction>> {
    match std::fs::read(path) {
        Ok(raw) => {
            let transaction: InstallTransaction = serde_json::from_slice(&raw)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            transaction.validate()?;
            Ok(Some(transaction))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn write(path: &Path, tx: &InstallTransaction) -> io::Result<()> {
    tx.validate()?;
    foundation::durable::atomic_write(
        path,
        ".install-",
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

    fn tx() -> InstallTransaction {
        InstallTransaction {
            id: "install-id".into(),
            release: release("1.0.0", "new"),
            archive_sha256: "archive".into(),
            repository_lineage: crate::state::RepositoryLineage::from_metadata_url(
                "https://repo/metadata/",
            ),
            lifecycle: provider(),
            phase: InstallPhase::Started,
        }
    }

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

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("itx-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("install.json")
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
    fn unknown_journal_shapes_are_rejected() {
        let path = tmp("strict-schema");
        std::fs::write(
            &path,
            br#"{"id":"x","release":{"version":"1","manifest_sha256":"a"},"legacy":true}"#,
        )
        .unwrap();
        assert!(
            read(&path).is_err(),
            "unknown fields are not a second schema"
        );
    }
}
