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

/// Durable intent for an in-flight executable replacement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    pub previous_release: ReleaseId,
    pub candidate_release: ReleaseId,
    pub candidate_archive_sha256: String,
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
    if active == Some(&tx.candidate_release) {
        if committed == Some(&tx.candidate_release) {
            Recovery::Committed
        } else {
            Recovery::RestorePredecessor
        }
    } else if active == Some(&tx.previous_release) {
        Recovery::NeverSwapped
    } else {
        Recovery::RestorePredecessor
    }
}

pub fn read(path: &Path) -> io::Result<Option<Transaction>> {
    match std::fs::read(path) {
        Ok(raw) => serde_json::from_slice(&raw)
            .map(Some)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

pub fn write(path: &Path, tx: &Transaction) -> io::Result<()> {
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
            previous_release: release("1.0.0", "old"),
            candidate_release: release("2.0.0", "new"),
            candidate_archive_sha256: "archive".into(),
        }
    }

    #[test]
    fn recovery_is_derived_from_active_pointer_and_commit() {
        let tx = tx();
        assert_eq!(
            classify_recovery(
                &tx,
                Some(&tx.candidate_release),
                Some(&tx.candidate_release)
            ),
            Recovery::Committed
        );
        assert_eq!(
            classify_recovery(&tx, Some(&tx.candidate_release), Some(&tx.previous_release)),
            Recovery::RestorePredecessor
        );
        assert_eq!(
            classify_recovery(&tx, Some(&tx.previous_release), Some(&tx.previous_release)),
            Recovery::NeverSwapped
        );
        assert_eq!(
            classify_recovery(&tx, None, Some(&tx.previous_release)),
            Recovery::RestorePredecessor
        );
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
    fn unreadable_journal_is_an_error_not_absent() {
        // A read error that is *not* NotFound (here, the path is a directory) must
        // propagate, never be mistaken for an absent journal.
        let d = std::env::temp_dir().join(format!("tx-{}-isdir", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        assert!(read(&d).is_err());
    }
}
