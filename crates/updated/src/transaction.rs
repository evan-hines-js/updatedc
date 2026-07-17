//! Shared durable update transaction and binary-state decisions.
//!
//! Both the continuously supervised updater and the one-shot launcher use this exact
//! journal format and recovery classifier. Process control and health policy remain in
//! their shells; deciding what durable state means lives here once.

use serde::{Deserialize, Serialize};
use std::io;
use std::path::Path;

use crate::apply;

/// Durable intent for an in-flight executable replacement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    pub old_sha256: String,
    pub new_sha256: String,
    pub to_version: String,
    #[serde(deserialize_with = "crate::required_option")]
    pub from_version: Option<String>,
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
    disk_sha: &str,
    committed_version: Option<&str>,
) -> Recovery {
    if hash_eq(disk_sha, &tx.new_sha256) {
        if committed_version == Some(tx.to_version.as_str()) {
            Recovery::Committed
        } else {
            Recovery::RestorePredecessor
        }
    } else if hash_eq(disk_sha, &tx.old_sha256) {
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

/// Pure drift decision shared by boot planning and one-shot execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryAction {
    Ready,
    RestoreRollback,
    FailClosed,
}

pub fn classify_binary(
    live_sha: Option<&str>,
    rollback_sha: Option<&str>,
    committed_sha: &str,
) -> BinaryAction {
    if live_sha.is_some_and(|sha| hash_eq(sha, committed_sha)) {
        BinaryAction::Ready
    } else if rollback_sha.is_some_and(|sha| hash_eq(sha, committed_sha)) {
        BinaryAction::RestoreRollback
    } else {
        BinaryAction::FailClosed
    }
}

/// Digest equality. The empty string is not a digest — callers substitute it for "this
/// file could not be hashed" (`store.binary_sha().unwrap_or_default()`) — so it matches
/// nothing, *including another empty string*. Letting unknown equal unknown would classify
/// an unhashable binary as a clean `NeverSwapped`/`Ready` and skip the very drift check
/// that must refuse to run bytes the supervisor cannot verify.
fn hash_eq(a: &str, b: &str) -> bool {
    !a.is_empty() && !b.is_empty() && a.eq_ignore_ascii_case(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tx() -> Transaction {
        Transaction {
            old_sha256: "old".into(),
            new_sha256: "new".into(),
            to_version: "2.0.0".into(),
            from_version: Some("1.0.0".into()),
        }
    }

    #[test]
    fn recovery_is_derived_from_disk_and_commit() {
        assert_eq!(
            classify_recovery(&tx(), "NEW", Some("2.0.0")),
            Recovery::Committed
        );
        assert_eq!(
            classify_recovery(&tx(), "new", Some("1.0.0")),
            Recovery::RestorePredecessor
        );
        assert_eq!(
            classify_recovery(&tx(), "OLD", Some("1.0.0")),
            Recovery::NeverSwapped
        );
        assert_eq!(
            classify_recovery(&tx(), "torn", Some("1.0.0")),
            Recovery::RestorePredecessor
        );
    }

    #[test]
    fn an_unhashable_binary_never_classifies_as_clean() {
        // Callers pass "" for a binary they could not hash (unreadable, EIO, stale handle).
        // "Unknown == unknown" must not read as a match: that would call an unverifiable
        // binary `NeverSwapped`/`Ready`, drop the rollback image, skip the drift check, and
        // launch bytes nothing ever verified.
        let mut unhashable = tx();
        unhashable.old_sha256 = String::new();
        assert_eq!(
            classify_recovery(&unhashable, "", Some("1.0.0")),
            Recovery::RestorePredecessor,
            "an unhashable disk and an unhashable predecessor must not agree"
        );
        assert_eq!(
            classify_binary(Some(""), None, ""),
            BinaryAction::FailClosed,
            "an unhashable binary is never Ready"
        );
        assert_eq!(
            classify_binary(Some("new"), Some(""), ""),
            BinaryAction::FailClosed
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
            br#"{"old_sha256":"old","new_sha256":"new","to_version":"2.0.0"}"#,
        )
        .unwrap();
        assert!(read(&path).is_err(), "from_version is required");

        std::fs::write(
            &path,
            br#"{"old_sha256":"old","new_sha256":"new","to_version":"2.0.0","from_version":"1.0.0","legacy":true}"#,
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

    #[test]
    fn binary_classifier_restores_verified_bytes_or_fails_closed() {
        assert_eq!(
            classify_binary(Some("good"), None, "GOOD"),
            BinaryAction::Ready
        );
        assert_eq!(
            classify_binary(Some("bad"), Some("good"), "GOOD"),
            BinaryAction::RestoreRollback
        );
        assert_eq!(
            classify_binary(Some("bad"), None, "good"),
            BinaryAction::FailClosed
        );
    }
}
