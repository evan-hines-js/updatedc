//! The committed application release and authenticated archive identity.
//!
//! Shared by the supervisor and the one-shot updater so the two never disagree about
//! the on-disk format, location, or the crucial distinction between *absent* (a
//! first install) and *corrupt* (which must fail closed, never silently reinstall).

use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::apply;
use crate::bundle::ReleaseId;

/// Version + the sha256 (hex) of the bytes that version was installed from, plus an
/// optional [`Pending`] record while a just-committed update is still proving itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledState {
    pub release: ReleaseId,
    pub archive_sha256: String,
    /// Set at the instant an update commits and cleared once it is confirmed. While it is
    /// set, the update is unconfirmed: a crash reactivates `previous_release`, and
    /// surviving the window confirms it. Absent for a
    /// steady-state install and a first install (nothing to revert to). Folded into this
    /// atomic record so the commit and its rollback intent land together — there is no
    /// separate "arm" step to be interrupted.
    #[serde(deserialize_with = "crate::required_option")]
    pub pending: Option<Pending>,
}

/// The rollback intent of an unconfirmed update: the version to revert to and when the
/// update committed (for the confirmation window).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub transition_id: String,
    pub previous_release: ReleaseId,
    pub previous_archive_sha256: String,
    /// A crash rollback requires the operator transition adapter.
    pub transition_required: bool,
    /// Unix seconds when the update committed.
    pub committed_at: u64,
}

impl InstalledState {
    fn validate(&self) -> io::Result<()> {
        if let Some(pending) = &self.pending {
            if pending.transition_id.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "pending transition id must not be empty",
                ));
            }
            if pending.previous_release == self.release {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "pending predecessor must differ from the installed release",
                ));
            }
        }
        Ok(())
    }

    /// A confirmed install (no pending rollback).
    pub fn confirmed(release: ReleaseId, archive_sha256: String) -> Self {
        InstalledState {
            release,
            archive_sha256,
            pending: None,
        }
    }
}

/// The outcome of reading the record, keeping *absent* and *corrupt* distinct: a
/// missing record is a legitimate first install, a corrupt one is not and the
/// caller must fail closed rather than treat it as a fresh start.
pub enum Installed {
    Present(InstalledState),
    Missing,
    Invalid,
}

/// Read the committed record at `path`, distinguishing absent from corrupt.
pub fn read_installed(path: &Path) -> Installed {
    match std::fs::read(path) {
        Ok(raw) => match serde_json::from_slice::<InstalledState>(&raw) {
            Ok(s) if s.validate().is_ok() => Installed::Present(s),
            Ok(_) | Err(_) => Installed::Invalid,
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => Installed::Missing,
        Err(_) => Installed::Invalid,
    }
}

/// Atomically and durably write the committed record.
pub fn write_installed(path: &Path, state: &InstalledState) -> io::Result<()> {
    state.validate()?;
    apply::atomic_write(path, &serde_json::to_vec(state).map_err(io::Error::other)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("state-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("installed.json")
    }

    #[test]
    fn round_trips() {
        let path = tmp("ok");
        write_installed(
            &path,
            &InstalledState {
                release: ReleaseId {
                    version: "2.3.4".into(),
                    manifest_sha256: "manifest".into(),
                },
                archive_sha256: "abcd".into(),
                pending: Some(Pending {
                    transition_id: "transition".into(),
                    previous_release: ReleaseId {
                        version: "2.3.3".into(),
                        manifest_sha256: "old-manifest".into(),
                    },
                    previous_archive_sha256: "beef".into(),
                    transition_required: true,
                    committed_at: 1_700_000_000,
                }),
            },
        )
        .unwrap();
        match read_installed(&path) {
            Installed::Present(s) => {
                assert_eq!(s.release.version, "2.3.4");
                assert_eq!(s.archive_sha256, "abcd");
                assert_eq!(s.pending.unwrap().previous_release.version, "2.3.3");
            }
            _ => panic!("expected Present"),
        }
    }

    #[test]
    fn obsolete_records_are_rejected_instead_of_migrated() {
        let path = tmp("obsolete");
        std::fs::write(&path, br#"{"version":"1.0.0","sha256":"aa"}"#).unwrap();
        assert!(matches!(read_installed(&path), Installed::Invalid));
    }

    #[test]
    fn unknown_fields_are_rejected_instead_of_silently_ignored() {
        let path = tmp("unknown-field");
        std::fs::write(
            &path,
            br#"{"version":"1.0.0","sha256":"aa","pending":null,"retired":true}"#,
        )
        .unwrap();
        assert!(matches!(read_installed(&path), Installed::Invalid));
    }

    #[test]
    fn missing_is_not_invalid() {
        assert!(matches!(
            read_installed(&tmp("missing")),
            Installed::Missing
        ));
    }

    #[test]
    fn corrupt_is_invalid_not_missing() {
        let path = tmp("corrupt");
        std::fs::write(&path, b"{not json").unwrap();
        assert!(matches!(read_installed(&path), Installed::Invalid));

        // A read error that is *not* NotFound (here, the path is a directory) must also
        // fail closed as Invalid — only a genuine NotFound is the legitimate first-install
        // case, so the NotFound guard must not be widened to catch every error.
        let dir = std::env::temp_dir().join(format!("state-{}-isdir", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(matches!(read_installed(&dir), Installed::Invalid));
    }
}
