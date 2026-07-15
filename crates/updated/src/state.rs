//! The committed installed-target record: the version that is installed and the
//! content hash (sha256, hex) of the exact bytes it was installed from. Written
//! atomically only after verified bytes are in place, and read at startup to learn
//! the current version and detect on-disk drift.
//!
//! Shared by the supervisor and the one-shot updater so the two never disagree about
//! the on-disk format, location, or the crucial distinction between *absent* (a
//! first install) and *corrupt* (which must fail closed, never silently reinstall).

use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::apply;

/// Version + the sha256 (hex) of the bytes that version was installed from, plus an
/// optional [`Pending`] record while a just-committed update is still proving itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstalledState {
    pub version: String,
    pub sha256: String,
    /// Set at the instant an update commits and cleared once it is confirmed. While it is
    /// set, the update is unconfirmed: a crash reverts to `previous_*` (the retained
    /// `<binary>.old` rollback image), and surviving the window confirms it. Absent for a
    /// steady-state install and a first install (nothing to revert to). Folded into this
    /// atomic record so the commit and its rollback intent land together — there is no
    /// separate "arm" step to be interrupted.
    #[serde(default)]
    pub pending: Option<Pending>,
}

/// The rollback intent of an unconfirmed update: the version to revert to and when the
/// update committed (for the confirmation window).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub previous_version: String,
    pub previous_sha256: String,
    /// Unix seconds when the update committed.
    pub committed_at: u64,
}

impl InstalledState {
    /// A confirmed install (no pending rollback).
    pub fn confirmed(version: String, sha256: String) -> Self {
        InstalledState {
            version,
            sha256,
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
            Ok(s) => Installed::Present(s),
            Err(_) => Installed::Invalid,
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => Installed::Missing,
        Err(_) => Installed::Invalid,
    }
}

/// Atomically and durably write the committed record.
pub fn write_installed(path: &Path, state: &InstalledState) -> io::Result<()> {
    apply::atomic_write(path, &serde_json::to_vec(state).map_err(io::Error::other)?)
}

/// Verify and atomically provision the installer-trusted baseline state.
pub fn verified_baseline(
    actual_sha256: &str,
    version: &str,
    expected_sha256: &str,
) -> io::Result<InstalledState> {
    if !actual_sha256.eq_ignore_ascii_case(expected_sha256) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("installer baseline {version} does not match its configured SHA-256"),
        ));
    }
    Ok(InstalledState::confirmed(
        version.to_string(),
        expected_sha256.to_ascii_lowercase(),
    ))
}

/// Verify and atomically provision the installer-trusted baseline state.
pub fn provision_baseline(
    binary: &Path,
    state_path: &Path,
    version: &str,
    sha256: &str,
) -> io::Result<InstalledState> {
    let actual = crate::hash::sha256_file(binary)?;
    let state = verified_baseline(&actual, version, sha256)?;
    write_installed(state_path, &state)?;
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("state-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d.join("app.installed")
    }

    #[test]
    fn round_trips() {
        let path = tmp("ok");
        write_installed(
            &path,
            &InstalledState {
                version: "2.3.4".into(),
                sha256: "abcd".into(),
                pending: Some(Pending {
                    previous_version: "2.3.3".into(),
                    previous_sha256: "beef".into(),
                    committed_at: 1_700_000_000,
                }),
            },
        )
        .unwrap();
        match read_installed(&path) {
            Installed::Present(s) => {
                assert_eq!(s.version, "2.3.4");
                assert_eq!(s.sha256, "abcd");
                assert_eq!(s.pending.unwrap().previous_version, "2.3.3");
            }
            _ => panic!("expected Present"),
        }
    }

    #[test]
    fn pending_defaults_to_none_for_old_records() {
        let path = tmp("legacy");
        std::fs::write(&path, br#"{"version":"1.0.0","sha256":"aa"}"#).unwrap();
        match read_installed(&path) {
            Installed::Present(s) => assert!(s.pending.is_none()),
            _ => panic!("expected Present"),
        }
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

    #[test]
    fn provisioning_verifies_bytes_before_committing_baseline() {
        let state = tmp("provision");
        let binary = state.with_extension("app");
        std::fs::write(&binary, b"installer bytes").unwrap();
        let digest = crate::hash::sha256_file(&binary).unwrap();
        let installed = provision_baseline(&binary, &state, "1.0.0", &digest).unwrap();
        assert_eq!(installed, InstalledState::confirmed("1.0.0".into(), digest));

        let bad_state = tmp("provision-bad");
        assert!(provision_baseline(&binary, &bad_state, "1.0.0", &"0".repeat(64)).is_err());
        assert!(
            !bad_state.exists(),
            "mismatch must not create trusted state"
        );
    }
}
