//! The committed application release and authenticated archive identity.
//!
//! Shared by the supervisor and the one-shot updater so the two never disagree about
//! the on-disk format, location, or the crucial distinction between *absent* (a
//! first install) and *corrupt* (which must fail closed, never silently reinstall).

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::bundle::ReleaseId;

/// Identity of the repository whose version ordering and rejection policy applies.
/// It deliberately depends only on the metadata URL: moving a node to another metadata
/// origin starts a new release lineage even when version strings move backwards.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RepositoryLineage(String);

impl RepositoryLineage {
    pub fn from_metadata_url(metadata_url: &str) -> Self {
        Self(crate::hash::sha256_bytes(metadata_url.as_bytes()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn rejection_key(&self, archive_sha256: &str) -> String {
        format!("{}:{archive_sha256}", self.0)
    }

    fn validate(&self) -> bool {
        updated_contracts::is_sha256_hex(&self.0)
    }
}

/// Exact independently signed lifecycle provider pinned to a release.
/// The supervisor stages it content-addressed on disk and invokes its manifest entrypoint
/// as an external CLI; this record holds only the signed reference plus its invocation args.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRelease {
    pub product: String,
    pub release: ReleaseId,
    pub archive_sha256: String,
    pub args: Vec<String>,
    pub timeout_millis: u64,
}

/// Version + the sha256 (hex) of the bytes that version was installed from, plus an
/// optional [`Pending`] record while a just-committed update is still proving itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstalledState {
    pub repository_lineage: RepositoryLineage,
    pub release: ReleaseId,
    pub archive_sha256: String,
    /// The reconciler of the currently installed release.
    /// Persisted with the install so `pre-start` can run on every boot — install, plain
    /// restart, and update — without first re-resolving the assignment over the network. The
    /// provider bytes are already content-addressed on disk from when the release was staged;
    /// this holds only the signed reference.
    pub lifecycle: Box<ProviderRelease>,
    /// Set at the instant an update commits and cleared once it is confirmed. While it is
    /// set, the update is unconfirmed: a crash reactivates `previous_release`, and
    /// surviving the window confirms it. Absent for a
    /// steady-state install and a first install (nothing to revert to). Folded into this
    /// atomic record so the commit and its rollback intent land together — there is no
    /// separate "arm" step to be interrupted.
    #[serde(deserialize_with = "crate::required_option")]
    pub pending: Option<Pending>,
    /// Whether this head has proven itself healthy at least once. `false` marks a *provisional*
    /// cold install: a head placed from the first trusted assignment that has never passed a
    /// health gate and has no predecessor to revert to. If a provisional head fails — crashes or
    /// wedges before its first passing gate — the boot rejects its bytes so the next cold install
    /// descends via ordered fallback past it; passing the gate flips this to `true` and it is then
    /// a normal steady-state head. Every non-cold-install commit (update, rollback, rebind) writes
    /// `true`: their failure recovery is the update state machine's rollback to a proven
    /// predecessor, not an ordered-fallback descent. This is the whole "first boot / clean
    /// environment" signal, kept atomic with the install record rather than in a side file.
    pub confirmed: bool,
}

/// The rollback intent of an unconfirmed update: the version to revert to and when the
/// update committed (for the confirmation window).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub lifecycle_attempt_id: String,
    pub previous_release: ReleaseId,
    pub previous_archive_sha256: String,
    pub previous_repository_lineage: RepositoryLineage,
    /// A crash rollback requires the operator lifecycle provider.
    pub lifecycle: Box<ProviderRelease>,
    /// Unix seconds when the update committed.
    pub committed_at: u64,
}

impl InstalledState {
    fn validate(&self) -> io::Result<()> {
        if !self.repository_lineage.validate() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid repository lineage",
            ));
        }
        if !self.confirmed && self.pending.is_some() {
            // A provisional cold install has no proven predecessor to revert to; a rollback intent
            // on an unconfirmed head is a contradiction. Every confirmed-write path clears or sets
            // pending deliberately, so this can only appear in a corrupt/hand-edited record.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "a provisional (unconfirmed) install must not carry a pending rollback",
            ));
        }
        if let Some(pending) = &self.pending {
            if !pending.previous_repository_lineage.validate() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid pending predecessor repository lineage",
                ));
            }
            if pending.lifecycle_attempt_id.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "pending lifecycle id must not be empty",
                ));
            }
            if pending.previous_release == self.release && pending.lifecycle == self.lifecycle {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "pending predecessor must differ by application or node reconciler",
                ));
            }
            if pending.lifecycle.product.is_empty() || pending.lifecycle.timeout_millis == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "pending provider identity is invalid",
                ));
            }
        }
        Ok(())
    }

    /// A confirmed install (no pending rollback): a head with a proven predecessor or one that
    /// has already passed a health gate. Its recovery on failure is the update state machine.
    pub fn confirmed(
        repository_lineage: RepositoryLineage,
        release: ReleaseId,
        archive_sha256: String,
        lifecycle: Box<ProviderRelease>,
    ) -> Self {
        InstalledState {
            repository_lineage,
            release,
            archive_sha256,
            lifecycle,
            pending: None,
            confirmed: true,
        }
    }

    /// A *provisional* cold install: the head placed from the first trusted assignment, not yet
    /// health-proven and with no predecessor. See the [`confirmed`](Self::confirmed) field — if it
    /// fails its first health gate the boot rejects it and the next cold install descends past it.
    pub fn provisional(
        repository_lineage: RepositoryLineage,
        release: ReleaseId,
        archive_sha256: String,
        lifecycle: Box<ProviderRelease>,
    ) -> Self {
        Self {
            confirmed: false,
            ..Self::confirmed(repository_lineage, release, archive_sha256, lifecycle)
        }
    }

    /// Promote a provisional cold install to confirmed after it passes its first health gate.
    /// Idempotent; returns whether the flag changed, so the caller only rewrites on transition.
    pub fn confirm(&mut self) -> bool {
        !std::mem::replace(&mut self.confirmed, true)
    }

    /// Version ordering is meaningful only inside one metadata lineage.
    pub fn version_floor_for(&self, lineage: &RepositoryLineage) -> Option<&str> {
        (self.repository_lineage == *lineage).then_some(self.release.version.as_str())
    }

    /// Rebind an unchanged, already-running artifact to a newly authenticated metadata
    /// lineage. Returning `None` means executable replacement is required.
    pub fn rebind_if_same_artifact(
        &self,
        lineage: RepositoryLineage,
        release: &ReleaseId,
        archive_sha256: &str,
        reconciler: &ProviderRelease,
    ) -> Option<Self> {
        (self.repository_lineage != lineage
            && self.release == *release
            && self.archive_sha256 == archive_sha256
            && self.lifecycle.as_ref() == reconciler)
            .then(|| {
                Self::confirmed(
                    lineage,
                    self.release.clone(),
                    self.archive_sha256.clone(),
                    self.lifecycle.clone(),
                )
            })
    }
}

/// The outcome of reading the record, keeping *absent* and *corrupt* distinct: a
/// missing record is a legitimate first install, a corrupt one is not and the
/// caller must fail closed rather than treat it as a fresh start.
pub enum Installed {
    Present(Box<InstalledState>),
    Missing,
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    initial_repository_lineage: RepositoryLineage,
}

pub enum EnrollmentState {
    Present,
    Missing,
    Invalid,
}

pub fn enrollment_path(installed_path: &Path) -> PathBuf {
    installed_path.with_file_name("enrollment.json")
}

/// Permanently consume bootstrap eligibility before the first installed-state commit.
/// A crash after this write can require operator recovery, but can never re-enter bootstrap.
pub fn enroll(installed_path: &Path, lineage: RepositoryLineage) -> io::Result<()> {
    let path = enrollment_path(installed_path);
    let bytes = serde_json::to_vec(&Enrollment {
        initial_repository_lineage: lineage,
    })
    .map_err(io::Error::other)?;
    // Once-only: this record is what makes bootstrap eligibility unrepeatable, so an existing one
    // is never overwritten. The single install lock makes this check sufficient — it is the same
    // owner that would have written it.
    if !matches!(read_enrollment(installed_path), EnrollmentState::Missing) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "this installation has already consumed its bootstrap enrollment",
        ));
    }
    // Atomically, via a temp file and rename. Writing in place would leave a truncated record if
    // the process died mid-write — and a record that is present but unparseable is worse than
    // either state it sits between: the node is refused a cold install (bootstrap is spent) and
    // refused a normal boot (the record is invalid), with nothing on disk able to resolve it.
    foundation::durable::atomic_write_managed(&path, ".enrollment-", &bytes)
}

pub fn read_enrollment(installed_path: &Path) -> EnrollmentState {
    match std::fs::read(enrollment_path(installed_path)) {
        Ok(raw) => match serde_json::from_slice::<Enrollment>(&raw) {
            Ok(enrollment) if enrollment.initial_repository_lineage.validate() => {
                EnrollmentState::Present
            }
            Ok(_) | Err(_) => EnrollmentState::Invalid,
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => EnrollmentState::Missing,
        Err(_) => EnrollmentState::Invalid,
    }
}

/// Read the committed record at `path`, distinguishing absent from corrupt.
pub fn read_installed(path: &Path) -> Installed {
    match std::fs::read(path) {
        Ok(raw) => match serde_json::from_slice::<InstalledState>(&raw) {
            Ok(s) if s.validate().is_ok() => Installed::Present(Box::new(s)),
            Ok(_) | Err(_) => Installed::Invalid,
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => Installed::Missing,
        Err(_) => Installed::Invalid,
    }
}

/// Atomically and durably write the committed record.
pub fn write_installed(path: &Path, state: &InstalledState) -> io::Result<()> {
    state.validate()?;
    foundation::durable::atomic_write_managed(
        path,
        ".state-",
        &serde_json::to_vec(state).map_err(io::Error::other)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::provider;

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
                repository_lineage: RepositoryLineage::from_metadata_url("https://repo/metadata/"),
                release: ReleaseId {
                    version: "2.3.4".into(),
                    manifest_sha256: "manifest".into(),
                },
                archive_sha256: "abcd".into(),
                lifecycle: provider(),
                pending: Some(Pending {
                    lifecycle_attempt_id: "lifecycle".into(),
                    previous_release: ReleaseId {
                        version: "2.3.3".into(),
                        manifest_sha256: "old-manifest".into(),
                    },
                    previous_archive_sha256: "beef".into(),
                    previous_repository_lineage: RepositoryLineage::from_metadata_url(
                        "https://old/metadata/",
                    ),
                    lifecycle: provider(),
                    committed_at: 1_700_000_000,
                }),
                confirmed: true,
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

    #[test]
    fn metadata_url_is_the_exact_lineage_boundary() {
        let x = RepositoryLineage::from_metadata_url("https://x/metadata/");
        assert_eq!(
            x,
            RepositoryLineage::from_metadata_url("https://x/metadata/")
        );
        assert_ne!(
            x,
            RepositoryLineage::from_metadata_url("https://y/metadata/")
        );
    }

    #[test]
    fn version_floor_and_rebind_share_the_same_lineage_rule() {
        let old = RepositoryLineage::from_metadata_url("https://gateway/metadata/");
        let new = RepositoryLineage::from_metadata_url("https://batch/metadata/");
        let release = ReleaseId {
            version: "8.0.0".into(),
            manifest_sha256: "manifest".into(),
        };
        let reconciler = ProviderRelease {
            product: "reconciler".into(),
            release: ReleaseId {
                version: "1.0.0".into(),
                manifest_sha256: "reconciler-manifest".into(),
            },
            archive_sha256: "reconciler-archive".into(),
            args: Vec::new(),
            timeout_millis: 1_000,
        };
        let installed = InstalledState::confirmed(
            old.clone(),
            release.clone(),
            "archive".into(),
            Box::new(reconciler.clone()),
        );
        assert_eq!(installed.version_floor_for(&old), Some("8.0.0"));
        assert_eq!(installed.version_floor_for(&new), None);
        assert_eq!(
            installed
                .rebind_if_same_artifact(new.clone(), &release, "archive", &reconciler)
                .unwrap()
                .repository_lineage,
            new
        );
        assert!(installed
            .rebind_if_same_artifact(new, &release, "different", &reconciler)
            .is_none());
    }

    #[test]
    fn enrollment_is_one_way_and_survives_missing_installed_state() {
        let path = tmp("enrollment");
        let lineage = RepositoryLineage::from_metadata_url("https://repo/metadata/");
        enroll(&path, lineage.clone()).unwrap();
        assert!(matches!(read_enrollment(&path), EnrollmentState::Present));
        assert_eq!(
            enroll(&path, lineage).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert!(matches!(read_installed(&path), Installed::Missing));
        assert!(matches!(read_enrollment(&path), EnrollmentState::Present));
    }
}
