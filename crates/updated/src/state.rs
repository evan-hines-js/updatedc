//! The committed application release and authenticated archive identity.
//!
//! Shared by the agent and the one-shot updater so the two never disagree about
//! the on-disk format, location, or the crucial distinction between *absent* (a
//! first install) and *corrupt* (which must fail closed, never silently reinstall).

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::bundle::ReleaseId;

/// Identity of the repository whose TUF rollback floor, installed-version ordering, and rejection
/// policy apply. It deliberately depends only on the canonical metadata base: moving a node to
/// another metadata origin starts a new release lineage even when version strings move backwards,
/// while a spelling-only change cannot manufacture blank trust history.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RepositoryLineage(String);

impl RepositoryLineage {
    pub fn from_metadata_url(metadata_url: &str) -> Result<Self, String> {
        let canonical = updated_contracts::assignment::canonical_repository_base(metadata_url)?;
        Ok(Self(updated_contracts::digest::sha256_bytes(
            canonical.as_str().as_bytes(),
        )))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn rejection_key(&self, digest: &str) -> String {
        format!("{}:{digest}", self.0)
    }

    /// Whether this is the canonical digest identity used by durable state and rejection keys.
    pub fn validate(&self) -> bool {
        updated_contracts::is_canonical_sha256(&self.0)
    }
}

/// Execution derived from a verified package, persisted with its transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReconcilerRelease {
    pub definition_sha256: String,
    pub product: String,
    pub api: u32,
    pub timeout_millis: u64,
}
impl ReconcilerRelease {
    pub(crate) const MAX_SERIALIZED_BYTES: usize = 1024;
    pub fn check_supported(&self) -> Result<(), String> {
        crate::command_adapter::check_api(self.api)
    }
    pub fn execution_digest(&self) -> String {
        self.definition_sha256.clone()
    }
    pub(crate) fn is_valid(&self) -> bool {
        updated_contracts::is_canonical_sha256(&self.definition_sha256)
            && updated_contracts::identity::is_segment(&self.product)
            && self.api > 0
            && (1..=crate::command_adapter::MAX_INVOCATION_MILLIS).contains(&self.timeout_millis)
    }
}

/// Derive the only runtime rejection identity an executable replacement may carry.
///
/// Runtime failure rejects this exact package within its repository lineage. Invalid archive
/// bytes are rejected separately at verification. A lineage rebind of identical bytes has no
/// runtime rejection identity and must not manufacture an update transaction.
pub fn candidate_rejection_sha256(
    previous_release: &ReleaseId,
    previous_archive_sha256: &str,
    candidate_release: &ReleaseId,
    candidate_archive_sha256: &str,
) -> Option<String> {
    if previous_release == candidate_release && previous_archive_sha256 == candidate_archive_sha256
    {
        return None;
    }
    updated_contracts::digest::deployment_rejection_sha256(candidate_archive_sha256)
}

const INSTALLED_RECORD_MAX_BYTES: usize = 2 * ReconcilerRelease::MAX_SERIALIZED_BYTES + 8 * 1024;

/// Version + the sha256 (hex) of the bytes that version was installed from, plus an
/// optional [`RollbackGuard`] while a just-committed update is still proving itself.
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
    pub reconciler: Box<ReconcilerRelease>,
    /// Set atomically when an update commits and cleared after its confirmation window. While it
    /// is set, a failed boot health gate reactivates `previous_release`. Absent for a steady-state
    /// install and a first install (nothing to revert to). Folding this guard into the installed
    /// record means commit and rollback authority land together; there is no separate arm step.
    #[serde(deserialize_with = "updated_contracts::required_option")]
    pub rollback_guard: Option<RollbackGuard>,
    /// Whether this head has passed an authoritative health gate. A first install is provisional
    /// until its first successful gate. Failure rejects it and requires explicit recovery; it
    /// never grants permission to reinstall through a different root. Updates carry their proven
    /// predecessor in the rollback guard and recover through the update transaction.
    pub maturity: Maturity,
}

/// Whether this payload has passed an authoritative health gate on this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Maturity {
    Provisional,
    Proven,
}

/// The rollback authority retained during an update's confirmation window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RollbackGuard {
    pub attempt_id: String,
    /// Candidate identity to reject if a boot health gate fails while this guard is armed.
    pub candidate_rejection_sha256: String,
    pub previous_release: ReleaseId,
    pub previous_archive_sha256: String,
    pub previous_repository_lineage: RepositoryLineage,
    /// A crash rollback requires the predecessor's exact reconciler.
    pub reconciler: Box<ReconcilerRelease>,
    /// Unix seconds when the update committed.
    pub committed_at: u64,
}

impl InstalledState {
    pub const fn is_proven(&self) -> bool {
        matches!(self.maturity, Maturity::Proven)
    }

    /// Validate the complete durable installed-state invariant.
    ///
    /// Persistence facades with non-file backends call this same rule before committing, while
    /// [`write_installed`] and [`read_installed`] retain it at the raw file boundary. Keeping the
    /// rule on the value prevents test and production stores from defining different accepted
    /// states.
    pub fn validate(&self) -> io::Result<()> {
        if !self.repository_lineage.validate() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid repository lineage",
            ));
        }
        if !self.reconciler.is_valid() {
            // The head reconciler is the one actually invoked, so it gets the same validation as
            // the predecessor reconciler retained by the rollback guard.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "installed reconciler identity is invalid",
            ));
        }
        self.release.validate()?;
        if !updated_contracts::is_canonical_sha256(&self.archive_sha256) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "installed archive identity is invalid",
            ));
        }
        if self.maturity == Maturity::Provisional && self.rollback_guard.is_some() {
            // A provisional cold install has no proven predecessor to revert to; a rollback guard
            // on it is a contradiction and can only appear in a corrupt or hand-edited record.
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "a provisional install must not carry a rollback guard",
            ));
        }
        if let Some(guard) = &self.rollback_guard {
            if guard.committed_at == 0 {
                // Zero is not a timestamp the update path can produce. Treating it as one would
                // make `window_passed` immediately settle the update on the next boot, erasing its
                // rollback intent before the candidate passed a health gate.
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "rollback guard timestamp is invalid",
                ));
            }
            if !guard.previous_repository_lineage.validate() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "rollback guard predecessor repository lineage is invalid",
                ));
            }
            if !crate::rand::is_token(&guard.attempt_id) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "rollback guard attempt id is invalid",
                ));
            }
            let expected_rejection = candidate_rejection_sha256(
                &guard.previous_release,
                &guard.previous_archive_sha256,
                &self.release,
                &self.archive_sha256,
            );
            if !updated_contracts::is_canonical_sha256(&guard.candidate_rejection_sha256)
                || expected_rejection.as_deref() != Some(guard.candidate_rejection_sha256.as_str())
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "rollback guard rejection identity does not match the executable replacement",
                ));
            }
            if !guard.reconciler.is_valid() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "rollback guard reconciler identity is invalid",
                ));
            }
            guard.previous_release.validate()?;
            if !updated_contracts::is_canonical_sha256(&guard.previous_archive_sha256) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "rollback guard predecessor archive identity is invalid",
                ));
            }
        }
        Ok(())
    }

    /// A health-proven install with no rollback guard.
    pub fn proven(
        repository_lineage: RepositoryLineage,
        release: ReleaseId,
        archive_sha256: String,
        reconciler: Box<ReconcilerRelease>,
    ) -> Self {
        InstalledState {
            repository_lineage,
            release,
            archive_sha256,
            reconciler,
            rollback_guard: None,
            maturity: Maturity::Proven,
        }
    }

    /// A *provisional* cold install: the head placed from the first trusted assignment, not yet
    /// health-proven and with no predecessor. If it fails its first health gate, boot rejects it
    /// and the next cold install descends past it.
    pub fn provisional(
        repository_lineage: RepositoryLineage,
        release: ReleaseId,
        archive_sha256: String,
        reconciler: Box<ReconcilerRelease>,
    ) -> Self {
        Self {
            maturity: Maturity::Provisional,
            ..Self::proven(repository_lineage, release, archive_sha256, reconciler)
        }
    }

    /// Promote a provisional cold install to proven after it passes its first health gate.
    /// Idempotent; returns whether the flag changed, so the caller only rewrites on transition.
    /// This deliberately does not disarm an update's [`RollbackGuard`] — that is the distinct
    /// [`InstalledState::disarm_rollback`] transition.
    pub fn prove_provisional(&mut self) -> bool {
        std::mem::replace(&mut self.maturity, Maturity::Proven) == Maturity::Provisional
    }

    /// Settle an update after its confirmation window by removing its rollback guard.
    /// Idempotent; returns whether durable state changed.
    pub fn disarm_rollback(&mut self) -> bool {
        self.rollback_guard.take().is_some()
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
        reconciler: &ReconcilerRelease,
    ) -> Option<Self> {
        (self.repository_lineage != lineage
            && self.release == *release
            && self.archive_sha256 == archive_sha256
            && self.reconciler.as_ref() == reconciler)
            .then(|| Self {
                repository_lineage: lineage,
                ..self.clone()
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

/// The only content an installation-history marker holds. Reading anything else back is corruption,
/// and [`read_install_history`] reports it as [`InstallHistory::Invalid`] so the node fails closed
/// instead of mistaking a damaged record for a node that was never installed.
const INSTALL_HISTORY_MARKER: &[u8] = b"installed\n";

pub enum InstallHistory {
    Present,
    Missing,
    Invalid,
}

pub fn install_history_path(installed_path: &Path) -> PathBuf {
    installed_path.with_file_name("install-history")
}

/// Permanently consume bootstrap eligibility before the first installed-state commit.
/// A crash after this write can require operator recovery, but can never re-enter bootstrap.
pub fn record_first_install(installed_path: &Path) -> io::Result<()> {
    let path = install_history_path(installed_path);
    // Once-only: this record is what makes bootstrap eligibility unrepeatable, so an existing one
    // is never overwritten. The single install lock makes this check sufficient — it is the same
    // owner that would have written it.
    if !matches!(
        read_install_history(installed_path),
        InstallHistory::Missing
    ) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "this installation has already consumed its bootstrap enrollment",
        ));
    }
    // Atomically, via a temp file and rename. Writing in place would leave a truncated record if
    // the process died mid-write — and a record that is present but unparseable is worse than
    // either state it sits between: the node is refused a cold install (bootstrap is spent) and
    // refused a normal boot (the record is invalid), with nothing on disk able to resolve it.
    foundation::durable::atomic_write_managed(&path, ".enrollment-", INSTALL_HISTORY_MARKER)
}

pub fn read_install_history(installed_path: &Path) -> InstallHistory {
    match foundation::file::read_bounded_regular(
        &install_history_path(installed_path),
        INSTALL_HISTORY_MARKER.len(),
        foundation::file::FinalSymlink::Refuse,
    ) {
        Ok(raw) if raw == INSTALL_HISTORY_MARKER => InstallHistory::Present,
        Ok(_) => InstallHistory::Invalid,
        Err(error) if error.kind() == io::ErrorKind::NotFound => InstallHistory::Missing,
        Err(_) => InstallHistory::Invalid,
    }
}

/// Read the committed record at `path`, distinguishing absent, corrupt, and an I/O failure.
///
/// Durable-state mutations use this form so a transient sharing/lock error retains its OS error
/// code and reaches the caller's retry policy. Treating that error as corrupt would turn a busy
/// Windows file into a permanent state verdict before the retry boundary can see it.
pub fn try_read_installed(path: &Path) -> io::Result<Installed> {
    match foundation::file::read_bounded_regular(
        path,
        INSTALLED_RECORD_MAX_BYTES,
        foundation::file::FinalSymlink::Refuse,
    ) {
        Ok(raw) => Ok(match serde_json::from_slice::<InstalledState>(&raw) {
            Ok(s) if s.validate().is_ok() => Installed::Present(Box::new(s)),
            Ok(_) | Err(_) => Installed::Invalid,
        }),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Installed::Missing),
        Err(error) => Err(error),
    }
}

/// Observe the committed record fail-closed: an unreadable record is not absence and must never
/// open the first-install path. Mutation code uses [`try_read_installed`] instead, preserving the
/// same parser and validation while allowing node-local I/O faults to be retried.
pub fn read_installed(path: &Path) -> Installed {
    try_read_installed(path).unwrap_or(Installed::Invalid)
}

/// Atomically and durably write the committed record.
pub fn write_installed(path: &Path, state: &InstalledState) -> io::Result<()> {
    state.validate()?;
    let bytes = serde_json::to_vec(state).map_err(io::Error::other)?;
    if bytes.len() > INSTALLED_RECORD_MAX_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "installed state exceeds its byte limit",
        ));
    }
    foundation::durable::atomic_write_managed(path, ".state-", &bytes)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::testing::provider;

    fn tmp(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join(name);
        std::fs::create_dir_all(&d).unwrap();
        let path = d.join("installed.json");
        (dir, path)
    }

    fn digest(byte: char) -> String {
        std::iter::repeat_n(byte, 64).collect()
    }

    fn lineage(metadata_url: &str) -> RepositoryLineage {
        RepositoryLineage::from_metadata_url(metadata_url).expect("fixture metadata URL is valid")
    }

    #[test]
    fn round_trips() {
        let (_dir, path) = tmp("ok");
        write_installed(
            &path,
            &InstalledState {
                repository_lineage: lineage("https://repo/metadata/"),
                release: ReleaseId {
                    version: "2.3.4".into(),
                    manifest_sha256: digest('a'),
                },
                archive_sha256: digest('b'),
                reconciler: provider(),
                rollback_guard: Some(RollbackGuard {
                    attempt_id: digest('c'),
                    candidate_rejection_sha256:
                        updated_contracts::digest::deployment_rejection_sha256(&digest('b'))
                            .unwrap(),
                    previous_release: ReleaseId {
                        version: "2.3.3".into(),
                        manifest_sha256: digest('d'),
                    },
                    previous_archive_sha256: digest('e'),
                    previous_repository_lineage: lineage("https://old/metadata/"),
                    reconciler: provider(),
                    committed_at: 1_700_000_000,
                }),
                maturity: Maturity::Proven,
            },
        )
        .unwrap();
        match read_installed(&path) {
            Installed::Present(s) => {
                assert_eq!(s.release.version, "2.3.4");
                assert_eq!(s.archive_sha256, digest('b'));
                assert_eq!(s.rollback_guard.unwrap().previous_release.version, "2.3.3");
            }
            _ => panic!("expected Present"),
        }
    }

    #[test]
    fn obsolete_records_are_rejected_instead_of_migrated() {
        let (_dir, path) = tmp("obsolete");
        std::fs::write(&path, br#"{"version":"1.0.0","sha256":"aa"}"#).unwrap();
        assert!(matches!(read_installed(&path), Installed::Invalid));
    }

    #[test]
    fn unknown_fields_are_rejected_instead_of_silently_ignored() {
        let (_dir, path) = tmp("unknown-field");
        std::fs::write(
            &path,
            br#"{"version":"1.0.0","sha256":"aa","pending":null,"retired":true}"#,
        )
        .unwrap();
        assert!(matches!(read_installed(&path), Installed::Invalid));
    }

    #[test]
    fn native_execution_survives_durable_state_without_a_fictitious_artifact() {
        let (root, path) = tmp("native-execution");
        let mut reconciler = provider();
        reconciler.api = 1;
        let state = InstalledState::proven(
            lineage("https://repo/metadata/"),
            ReleaseId {
                version: "4.0.0".into(),
                manifest_sha256: digest('a'),
            },
            digest('b'),
            reconciler,
        );
        write_installed(&path, &state).unwrap();
        let Installed::Present(restored) = read_installed(&path) else {
            panic!("valid native state was lost")
        };
        assert_eq!(*restored, state);
        assert_eq!(restored.reconciler.api, 1);
        drop(root);
    }

    #[test]
    fn the_installed_artifact_identity_is_revalidated_as_one_unit() {
        let valid = InstalledState::proven(
            lineage("https://repo/metadata/"),
            ReleaseId {
                version: "2.3.4".into(),
                manifest_sha256: digest('a'),
            },
            digest('b'),
            provider(),
        );
        let mut malformed_release = valid.clone();
        malformed_release.release.manifest_sha256 = "bad".into();
        let mut malformed_archive = valid;
        malformed_archive.archive_sha256 = "bad".into();

        for state in [malformed_release, malformed_archive] {
            let (_dir, path) = tmp("malformed-artifact");
            assert_eq!(
                write_installed(&path, &state).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
            assert!(matches!(read_installed(&path), Installed::Invalid));
        }
    }

    #[test]
    fn a_zero_confirmation_timestamp_cannot_erase_rollback_intent() {
        let tx = crate::testing::update_transaction();
        let state = InstalledState {
            repository_lineage: tx.candidate_repository_lineage,
            release: tx.candidate_release,
            archive_sha256: tx.candidate_archive_sha256,
            reconciler: provider(),
            rollback_guard: Some(RollbackGuard {
                attempt_id: tx.id,
                candidate_rejection_sha256: tx.candidate_rejection_sha256,
                previous_release: tx.previous_release,
                previous_archive_sha256: tx.previous_archive_sha256,
                previous_repository_lineage: tx.previous_repository_lineage,
                reconciler: tx.previous_reconciler,
                committed_at: 0,
            }),
            maturity: Maturity::Proven,
        };
        assert_eq!(
            state.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let (_dir, path) = tmp("zero-confirmation-time");
        assert_eq!(
            write_installed(&path, &state).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn every_runtime_failure_rejects_the_exact_deployment_only() {
        let tx = crate::testing::update_transaction();
        let mut state = InstalledState {
            repository_lineage: tx.candidate_repository_lineage,
            release: tx.candidate_release,
            archive_sha256: tx.candidate_archive_sha256,
            reconciler: tx.candidate_reconciler,
            rollback_guard: Some(RollbackGuard {
                attempt_id: tx.id,
                candidate_rejection_sha256: digest('0'),
                previous_release: tx.previous_release,
                previous_archive_sha256: tx.previous_archive_sha256,
                previous_repository_lineage: tx.previous_repository_lineage,
                reconciler: tx.previous_reconciler,
                committed_at: 1,
            }),
            maturity: Maturity::Proven,
        };
        assert_eq!(
            state.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let deployment_rejection =
            updated_contracts::digest::deployment_rejection_sha256(&state.archive_sha256).unwrap();
        state
            .rollback_guard
            .as_mut()
            .unwrap()
            .candidate_rejection_sha256 = deployment_rejection.clone();
        state.validate().unwrap();

        state
            .rollback_guard
            .as_mut()
            .unwrap()
            .candidate_rejection_sha256 = state.archive_sha256.clone();
        assert_eq!(
            state.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "runtime evidence cannot poison reusable application bytes"
        );
        state
            .rollback_guard
            .as_mut()
            .unwrap()
            .candidate_rejection_sha256 = state.reconciler.definition_sha256.clone();
        assert_eq!(
            state.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "runtime evidence cannot poison a reusable provider set"
        );

        // Identical package bytes cannot manufacture a second execution-only transition.
        let pending = state.rollback_guard.as_mut().unwrap();
        pending.previous_release = state.release.clone();
        pending.previous_archive_sha256 = state.archive_sha256.clone();
        pending.reconciler.definition_sha256 = digest('e');
        state
            .rollback_guard
            .as_mut()
            .unwrap()
            .candidate_rejection_sha256 = deployment_rejection.clone();
        assert!(state.validate().is_err());

        // Reaching it with both artifacts changed still yields that one candidate identity.
        let pending = state.rollback_guard.as_mut().unwrap();
        pending.previous_release.version = "0.9.0".into();
        pending.previous_archive_sha256 = digest('b');
        state
            .rollback_guard
            .as_mut()
            .unwrap()
            .candidate_rejection_sha256 = deployment_rejection;
        state.validate().unwrap();
    }

    #[test]
    fn missing_is_not_invalid() {
        let (_dir, path) = tmp("missing");
        assert!(matches!(read_installed(&path), Installed::Missing));
    }

    #[test]
    fn corrupt_is_invalid_not_missing() {
        let (_dir, path) = tmp("corrupt");
        std::fs::write(&path, b"{not json").unwrap();
        assert!(matches!(read_installed(&path), Installed::Invalid));

        // A read error that is *not* NotFound (here, the path is a directory) must also
        // fail closed as Invalid — only a genuine NotFound is the legitimate first-install
        // case, so the NotFound guard must not be widened to catch every error.
        let isdir = tempfile::tempdir().unwrap();
        assert!(matches!(read_installed(isdir.path()), Installed::Invalid));
    }

    #[test]
    fn checked_reads_separate_state_verdicts_from_io_failures() {
        let (_dir, path) = tmp("checked-read");
        assert!(matches!(try_read_installed(&path), Ok(Installed::Missing)));

        std::fs::write(&path, b"{not json").unwrap();
        assert!(matches!(try_read_installed(&path), Ok(Installed::Invalid)));

        let isdir = tempfile::tempdir().unwrap();
        assert!(try_read_installed(isdir.path()).is_err());
    }

    #[test]
    fn canonical_metadata_base_is_the_exact_lineage_boundary() {
        let x = lineage("https://EXAMPLE.com:443/a/../metadata/");
        assert_eq!(x, lineage("https://example.com/metadata/"));
        assert_ne!(x, lineage("https://example.com/other/"));
        assert!(RepositoryLineage::from_metadata_url("http://example.com/metadata/").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn absolute_path_and_file_url_share_one_offline_lineage() {
        assert_eq!(
            lineage("/opt/updated/repository/metadata/"),
            lineage("file:///opt/updated/repository/metadata/")
        );
    }

    #[test]
    fn version_floor_and_rebind_share_the_same_lineage_rule() {
        let old = lineage("https://gateway/metadata/");
        let new = lineage("https://batch/metadata/");
        let release = ReleaseId {
            version: "8.0.0".into(),
            manifest_sha256: digest('a'),
        };
        let reconciler = ReconcilerRelease {
            definition_sha256: "f".repeat(64),
            product: "reconciler".into(),
            api: 1,
            timeout_millis: 1_000,
        };
        let installed = InstalledState::proven(
            old.clone(),
            release.clone(),
            digest('d'),
            Box::new(reconciler.clone()),
        );
        assert_eq!(installed.version_floor_for(&old), Some("8.0.0"));
        assert_eq!(installed.version_floor_for(&new), None);
        assert_eq!(
            installed
                .rebind_if_same_artifact(new.clone(), &release, &digest('d'), &reconciler)
                .unwrap()
                .repository_lineage,
            new
        );
        assert!(installed
            .rebind_if_same_artifact(new, &release, &digest('e'), &reconciler)
            .is_none());
    }

    #[test]
    fn rebind_changes_only_lineage_and_cannot_settle_reconciler_state() {
        let old = lineage("https://old/metadata/");
        let new = lineage("https://new/metadata/");
        let release = ReleaseId {
            version: "8.0.0".into(),
            manifest_sha256: digest('a'),
        };
        let reconciler = Box::new(ReconcilerRelease {
            definition_sha256: digest('b'),
            product: "reconciler".into(),
            api: 1,
            timeout_millis: 1_000,
        });
        let mut installed = InstalledState::proven(
            old.clone(),
            release.clone(),
            digest('e'),
            reconciler.clone(),
        );
        installed.rollback_guard = Some(RollbackGuard {
            attempt_id: digest('f'),
            candidate_rejection_sha256: updated_contracts::digest::deployment_rejection_sha256(
                &digest('e'),
            )
            .unwrap(),
            previous_release: ReleaseId {
                version: "7.0.0".into(),
                manifest_sha256: digest('2'),
            },
            previous_archive_sha256: digest('3'),
            previous_repository_lineage: old,
            reconciler,
            committed_at: 42,
        });

        let rebound = installed
            .rebind_if_same_artifact(new.clone(), &release, &digest('e'), &installed.reconciler)
            .unwrap();
        assert_eq!(rebound.repository_lineage, new);
        assert_eq!(rebound.rollback_guard, installed.rollback_guard);
        assert_eq!(rebound.is_proven(), installed.is_proven());

        let mut provisional = installed;
        provisional.rollback_guard = None;
        provisional.maturity = Maturity::Provisional;
        let rebound = provisional
            .rebind_if_same_artifact(
                lineage("https://third/metadata/"),
                &release,
                &digest('e'),
                &provisional.reconciler,
            )
            .unwrap();
        assert!(!rebound.is_proven());
    }

    #[test]
    fn install_history_is_one_way_and_independent_of_enrollment() {
        let (_dir, path) = tmp("enrollment");
        let enrollment = path.with_file_name("enrollment.json");
        std::fs::create_dir_all(enrollment.parent().unwrap()).unwrap();
        std::fs::write(&enrollment, b"signed enrollment artifact").unwrap();
        assert!(matches!(
            read_install_history(&path),
            InstallHistory::Missing
        ));
        record_first_install(&path).unwrap();
        assert_eq!(
            std::fs::read(&enrollment).unwrap(),
            b"signed enrollment artifact"
        );
        assert!(matches!(
            read_install_history(&path),
            InstallHistory::Present
        ));
        assert_eq!(
            record_first_install(&path).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert!(matches!(read_installed(&path), Installed::Missing));
        assert!(matches!(
            read_install_history(&path),
            InstallHistory::Present
        ));
        // A damaged record fails closed: it is neither a usable installation history nor a fresh start.
        std::fs::write(install_history_path(&path), b"tampered").unwrap();
        assert!(matches!(
            read_install_history(&path),
            InstallHistory::Invalid
        ));
    }
}
