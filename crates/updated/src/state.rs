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

/// Exact independently signed lifecycle provider pinned to a release.
/// The agent stages it content-addressed on disk and invokes its manifest entrypoint
/// as an external CLI; this record holds only the signed reference plus its invocation args.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderRelease {
    /// SHA-256 of the signed provider-set document this reconciler was resolved from. This is the
    /// provider half of the deployed release identity: telemetry and the update loop compare it
    /// with the live assignment so a provider-only revision cannot be mistaken for convergence.
    pub provider_set_sha256: String,
    pub product: String,
    pub release: ReleaseId,
    pub archive_sha256: String,
    pub args: Vec<String>,
    pub timeout_millis: u64,
}

impl ProviderRelease {
    /// Upper bound for the serialized provider identity carried inside durable state. The
    /// provider-set contract already accounts for the worst-case JSON expansion of its bounded
    /// arguments; this shape adds only fixed-width digests and a bounded release identity.
    pub(crate) const MAX_SERIALIZED_BYTES: usize =
        updated_contracts::artifact::ProviderSet::MAX_DOCUMENT_BYTES;

    /// Re-check on the way in everything the signed provider contract enforced on the way out.
    ///
    /// The installed record is plain JSON with no integrity check, so a value that reached disk
    /// some other way must not become the reconciler identity this node invokes on every boot,
    /// probe and fingerprint. A zero timeout is the sharp case: every hook would be past its
    /// deadline before its first poll and be killed as "exceeded its 0s timeout", so the node
    /// crash-loops blaming the operator's hook instead of failing closed on a corrupt record.
    ///
    /// The one home for that rule: the installed record, the update transaction and the install
    /// transaction all persist the same identity and all re-check it here.
    pub(crate) fn is_valid(&self) -> bool {
        use updated_contracts::artifact::ProviderSet;
        updated_contracts::is_canonical_sha256(&self.provider_set_sha256)
            && updated_contracts::identity::is_segment(&self.product)
            && self.release.validate().is_ok()
            && updated_contracts::is_canonical_sha256(&self.archive_sha256)
            && self.args.len() <= ProviderSet::MAX_ARGS
            && self
                .args
                .iter()
                .all(|arg| arg.len() <= ProviderSet::MAX_ARG_BYTES)
            && (ProviderSet::MIN_TIMEOUT_MILLIS..=ProviderSet::MAX_TIMEOUT_MILLIS)
                .contains(&self.timeout_millis)
    }
}

/// Derive the only runtime rejection identity an executable replacement may carry.
///
/// A health or lifecycle failure proves that the exact application/provider deployment failed; it
/// does not prove either independently reusable artifact malformed. The identity is therefore the
/// same domain-separated pair whether one artifact changed or both did. Structurally invalid
/// content is rejected directly at its verification boundary instead. A metadata-only lineage
/// rebind returns `None`: it is not an executable replacement and must use
/// [`InstalledState::rebind_if_same_artifact`] instead of manufacturing an update transaction.
/// Durable records and the agent's transaction constructor all call this function, so cold install,
/// update, rollback, and validation cannot drift into different runtime verdicts.
pub fn candidate_rejection_sha256(
    previous_release: &ReleaseId,
    previous_archive_sha256: &str,
    previous_lifecycle: &ProviderRelease,
    candidate_release: &ReleaseId,
    candidate_archive_sha256: &str,
    candidate_lifecycle: &ProviderRelease,
) -> Option<String> {
    if previous_release == candidate_release
        && previous_archive_sha256 == candidate_archive_sha256
        && previous_lifecycle == candidate_lifecycle
    {
        return None;
    }
    updated_contracts::digest::deployment_rejection_sha256(
        candidate_archive_sha256,
        &candidate_lifecycle.provider_set_sha256,
    )
}

const INSTALLED_RECORD_MAX_BYTES: usize = 2 * ProviderRelease::MAX_SERIALIZED_BYTES + 8 * 1024;

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
    #[serde(deserialize_with = "updated_contracts::required_option")]
    pub pending: Option<Pending>,
    /// Whether this head has proven itself healthy at least once. `false` marks a *provisional*
    /// cold install: a head placed from the first trusted assignment that has never passed a
    /// health gate and has no predecessor to revert to. If a provisional head fails — crashes or
    /// wedges before its first passing gate — the boot rejects its bytes so the next cold install
    /// descends via cold-install fallback past it; passing the gate flips this to `true` and it is then
    /// a normal steady-state head. Every non-cold-install commit (update, rollback, rebind) writes
    /// `true`: their failure recovery is the update state machine's rollback to a proven
    /// predecessor, not a cold-install-fallback descent. This is the whole "first boot / clean
    /// environment" signal, kept atomic with the install record rather than in a side file.
    pub confirmed: bool,
}

/// The rollback intent of an unconfirmed update: the version to revert to and when the
/// update committed (for the confirmation window).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub lifecycle_attempt_id: String,
    /// Candidate identity to reject if this confirmation window later fails.
    pub candidate_rejection_sha256: String,
    pub previous_release: ReleaseId,
    pub previous_archive_sha256: String,
    pub previous_repository_lineage: RepositoryLineage,
    /// A crash rollback requires the operator lifecycle provider.
    pub lifecycle: Box<ProviderRelease>,
    /// Unix seconds when the update committed.
    pub committed_at: u64,
}

impl InstalledState {
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
        if !self.lifecycle.is_valid() {
            // The head reconciler is the one actually invoked, so it gets the check the pending
            // predecessor already got. See [`ProviderRelease::is_valid`].
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "installed provider identity is invalid",
            ));
        }
        self.release.validate()?;
        if !updated_contracts::is_canonical_sha256(&self.archive_sha256) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "installed archive identity is invalid",
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
            if pending.committed_at == 0 {
                // Zero is not a timestamp the update path can produce. Treating it as one would
                // make `window_passed` immediately settle the update on the next boot, erasing its
                // rollback intent before the candidate passed a health gate.
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "pending confirmation timestamp is invalid",
                ));
            }
            if !pending.previous_repository_lineage.validate() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid pending predecessor repository lineage",
                ));
            }
            if !crate::rand::is_token(&pending.lifecycle_attempt_id) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "pending lifecycle id is invalid",
                ));
            }
            let expected_rejection = candidate_rejection_sha256(
                &pending.previous_release,
                &pending.previous_archive_sha256,
                &pending.lifecycle,
                &self.release,
                &self.archive_sha256,
                &self.lifecycle,
            );
            if !updated_contracts::is_canonical_sha256(&pending.candidate_rejection_sha256)
                || expected_rejection.as_deref()
                    != Some(pending.candidate_rejection_sha256.as_str())
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "pending rejection identity does not match the executable replacement",
                ));
            }
            if !pending.lifecycle.is_valid() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "pending provider identity is invalid",
                ));
            }
            pending.previous_release.validate()?;
            if !updated_contracts::is_canonical_sha256(&pending.previous_archive_sha256) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "pending predecessor archive identity is invalid",
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
    /// This deliberately does not settle an update's [`Pending`] rollback intent — that is the
    /// distinct [`InstalledState::settle_update`] transition.
    pub fn confirm_provisional(&mut self) -> bool {
        !std::mem::replace(&mut self.confirmed, true)
    }

    /// Settle an update after its confirmation window by removing its rollback intent.
    /// Idempotent; returns whether durable state changed.
    pub fn settle_update(&mut self) -> bool {
        self.pending.take().is_some()
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

/// The only content an enrollment record ever holds. Reading anything else back is corruption,
/// and [`read_enrollment`] reports it as [`EnrollmentState::Invalid`] so the node fails closed
/// instead of mistaking a damaged record for a node that was never enrolled.
const ENROLLMENT_MARKER: &[u8] = b"enrolled\n";

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
pub fn enroll(installed_path: &Path) -> io::Result<()> {
    let path = enrollment_path(installed_path);
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
    foundation::durable::atomic_write_managed(&path, ".enrollment-", ENROLLMENT_MARKER)
}

pub fn read_enrollment(installed_path: &Path) -> EnrollmentState {
    match foundation::file::read_bounded_regular(
        &enrollment_path(installed_path),
        ENROLLMENT_MARKER.len(),
        foundation::file::FinalSymlink::Refuse,
    ) {
        Ok(raw) if raw == ENROLLMENT_MARKER => EnrollmentState::Present,
        Ok(_) => EnrollmentState::Invalid,
        Err(error) if error.kind() == io::ErrorKind::NotFound => EnrollmentState::Missing,
        Err(_) => EnrollmentState::Invalid,
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
                lifecycle: provider(),
                pending: Some(Pending {
                    lifecycle_attempt_id: digest('c'),
                    candidate_rejection_sha256:
                        updated_contracts::digest::deployment_rejection_sha256(
                            &digest('b'),
                            &provider().provider_set_sha256,
                        )
                        .unwrap(),
                    previous_release: ReleaseId {
                        version: "2.3.3".into(),
                        manifest_sha256: digest('d'),
                    },
                    previous_archive_sha256: digest('e'),
                    previous_repository_lineage: lineage("https://old/metadata/"),
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
                assert_eq!(s.archive_sha256, digest('b'));
                assert_eq!(s.pending.unwrap().previous_release.version, "2.3.3");
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
    fn a_head_reconciler_identity_the_contract_would_refuse_is_a_corrupt_record() {
        // The head reconciler is the one this node invokes on every boot, probe and fingerprint,
        // so it gets the check the pending predecessor already gets. A zero timeout is the sharp
        // case: `lifecycle_timeout` would hand every hook a deadline already in the past and kill
        // it as "exceeded its 0s timeout", crash-looping the node with a message blaming the
        // operator's hook — where refusing the record fails closed on the real cause.
        let head = |mutate: fn(&mut ProviderRelease)| {
            let mut lifecycle = provider();
            mutate(&mut lifecycle);
            InstalledState::confirmed(
                lineage("https://repo/metadata/"),
                ReleaseId {
                    version: "2.3.4".into(),
                    manifest_sha256: digest('a'),
                },
                digest('b'),
                lifecycle,
            )
        };
        for (name, state) in [
            ("zero-timeout", head(|p| p.timeout_millis = 0)),
            (
                "over-timeout",
                head(|p| {
                    p.timeout_millis =
                        updated_contracts::artifact::ProviderSet::MAX_TIMEOUT_MILLIS + 1
                }),
            ),
            // `product` becomes a directory name under the install root; staging refuses anything
            // that could escape it, and so must the record that outlives staging.
            (
                "traversal-product",
                head(|p| p.product = "../escape".into()),
            ),
            ("empty-product", head(|p| p.product = String::new())),
            (
                "leading-dash-product",
                head(|p| p.product = "-unsafe".into()),
            ),
            (
                "overlong-product",
                head(|p| {
                    p.product = "a".repeat(updated_contracts::identity::MAX_SEGMENT_BYTES + 1)
                }),
            ),
            (
                "bad-provider-archive",
                head(|p| p.archive_sha256 = "bad".into()),
            ),
            (
                "bad-provider-release",
                head(|p| p.release.manifest_sha256 = "bad".into()),
            ),
            (
                "too-many-provider-args",
                head(|p| {
                    p.args =
                        vec![String::new(); updated_contracts::artifact::ProviderSet::MAX_ARGS + 1]
                }),
            ),
            (
                "overlong-provider-arg",
                head(|p| {
                    p.args = vec![
                        "x".repeat(updated_contracts::artifact::ProviderSet::MAX_ARG_BYTES + 1)
                    ]
                }),
            ),
        ] {
            let (_dir, path) = tmp(name);
            assert_eq!(
                write_installed(&path, &state).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{name} must never be written"
            );
            // Present on disk some other way (a hand-edited or truncated-then-rewritten record):
            // it must read as corrupt, not as a usable head.
            std::fs::write(&path, serde_json::to_vec(&state).unwrap()).unwrap();
            assert!(
                matches!(read_installed(&path), Installed::Invalid),
                "{name} must read as corrupt"
            );
        }
    }

    #[test]
    fn the_installed_artifact_identity_is_revalidated_as_one_unit() {
        let valid = InstalledState::confirmed(
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
            lifecycle: provider(),
            pending: Some(Pending {
                lifecycle_attempt_id: tx.id,
                candidate_rejection_sha256: tx.candidate_rejection_sha256,
                previous_release: tx.previous_release,
                previous_archive_sha256: tx.previous_archive_sha256,
                previous_repository_lineage: tx.previous_repository_lineage,
                lifecycle: tx.previous_lifecycle,
                committed_at: 0,
            }),
            confirmed: true,
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
            lifecycle: tx.candidate_lifecycle,
            pending: Some(Pending {
                lifecycle_attempt_id: tx.id,
                candidate_rejection_sha256: digest('0'),
                previous_release: tx.previous_release,
                previous_archive_sha256: tx.previous_archive_sha256,
                previous_repository_lineage: tx.previous_repository_lineage,
                lifecycle: tx.previous_lifecycle,
                committed_at: 1,
            }),
            confirmed: true,
        };
        assert_eq!(
            state.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );

        let deployment_rejection = updated_contracts::digest::deployment_rejection_sha256(
            &state.archive_sha256,
            &state.lifecycle.provider_set_sha256,
        )
        .unwrap();
        state.pending.as_mut().unwrap().candidate_rejection_sha256 = deployment_rejection.clone();
        state.validate().unwrap();

        state.pending.as_mut().unwrap().candidate_rejection_sha256 = state.archive_sha256.clone();
        assert_eq!(
            state.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "runtime evidence cannot poison reusable application bytes"
        );
        state.pending.as_mut().unwrap().candidate_rejection_sha256 =
            state.lifecycle.provider_set_sha256.clone();
        assert_eq!(
            state.validate().unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "runtime evidence cannot poison a reusable provider set"
        );

        // Reaching the same candidate through a provider-only transition yields the same identity.
        let pending = state.pending.as_mut().unwrap();
        pending.previous_release = state.release.clone();
        pending.previous_archive_sha256 = state.archive_sha256.clone();
        pending.lifecycle.provider_set_sha256 = digest('e');
        state.pending.as_mut().unwrap().candidate_rejection_sha256 = deployment_rejection.clone();
        state.validate().unwrap();

        // Reaching it with both artifacts changed still yields that one candidate identity.
        let pending = state.pending.as_mut().unwrap();
        pending.previous_release.version = "0.9.0".into();
        pending.previous_archive_sha256 = digest('b');
        state.pending.as_mut().unwrap().candidate_rejection_sha256 = deployment_rejection;
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
        let reconciler = ProviderRelease {
            provider_set_sha256: "f".repeat(64),
            product: "reconciler".into(),
            release: ReleaseId {
                version: "1.0.0".into(),
                manifest_sha256: digest('b'),
            },
            archive_sha256: digest('c'),
            args: Vec::new(),
            timeout_millis: 1_000,
        };
        let installed = InstalledState::confirmed(
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
    fn rebind_changes_only_lineage_and_cannot_settle_lifecycle_state() {
        let old = lineage("https://old/metadata/");
        let new = lineage("https://new/metadata/");
        let release = ReleaseId {
            version: "8.0.0".into(),
            manifest_sha256: digest('a'),
        };
        let lifecycle = Box::new(ProviderRelease {
            provider_set_sha256: digest('b'),
            product: "reconciler".into(),
            release: ReleaseId {
                version: "1.0.0".into(),
                manifest_sha256: digest('c'),
            },
            archive_sha256: digest('d'),
            args: Vec::new(),
            timeout_millis: 1_000,
        });
        let mut installed =
            InstalledState::confirmed(old.clone(), release.clone(), digest('e'), lifecycle.clone());
        installed.pending = Some(Pending {
            lifecycle_attempt_id: digest('f'),
            candidate_rejection_sha256: updated_contracts::digest::deployment_rejection_sha256(
                &digest('e'),
                &installed.lifecycle.provider_set_sha256,
            )
            .unwrap(),
            previous_release: ReleaseId {
                version: "7.0.0".into(),
                manifest_sha256: digest('2'),
            },
            previous_archive_sha256: digest('3'),
            previous_repository_lineage: old,
            lifecycle,
            committed_at: 42,
        });

        let rebound = installed
            .rebind_if_same_artifact(new.clone(), &release, &digest('e'), &installed.lifecycle)
            .unwrap();
        assert_eq!(rebound.repository_lineage, new);
        assert_eq!(rebound.pending, installed.pending);
        assert_eq!(rebound.confirmed, installed.confirmed);

        let mut provisional = installed;
        provisional.pending = None;
        provisional.confirmed = false;
        let rebound = provisional
            .rebind_if_same_artifact(
                lineage("https://third/metadata/"),
                &release,
                &digest('e'),
                &provisional.lifecycle,
            )
            .unwrap();
        assert!(!rebound.confirmed);
    }

    #[test]
    fn enrollment_is_one_way_and_survives_missing_installed_state() {
        let (_dir, path) = tmp("enrollment");
        enroll(&path).unwrap();
        assert!(matches!(read_enrollment(&path), EnrollmentState::Present));
        assert_eq!(
            enroll(&path).unwrap_err().kind(),
            io::ErrorKind::AlreadyExists
        );
        assert!(matches!(read_installed(&path), Installed::Missing));
        assert!(matches!(read_enrollment(&path), EnrollmentState::Present));
        // A damaged record fails closed: it is neither a usable enrollment nor a fresh start.
        std::fs::write(enrollment_path(&path), b"tampered").unwrap();
        assert!(matches!(read_enrollment(&path), EnrollmentState::Invalid));
    }
}
