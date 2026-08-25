//! Shared durable-state fixtures for this crate's tests.
//!
//! `state`, `install`, `transaction` and `journal` all build the same values — a [`ReleaseId`], the
//! `ProviderRelease` that accompanies it, and the two journalled records that carry both — to
//! exercise what they persist. Keeping one definition means a field added to any of those types is
//! fixed in one place instead of four, and the modules' fixtures cannot quietly drift into testing
//! different shapes. The two records live here rather than beside their own tests because
//! [`crate::journal`] exercises the same three operations over both.

use crate::bundle::ReleaseId;
use crate::install::{InstallPhase, InstallTransaction};
use crate::state::{ProviderRelease, RepositoryLineage};
use crate::transaction::{Phase, Transaction};

/// A release identity from a version and a fixture label, deterministically hashed into the same
/// digest shape production persists.
pub(crate) fn release(version: &str, label: &str) -> ReleaseId {
    ReleaseId {
        version: version.into(),
        manifest_sha256: updated_contracts::digest::sha256_bytes(label.as_bytes()),
    }
}

/// The node reconciler a fixture release is installed with.
pub(crate) fn provider() -> Box<ProviderRelease> {
    Box::new(ProviderRelease {
        provider_set_sha256: "f".repeat(64),
        product: "reconciler".into(),
        release: release("1.0.0", "reconciler-manifest"),
        archive_sha256: updated_contracts::digest::sha256_bytes(b"reconciler-archive"),
        args: Vec::new(),
        timeout_millis: 1_000,
    })
}

/// A first install at its first phase: intent durable, nothing on disk changed yet.
pub(crate) fn install_transaction() -> InstallTransaction {
    InstallTransaction {
        id: "a".repeat(64),
        release: release("1.0.0", "new"),
        archive_sha256: updated_contracts::digest::sha256_bytes(b"archive"),
        repository_lineage: RepositoryLineage::from_metadata_url("https://repo/metadata/")
            .expect("fixture metadata URL is valid"),
        lifecycle: provider(),
        phase: InstallPhase::Started,
    }
}

/// An update transaction at its first phase, with a predecessor to compensate back to.
pub(crate) fn update_transaction() -> Transaction {
    Transaction {
        id: "b".repeat(64),
        previous_release: release("1.0.0", "old"),
        previous_archive_sha256: updated_contracts::digest::sha256_bytes(b"previous-archive"),
        previous_repository_lineage: RepositoryLineage::from_metadata_url("https://old/metadata/")
            .expect("fixture metadata URL is valid"),
        candidate_release: release("2.0.0", "new"),
        candidate_archive_sha256: updated_contracts::digest::sha256_bytes(b"archive"),
        candidate_rejection_sha256: updated_contracts::digest::deployment_rejection_sha256(
            &updated_contracts::digest::sha256_bytes(b"archive"),
            &provider().provider_set_sha256,
        )
        .expect("fixture artifact identities are canonical"),
        candidate_repository_lineage: RepositoryLineage::from_metadata_url("https://new/metadata/")
            .expect("fixture metadata URL is valid"),
        candidate_rejection_required: false,
        previous_lifecycle: provider(),
        candidate_lifecycle: provider(),
        rollback_health_failures: 0,
        phase: Phase::Prepared,
    }
}
