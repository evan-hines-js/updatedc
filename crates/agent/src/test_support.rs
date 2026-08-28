//! The agent's shared test fixtures.
//!
//! `release`, `lineage` and `provider` describe the same three nominal values in every one of this
//! crate's test modules, and each module used to spell them itself — `release` three times,
//! `provider` twice, `lineage` twice. Identical copies are the ones that quietly stop being
//! identical: a field added to `ProviderRelease` gets a considered value in the copy the author was
//! looking at and a filler in the others, and the tests then disagree about what a nominal install
//! looks like. One definition each, so they cannot.

use updated::bundle::ReleaseId;
use updated::state::{ProviderRelease, RepositoryLineage};

/// An absolute path that is deliberately absent, portable across every host in the CI matrix.
///
/// Tests use this wherever production requires an absolute install or offline-repository path.
/// Keeping it here prevents Unix literals from quietly becoming relative paths on Windows and
/// gives all nominal agent fixtures one filesystem identity.
pub(crate) fn nonexistent_root() -> std::path::PathBuf {
    std::env::temp_dir().join("updated-agent-tests-do-not-create")
}

/// The directory-shaped spelling accepted by the canonical repository parser.
pub(crate) fn local_repository_base() -> String {
    format!(
        "{}{}",
        nonexistent_root().join("routing").display(),
        std::path::MAIN_SEPARATOR
    )
}

/// Canonical LF form for structural source assertions, independent of checkout policy.
pub(crate) fn normalized_source(source: &str) -> String {
    source.lines().collect::<Vec<_>>().join("\n")
}

/// A stable canonical digest for a human-readable fixture identity.
pub(crate) fn digest(identity: &str) -> String {
    if updated_contracts::is_canonical_sha256(identity) {
        identity.to_string()
    } else {
        updated_contracts::digest::sha256_bytes(identity.as_bytes())
    }
}

/// The runtime verdict identity shared by every nominal test transaction.
pub(crate) fn deployment_rejection(application_sha256: &str, provider_set_sha256: &str) -> String {
    updated_contracts::digest::deployment_rejection_sha256(application_sha256, provider_set_sha256)
        .expect("fixture deployment identities are canonical")
}

/// A release identity from a version and a readable digest identity, so tests remain legible while
/// every nominal fixture is still a value production persistence accepts.
pub(crate) fn release(version: &str, identity: &str) -> ReleaseId {
    ReleaseId {
        version: version.into(),
        manifest_sha256: digest(identity),
    }
}

/// The repository every fixture's state descends from.
pub(crate) fn lineage() -> RepositoryLineage {
    RepositoryLineage::from_metadata_url("https://repo/metadata/")
        .expect("fixture metadata URL is valid")
}

/// The node reconciler a fixture release is installed with.
pub(crate) fn provider() -> Box<ProviderRelease> {
    Box::new(ProviderRelease {
        provider_set_sha256: "f".repeat(64),
        product: "reconciler".into(),
        release: release("1.0.0", "reconciler-manifest"),
        archive_sha256: digest("reconciler-archive"),
        args: Vec::new(),
        timeout_millis: 1_000,
    })
}
