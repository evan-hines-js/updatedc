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

/// A release identity from a version and an explicit manifest digest, so a test that cares which
/// release a record names can say so.
pub(crate) fn release(version: &str, digest: &str) -> ReleaseId {
    ReleaseId {
        version: version.into(),
        manifest_sha256: digest.into(),
    }
}

/// The repository every fixture's state descends from.
pub(crate) fn lineage() -> RepositoryLineage {
    RepositoryLineage::from_metadata_url("https://repo/metadata/")
}

/// The node reconciler a fixture release is installed with.
pub(crate) fn provider() -> Box<ProviderRelease> {
    Box::new(ProviderRelease {
        provider_set_sha256: "f".repeat(64),
        product: "reconciler".into(),
        release: release("1.0.0", "reconciler-manifest"),
        archive_sha256: "reconciler-archive".into(),
        args: Vec::new(),
        timeout_millis: 1_000,
    })
}
