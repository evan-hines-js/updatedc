//! Shared durable-state fixtures for this crate's tests.
//!
//! `state`, `install`, and `transaction` all build the same two values — a [`ReleaseId`] and the
//! `ProviderRelease` that accompanies it — to exercise the records they persist. Keeping one
//! definition means a field added to either type is fixed in one place instead of three, and the
//! three modules' fixtures cannot quietly drift into testing different shapes.

use crate::bundle::ReleaseId;
use crate::state::ProviderRelease;

/// A release identity from a version and a stand-in manifest digest.
pub(crate) fn release(version: &str, digest: &str) -> ReleaseId {
    ReleaseId {
        version: version.into(),
        manifest_sha256: digest.into(),
    }
}

/// The node reconciler a fixture release is installed with.
pub(crate) fn provider() -> Box<ProviderRelease> {
    Box::new(ProviderRelease {
        product: "reconciler".into(),
        release: release("1.0.0", "reconciler-manifest"),
        archive_sha256: "reconciler-archive".into(),
        args: Vec::new(),
        timeout_millis: 1_000,
    })
}
