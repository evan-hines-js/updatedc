//! Repository fixtures, for this crate's tests and its integration tests.
//!
//! A `file://` repository source is nine fields, and two test modules — this crate's `select` unit
//! tests and its `roundtrip` integration test — each spelled them out, the second with a comment
//! noting it followed "the same convention as the roundtrip tests". That is what a copy looks like
//! when it knows it is one.
//!
//! It lives here rather than beside [`updated::config::RepositorySource`] because building a
//! `file://` URL correctly needs the `url` crate, and `updated` does not depend on it. Adding a
//! production dependency to hold a fixture would be the wrong trade; both callers are in this
//! crate, which already has `url`.
//!
//! Not `#[cfg(test)]`: an integration test is a separate crate and cannot see a `test`-gated item,
//! and that invisibility is exactly what forced the copy.

use std::path::Path;
use std::time::Duration;

use updated::config::{RepositoryAccess, RepositorySource};

/// The offline repository under `repo_dir`, addressed by `file://`.
///
/// `file://` is offline, so the transport never reads the mTLS identity's paths; they are named only
/// because the type requires them. A test that cares about a particular field overrides it on the
/// returned value.
pub fn offline_source(repo_dir: &Path) -> RepositorySource {
    let url =
        |sub: &str| {
            url::Url::from_directory_path(std::fs::canonicalize(repo_dir.join(sub)).unwrap_or_else(
                |error| panic!("canonicalizing {sub} under the repository: {error}"),
            ))
            .expect("an absolute repository directory is a file:// URL")
            .to_string()
        };
    RepositorySource {
        root: repo_dir.join("metadata/root.json"),
        metadata_url: url("metadata"),
        targets_url: url("targets"),
        metadata_limit: 1024 * 1024,
        target_limit: 100 * 1024 * 1024,
        transport_timeout: Duration::from_secs(5),
        access: RepositoryAccess::Direct,
        mtls: updated::tls::Identity::new(
            repo_dir.join("client.crt"),
            repo_dir.join("client.key"),
            repo_dir.join("ca.crt"),
        ),
    }
}
