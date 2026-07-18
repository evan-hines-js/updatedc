//! Immutable manifested-bundle storage.
//!
//! This is deliberately not a deployment provider. It authenticates, materializes,
//! resolves, and locates bundles for both the application and executable providers.
//! Deployment policy lives behind the supervisor's single provider phase protocol.

use std::io;
use std::path::{Path, PathBuf};

use crate::bundle::{self, BundleLimits, ExpectedBundle, ReleaseId, StagedRelease};
use crate::config::Paths;

/// A release store rooted at `versions/` plus its `staging/` scratch. The tower keeps
/// separate stores for applications and executable provider bundles.
pub struct BundleStore {
    versions: PathBuf,
    staging: PathBuf,
    limits: BundleLimits,
}

/// How to launch a materialized release: the program to exec, its working directory, and
/// the product identity its manifest declares (a defence-in-depth cross-check for pinned
/// provider bundles).
pub struct Resolved {
    pub program: PathBuf,
    pub cwd: PathBuf,
    pub product: String,
}

impl BundleStore {
    /// A bundle store over explicit directories, with default ingest limits.
    pub fn new(versions: PathBuf, staging: PathBuf) -> Self {
        BundleStore {
            versions,
            staging,
            limits: BundleLimits::default(),
        }
    }

    /// The application release store.
    pub fn for_app(paths: &Paths) -> Self {
        Self::new(paths.versions.clone(), paths.staging.clone())
    }

    /// The executable-provider release store.
    pub fn for_lifecycle(paths: &Paths) -> Self {
        Self::new(
            paths.provider_versions.clone(),
            paths.provider_staging.clone(),
        )
    }

    /// Cap the archive size accepted at ingest — only [`install`](Self::install) reads it,
    /// so resolving or locating an already-committed release needs no limit.
    pub fn with_target_limit(mut self, target_limit: u64) -> Self {
        self.limits.archive_bytes = target_limit;
        self
    }

    /// Materialize a TUF-verified downloaded archive at `archive` into the immutable
    /// store, returning the release identity the tower tracks.
    /// This is the one ingest-time verification gate: the store expands the
    /// signed bundle and re-hashes the fresh tree against its manifest before publishing
    /// it; a committed store is trusted forever after.
    pub fn install(
        &self,
        archive: &Path,
        expected: &ExpectedBundle<'_>,
    ) -> io::Result<StagedRelease> {
        bundle::stage_bundle(
            archive,
            &self.staging,
            &self.versions,
            expected,
            &self.limits,
        )
    }

    /// Resolve how to launch a materialized release: its entrypoint program, working
    /// directory, and declared product. Trusts the already-verified committed tree,
    /// confirming only that the bytes still resolve by identity.
    pub fn resolve(&self, release: &ReleaseId) -> io::Result<Resolved> {
        let (manifest, program) = bundle::read_manifest(&self.versions, release)?;
        Ok(Resolved {
            program,
            cwd: self.location(release),
            product: manifest.product,
        })
    }

    /// The on-disk directory of a materialized release — the launch working directory and
    /// the `UPDATED_CANDIDATE`/`UPDATED_PREDECESSOR` path handed to lifecycle providers.
    pub fn location(&self, release: &ReleaseId) -> PathBuf {
        self.versions.join(release.directory_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("provider-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn install_hands_off_a_filepath_and_resolve_round_trips_the_release() {
        let root = scratch("roundtrip");
        let source = root.join("source");
        fs::create_dir_all(source.join("bin")).unwrap();
        fs::write(source.join("bin/app"), b"the entrypoint").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(source.join("bin/app"), fs::Permissions::from_mode(0o755)).unwrap();
        }
        // The supervisor only ever hands the provider a filepath to a verified archive.
        let archive = root.join("bundle.tar.zst");
        bundle::create_bundle(
            &source,
            &archive,
            "demo",
            "1.2.3",
            "test-platform",
            "bin/app",
        )
        .unwrap();

        let provider = BundleStore::new(root.join("versions"), root.join("staging"));
        let staged = provider
            .install(
                &archive,
                &ExpectedBundle {
                    product: "demo",
                    version: "1.2.3",
                    platform: "test-platform",
                },
            )
            .unwrap();

        let resolved = provider.resolve(&staged.id).unwrap();
        assert_eq!(resolved.product, "demo");
        assert_eq!(resolved.cwd, provider.location(&staged.id));
        assert_eq!(
            resolved.program,
            provider.location(&staged.id).join("bin/app")
        );
        assert!(resolved.program.exists());
    }

    #[test]
    fn resolving_an_uninstalled_release_fails_closed() {
        let root = scratch("unknown");
        let provider = BundleStore::new(root.join("versions"), root.join("staging"));
        let missing = ReleaseId {
            version: "9.9.9".into(),
            manifest_sha256: "a".repeat(64),
        };
        assert!(provider.resolve(&missing).is_err());
    }
}
