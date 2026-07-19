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
    /// The provider's activation (reload) script, when the bundle declares one — run for the
    /// activate hook. Its presence makes the deployment reload in place instead of the guardian
    /// restarting the process.
    pub activate: Option<PathBuf>,
    /// The provider's rollback script, when the bundle declares one — run for the rollback hook in
    /// place of `program`. `None` for an application bundle or a provider that keeps its rollback in
    /// its single forward entrypoint.
    pub rollback: Option<PathBuf>,
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

    /// Resolve how to launch a materialized release after re-verifying every file.
    /// Providers are executable policy and may sit unused between deployments, so
    /// ingest-time verification alone is not an execution-time trust boundary.
    pub fn resolve(&self, release: &ReleaseId) -> io::Result<Resolved> {
        let (manifest, program) = bundle::read_release(&self.versions, release)?;
        let cwd = self.location(release);
        let activate = manifest.activate.as_ref().map(|relative| cwd.join(relative));
        let rollback = manifest.rollback.as_ref().map(|relative| cwd.join(relative));
        Ok(Resolved {
            program,
            activate,
            rollback,
            cwd,
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
            &bundle::Entrypoints::new("bin/app"),
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

    #[test]
    fn resolving_a_provider_with_post_install_drift_fails_closed() {
        let root = scratch("provider-drift");
        let source = root.join("source");
        fs::create_dir_all(source.join("bin")).unwrap();
        fs::write(source.join("bin/app"), b"trusted").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(source.join("bin/app"), fs::Permissions::from_mode(0o755)).unwrap();
        }
        let archive = root.join("provider.tar.zst");
        let platform = foundation::platform::platform_key();
        bundle::create_bundle(
            &source,
            &archive,
            "lifecycle",
            "1.0.0",
            &platform,
            &bundle::Entrypoints::new("bin/app"),
        )
        .unwrap();
        let store = BundleStore::new(root.join("versions"), root.join("staging"));
        let staged = store
            .install(
                &archive,
                &bundle::ExpectedBundle {
                    product: "lifecycle",
                    version: "1.0.0",
                    platform: &platform,
                },
            )
            .unwrap();
        let installed_entrypoint = store.location(&staged.id).join("bin/app");
        fs::rename(
            &installed_entrypoint,
            installed_entrypoint.with_extension("trusted"),
        )
        .unwrap();
        fs::write(installed_entrypoint, b"tampered").unwrap();
        assert!(store.resolve(&staged.id).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_provider_with_an_activate_script_resolves_it() {
        let root = scratch("provider-activate");
        let source = root.join("source");
        fs::create_dir_all(source.join("bin")).unwrap();
        fs::write(source.join("bin/deploy.sh"), b"#!/bin/sh\ntrue\n").unwrap();
        fs::write(source.join("bin/reload.sh"), b"#!/bin/sh\ntrue\n").unwrap();
        let archive = root.join("provider.tar.zst");
        let platform = foundation::platform::platform_key();
        bundle::create_bundle(
            &source,
            &archive,
            "lifecycle",
            "1.0.0",
            &platform,
            &bundle::Entrypoints {
                entrypoint: "bin/deploy.sh",
                activate: Some("bin/reload.sh"),
                rollback: None,
            },
        )
        .unwrap();
        let store = BundleStore::new(root.join("versions"), root.join("staging"));
        let staged = store
            .install(
                &archive,
                &bundle::ExpectedBundle {
                    product: "lifecycle",
                    version: "1.0.0",
                    platform: &platform,
                },
            )
            .unwrap();
        let resolved = store.resolve(&staged.id).unwrap();
        // The activate script's presence is what the supervisor reads to reload in place.
        assert_eq!(
            resolved.activate,
            Some(store.location(&staged.id).join("bin/reload.sh"))
        );
        assert_eq!(resolved.rollback, None);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_provider_with_a_rollback_resolves_both_scripts() {
        let root = scratch("provider-rollback");
        let source = root.join("source");
        fs::create_dir_all(source.join("bin")).unwrap();
        fs::write(source.join("bin/deploy.sh"), b"#!/bin/sh\ntrue\n").unwrap();
        fs::write(source.join("bin/rollback.sh"), b"#!/bin/sh\ntrue\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for name in ["bin/deploy.sh", "bin/rollback.sh"] {
                fs::set_permissions(source.join(name), fs::Permissions::from_mode(0o644)).unwrap();
            }
        }
        let archive = root.join("provider.tar.zst");
        let platform = foundation::platform::platform_key();
        // The source files are *not* +x; the bundle marks both declared scripts executable.
        bundle::create_bundle(
            &source,
            &archive,
            "lifecycle",
            "1.0.0",
            &platform,
            &bundle::Entrypoints {
                entrypoint: "bin/deploy.sh",
                activate: None,
                rollback: Some("bin/rollback.sh"),
            },
        )
        .unwrap();
        let store = BundleStore::new(root.join("versions"), root.join("staging"));
        let staged = store
            .install(
                &archive,
                &bundle::ExpectedBundle {
                    product: "lifecycle",
                    version: "1.0.0",
                    platform: &platform,
                },
            )
            .unwrap();
        let resolved = store.resolve(&staged.id).unwrap();
        let dir = store.location(&staged.id);
        assert_eq!(resolved.program, dir.join("bin/deploy.sh"));
        assert_eq!(resolved.rollback, Some(dir.join("bin/rollback.sh")));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_provider_without_a_rollback_resolves_none() {
        let root = scratch("provider-no-rollback");
        let source = root.join("source");
        fs::create_dir_all(source.join("bin")).unwrap();
        fs::write(source.join("bin/app"), b"trusted").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(source.join("bin/app"), fs::Permissions::from_mode(0o755)).unwrap();
        }
        let archive = root.join("provider.tar.zst");
        let platform = foundation::platform::platform_key();
        bundle::create_bundle(
            &source,
            &archive,
            "lifecycle",
            "1.0.0",
            &platform,
            &bundle::Entrypoints::new("bin/app"),
        )
        .unwrap();
        let store = BundleStore::new(root.join("versions"), root.join("staging"));
        let staged = store
            .install(
                &archive,
                &bundle::ExpectedBundle {
                    product: "lifecycle",
                    version: "1.0.0",
                    platform: &platform,
                },
            )
            .unwrap();
        assert_eq!(store.resolve(&staged.id).unwrap().rollback, None);
        let _ = fs::remove_dir_all(root);
    }
}
