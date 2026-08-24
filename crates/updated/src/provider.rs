//! Immutable manifested-bundle storage.
//!
//! This is deliberately not a deployment provider. It authenticates, materializes,
//! resolves, and locates bundles for both the application and executable providers.
//! Deployment policy lives behind the agent's single provider phase protocol.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::bundle::{self, BundleLimits, BundleManifest, ExpectedBundle, InstallError, ReleaseId};
use crate::config::Paths;

/// A release store rooted at `versions/` plus its `staging/` scratch and the `work/` root that
/// holds each release's writable working directory. The tower keeps separate stores for
/// applications and executable provider bundles.
pub struct BundleStore {
    versions: PathBuf,
    staging: PathBuf,
    work: PathBuf,
    limits: BundleLimits,
}

/// How to launch a materialized release: the program to exec, its working directory, and
/// the product identity its manifest declares (a defence-in-depth cross-check for pinned
/// provider bundles).
pub struct Resolved {
    pub program: PathBuf,
    /// The launched process's working directory: this release's [workspace], never its
    /// content-addressed tree — but seeded with a copy of every file the release declares, so a
    /// program that reads its own bundled configuration or assets by relative path still finds
    /// them.
    ///
    /// [workspace]: BundleStore::workspace
    pub cwd: PathBuf,
    pub product: String,
}

impl BundleStore {
    /// A bundle store over explicit directories, with default ingest limits.
    pub fn new(versions: PathBuf, staging: PathBuf, work: PathBuf) -> Self {
        BundleStore {
            versions,
            staging,
            work,
            limits: BundleLimits::default(),
        }
    }

    /// The application release store.
    pub fn for_app(paths: &Paths) -> Self {
        Self::new(
            paths.versions.clone(),
            paths.staging.clone(),
            paths.work.clone(),
        )
    }

    /// The executable-provider release store.
    pub fn for_lifecycle(paths: &Paths) -> Self {
        Self::new(
            paths.provider_versions.clone(),
            paths.provider_staging.clone(),
            paths.provider_work.clone(),
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
    ///
    /// The error is [`InstallError`], not `io::Error`, because callers persist a durable,
    /// never-expiring rejection from one of its two cases and must retry the other.
    pub fn install(
        &self,
        archive: &Path,
        expected: &ExpectedBundle<'_>,
    ) -> Result<ReleaseId, InstallError> {
        bundle::stage_bundle(
            archive,
            &self.staging,
            &self.versions,
            expected,
            &self.limits,
        )
    }

    /// Materialize a bundle from an already-open, metadata-authenticated archive handle.
    /// Production TUF acquisition uses this method; the path wrapper above exists for local bundle
    /// construction and tests but delegates to the same ingest implementation.
    pub fn install_file(
        &self,
        archive: &mut std::fs::File,
        expected: &ExpectedBundle<'_>,
    ) -> Result<ReleaseId, InstallError> {
        bundle::stage_bundle_file(
            archive,
            &self.staging,
            &self.versions,
            expected,
            &self.limits,
        )
    }

    /// Resolve how to launch a materialized release after re-verifying every file, and prepare
    /// the writable working directory the process is launched in.
    /// Providers are executable policy and may sit unused between deployments, so
    /// ingest-time verification alone is not an execution-time trust boundary.
    pub fn resolve(&self, release: &ReleaseId) -> io::Result<Resolved> {
        let (manifest, program) = bundle::read_release(&self.versions, release)?;
        let cwd = self.prepare_workspace(release, &manifest)?;
        Ok(Resolved {
            program,
            cwd,
            product: manifest.product,
        })
    }

    /// The on-disk directory of a materialized release — the candidate/predecessor path handed
    /// to node reconcilers, and the tree [`bundle::verify_release`] re-hashes.
    pub fn location(&self, release: &ReleaseId) -> PathBuf {
        self.versions.join(release.directory_name())
    }

    /// A release's writable working directory: `work/<version>-<manifest_sha256>`, a sibling of
    /// its immutable tree under the same store.
    ///
    /// Deliberately NOT [`location`](Self::location). That directory is content-addressed state
    /// this store owns: every check tick re-hashes it against its manifest and refuses any file
    /// the manifest does not declare, so an ordinary application writing a log, a pid file, a
    /// sqlite journal or a listening socket into its own working directory would condemn its own
    /// release — the agent would stop it, discard the drifted tree, re-download the archive
    /// and relaunch, every tick, forever. The working directory therefore has to be somewhere the
    /// integrity check does not own, and per-release rather than shared so two releases never
    /// inherit each other's scratch.
    fn workspace(&self, release: &ReleaseId) -> PathBuf {
        self.work.join(release.directory_name())
    }

    /// Create (or keep) this release's workspace, make the release's own declared files reachable
    /// from it by relative path, and drop the workspaces of releases the store no longer holds.
    ///
    /// Creation is idempotent, so a restart — or an update that rolls back onto a release this
    /// node ran before — finds whatever the application left there last time; only garbage
    /// collecting the release itself takes it away, which is what the reaping half enforces: a
    /// workspace exists exactly while its release does, so a node that has cycled through many
    /// releases does not accumulate their scratch forever.
    fn prepare_workspace(
        &self,
        release: &ReleaseId,
        manifest: &BundleManifest,
    ) -> io::Result<PathBuf> {
        let workspace = self.workspace(release);
        // `create_dir_all(workspace)` follows a pre-existing symlink at the workspace itself. The
        // application owns this directory after launch and may replace it, so accepting that link
        // on a later resolve would run the release with an attacker-chosen cwd and materialize its
        // bundled files outside the store. The store root is agent-owned; create it first, then
        // require the application-owned child itself to be a real directory.
        std::fs::create_dir_all(&self.work)?;
        create_real_directory(&workspace)?;
        self.materialize_bundle_files(release, manifest, &workspace)?;
        crate::gc::reap_orphaned_workspaces(&self.work, &self.versions);
        Ok(workspace)
    }

    /// Give the workspace its own copy of every file the release's manifest declares.
    ///
    /// The launch contract is that a program finds its own bundled files where it was told to look
    /// for them: applications read `config/...`, templates and static assets *relative to their
    /// working directory* (this repository's own `sampleapp` opens `config/release.toml` and exits
    /// with status 2 if it cannot), so moving the `cwd` off the release tree without moving the
    /// files with it would break every such program.
    ///
    /// A **copy**, deliberately — not a symlink or a hard link into `versions/<id>`. Both of those
    /// make an ordinary in-place write to a bundled path (an application rewriting its own config,
    /// or truncating a shipped file it also owns) land inside the content-addressed tree, which is
    /// exactly the drift [`workspace`](Self::workspace) exists to keep out: the next check tick
    /// would re-hash the tree, condemn a good release and re-download it forever. A copy is
    /// disjoint from the tree, so the integrity check owns `versions/<id>` alone and the
    /// application owns everything under `work/<id>`.
    ///
    /// Anything already present under the workspace is left untouched: it is either this same copy
    /// (the release identity is a content hash, so its bytes cannot differ) or state the
    /// application deliberately wrote there, and scratch surviving restarts is the point of the
    /// directory. Each copy lands by temp-then-rename, so an interrupted one never becomes a
    /// truncated file the next launch would keep forever.
    ///
    /// "Left untouched" includes not being resolved *through*: the intermediate directories are
    /// created by [`create_real_directories`], which refuses a component the application replaced
    /// with a symlink instead of following it out of the store.
    fn materialize_bundle_files(
        &self,
        release: &ReleaseId,
        manifest: &BundleManifest,
        workspace: &Path,
    ) -> io::Result<()> {
        let tree = self.location(release);
        for file in &manifest.files {
            let destination = workspace.join(&file.path);
            if std::fs::symlink_metadata(&destination).is_ok() {
                continue;
            }
            if let Some(parent) = Path::new(&file.path).parent() {
                create_real_directories(workspace, parent)?;
            }
            let staged = staging_name(&destination)?;
            std::fs::copy(tree.join(&file.path), &staged)?;
            grant_workspace_ownership(&staged, file.executable)?;
            // The workspace is the one directory the application itself writes into, so the file
            // being replaced may well be open right now — the case `durable::replace` retries and a
            // bare rename fails outright.
            if let Err(error) = foundation::durable::replace(&staged, &destination) {
                let _ = std::fs::remove_file(&staged);
                return Err(error);
            }
        }
        Ok(())
    }
}

/// Create every component of `relative` under `root`, refusing one that is not a real directory.
///
/// `create_dir_all` would resolve a symlink instead of refusing it, and the workspace is the one
/// part of this store the store does NOT own: the application writes into it freely, which is the
/// whole reason it is not the release tree ([`BundleStore::workspace`]). So a `config` replaced by a
/// link to somewhere else would make the copy-and-rename below publish release bytes outside the
/// store, at a path the application chose. Every sibling path in this crate already refuses a link
/// rather than following it — [`crate::bundle::extract`] opens members with `create_new`, `discard`
/// unlinks through `symlink_metadata`, `collect_release_files` rejects a symlink in a release tree
/// — and this is the same rule on the one path that still resolved through untrusted components.
///
/// Idempotent, like the materialization it serves: an existing real directory is kept, since the
/// workspace deliberately survives restarts.
fn create_real_directories(root: &Path, relative: &Path) -> io::Result<()> {
    let mut at = root.to_path_buf();
    for component in relative.components() {
        let std::path::Component::Normal(component) = component else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "workspace directory {} is not a relative normal path",
                    relative.display()
                ),
            ));
        };
        at.push(component);
        create_real_directory(&at)?;
    }
    Ok(())
}

/// Create `path` if absent, or require the existing entry to be a directory rather than a link.
fn create_real_directory(path: &Path) -> io::Result<()> {
    match std::fs::create_dir(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if std::fs::symlink_metadata(path)?.is_dir() {
                Ok(())
            } else {
                Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "workspace path {} is not a real directory; refusing to materialize \
                         release files through it",
                        path.display()
                    ),
                ))
            }
        }
        Err(error) => Err(error),
    }
}

/// Hand a materialized copy to the application: writable by its owner, and executable exactly when
/// the manifest says the file is.
///
/// Committed release members are read-only (`0o444`/`0o555`) because the store owns them and
/// re-hashes them; a workspace copy is the application's own file, so keeping it read-only would
/// leave a program unable to rewrite the very config it is expected to manage.
#[cfg(unix)]
fn grant_workspace_ownership(path: &Path, executable: bool) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        path,
        std::fs::Permissions::from_mode(if executable { 0o755 } else { 0o644 }),
    )
}

#[cfg(not(unix))]
fn grant_workspace_ownership(path: &Path, _executable: bool) -> io::Result<()> {
    let mut permissions = std::fs::metadata(path)?.permissions();
    #[allow(clippy::permissions_set_readonly_false)]
    permissions.set_readonly(false);
    std::fs::set_permissions(path, permissions)
}

/// A private sibling name to copy into before the rename that publishes it. Unique per process and
/// per call, so two agent generations materializing the same workspace never share one.
fn staging_name(destination: &Path) -> io::Result<PathBuf> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let name = destination
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bundle path has no file name"))?
        .to_string_lossy()
        .into_owned();
    let parent = destination.parent().unwrap_or(Path::new("."));
    Ok(parent.join(format!(
        ".materializing-{}-{}-{name}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(name);
        fs::create_dir_all(&path).unwrap();
        (dir, path)
    }

    fn store(root: &Path) -> BundleStore {
        BundleStore::new(
            root.join("versions"),
            root.join("staging"),
            root.join("work"),
        )
    }

    /// A release archive shaped like the ones the tower actually ships — an entrypoint plus a
    /// bundled config the program reads relative to its working directory, exactly as
    /// `crates/sampleapp` and the e2e fixtures stage it.
    fn archive(root: &Path, product: &str, version: &str, platform: &str) -> PathBuf {
        let source = root.join(format!("source-{product}-{version}"));
        fs::create_dir_all(source.join("bin")).unwrap();
        fs::create_dir_all(source.join("config")).unwrap();
        fs::write(source.join("bin/app"), format!("{product} {version}")).unwrap();
        fs::write(
            source.join("config/release.toml"),
            format!("version = \"{version}\"\n"),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(source.join("bin/app"), fs::Permissions::from_mode(0o755)).unwrap();
        }
        let archive = root.join(format!("{product}-{version}.tar.zst"));
        bundle::create_bundle(&source, &archive, product, version, platform, "bin/app").unwrap();
        archive
    }

    #[test]
    fn install_hands_off_a_filepath_and_resolve_round_trips_the_release() {
        let (_dir, root) = scratch("roundtrip");
        let source = root.join("source");
        fs::create_dir_all(source.join("bin")).unwrap();
        fs::write(source.join("bin/app"), b"the entrypoint").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(source.join("bin/app"), fs::Permissions::from_mode(0o755)).unwrap();
        }
        // The agent only ever hands the provider a filepath to a verified archive.
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

        let provider = store(&root);
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

        let resolved = provider.resolve(&staged).unwrap();
        assert_eq!(resolved.product, "demo");
        assert_eq!(resolved.cwd, provider.workspace(&staged));
        assert_eq!(resolved.program, provider.location(&staged).join("bin/app"));
        assert!(resolved.program.exists());
    }

    #[test]
    fn resolving_an_uninstalled_release_fails_closed() {
        let (_dir, root) = scratch("unknown");
        let provider = store(&root);
        let missing = ReleaseId {
            version: "9.9.9".into(),
            manifest_sha256: "a".repeat(64),
        };
        assert!(provider.resolve(&missing).is_err());
    }

    #[test]
    fn resolving_a_provider_with_post_install_drift_fails_closed() {
        let (_dir, root) = scratch("provider-drift");
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
            "bin/app",
        )
        .unwrap();
        let provider = store(&root);
        let staged = provider
            .install(
                &archive,
                &bundle::ExpectedBundle {
                    product: "lifecycle",
                    version: "1.0.0",
                    platform: &platform,
                },
            )
            .unwrap();
        let installed_entrypoint = provider.location(&staged).join("bin/app");
        fs::rename(
            &installed_entrypoint,
            installed_entrypoint.with_extension("trusted"),
        )
        .unwrap();
        fs::write(installed_entrypoint, b"tampered").unwrap();
        assert!(provider.resolve(&staged).is_err());
        let _ = fs::remove_dir_all(root);
    }

    /// The defect: the launch `cwd` used to be the content-addressed tree, so the first file the
    /// application wrote to its own working directory made the release fail verification — and the
    /// agent then condemned, re-downloaded and relaunched it on every check tick.
    #[test]
    fn an_application_writing_to_its_working_directory_leaves_the_release_verifiable() {
        let (_dir, root) = scratch("workspace-drift");
        let platform = foundation::platform::platform_key();
        let archive = archive(&root, "demo", "1.2.3", &platform);
        let provider = store(&root);
        let staged = provider
            .install(
                &archive,
                &ExpectedBundle {
                    product: "demo",
                    version: "1.2.3",
                    platform: &platform,
                },
            )
            .unwrap();

        let resolved = provider.resolve(&staged).unwrap();
        assert_ne!(resolved.cwd, provider.location(&staged));
        assert!(resolved.cwd.is_dir());
        // Exactly what an ordinary application does: a log file, a pid file, a scratch subtree.
        fs::write(resolved.cwd.join("app.log"), b"started").unwrap();
        fs::create_dir_all(resolved.cwd.join(".cache/objects")).unwrap();

        bundle::verify_release(&root.join("versions"), &staged).unwrap();
        // And the scratch survives the relaunch that verification no longer forces.
        let relaunch = provider.resolve(&staged).unwrap();
        assert_eq!(relaunch.cwd, resolved.cwd);
        assert_eq!(fs::read(relaunch.cwd.join("app.log")).unwrap(), b"started");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_workspace_outlives_its_release_no_longer_than_the_release_itself() {
        let (_dir, root) = scratch("workspace-reap");
        let platform = foundation::platform::platform_key();
        let provider = store(&root);
        let mut ids = Vec::new();
        for version in ["1.0.0", "2.0.0"] {
            let archive = archive(&root, "demo", version, &platform);
            let staged = provider
                .install(
                    &archive,
                    &ExpectedBundle {
                        product: "demo",
                        version,
                        platform: &platform,
                    },
                )
                .unwrap();
            provider.resolve(&staged).unwrap();
            ids.push(staged);
        }
        assert!(provider.workspace(&ids[0]).is_dir());

        // Garbage collection removes the superseded release; its scratch must not outlive it —
        // once its absence has stood for a pass, which is what keeps a staging window from
        // deleting a live release's state (see `crate::gc`).
        fs::remove_dir_all(provider.location(&ids[0])).unwrap();
        provider.resolve(&ids[1]).unwrap();
        crate::gc::reap_orphaned_workspaces_after(
            &root.join("work"),
            &root.join("versions"),
            std::time::Duration::ZERO,
        );
        crate::gc::reap_orphaned_workspaces_after(
            &root.join("work"),
            &root.join("versions"),
            std::time::Duration::ZERO,
        );
        assert!(!provider.workspace(&ids[0]).exists());
        assert!(provider.workspace(&ids[1]).is_dir());
        let _ = fs::remove_dir_all(root);
    }

    /// The defect: the launch `cwd` moved to an empty workspace, so a program that reads its own
    /// bundled files by relative path — `crates/sampleapp` opens `config/release.toml` and exits
    /// with status 2 if it cannot — died on every launch and failed the boot health gate.
    #[test]
    fn a_release_reads_its_own_bundled_files_relative_to_the_launch_directory() {
        let (_dir, root) = scratch("workspace-bundled-files");
        let platform = foundation::platform::platform_key();
        let archive = archive(&root, "demo", "1.2.3", &platform);
        let provider = store(&root);
        let staged = provider
            .install(
                &archive,
                &ExpectedBundle {
                    product: "demo",
                    version: "1.2.3",
                    platform: &platform,
                },
            )
            .unwrap();

        let resolved = provider.resolve(&staged).unwrap();
        // Exactly the read the sampleapp performs from its working directory.
        assert_eq!(
            fs::read_to_string(resolved.cwd.join("config/release.toml")).unwrap(),
            "version = \"1.2.3\"\n"
        );
        assert_eq!(
            fs::read_to_string(resolved.cwd.join("bin/app")).unwrap(),
            "demo 1.2.3"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(resolved.cwd.join("bin/app"))
                .unwrap()
                .permissions()
                .mode();
            assert_ne!(mode & 0o111, 0, "a bundled program stays executable");
        }
        let _ = fs::remove_dir_all(root);
    }

    /// The copies are the application's, not the store's: rewriting one is an ordinary thing for a
    /// program to do to its own config, and it must not reach the content-addressed tree.
    #[test]
    fn rewriting_a_bundled_file_in_the_workspace_leaves_the_release_verifiable() {
        let (_dir, root) = scratch("workspace-bundled-rewrite");
        let platform = foundation::platform::platform_key();
        let archive = archive(&root, "demo", "1.2.3", &platform);
        let provider = store(&root);
        let staged = provider
            .install(
                &archive,
                &ExpectedBundle {
                    product: "demo",
                    version: "1.2.3",
                    platform: &platform,
                },
            )
            .unwrap();

        let resolved = provider.resolve(&staged).unwrap();
        fs::write(
            resolved.cwd.join("config/release.toml"),
            b"version = \"rewritten\"\n",
        )
        .unwrap();
        bundle::verify_release(&root.join("versions"), &staged).unwrap();
        assert_eq!(
            fs::read_to_string(provider.location(&staged).join("config/release.toml")).unwrap(),
            "version = \"1.2.3\"\n"
        );
        // And the relaunch keeps what the application wrote rather than reinstating the bundled
        // copy over it.
        let relaunch = provider.resolve(&staged).unwrap();
        assert_eq!(
            fs::read_to_string(relaunch.cwd.join("config/release.toml")).unwrap(),
            "version = \"rewritten\"\n"
        );
        let _ = fs::remove_dir_all(root);
    }

    /// The workspace is the one directory in the store the application owns, so it is also the one
    /// set of path components the store must not resolve through. Planting a link where a bundled
    /// subdirectory goes used to make the next `resolve()` create it and rename the release's own
    /// `config/release.toml` into whatever it pointed at — release bytes written outside the store,
    /// to a path the application chose. Every other path in this crate already refuses a link here;
    /// this one followed it.
    #[cfg(unix)]
    #[test]
    fn a_symlink_planted_where_a_bundled_directory_goes_is_refused_not_followed() {
        let (_dir, root) = scratch("workspace-planted-symlink");
        let platform = foundation::platform::platform_key();
        let archive = archive(&root, "demo", "1.2.3", &platform);
        let provider = store(&root);
        let staged = provider
            .install(
                &archive,
                &ExpectedBundle {
                    product: "demo",
                    version: "1.2.3",
                    platform: &platform,
                },
            )
            .unwrap();

        // Everything the application can reach: its own workspace, before the first materialization.
        let workspace = provider.workspace(&staged);
        let elsewhere = root.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::create_dir_all(&workspace).unwrap();
        std::os::unix::fs::symlink(&elsewhere, workspace.join("config")).unwrap();

        let Err(error) = provider.resolve(&staged) else {
            panic!("a workspace component that is not a real directory must be refused");
        };
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "{error}");
        assert!(
            !elsewhere.join("release.toml").exists(),
            "no release byte may be written through the link"
        );
        let _ = fs::remove_dir_all(root);
    }

    /// The workspace entry itself is application-owned too. Checking only its descendants leaves
    /// a simpler escape: replace `work/<release>` with a link before the next resolve, and
    /// `create_dir_all` follows it before any descendant check runs.
    #[cfg(unix)]
    #[test]
    fn a_symlink_planted_where_the_workspace_goes_is_refused_not_followed() {
        let (_dir, root) = scratch("workspace-root-symlink");
        let platform = foundation::platform::platform_key();
        let archive = archive(&root, "demo", "1.2.3", &platform);
        let provider = store(&root);
        let staged = provider
            .install(
                &archive,
                &ExpectedBundle {
                    product: "demo",
                    version: "1.2.3",
                    platform: &platform,
                },
            )
            .unwrap();

        let workspace = provider.workspace(&staged);
        let elsewhere = root.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::create_dir_all(workspace.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &workspace).unwrap();

        let Err(error) = provider.resolve(&staged) else {
            panic!("a workspace root that is not a real directory must be refused");
        };
        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "{error}");
        assert!(
            !elsewhere.join("config/release.toml").exists(),
            "no release byte may be written through the workspace-root link"
        );
        let _ = fs::remove_dir_all(root);
    }
}
