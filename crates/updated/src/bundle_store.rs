//! Verified immutable package storage. Execution belongs to the native runtime.
use crate::{
    bundle::{self, BundleLimits, ExpectedBundle, InstallError, ReleaseId},
    config::Paths,
};
use std::{
    fs::File,
    path::{Path, PathBuf},
};
pub struct BundleStore {
    versions: PathBuf,
    staging: PathBuf,
    limits: BundleLimits,
}
impl BundleStore {
    pub fn for_app(paths: &Paths) -> Self {
        Self {
            versions: paths.versions.clone(),
            staging: paths.staging.clone(),
            limits: BundleLimits::default(),
        }
    }
    pub fn with_target_limit(mut self, limit: u64) -> Self {
        self.limits.archive_bytes = limit;
        self
    }
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
    pub fn install_file(
        &self,
        archive: &mut File,
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
    /// Parse only bytes matching the authenticated manifest. Local drift and I/O failures never
    /// become archive verdicts; unsupported runtime APIs remain retryable after an agent upgrade.
    pub fn execution(
        &self,
        id: &ReleaseId,
    ) -> Result<crate::state::ReconcilerRelease, InstallError> {
        let manifest = bundle::read_release(&self.versions, id)?;
        let invalid = |message| {
            InstallError::Archive(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                message,
            ))
        };
        let entry = manifest
            .files
            .iter()
            .find(|file| file.path == crate::command_adapter::CONFIG)
            .ok_or_else(|| invalid("package has no execution definition"))?;
        if entry.size > crate::command_adapter::LIMIT as u64 {
            return Err(invalid("execution definition exceeds size limit"));
        }
        let bytes = crate::command_adapter::read_config_bytes(&self.location(id))?;
        if updated_contracts::digest::sha256_bytes(&bytes) != entry.sha256 {
            return Err(
                std::io::Error::other("execution definition changed after verification").into(),
            );
        }
        crate::command_adapter::execution_from_bytes(&bytes, &manifest.product).map_err(|error| {
            if error.kind() == std::io::ErrorKind::InvalidData {
                InstallError::Archive(error)
            } else {
                InstallError::Storage(error)
            }
        })
    }
    pub fn location(&self, release: &ReleaseId) -> PathBuf {
        self.versions.join(release.directory_name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_authenticated_invalid_definitions_are_permanent_verdicts() {
        let valid = r#"{"schema":1,"deploy":{"argv":["./app"],"timeoutSeconds":1},"replay":{"policy":"safe"},"recovery":{"policy":"manual"}}"#;
        for (definition, archive_verdict) in [
            (None, true),
            (Some("invalid json"), true),
            (Some(r#"{"schema":2,"futureField":true}"#), false),
            (Some(valid), false),
        ] {
            let root = tempfile::tempdir().unwrap();
            let source = root.path().join("source");
            std::fs::create_dir(&source).unwrap();
            std::fs::write(source.join("app"), "opaque customer program").unwrap();
            if let Some(definition) = definition {
                std::fs::write(source.join(crate::command_adapter::CONFIG), definition).unwrap();
            }
            let archive = root.path().join("package");
            bundle::create_bundle(&source, &archive, "app", "1.0.0", "linux-x86_64").unwrap();
            let store =
                BundleStore::for_app(&Paths::resolve(&root.path().join("install"), root.path()));
            let id = store
                .install(
                    &archive,
                    &ExpectedBundle {
                        product: "app",
                        version: "1.0.0",
                        platform: "linux-x86_64",
                    },
                )
                .unwrap();
            let execution = store.execution(&id);
            assert_eq!(
                matches!(execution, Err(InstallError::Archive(_))),
                archive_verdict
            );
            if definition == Some(valid) {
                let execution = execution.unwrap();
                assert_eq!(
                    execution.definition_sha256,
                    updated_contracts::digest::sha256_bytes(valid.as_bytes())
                );
                let config = store.location(&id).join(crate::command_adapter::CONFIG);
                // Model deliberate local corruption, bypassing the installed file's write
                // protection. Windows refuses atomic replacement of a read-only destination.
                #[cfg(windows)]
                {
                    let mut permissions = std::fs::metadata(&config).unwrap().permissions();
                    permissions.set_readonly(false);
                    std::fs::set_permissions(&config, permissions).unwrap();
                }
                foundation::durable::atomic_write_managed(&config, ".tamper-", b"local corruption")
                    .unwrap();
                assert!(matches!(
                    store.execution(&id),
                    Err(InstallError::Storage(_))
                ));
            } else {
                assert!(execution.is_err());
            }
        }
    }
}
