//! Atomic TUF publication. Storage mirroring is deliberately a separate final step:
//! targets are uploaded first and timestamp metadata last.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use updated_tuf::repo::{self, PublishTarget};

use crate::PublicationPlan;

#[derive(Debug)]
pub struct PublishError(String);

impl std::fmt::Display for PublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PublishError {}

/// Add every route in a reconciliation to one signed TUF metadata revision.
/// A failed build leaves the previously signed repository untouched.
pub async fn sign_plan(
    repository_dir: &Path,
    keys_dir: &Path,
    plan: &PublicationPlan,
    expiry_days: i64,
) -> Result<(), PublishError> {
    let staging = tempfile::tempdir_in(repository_dir.parent().unwrap_or(repository_dir))
        .map_err(|e| PublishError(format!("creating publication staging directory: {e}")))?;
    let mut targets = Vec::with_capacity(plan.targets.len());
    for (index, target) in plan.targets.iter().enumerate() {
        let source = staging.path().join(index.to_string());
        std::fs::write(&source, &target.bytes)
            .map_err(|e| PublishError(format!("staging {}: {e}", target.path)))?;
        targets.push(PublishTarget {
            name: target.path.clone(),
            source,
            custom: HashMap::new(),
        });
    }
    repo::replace_release(
        repository_dir,
        &repo::Keys::in_dir(keys_dir),
        targets,
        expiry_days,
    )
    .await
    .map_err(|e| PublishError(format!("signing TUF publication: {e}")))
}

/// Stable S3 upload order. Immutable target bytes precede metadata; timestamp is the
/// final visibility/commit object.
pub fn upload_order(repository_dir: &Path) -> Result<Vec<PathBuf>, PublishError> {
    let mut targets = files_below(&repository_dir.join("targets"))?;
    let mut metadata = files_below(&repository_dir.join("metadata"))?;
    let mut timestamp = Vec::new();
    metadata.retain(|path| {
        if path.file_name().and_then(|name| name.to_str()) == Some("timestamp.json") {
            timestamp.push(path.clone());
            false
        } else {
            true
        }
    });
    targets.sort();
    metadata.sort();
    targets.extend(metadata);
    targets.extend(timestamp);
    Ok(targets)
}

fn files_below(root: &Path) -> Result<Vec<PathBuf>, PublishError> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(&path)
            .map_err(|e| PublishError(format!("reading {}: {e}", path.display())))?
        {
            let path = entry
                .map_err(|e| PublishError(format!("reading {}: {e}", path.display())))?
                .path();
            let kind = std::fs::symlink_metadata(&path)
                .map_err(|e| PublishError(format!("inspecting {}: {e}", path.display())))?
                .file_type();
            if kind.is_symlink() {
                return Err(PublishError(format!(
                    "repository contains a symlink: {}",
                    path.display()
                )));
            }
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() {
                files.push(path);
            } else {
                return Err(PublishError(format!(
                    "repository contains a non-regular file: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_is_always_uploaded_last() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("metadata")).unwrap();
        std::fs::create_dir_all(root.path().join("targets/a")).unwrap();
        std::fs::write(root.path().join("targets/a/value"), b"target").unwrap();
        std::fs::write(root.path().join("metadata/targets.json"), b"targets").unwrap();
        std::fs::write(root.path().join("metadata/timestamp.json"), b"timestamp").unwrap();
        let files = upload_order(root.path()).unwrap();
        assert_eq!(files.last().unwrap().file_name().unwrap(), "timestamp.json");
        assert!(files[0].starts_with(root.path().join("targets")));
    }

    #[cfg(unix)]
    #[test]
    fn upload_order_rejects_symlinks() {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("metadata")).unwrap();
        std::fs::create_dir_all(root.path().join("targets")).unwrap();
        std::fs::write(root.path().join("outside"), b"secret").unwrap();
        std::os::unix::fs::symlink(
            root.path().join("outside"),
            root.path().join("targets/link"),
        )
        .unwrap();
        assert!(upload_order(root.path()).is_err());
    }
}
