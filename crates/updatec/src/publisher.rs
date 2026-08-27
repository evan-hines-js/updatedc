//! Atomic TUF publication. Storage mirroring is deliberately a separate final step:
//! targets are uploaded first and timestamp metadata last.

use std::collections::HashMap;
use std::path::Path;

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
    let keys = repo::Keys::in_dir(keys_dir)
        .map_err(|e| PublishError(format!("resolving TUF signing keys: {e}")))?;
    repo::replace_release(repository_dir, &keys, targets, expiry_days)
        .await
        .map_err(|e| PublishError(format!("signing TUF publication: {e}")))
}

/// Resolve the one publication plan: local immutable bytes precede metadata, retained
/// content-addressed targets must already exist remotely, and timestamp is the final commit.
pub async fn publication_plan(
    repository_dir: &Path,
) -> Result<repo::PublicationPlan, PublishError> {
    repo::current_publication_plan(repository_dir)
        .await
        .map_err(|e| PublishError(format!("resolving current TUF publication closure: {e}")))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::path::PathBuf;

    async fn repository_with_target(root: &Path) -> (PathBuf, repo::Keys) {
        let repo_dir = root.join("repo");
        let keys = repo::generate_keys(&root.join("keys")).await.unwrap();
        repo::init(&repo_dir, &keys, 365).await.unwrap();
        let source = root.join("application");
        std::fs::write(&source, b"target").unwrap();
        repo::replace_release(
            &repo_dir,
            &keys,
            vec![PublishTarget::application(
                "app", "stable", "1.0.0", "linux", "x86_64", "app", source,
            )],
            365,
        )
        .await
        .unwrap();
        (repo_dir, keys)
    }

    #[tokio::test]
    async fn timestamp_is_always_uploaded_last() {
        let root = tempfile::tempdir().unwrap();
        let (repo_dir, _) = repository_with_target(root.path()).await;
        let plan = publication_plan(&repo_dir).await.unwrap();
        assert_eq!(
            plan.uploads.last().unwrap().file_name().unwrap(),
            "timestamp.json"
        );
        assert!(plan.uploads[0].starts_with(repo_dir.join("targets")));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn publication_plan_rejects_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let (repo_dir, _) = repository_with_target(root.path()).await;
        let target = publication_plan(&repo_dir)
            .await
            .unwrap()
            .uploads
            .into_iter()
            .find(|path| path.starts_with(repo_dir.join("targets")))
            .unwrap();
        std::fs::write(root.path().join("outside"), b"secret").unwrap();
        std::fs::remove_file(&target).unwrap();
        std::os::unix::fs::symlink(root.path().join("outside"), target).unwrap();
        assert!(publication_plan(&repo_dir).await.is_err());
    }

    #[tokio::test]
    async fn later_publications_do_not_reupload_historical_targets_or_online_roles() {
        let root = tempfile::tempdir().unwrap();
        let (repo_dir, keys) = repository_with_target(root.path()).await;
        let first = publication_plan(&repo_dir).await.unwrap().uploads;
        let old_target = first
            .iter()
            .find(|path| path.starts_with(repo_dir.join("targets")))
            .unwrap()
            .clone();
        let old_targets_role = first
            .iter()
            .find(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(".targets.json"))
            })
            .unwrap()
            .clone();

        let source = root.path().join("application-v2");
        std::fs::write(&source, b"target-v2").unwrap();
        repo::replace_release(
            &repo_dir,
            &keys,
            vec![PublishTarget::application(
                "app", "stable", "2.0.0", "linux", "x86_64", "app", source,
            )],
            365,
        )
        .await
        .unwrap();
        let current = publication_plan(&repo_dir).await.unwrap().uploads;
        assert!(!current.contains(&old_target));
        assert!(!current.contains(&old_targets_role));
        assert_eq!(
            current.last().unwrap().file_name().unwrap(),
            "timestamp.json"
        );
    }
}
