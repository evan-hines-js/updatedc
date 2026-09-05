//! Conservative garbage collection for content-addressed immutable directories.

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::bundle::ReleaseId;

struct Entry {
    path: PathBuf,
    bytes: u64,
    modified: SystemTime,
}

/// Remove oldest unprotected release directories until both inactive limits hold.
/// Unknown files and symlinks are ignored: this routine never follows attacker-chosen
/// paths and never deletes anything outside a direct child directory of `root`.
pub fn prune_releases(
    root: &Path,
    protected: &[ReleaseId],
    max_inactive: usize,
    max_inactive_bytes: u64,
) -> io::Result<usize> {
    let protected: HashSet<OsString> = protected
        .iter()
        .map(|release| release.directory_name().into())
        .collect();
    // The first protected release is the active one. Any additional protected release
    // is rollback state and must consume the same inactive retention budget as any other
    // retained directory; otherwise `active + rollback predecessor + N inactive` silently
    // exceeds the configured bound.
    let protected_inactive = protected.len().saturating_sub(1);
    prune_directories(
        root,
        &protected,
        max_inactive.saturating_sub(protected_inactive),
        max_inactive_bytes,
    )
}

/// Prune direct content-addressed child directories while preserving exact names.
/// This is also used for agent and repository caches, whose identities are hashes
/// rather than [`ReleaseId`] values.
pub fn prune_directories(
    root: &Path,
    protected: &HashSet<OsString>,
    max_inactive: usize,
    max_inactive_bytes: u64,
) -> io::Result<usize> {
    match fs::symlink_metadata(root) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "garbage-collection root is not a real directory",
            ))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    }
    let mut entries = Vec::new();
    match fs::read_dir(root) {
        Ok(children) => {
            for child in children {
                let child = child?;
                if protected.contains(&child.file_name()) {
                    continue;
                }
                let metadata = fs::symlink_metadata(child.path())?;
                if metadata.is_dir() && !metadata.file_type().is_symlink() {
                    entries.push(Entry {
                        bytes: tree_bytes(&child.path())?,
                        modified: metadata.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                        path: child.path(),
                    });
                }
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error),
    }
    entries.sort_by_key(|entry| entry.modified);
    let mut count = entries.len();
    let mut bytes = saturating_sum(entries.iter().map(|entry| entry.bytes));
    let mut removed = 0;
    for entry in entries {
        if count <= max_inactive && bytes <= max_inactive_bytes {
            break;
        }
        foundation::durable::remove_path(&entry.path)?;
        count -= 1;
        bytes = bytes.saturating_sub(entry.bytes);
        removed += 1;
    }
    Ok(removed)
}

fn saturating_sum(values: impl IntoIterator<Item = u64>) -> u64 {
    values
        .into_iter()
        .fold(0u64, |total, value| total.saturating_add(value))
}

fn tree_bytes(root: &Path) -> io::Result<u64> {
    let mut total = 0u64;
    let mut dirs = vec![root.to_path_buf()];
    while let Some(dir) = dirs.pop() {
        for child in fs::read_dir(dir)? {
            let child = child?;
            let metadata = fs::symlink_metadata(child.path())?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                dirs.push(child.path());
            } else {
                total = total.saturating_add(metadata.len());
            }
        }
    }
    Ok(total)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn temp() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("root");
        fs::create_dir_all(&path).unwrap();
        (dir, path)
    }

    fn release(version: &str, byte: u8) -> ReleaseId {
        ReleaseId {
            version: version.into(),
            manifest_sha256: format!("{byte:02x}").repeat(32),
        }
    }

    #[test]
    fn protected_releases_survive_even_when_limits_are_zero() {
        let (_dir, root) = temp();
        let protected = release("1.0.0", 1);
        let stale = release("2.0.0", 2);
        for item in [&protected, &stale] {
            let dir = root.join(item.directory_name());
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("data"), b"bytes").unwrap();
        }
        assert_eq!(
            prune_releases(&root, std::slice::from_ref(&protected), 0, 1).unwrap(),
            1
        );
        assert!(root.join(protected.directory_name()).is_dir());
        assert!(!root.join(stale.directory_name()).exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rollback_predecessor_consumes_inactive_retention_budget() {
        let (_dir, root) = temp();
        let active = release("1.0.0", 1);
        let predecessor = release("0.9.0", 2);
        let stale_a = release("2.0.0", 3);
        let stale_b = release("3.0.0", 4);
        for item in [&active, &predecessor, &stale_a, &stale_b] {
            let dir = root.join(item.directory_name());
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("data"), b"bytes").unwrap();
        }
        assert_eq!(
            prune_releases(&root, &[active.clone(), predecessor.clone()], 2, u64::MAX).unwrap(),
            1
        );
        assert!(root.join(active.directory_name()).is_dir());
        assert!(root.join(predecessor.directory_name()).is_dir());
        assert_eq!(
            fs::read_dir(&root).unwrap().filter_map(Result::ok).count(),
            3
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn generic_pruning_ignores_files_and_symlinks() {
        let (_dir, root) = temp();
        fs::create_dir(root.join("stale")).unwrap();
        fs::write(root.join("stale/data"), b"bytes").unwrap();
        fs::write(root.join("unknown-file"), b"keep").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.join("stale"), root.join("unknown-link")).unwrap();
        assert_eq!(prune_directories(&root, &HashSet::new(), 0, 1).unwrap(), 1);
        assert!(root.join("unknown-file").is_file());
        #[cfg(unix)]
        assert!(fs::symlink_metadata(root.join("unknown-link"))
            .unwrap()
            .file_type()
            .is_symlink());
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn pruning_never_follows_a_redirected_root() {
        let (_dir, root) = temp();
        let target = root.join("target");
        let redirect = root.join("redirect");
        fs::create_dir(&target).unwrap();
        fs::create_dir(target.join("release")).unwrap();
        fs::write(target.join("release/keep"), b"outside the configured root").unwrap();
        std::os::unix::fs::symlink(&target, &redirect).unwrap();

        assert_eq!(
            prune_directories(&redirect, &HashSet::new(), 0, 0)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            fs::read(target.join("release/keep")).unwrap(),
            b"outside the configured root"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn byte_accounting_saturates_instead_of_wrapping() {
        let entries = [u64::MAX, 1];
        assert_eq!(saturating_sum(entries), u64::MAX);
    }
}
