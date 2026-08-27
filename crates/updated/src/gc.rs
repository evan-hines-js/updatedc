//! Conservative garbage collection for content-addressed immutable directories.

use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::bundle::ReleaseId;

struct Entry {
    path: PathBuf,
    bytes: u64,
    modified: SystemTime,
}

/// Marker written into a workspace the moment its release directory is first observed missing.
///
/// The workspace belongs to the application, so this reserved entry is hostile input whenever the
/// privileged agent examines it. Every marker operation must inspect or replace the entry itself,
/// never follow it. Keeping that policy in [`orphaned_for`], [`mark_orphaned`], and
/// [`clear_orphan_marker`] makes the whole marker lifecycle use one no-follow path.
const ORPHAN_MARKER: &str = ".updated-orphaned-since";

/// How long a release directory must stay missing before its workspace is scratch nobody owns.
///
/// This only has to outlast the window in which a *live* release is legitimately absent from
/// `versions/`: [`crate::bundle::stage_bundle`] unlinks a drifted committed tree and republishes
/// the verified one over it (`discard` → `sync_tree` → `rename`), which is milliseconds to seconds
/// even for a large tree on a slow device. Ten minutes is far past that and still bounds how long
/// genuinely dead scratch can occupy disk, given that a reap runs on every resolve and every
/// confirmation tick.
const ORPHAN_GRACE: Duration = Duration::from_secs(600);

/// Drop every writable workspace under `work` whose release directory has been gone from
/// `versions` since a previous pass.
///
/// A release's scratch (`work/<version>-<sha>`) must exist exactly as long as the release does: it
/// is deliberately outside the content-addressed tree so the application can write to its own
/// working directory without failing release verification, which also means nothing else prunes it.
/// Both the launch path — which creates the workspace it is about to hand out — and the periodic
/// collector that prunes the release directories call this, so scratch disappears once its release
/// is gone rather than lingering until the node happens to launch something.
///
/// **A single observation of a missing release directory is not evidence of an orphan.** A release
/// that is very much alive is transiently absent while [`crate::bundle::stage_bundle`] repairs a
/// drifted committed tree: it `discard`s `versions/<id>` and only republishes the verified tree
/// over it after `sync_tree`. A reap landing inside that window used to delete the running
/// application's logs, pid file and database. The decision is therefore anchored on *persistent*
/// absence: the first pass that sees the release missing only stamps [`ORPHAN_MARKER`] into the
/// workspace, and a later pass removes the workspace only once that stamp has stood unchallenged
/// for [`ORPHAN_GRACE`]. A release that comes back — a repair completing, or a crash between
/// discard and rename healed by the next install — clears the stamp again, so its scratch survives.
/// Nothing here takes a lock: this runs on the per-resolve launch path, which must never block on
/// an installer.
///
/// Best-effort by design: leftover scratch costs disk, never correctness, and neither a launch nor
/// a collection pass may fail because one stale directory resisted removal. Only direct children of
/// `work` that are real directories are touched, and the release check examines the entry itself
/// rather than following it, so a symlink or an unknown file never protects a
/// workspace or leads deletion elsewhere.
pub fn reap_orphaned_workspaces(work: &Path, versions: &Path) {
    reap_orphaned_workspaces_after(work, versions, ORPHAN_GRACE);
}

/// [`reap_orphaned_workspaces`] with an explicit grace, so tests can drive the two-observation rule
/// without sleeping.
pub(crate) fn reap_orphaned_workspaces_after(work: &Path, versions: &Path, grace: Duration) {
    // The roots themselves are configuration/state boundaries, not traversal hints. Following a
    // replaced `work` root would turn arbitrary sibling directories into deletion candidates; a
    // missing/unreadable `versions` root is likewise not evidence that every release disappeared.
    if !matches!(real_directory_exists(work), Ok(true))
        || !matches!(real_directory_exists(versions), Ok(true))
    {
        return;
    }
    let Ok(entries) = fs::read_dir(work) else {
        return;
    };
    for entry in entries.flatten() {
        let workspace = entry.path();
        let Ok(metadata) = fs::symlink_metadata(&workspace) else {
            continue;
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            continue;
        }
        let marker = workspace.join(ORPHAN_MARKER);
        let release = versions.join(entry.file_name());
        let release_present = match real_directory_exists(&release) {
            Ok(present) => present,
            // An I/O or permission failure is not proof that a release disappeared. Skip this
            // workspace so an unreadable versions volume can never authorize deletion.
            Err(_) => continue,
        };
        if release_present {
            // The release is here, so any earlier suspicion was the staging window (or a repair
            // that has since completed). Forget it, or a future absence would be judged by a
            // long-expired stamp.
            clear_orphan_marker(&marker);
            continue;
        }
        match orphaned_for(&marker) {
            Some(elapsed) if elapsed >= grace => {
                let _ = foundation::durable::remove_path(&workspace);
            }
            Some(_) => {}
            None => mark_orphaned(&marker),
        }
    }
}

/// Whether `path` names a real directory entry, distinguishing proven absence/garbage from an
/// observation failure. A symlink is not a release, while an I/O error is not evidence of absence.
fn real_directory_exists(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(metadata.file_type().is_dir()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// How long this workspace has been marked orphaned, or `None` if it carries no usable mark yet.
/// A clock that moved backwards since the mark was written reads as "not long enough", which only
/// ever delays a deletion. `symlink_metadata` is load-bearing: the workspace is application
/// writable, so following a marker symlink would let the application choose the file whose mtime
/// authorizes deletion.
fn orphaned_for(marker: &Path) -> Option<Duration> {
    let metadata = fs::symlink_metadata(marker).ok()?;
    if !metadata.file_type().is_file() {
        return None;
    }
    let modified = metadata.modified().ok()?;
    Some(
        SystemTime::now()
            .duration_since(modified)
            .unwrap_or_default(),
    )
}

/// Install a fresh orphan clock without ever opening an application-chosen path.
///
/// A workload may have planted a symlink, directory, or other non-file at the reserved name. The
/// shared removal primitive unlinks a symlink rather than following it, then the shared atomic
/// writer commits a newly created sibling over the now-empty name. Failure is intentionally
/// best-effort: it can only delay garbage collection.
fn mark_orphaned(marker: &Path) {
    let _ = foundation::durable::remove_path(marker)
        .and_then(|()| foundation::durable::atomic_write_managed(marker, ".orphan-marker-", b""));
}

/// Forget a disproved orphan observation through the same shape-agnostic, no-follow removal path.
fn clear_orphan_marker(marker: &Path) {
    let _ = foundation::durable::remove_path(marker);
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

    /// A workspace and its release directory, with application scratch already in the workspace.
    fn workspace_pair(root: &Path, id: &ReleaseId) -> (PathBuf, PathBuf) {
        let work = root.join("work").join(id.directory_name());
        let release = root.join("versions").join(id.directory_name());
        fs::create_dir_all(&work).unwrap();
        fs::create_dir_all(&release).unwrap();
        fs::write(work.join("app.db"), b"live application state").unwrap();
        (work, release)
    }

    /// The defect: `stage_bundle` unlinks a drifted committed release before renaming the verified
    /// tree over it, so a reap landing in that window saw `versions/<id>` missing and deleted the
    /// *running* application's state. One observation of absence must decide nothing.
    #[test]
    fn a_transiently_absent_release_does_not_cost_its_workspace_its_scratch() {
        let (_dir, root) = temp();
        let id = release("1.0.0", 1);
        let (work_dir, release_dir) = workspace_pair(&root, &id);
        let work = root.join("work");
        let versions = root.join("versions");

        // Inside stage_bundle's discard -> sync_tree -> rename window.
        fs::remove_dir_all(&release_dir).unwrap();
        for _ in 0..3 {
            reap_orphaned_workspaces(&work, &versions);
        }
        assert_eq!(
            fs::read(work_dir.join("app.db")).unwrap(),
            b"live application state"
        );

        // The repair republishes the tree; the suspicion must be forgotten, not banked.
        fs::create_dir_all(&release_dir).unwrap();
        reap_orphaned_workspaces(&work, &versions);
        assert!(!work_dir.join(ORPHAN_MARKER).exists());
        assert!(work_dir.is_dir());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_workspace_is_reaped_once_its_release_has_stayed_gone() {
        let (_dir, root) = temp();
        let id = release("1.0.0", 1);
        let (work_dir, release_dir) = workspace_pair(&root, &id);
        let kept = release("2.0.0", 2);
        let (kept_dir, _) = workspace_pair(&root, &kept);
        let work = root.join("work");
        let versions = root.join("versions");

        fs::remove_dir_all(&release_dir).unwrap();
        // First pass only records the absence, however long the grace.
        reap_orphaned_workspaces_after(&work, &versions, Duration::ZERO);
        assert!(work_dir.join(ORPHAN_MARKER).is_file());
        assert!(work_dir.is_dir());
        // A later pass, with the absence still standing, removes it.
        reap_orphaned_workspaces_after(&work, &versions, Duration::ZERO);
        assert!(!work_dir.exists());
        assert!(kept_dir.is_dir());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_release_that_returns_restarts_the_orphan_clock() {
        let (_dir, root) = temp();
        let id = release("1.0.0", 1);
        let (work_dir, release_dir) = workspace_pair(&root, &id);
        let work = root.join("work");
        let versions = root.join("versions");

        fs::remove_dir_all(&release_dir).unwrap();
        reap_orphaned_workspaces_after(&work, &versions, Duration::ZERO);
        fs::create_dir_all(&release_dir).unwrap();
        reap_orphaned_workspaces_after(&work, &versions, Duration::ZERO);
        // The stamp from the earlier absence must not authorize the next pass to delete.
        fs::remove_dir_all(&release_dir).unwrap();
        reap_orphaned_workspaces_after(&work, &versions, Duration::ZERO);
        assert!(work_dir.is_dir());
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn a_hostile_orphan_marker_never_redirects_the_privileged_writer() {
        let (_dir, root) = temp();
        let id = release("1.0.0", 1);
        let (work_dir, release_dir) = workspace_pair(&root, &id);
        let work = root.join("work");
        let versions = root.join("versions");
        let victim = root.join("agent-owned-file");
        let marker = work_dir.join(ORPHAN_MARKER);

        fs::remove_dir_all(release_dir).unwrap();
        std::os::unix::fs::symlink(&victim, &marker).unwrap();
        reap_orphaned_workspaces_after(&work, &versions, Duration::ZERO);

        assert!(!victim.exists());
        assert!(fs::symlink_metadata(marker).unwrap().file_type().is_file());
        assert!(work_dir.is_dir());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_hostile_directory_at_the_marker_is_repaired() {
        let (_dir, root) = temp();
        let id = release("1.0.0", 1);
        let (work_dir, release_dir) = workspace_pair(&root, &id);
        let work = root.join("work");
        let versions = root.join("versions");
        let marker = work_dir.join(ORPHAN_MARKER);

        fs::remove_dir_all(release_dir).unwrap();
        fs::create_dir(&marker).unwrap();
        fs::write(marker.join("blocker"), b"application-controlled").unwrap();
        reap_orphaned_workspaces_after(&work, &versions, Duration::ZERO);

        assert!(fs::symlink_metadata(marker).unwrap().file_type().is_file());
        assert!(work_dir.is_dir());
        reap_orphaned_workspaces_after(&work, &versions, Duration::ZERO);
        assert!(!work_dir.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn a_release_symlink_cannot_protect_or_redirect_workspace_collection() {
        let (_dir, root) = temp();
        let id = release("1.0.0", 1);
        let (work_dir, release_dir) = workspace_pair(&root, &id);
        let work = root.join("work");
        let versions = root.join("versions");
        let elsewhere = root.join("elsewhere");

        fs::remove_dir_all(&release_dir).unwrap();
        fs::create_dir(&elsewhere).unwrap();
        fs::write(elsewhere.join("keep"), b"outside the versions tree").unwrap();
        std::os::unix::fs::symlink(&elsewhere, release_dir).unwrap();
        for _ in 0..2 {
            reap_orphaned_workspaces_after(&work, &versions, Duration::ZERO);
        }

        assert!(!work_dir.exists());
        assert_eq!(
            fs::read(elsewhere.join("keep")).unwrap(),
            b"outside the versions tree"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn workspace_collection_never_follows_a_redirected_root() {
        let (_dir, root) = temp();
        let work = root.join("work");
        let versions = root.join("versions");
        let elsewhere = root.join("elsewhere");
        let redirected = root.join("redirected-work");
        let id = release("1.0.0", 1);
        fs::create_dir_all(elsewhere.join(id.directory_name())).unwrap();
        fs::write(
            elsewhere.join(id.directory_name()).join("keep"),
            b"outside the configured work root",
        )
        .unwrap();
        fs::create_dir_all(&versions).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &redirected).unwrap();

        for _ in 0..2 {
            reap_orphaned_workspaces_after(&redirected, &versions, Duration::ZERO);
        }

        assert_eq!(
            fs::read(elsewhere.join(id.directory_name()).join("keep")).unwrap(),
            b"outside the configured work root"
        );
        assert!(!work.exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn reaping_ignores_files_and_symlinks_under_work() {
        let (_dir, root) = temp();
        let work = root.join("work");
        let versions = root.join("versions");
        fs::create_dir_all(&work).unwrap();
        fs::create_dir_all(&versions).unwrap();
        fs::write(work.join("stray-file"), b"bytes").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&versions, work.join("stray-link")).unwrap();
        for _ in 0..2 {
            reap_orphaned_workspaces_after(&work, &versions, Duration::ZERO);
        }
        assert!(work.join("stray-file").is_file());
        #[cfg(unix)]
        assert!(fs::symlink_metadata(work.join("stray-link"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(versions.is_dir());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn byte_accounting_saturates_instead_of_wrapping() {
        let entries = [u64::MAX, 1];
        assert_eq!(saturating_sum(entries), u64::MAX);
    }
}
