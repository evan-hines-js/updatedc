//! Crash-safe replacement of a stopped executable. Sibling temporary files keep
//! renames atomic; `<target>.old` remains available until commit.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn old_path(target: &Path) -> PathBuf {
    crate::config::with_suffix(target, ".old")
}

pub fn cleanup_previous(target: &Path) {
    let _ = fs::remove_file(old_path(target));
}

/// Restore the previous binary saved during the last update. Streams from
/// `<target>.old`, and deliberately does not rotate the rejected binary into the
/// rollback slot: the known-good image stays available until the transaction is
/// durably committed.
pub fn rollback(target: &Path) -> io::Result<()> {
    let old = old_path(target);
    if !old.exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no rollback binary at {}", old.display()),
        ));
    }
    atomic_install_file(target, &old)
}

fn create_temp(dir: &Path, prefix: &str) -> io::Result<(File, PathBuf)> {
    let pid = std::process::id();
    for attempt in 0..10_000u32 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.subsec_nanos())
            .unwrap_or(attempt);
        let path = dir.join(format!("{prefix}{pid}-{nanos}-{attempt}"));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(f) => return Ok((f, path)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create a unique temp file",
    ))
}

/// Atomically replace a stopped target while retaining `<target>.old` for rollback.
pub fn atomic_swap_file(target: &Path, source: &Path) -> io::Result<()> {
    swap(target, |tmp| {
        let mut source = File::open(source)?;
        io::copy(&mut source, tmp).map(|_| ())
    })
}

/// Atomically install the staged `source` at `target`, streamed. Unlike
/// [`atomic_swap_file`], no `<target>.old` rollback file is created — this backs
/// [`rollback`], which restores the previous image from `<target>.old`.
fn atomic_install_file(target: &Path, source: &Path) -> io::Result<()> {
    install(target, |tmp| {
        let mut source = File::open(source)?;
        io::copy(&mut source, tmp).map(|_| ())
    })
}

fn swap(target: &Path, write: impl FnOnce(&mut File) -> io::Result<()>) -> io::Result<()> {
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let tmp_path = stage(dir, target, write)?;
    // The rollback image must be durable before replacement.
    if let Err(e) = backup(target) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    if let Err(e) = replace_path(&tmp_path, target) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    sync_dir(dir)
}

/// Install `source`'s bytes as `target`, atomically and with the executable bit
/// set, keeping no rollback copy. `target` must not be a currently-running image.
/// Supervisor self-update candidates use a fresh content-addressed path, so this
/// never overwrites the running supervisor. (TUF downloads are `0o600`, so the
/// executable bit is set here.)
pub fn install_executable(target: &Path, source: &Path) -> io::Result<()> {
    install(target, |dst| {
        let mut src = File::open(source)?;
        io::copy(&mut src, dst).map(|_| ())
    })
}

fn install(target: &Path, write: impl FnOnce(&mut File) -> io::Result<()>) -> io::Result<()> {
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let tmp_path = stage(dir, target, write)?;
    if let Err(e) = replace_path(&tmp_path, target) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    sync_dir(dir)
}

/// Create a temp file next to `target`, run `write`, fsync it, and (on Unix)
/// carry over the target's mode with the executable bit forced on. Returns the
/// temp path, ready to rename over `target`.
fn stage(
    dir: &Path,
    _target: &Path,
    write: impl FnOnce(&mut File) -> io::Result<()>,
) -> io::Result<PathBuf> {
    let (mut tmp, tmp_path) = create_temp(dir, ".update-")?;
    if let Err(e) = write(&mut tmp).and_then(|_| tmp.sync_all()) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    drop(tmp);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(_target)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0o755);
        if let Err(e) = fs::set_permissions(&tmp_path, PermissionsExt::from_mode(mode | 0o700)) {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
        // chmod changes inode metadata after the first sync. Persist the final
        // executable mode before the file can become the installed image.
        if let Err(e) = File::open(&tmp_path).and_then(|f| f.sync_all()) {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
    }
    Ok(tmp_path)
}

fn backup(target: &Path) -> io::Result<()> {
    let old = old_path(target);
    let dir = target.parent().unwrap_or_else(|| Path::new("."));
    let _ = fs::remove_file(&old);
    fs::copy(target, &old)?;
    // Reopen writable to fsync it: `FlushFileBuffers` (what `sync_all` issues on
    // Windows) requires a writable handle, so a read-only `File::open` fails there
    // with ERROR_ACCESS_DENIED. Unix `fsync` accepts a read-only fd, which hid this.
    OpenOptions::new().write(true).open(&old)?.sync_all()?;
    sync_dir(dir) // the .old entry must be durable before the swap commits
}

/// Atomically replace `to` with `from`, retrying a *transient* lock. Our staged
/// `from` is untouched when a replace fails, so retrying is always safe. This is
/// production hardening, not a test crutch: real deployments hit it — Windows
/// real-time antivirus briefly locks a just-written file (surfacing as
/// `ERROR_ACCESS_DENIED`), and a busy file on a network/overlay filesystem can
/// return `EBUSY`/`ETXTBSY`. A genuine permission or space error is not transient
/// and surfaces after the bounded retry budget (~5s) is spent. Five seconds is
/// intentional: on Windows a process can be gone while teardown of its executable
/// mapping (or an antivirus scan triggered by that teardown) still briefly makes
/// replacement return `ERROR_ACCESS_DENIED`.
fn replace_path(from: &Path, to: &Path) -> io::Result<()> {
    let mut attempt = 0u32;
    loop {
        match replace_once(from, to) {
            Ok(()) => return Ok(()),
            Err(e) if attempt < 50 && is_transient_lock(&e) => {
                attempt += 1;
                std::thread::sleep(std::time::Duration::from_millis(
                    (20 * attempt as u64).min(100),
                ));
            }
            Err(e) => return Err(e),
        }
    }
}

fn is_transient_lock(e: &io::Error) -> bool {
    match e.raw_os_error() {
        #[cfg(windows)]
        Some(5) | Some(32) | Some(33) => true,
        #[cfg(unix)]
        Some(16) | Some(26) => true,
        _ => false,
    }
}

/// Atomically replace an existing file. `fs::rename` is a replace-existing rename
/// on every target we support: `rename(2)` on Unix, and
/// `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` on Windows (what Rust's `fs::rename`
/// issues). We deliberately do NOT use `ReplaceFileW`: its internal rename-aside
/// dance returns `ERROR_ACCESS_DENIED` in some environments even for an idle plain
/// file, whereas the single MoveFileEx is robust. The target is never a running
/// image here — the supervisor stops the child before a Windows swap.
fn replace_once(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()?;
    }
    #[cfg(not(unix))]
    // Windows has no directly equivalent directory-fsync operation in Rust's
    // standard library. File contents are flushed before replacement, and rename
    // remains atomic, but a sudden power loss may lose the newest directory-entry
    // change (creation, removal, or rename). Process-crash recovery is unaffected.
    let _ = dir;
    Ok(())
}

/// Atomically write `data` to `path`, flushing its contents before replacement.
/// Unix also fsyncs the containing directory; see [`sync_dir`] for the narrower
/// Windows sudden-power-loss guarantee.
pub fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let (mut tmp, tmp_path) = create_temp(dir, ".state-")?;
    if let Err(e) = tmp.write_all(data).and_then(|_| tmp.sync_all()) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    drop(tmp);
    if let Err(e) = replace_path(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    sync_dir(dir)
}

/// Remove `path` and, on Unix, durably record its absence by fsyncing the containing
/// directory. This is used when deleting a transaction journal is itself a commit
/// step. Already-absent is
/// success. On Windows removal is atomic and process-crash-safe, but an abrupt power
/// loss may retain the old directory entry; callers still get ordinary I/O errors.
pub fn remove_file_durable(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    }
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    sync_dir(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_whole_file() {
        let dir = std::env::temp_dir().join(format!("aw-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("state");
        atomic_write(&p, b"first").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"first");
        atomic_write(&p, b"second-longer").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"second-longer");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn atomic_swap_replaces_and_keeps_rollback() {
        let dir = std::env::temp_dir().join(format!("swap-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("app");
        fs::write(&target, b"OLD").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, PermissionsExt::from_mode(0o755)).unwrap();
        }

        let source = dir.join("staged");
        fs::write(&source, b"NEW-BINARY-CONTENTS").unwrap();
        atomic_swap_file(&target, &source).unwrap();

        assert_eq!(fs::read(&target).unwrap(), b"NEW-BINARY-CONTENTS");
        assert_eq!(
            fs::read(old_path(&target)).unwrap(),
            b"OLD",
            "rollback copy preserved"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&target).unwrap().permissions().mode();
            // The target's own 0o755 must be carried over verbatim (not widened to
            // 0o777, nor collapsed to 0o700), with the executable bits forced on.
            assert_eq!(mode & 0o777, 0o755, "mode preserved + executable: {mode:o}");
        }

        // Committing the update drops the rollback image.
        assert!(old_path(&target).exists());
        cleanup_previous(&target);
        assert!(
            !old_path(&target).exists(),
            "cleanup removes the rollback copy"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_durable_is_idempotent() {
        let dir = std::env::temp_dir().join(format!("rm-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("journal");
        fs::write(&p, b"tx").unwrap();
        remove_file_durable(&p).unwrap();
        assert!(!p.exists(), "removed");
        // Already-absent (NotFound) is success, not an error.
        remove_file_durable(&p).unwrap();
        // But a non-NotFound failure must propagate — removing a directory as a file
        // errors, and the NotFound guard must not swallow it as "already gone".
        assert!(
            remove_file_durable(&dir).is_err(),
            "a directory is not a silently-absent file"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rollback_restores_previous() {
        let dir = std::env::temp_dir().join(format!("rollback-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("app");
        fs::write(&target, b"v1").unwrap();

        let source = dir.join("staged");
        fs::write(&source, b"v2").unwrap();
        atomic_swap_file(&target, &source).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"v2");

        rollback(&target).unwrap();
        assert_eq!(
            fs::read(&target).unwrap(),
            b"v1",
            "rolled back to previous bytes"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_busy_style_errors_are_transient() {
        // Exactly the "someone briefly holds this file" codes retry; a real
        // permission/space/not-found failure must not be treated as transient.
        #[cfg(unix)]
        {
            assert!(is_transient_lock(&io::Error::from_raw_os_error(16))); // EBUSY
            assert!(is_transient_lock(&io::Error::from_raw_os_error(26))); // ETXTBSY
        }
        #[cfg(windows)]
        {
            assert!(is_transient_lock(&io::Error::from_raw_os_error(5))); // ACCESS_DENIED
            assert!(is_transient_lock(&io::Error::from_raw_os_error(32))); // SHARING_VIOLATION
            assert!(is_transient_lock(&io::Error::from_raw_os_error(33))); // LOCK_VIOLATION
        }
        assert!(!is_transient_lock(&io::Error::from(
            io::ErrorKind::NotFound
        )));
        assert!(!is_transient_lock(&io::Error::from(
            io::ErrorKind::PermissionDenied
        )));
        assert!(!is_transient_lock(&io::Error::other("nope")));
    }

    #[test]
    fn install_executable_writes_bytes_and_sets_exec_bit() {
        let dir = std::env::temp_dir().join(format!("inst-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let source = dir.join("staged");
        fs::write(&source, b"CANDIDATE").unwrap();
        let target = dir.join("supervisors").join("abc").join("supervisor");
        fs::create_dir_all(target.parent().unwrap()).unwrap();

        install_executable(&target, &source).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"CANDIDATE");
        assert!(!old_path(&target).exists(), "keeps no rollback copy");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&target).unwrap().permissions().mode();
            assert!(mode & 0o100 != 0, "executable bit set: {mode:o}");
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
