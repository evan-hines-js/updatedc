//! Crash-safe file writes, reimplemented locally (std only) so the guardian needs no
//! project dependency. A durable state change is a fsynced temp file renamed over the
//! target, with the containing directory fsynced on Unix; a durable removal fsyncs the
//! directory after unlinking. Windows has no portable directory fsync in std, so it
//! gets the process-crash guarantee (atomic rename/unlink) but not the power-loss one
//! — the same tradeoff the rest of the tower documents.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Atomically write `data` to `path`, flushing contents before the rename and (on
/// Unix) the directory entry after it.
pub fn atomic_write(path: &Path, data: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let (mut tmp, tmp_path) = create_temp(dir)?;
    if let Err(e) = tmp.write_all(data).and_then(|_| tmp.sync_all()) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    drop(tmp);
    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    sync_dir(dir)
}

fn create_temp(dir: &Path) -> io::Result<(File, PathBuf)> {
    create_temp_with(dir, |path| {
        OpenOptions::new().write(true).create_new(true).open(path)
    })
}

fn create_temp_with(
    dir: &Path,
    mut open: impl FnMut(&Path) -> io::Result<File>,
) -> io::Result<(File, PathBuf)> {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let pid = std::process::id();
    for _ in 0..10_000u32 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!(".guardian-{pid}-{nanos}-{seq}.tmp"));
        match open(&path) {
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

fn sync_dir(dir: &Path) -> io::Result<()> {
    crate::sys::sync_dir(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("guardian-durable-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn create_temp_propagates_a_non_collision_error_instead_of_retrying() {
        // Only an AlreadyExists collision retries; any other error (here a missing parent
        // dir ⇒ NotFound) is returned at once, never mis-classified as a name collision.
        let err = create_temp(Path::new("/no/such/guardian/dir/here")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn create_temp_retries_only_after_a_name_collision() {
        let d = tmp("collision");
        let mut attempts = 0;
        let (file, path) = create_temp_with(&d, |path| {
            attempts += 1;
            if attempts == 1 {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "forced collision",
                ));
            }
            OpenOptions::new().write(true).create_new(true).open(path)
        })
        .unwrap();
        drop(file);

        assert_eq!(attempts, 2, "one collision causes exactly one retry");
        assert!(path.exists(), "the retry creates its newly selected path");
    }

    #[cfg(unix)]
    #[test]
    fn syncing_a_missing_directory_reports_the_error() {
        let d = tmp("missing-sync");
        fs::remove_dir(&d).unwrap();
        assert_eq!(sync_dir(&d).unwrap_err().kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn atomic_write_replaces_whole_file() {
        let d = tmp("write");
        let p = d.join("state");
        atomic_write(&p, b"first").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"first");
        atomic_write(&p, b"second-and-longer").unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"second-and-longer");
    }
}
