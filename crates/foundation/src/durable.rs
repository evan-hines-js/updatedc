//! Crash-safe sibling-file replacement and removal.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub fn create_temp(dir: &Path, prefix: &str) -> io::Result<(File, PathBuf)> {
    create_temp_with(dir, prefix, |path| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options.open(path)
    })
}

fn create_temp_with(
    dir: &Path,
    prefix: &str,
    mut open: impl FnMut(&Path) -> io::Result<File>,
) -> io::Result<(File, PathBuf)> {
    let pid = std::process::id();
    for _ in 0..10_000u32 {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!("{prefix}{pid}-{nanos}-{seq}.tmp"));
        match open(&path) {
            Ok(file) => return Ok((file, path)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not create a unique temp file",
    ))
}

pub fn atomic_write(path: &Path, prefix: &str, data: &[u8]) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let (mut tmp, tmp_path) = create_temp(dir, prefix)?;
    if let Err(e) = tmp.write_all(data).and_then(|_| tmp.sync_all()) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    drop(tmp);
    if let Err(e) = replace(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    sync_dir(dir)
}

pub fn remove_file(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    }
    sync_dir(path.parent().unwrap_or_else(|| Path::new(".")))
}

/// Replace `to` with `from`, tolerating the short-lived executable/file locks seen
/// during process teardown and antivirus scanning. Permanent errors surface at once.
pub fn replace(from: &Path, to: &Path) -> io::Result<()> {
    let mut attempt = 0u32;
    loop {
        match fs::rename(from, to) {
            Ok(()) => return Ok(()),
            Err(e) if attempt < 50 && is_transient_lock(&e) => {
                attempt += 1;
                std::thread::sleep(std::time::Duration::from_millis(
                    (20 * u64::from(attempt)).min(100),
                ));
            }
            Err(e) => return Err(e),
        }
    }
}

pub fn is_transient_lock(error: &io::Error) -> bool {
    match error.raw_os_error() {
        #[cfg(windows)]
        Some(5) | Some(32) | Some(33) => true,
        #[cfg(unix)]
        Some(16) | Some(26) => true,
        _ => false,
    }
}

pub fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("foundation-durable-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn atomic_write_replaces_the_whole_file() {
        let p = dir("replace").join("state");
        atomic_write(&p, ".test-", b"first").unwrap();
        atomic_write(&p, ".test-", b"second-longer").unwrap();
        assert_eq!(fs::read(p).unwrap(), b"second-longer");
    }

    #[test]
    fn temp_creation_only_retries_collisions() {
        let d = dir("collision");
        let mut attempts = 0;
        let _ = create_temp_with(&d, ".test-", |path| {
            attempts += 1;
            if attempts == 1 {
                return Err(io::Error::from(io::ErrorKind::AlreadyExists));
            }
            OpenOptions::new().write(true).create_new(true).open(path)
        })
        .unwrap();
        assert_eq!(attempts, 2);
    }

    #[cfg(unix)]
    #[test]
    fn temporary_files_are_owner_only_from_creation() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir("private");
        let (_file, path) = create_temp(&d, ".secret-").unwrap();
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
