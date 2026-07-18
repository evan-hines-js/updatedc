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

/// The directory holding `path`, as an fsync target. `Path::parent` returns `Some("")`
/// — never `None` — for a bare relative filename, and the empty path cannot be opened,
/// so both that case and a true parentless path resolve to the current directory.
/// Every durable primitive derives its fsync target through here.
pub fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

pub fn atomic_write(path: &Path, prefix: &str, data: &[u8]) -> io::Result<()> {
    let dir = parent_dir(path);
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

/// Copy a verified executable into a fresh sibling file, persist its final mode,
/// and atomically install it at `target`.
pub fn install_executable(target: &Path, source: &Path) -> io::Result<()> {
    let dir = parent_dir(target);
    let (mut tmp, tmp_path) = create_temp(dir, ".executable-")?;
    let staged = File::open(source)
        .and_then(|mut source| io::copy(&mut source, &mut tmp))
        .and_then(|_| tmp.sync_all());
    if let Err(error) = staged {
        let _ = fs::remove_file(&tmp_path);
        return Err(error);
    }
    drop(tmp);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(target)
            .map(|metadata| metadata.permissions().mode() & 0o777)
            .unwrap_or(0o755);
        if let Err(error) = fs::set_permissions(&tmp_path, PermissionsExt::from_mode(mode | 0o700))
            .and_then(|_| File::open(&tmp_path)?.sync_all())
        {
            let _ = fs::remove_file(&tmp_path);
            return Err(error);
        }
    }

    if let Err(error) = replace(&tmp_path, target) {
        let _ = fs::remove_file(&tmp_path);
        return Err(error);
    }
    sync_dir(dir)
}

pub fn remove_file(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    }
    sync_dir(parent_dir(path))
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
    fn executable_install_uses_the_canonical_durable_path() {
        let root = dir("executable");
        let source = root.join("download");
        let target = root.join("supervisor");
        fs::write(&source, b"verified bytes").unwrap();

        install_executable(&target, &source).unwrap();

        assert_eq!(fs::read(&target).unwrap(), b"verified bytes");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_ne!(
                fs::metadata(target).unwrap().permissions().mode() & 0o100,
                0
            );
        }
    }

    #[test]
    fn parent_dir_resolves_a_bare_filename_to_the_current_directory() {
        // Path::parent yields Some("") for a bare filename, so a naive
        // `parent().unwrap_or(".")` hands sync_dir an unopenable empty path and reports
        // an already-committed write as failed.
        assert_eq!(Path::new("state").parent(), Some(Path::new("")));
        assert_eq!(parent_dir(Path::new("state")), Path::new("."));
        assert_eq!(parent_dir(Path::new("/")), Path::new("."));
        assert_eq!(
            parent_dir(Path::new("/var/lib/state")),
            Path::new("/var/lib")
        );
    }

    #[test]
    fn durable_operations_on_a_bare_relative_path_report_success() {
        // A relative `application.state` makes every derived path bare; a committed write
        // reported as Err drives callers into bogus crash recovery.
        let d = dir("relative");
        struct RestoreDir(std::path::PathBuf);
        impl Drop for RestoreDir {
            fn drop(&mut self) {
                std::env::set_current_dir(&self.0).expect("restore test working directory");
            }
        }
        let restore = RestoreDir(std::env::current_dir().unwrap());
        std::env::set_current_dir(&d).unwrap();
        atomic_write(Path::new("bare.state"), ".test-", b"payload").unwrap();
        remove_file(Path::new("bare.state")).unwrap();
        drop(restore);
        assert!(!d.join("bare.state").exists());
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
