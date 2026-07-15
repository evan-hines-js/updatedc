//! Single-instance advisory lock for an installation transaction.
//!
//! One portable path via the standard-library file lock (`File::try_lock`, stable
//! since 1.89) — `flock` on Unix, `LockFileEx` on Windows — rather than hand-rolled
//! `flock`/`CreateFileW` FFI. The OS releases the lock when the owning handle is
//! dropped, or unconditionally when the process exits or crashes.

use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::path::Path;

/// Holds the lock for as long as it is alive.
pub struct InstanceLock {
    _file: File,
}

impl InstanceLock {
    /// Acquire an exclusive, non-blocking lock on `path`, creating it if needed.
    /// Errors with [`io::ErrorKind::WouldBlock`] if another live process holds it.
    pub fn acquire(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        match file.try_lock() {
            Ok(()) => Ok(Self { _file: file }),
            Err(TryLockError::WouldBlock) => Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("another instance already owns {}", path.display()),
            )),
            Err(TryLockError::Error(e)) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_owner_at_a_time() {
        let dir = std::env::temp_dir().join(format!("lock-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("x.lock");

        let first = InstanceLock::acquire(&path).unwrap();
        assert!(
            InstanceLock::acquire(&path).is_err(),
            "second acquire must fail"
        );
        drop(first);
        assert!(
            InstanceLock::acquire(&path).is_ok(),
            "released lock is reacquirable"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
