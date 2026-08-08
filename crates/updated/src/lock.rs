//! Single-instance advisory lock for an installation transaction.
//!
//! `File::try_lock` maps to the platform lock primitive. The OS releases the lock
//! when the handle is dropped or the owning process exits.

use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::path::Path;

/// Holds the installation lock for as long as it is alive.
pub struct InstanceLock {
    _file: File,
}

impl InstanceLock {
    /// Acquire an exclusive, non-blocking lock, creating its file if needed.
    pub fn acquire(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
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
            Err(TryLockError::Error(error)) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_owner_at_a_time() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.lock");
        let first = InstanceLock::acquire(&path).unwrap();
        assert!(InstanceLock::acquire(&path).is_err());
        drop(first);
        assert!(InstanceLock::acquire(&path).is_ok());
    }

    #[test]
    fn creates_the_lock_parent_for_a_cold_install() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing/state/installed.json.lock");
        let lock = InstanceLock::acquire(&path).unwrap();
        assert!(path.is_file());
        drop(lock);
    }
}
