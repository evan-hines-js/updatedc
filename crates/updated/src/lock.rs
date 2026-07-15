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
        let dir = std::env::temp_dir().join(format!("lock-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("x.lock");
        let first = InstanceLock::acquire(&path).unwrap();
        assert!(InstanceLock::acquire(&path).is_err());
        drop(first);
        assert!(InstanceLock::acquire(&path).is_ok());
        let _ = std::fs::remove_dir_all(dir);
    }
}
