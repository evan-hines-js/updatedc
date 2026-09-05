//! Single-instance advisory lock for an installation transaction.
//!
//! `File::try_lock` maps to the platform lock primitive. The OS releases the lock
//! when the handle is dropped or the owning process exits.

use std::fs::{File, TryLockError};
use std::io;
use std::path::Path;

/// Holds the installation lock for as long as it is alive.
pub struct InstanceLock {
    _file: File,
}

impl InstanceLock {
    /// Acquire an exclusive, non-blocking lock, creating its file if needed.
    pub fn acquire(path: &Path) -> io::Result<Self> {
        std::fs::create_dir_all(foundation::durable::parent_dir(path))?;
        let file = foundation::file::open_lock_file(
            path,
            foundation::file::LockFileDisposition::OpenOrCreate,
        )?;
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

impl Drop for InstanceLock {
    fn drop(&mut self) {
        // Release explicitly: a concurrent fork may briefly inherit the open description.
        let _ = self._file.unlock();
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
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

    #[cfg(unix)]
    #[test]
    fn a_lock_path_can_never_redirect_locking_to_another_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("unrelated");
        let path = dir.path().join("x.lock");
        std::fs::write(&target, b"unrelated state").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();

        assert_eq!(
            InstanceLock::acquire(&path).err().unwrap().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(std::fs::read(target).unwrap(), b"unrelated state");
    }
}
