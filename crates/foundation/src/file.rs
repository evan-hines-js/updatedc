//! Small filesystem primitives whose security properties must not drift between binaries.

use std::{
    fs::{File, OpenOptions},
    io::{self, Read as _},
    path::Path,
};

/// Whether the final path component may be a symlink/reparse point.
///
/// Mounted Kubernetes Secret and ConfigMap keys are symlinks by construction, while durable state
/// records and application outputs must never redirect their reader. Making the distinction an
/// argument to the one reader keeps both policies explicit without duplicating the bounded-read
/// mechanism.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FinalSymlink {
    Follow,
    Refuse,
}

/// Open one regular file under an explicit final-symlink policy.
///
/// Callers that need streaming rather than collection use this handle directly; bounded in-memory
/// readers below build on the same primitive, so type/symlink policy cannot drift by payload size.
pub fn open_regular(path: &Path, final_symlink: FinalSymlink) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let no_follow = match final_symlink {
            FinalSymlink::Follow => 0,
            FinalSymlink::Refuse => libc::O_NOFOLLOW,
        };
        options.custom_flags(libc::O_CLOEXEC | no_follow);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        if final_symlink == FinalSymlink::Refuse {
            options.custom_flags(
                windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
            );
        }
    }

    let opened = options.open(path);
    // The `cfg` is on the whole mapping, not on a branch inside it. With it inside, Windows built
    // `map_err(|error| error)` — an identity closure that `-D warnings` rejects, so this file only
    // compiled on the platform it was written on. `ELOOP` is the Unix answer to a final symlink;
    // Windows refuses one through `FILE_FLAG_OPEN_REPARSE_POINT` and the reparse-point check below.
    #[cfg(unix)]
    let opened = opened.map_err(|error| {
        if error.raw_os_error() == Some(libc::ELOOP) {
            return io::Error::new(
                io::ErrorKind::InvalidData,
                "path resolves through a symbolic link",
            );
        }
        error
    });
    let file = opened?;
    let metadata = file.metadata()?;
    #[cfg(windows)]
    let is_reparse_point = {
        use std::os::windows::fs::MetadataExt as _;
        metadata.file_attributes()
            & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
            != 0
    };
    #[cfg(not(windows))]
    let is_reparse_point = false;
    if !metadata.is_file() || (final_symlink == FinalSymlink::Refuse && is_reparse_point) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "path does not resolve to a regular file",
        ));
    }
    Ok(file)
}

/// Read at most `limit` bytes from one opened regular file under an explicit final-symlink policy.
///
/// The no-follow open, regular-file check, and bounded read are one operation on one handle.
/// Checking path metadata before a separate read would leave a replacement race, while an
/// unbounded convenience read would let a growing local file consume arbitrary memory.
pub fn read_bounded_regular(
    path: &Path,
    limit: usize,
    final_symlink: FinalSymlink,
) -> io::Result<Vec<u8>> {
    let mut file = open_regular(path, final_symlink)?;
    read_opened_bounded(&mut file, limit)
}

/// Read a node-owned private file from one no-follow handle and require owner-only access.
///
/// This is the signing/private-key variant of [`read_bounded_regular`]. On Unix an owner-readable
/// file with any group/world permission is rejected. Windows callers still get the regular-file,
/// no-reparse, bounded-handle guarantees; ACL construction is owned by
/// `durable::create_private_new`, because std does not expose a stable ACL inspection API.
pub fn read_bounded_private_regular(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    let mut file = open_regular(path, FinalSymlink::Refuse)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let metadata = file.metadata()?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o077 != 0 || mode & 0o400 == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("private file must be owner-readable with no group/world access, found mode {mode:04o}"),
            ));
        }
        // A root-run service can read a 0400 file owned by a different account. Treat that as
        // ownership drift, not as permission to adopt someone else's secret.
        let effective_uid = unsafe { libc::geteuid() };
        if metadata.uid() != effective_uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private file must be owned by the current process identity",
            ));
        }
    }
    read_opened_bounded(&mut file, limit)
}

/// UTF-8 form of [`read_bounded_private_regular`], retaining the same handle, size, mode, and
/// no-follow guarantees.
pub fn read_bounded_private_regular_string(path: &Path, limit: usize) -> io::Result<String> {
    String::from_utf8(read_bounded_private_regular(path, limit)?).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "bounded private regular file is not valid UTF-8",
        )
    })
}

/// Collect at most `limit` bytes from one already-open regular file.
///
/// This is public for verified-download handles: the caller keeps the exact inode TUF checked,
/// instead of closing it and reopening a pathname that another process could replace.
pub fn read_opened_bounded(file: &mut File, limit: usize) -> io::Result<Vec<u8>> {
    let read_limit = limit
        .checked_add(1)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file limit is too large"))?;

    let mut bytes = Vec::new();
    file.take(read_limit as u64).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file exceeds its size limit",
        ));
    }
    Ok(bytes)
}

/// UTF-8 form of [`read_bounded_regular`], retaining the same handle, size, and symlink policy.
pub fn read_bounded_regular_string(
    path: &Path,
    limit: usize,
    final_symlink: FinalSymlink,
) -> io::Result<String> {
    String::from_utf8(read_bounded_regular(path, limit, final_symlink)?).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "bounded regular file is not valid UTF-8",
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_opened_regular_file_only_within_the_limit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("value");
        std::fs::write(&path, b"bounded").unwrap();

        assert_eq!(
            read_bounded_regular(&path, 7, FinalSymlink::Refuse).unwrap(),
            b"bounded"
        );
        assert_eq!(
            read_bounded_regular(&path, 6, FinalSymlink::Refuse)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            read_bounded_regular(directory.path(), 1024, FinalSymlink::Refuse)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );

        std::fs::write(&path, [0xff]).unwrap();
        assert_eq!(
            read_bounded_regular_string(&path, 1, FinalSymlink::Refuse)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        std::fs::write(&path, b"bounded").unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(read_bounded_private_regular(&path, 7).unwrap(), b"bounded");
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
            assert_eq!(
                read_bounded_private_regular(&path, 7).unwrap_err().kind(),
                io::ErrorKind::PermissionDenied
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }

        std::fs::write(&path, [0xff]).unwrap();
        assert_eq!(
            read_bounded_private_regular_string(&path, 1)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
        std::fs::write(&path, b"bounded").unwrap();

        #[cfg(unix)]
        {
            let link = directory.path().join("link");
            std::os::unix::fs::symlink(&path, &link).unwrap();
            assert_eq!(
                read_bounded_regular(&link, 1024, FinalSymlink::Follow).unwrap(),
                b"bounded"
            );
            assert_eq!(
                read_bounded_regular(&link, 1024, FinalSymlink::Refuse)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
    }
}
