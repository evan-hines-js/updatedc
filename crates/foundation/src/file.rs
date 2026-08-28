//! Small filesystem primitives whose security properties must not drift between binaries.

use std::{
    fs::{self, File, OpenOptions},
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

/// How the single lock-file opener treats an occupied or absent name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockFileDisposition {
    /// The lease must already exist; absence is an error.
    OpenExisting,
    /// The caller is publishing a fresh lease; any occupied name is an error.
    CreateNew,
    /// A long-lived instance lock survives process restarts, so create it once or reopen it.
    OpenOrCreate,
}

/// Whether a directory entry occupies `path`, without following its final symlink/reparse point.
///
/// [`Path::try_exists`] answers whether the *target* exists. That is the wrong question for trust
/// anchors, one-way markers, durable identities, and exclusive destinations: a dangling symlink
/// still occupies the name and must fail closed rather than silently turning configured state into
/// absence. Every security-sensitive presence decision goes through this primitive so that policy
/// cannot drift between platforms or callers.
pub fn path_entry_exists(path: &Path) -> io::Result<bool> {
    match path.symlink_metadata() {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

/// Open one regular file under an explicit final-symlink policy.
///
/// Callers that need streaming rather than collection use this handle directly; bounded in-memory
/// readers below build on the same primitive, so type/symlink policy cannot drift by payload size.
pub fn open_regular(path: &Path, final_symlink: FinalSymlink) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);

    open_regular_with_options(path, final_symlink, options)
}

/// Open one regular file and prove the opened handle remains confined beneath `root`.
///
/// Refusing only a final symlink does not stop an attacker from replacing an ancestor directory.
/// Conversely, canonicalizing before opening leaves a replacement race. This operation opens
/// first, canonicalizes afterward, and requires the canonical path to remain below the canonical
/// root *and* name the same file as the already-open handle. Callers choose whether a stable final
/// symlink inside the root is part of their contract.
pub fn open_regular_beneath(
    root: &Path,
    path: &Path,
    final_symlink: FinalSymlink,
) -> io::Result<File> {
    let file = open_regular(path, final_symlink)?;
    let canonical_root = fs::canonicalize(root)?;
    if !canonical_root.metadata()?.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "confinement root is not a directory",
        ));
    }
    let canonical_path = fs::canonicalize(path)?;
    if !canonical_path.starts_with(&canonical_root) || !same_named_file(&file, &canonical_path)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "opened file is outside its confinement root",
        ));
    }
    Ok(file)
}

#[cfg(unix)]
fn same_named_file(file: &File, path: &Path) -> io::Result<bool> {
    use std::os::unix::fs::MetadataExt as _;

    let opened = file.metadata()?;
    let named = path.metadata()?;
    Ok(opened.dev() == named.dev() && opened.ino() == named.ino())
}

#[cfg(windows)]
fn same_named_file(file: &File, path: &Path) -> io::Result<bool> {
    let named = open_regular(path, FinalSymlink::Follow)?;
    Ok(windows_file_identity(file)? == windows_file_identity(&named)?)
}

#[cfg(windows)]
fn windows_file_identity(file: &File) -> io::Result<(u32, u64)> {
    use std::os::windows::io::AsRawHandle as _;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut information = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
    // SAFETY: `file` owns a live handle for the duration of the call, and the output points to
    // writable storage for the exact structure Windows fills on success.
    let succeeded =
        unsafe { GetFileInformationByHandle(file.as_raw_handle() as _, information.as_mut_ptr()) };
    if succeeded == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful call initialized the complete structure.
    let information = unsafe { information.assume_init() };
    Ok((
        information.dwVolumeSerialNumber,
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow),
    ))
}

#[cfg(not(any(unix, windows)))]
fn same_named_file(_file: &File, _path: &Path) -> io::Result<bool> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "confined file identity is unsupported on this platform",
    ))
}

/// Open a regular lock file for reading and writing without following its final path component.
///
/// Locking a symlink target is still an externally visible privileged side effect even when no
/// bytes are written. Instance locks and temporary-directory leases therefore share this one
/// opener, including its handle-based regular-file check and Windows reparse-point refusal.
pub fn open_lock_file(path: &Path, disposition: LockFileDisposition) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).truncate(false);
    match disposition {
        LockFileDisposition::OpenExisting => {}
        LockFileDisposition::CreateNew => {
            options.create_new(true);
        }
        LockFileDisposition::OpenOrCreate => {
            options.create(true);
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    open_regular_with_options(path, FinalSymlink::Refuse, options)
}

/// Open one regular append-only record without following its final path component.
///
/// Append-only journals and process output files must not turn a planted symlink into writes
/// through an unrelated path. Append semantics and the regular/no-follow proof are established on
/// the same handle, avoiding the replacement race created by checking path metadata before a
/// separate open.
pub fn open_append_file(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    open_regular_with_options(path, FinalSymlink::Refuse, options)
}

/// Apply the final-component policy and regular-file proof to one configured open operation.
/// Reads and advisory-lock handles deliberately converge here so neither platform grows a second
/// interpretation of "refuse a symlink."
fn open_regular_with_options(
    path: &Path,
    final_symlink: FinalSymlink,
    mut options: OpenOptions,
) -> io::Result<File> {
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
        // Windows rejects an ordinary file open on a directory with ACCESS_DENIED before we can
        // inspect the returned handle. BACKUP_SEMANTICS is the documented flag that permits the
        // open; the handle-based `metadata().is_file()` check below then classifies the directory
        // as InvalidData, exactly as Unix does. This matters to every caller that distinguishes a
        // malformed path entry from a genuine permission failure. It does not relax the regular-
        // file invariant: no handle is returned until the common check below accepts it.
        let mut flags = windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;
        if final_symlink == FinalSymlink::Refuse {
            flags |= windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
        }
        options.custom_flags(flags);
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
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::io::Write as _;

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

    #[test]
    fn confined_opens_prove_the_opened_handle_is_beneath_the_root() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("root");
        let nested = root.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        let file = nested.join("file");
        std::fs::write(&file, b"inside").unwrap();
        assert!(open_regular_beneath(&root, &file, FinalSymlink::Refuse).is_ok());

        #[cfg(unix)]
        {
            let outside = directory.path().join("outside");
            std::fs::create_dir(&outside).unwrap();
            std::fs::write(outside.join("file"), b"outside").unwrap();
            let redirected_parent = root.join("redirected-parent");
            std::os::unix::fs::symlink(&outside, &redirected_parent).unwrap();
            assert_eq!(
                open_regular_beneath(&root, &redirected_parent.join("file"), FinalSymlink::Refuse,)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );

            let inside_link = root.join("inside-link");
            std::os::unix::fs::symlink(&file, &inside_link).unwrap();
            assert!(open_regular_beneath(&root, &inside_link, FinalSymlink::Follow).is_ok());
            assert!(open_regular_beneath(&root, &inside_link, FinalSymlink::Refuse).is_err());
        }
    }

    #[test]
    fn entry_presence_never_follows_the_final_symlink() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("file");
        let absent = directory.path().join("absent");
        std::fs::write(&file, b"present").unwrap();

        assert!(path_entry_exists(&file).unwrap());
        assert!(!path_entry_exists(&absent).unwrap());

        #[cfg(unix)]
        {
            let dangling = directory.path().join("dangling");
            std::os::unix::fs::symlink(&absent, &dangling).unwrap();
            assert!(path_entry_exists(&dangling).unwrap());
            assert!(!dangling.try_exists().unwrap());
        }
    }

    #[test]
    fn every_lock_disposition_uses_the_same_regular_no_follow_gate() {
        let directory = tempfile::tempdir().unwrap();
        let lock = directory.path().join("state.lock");

        assert_eq!(
            open_lock_file(&lock, LockFileDisposition::OpenExisting)
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
        drop(open_lock_file(&lock, LockFileDisposition::CreateNew).unwrap());
        assert!(open_lock_file(&lock, LockFileDisposition::OpenOrCreate).is_ok());
        assert_eq!(
            open_lock_file(&lock, LockFileDisposition::CreateNew)
                .unwrap_err()
                .kind(),
            io::ErrorKind::AlreadyExists
        );

        #[cfg(unix)]
        {
            let target = directory.path().join("target");
            let redirect = directory.path().join("redirect.lock");
            std::fs::write(&target, b"must not become the lock").unwrap();
            std::os::unix::fs::symlink(&target, &redirect).unwrap();
            assert_eq!(
                open_lock_file(&redirect, LockFileDisposition::OpenOrCreate)
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(std::fs::read(target).unwrap(), b"must not become the lock");
        }
    }

    #[test]
    fn append_files_use_the_same_regular_no_follow_gate() {
        let directory = tempfile::tempdir().unwrap();
        let journal = directory.path().join("journal.jsonl");
        let mut first = open_append_file(&journal).unwrap();
        first.write_all(b"first\n").unwrap();
        drop(first);
        let mut second = open_append_file(&journal).unwrap();
        second.write_all(b"second\n").unwrap();
        drop(second);
        assert_eq!(std::fs::read(&journal).unwrap(), b"first\nsecond\n");

        assert!(
            open_append_file(directory.path()).is_err(),
            "a directory can never become an append record"
        );

        #[cfg(unix)]
        {
            let target = directory.path().join("target");
            let redirect = directory.path().join("redirect.jsonl");
            std::fs::write(&target, b"ordinary state").unwrap();
            std::os::unix::fs::symlink(&target, &redirect).unwrap();
            assert_eq!(
                open_append_file(&redirect).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(std::fs::read(target).unwrap(), b"ordinary state");
        }
    }
}
