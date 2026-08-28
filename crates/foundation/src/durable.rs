//! Crash-safe sibling-file replacement and removal.

use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A temp file untouched for at least this long is an abandoned crash leftover, not one a
/// writer is mid-way through — [`sweep_stale_temps`] leaves anything newer alone so it can
/// be called at any time without racing an in-flight [`atomic_write`].
const STALE_TEMP_AGE: Duration = Duration::from_secs(60);

/// A staged directory carries this locked file for its entire active lifetime. Directory mtimes do
/// not change when an existing child grows, so age alone can never prove a directory abandoned.
pub const TEMP_DIRECTORY_LEASE_FILE: &str = ".updated-active.lock";

/// The prefix [`install_executable`] stages under, and the one it sweeps.
const EXECUTABLE_TEMP_PREFIX: &str = ".executable-";

/// One bounded policy for the short-lived sharing and executable-lock contention that can affect
/// durable rename and removal. Keeping the budget here prevents individual callers from drifting
/// into either an immediate restart loop or an unbounded wait.
const FILESYSTEM_CONTENTION_RETRIES: u32 = 50;

/// Who may read a durable file once it is committed. Every file this module creates commits to
/// exactly one of these at `open(2)`/`CreateFileW` time — permissions are never widened and then
/// narrowed, and no caller ever chmods (or `icacls`es) afterwards, which is the property that
/// makes "write it durably" a single operation rather than a write plus a repair.
///
/// The ladder is *who*, not *how much*: the writer alone, the principals the deployment's own
/// ACL names, or everybody.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Visibility {
    /// The writing account only. Secrets: an enrollment key, a minted TLS private key.
    Private,
    /// Whoever the containing directory's ACL grants. On Windows, managed files deliberately
    /// inherit the state directory's access rather than replacing it with a private DACL.
    Managed,
    /// Everybody. A signed repository artifact served to the whole fleet.
    Published,
}

/// Create a fresh, uniquely named temp file in `dir` that keeps the access its directory
/// confers: on Windows the directory's inheritable ACEs apply; on unix it is `0o600`.
/// Every file under the node state directory that is not a secret goes through here: with a
/// protected DACL, a state file written by an elevated operator CLI or an installer step would
/// commit without the directory's intended inherited access.
///
/// There is deliberately no owner-only *temp* counterpart to this: a secret is never streamed
/// here — it is always one in-memory buffer — so [`atomic_write`] and [`create_private_new`] are
/// the only doors to [`Visibility::Private`], and both go through the same [`create`].
pub fn create_temp_managed(dir: &Path, prefix: &str) -> io::Result<(File, PathBuf)> {
    create_temp_with(dir, prefix, |path| create(path, Visibility::Managed))
}

/// Create `path` exclusively, readable by **the writing account alone** on every platform
/// (`0o600` at `open(2)` on unix, an explicit protected DACL passed to `CreateFileW` on Windows),
/// failing if it already exists.
///
/// This is [`atomic_write`]'s permission guarantee for the one shape that write cannot serve: a
/// secret whose *creation* must be the exclusion — a signing key that may be minted only if the
/// node does not already hold one, where a rename-over would silently replace the existing key
/// instead of refusing. The caller owns writing, syncing, and cleaning up a partial file; what it
/// must not own is the permissions, which is why this exists rather than a second
/// `OpenOptions` call site that has to keep the Windows descriptor in step by hand.
pub fn create_private_new(path: &Path) -> io::Result<File> {
    create(path, Visibility::Private)
}

/// Create `path` exclusively as an owner-only directory on every supported platform.
///
/// Plaintext exchanges use directories as their first access-control boundary: a reconciler
/// creates output files itself, so protecting only files the agent creates would leave those
/// outputs readable through an inherited `%ProgramData%` ACL on Windows. Like
/// [`create_private_new`], this applies the final policy at creation time—`0o700` on Unix and a
/// protected owner/SYSTEM/Administrators DACL with private child inheritance on Windows.
pub fn create_private_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(path)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt as _;
        use windows_sys::Win32::Storage::FileSystem::CreateDirectoryW;

        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        let (created, error) = with_owner_only_security(true, |attributes| unsafe {
            CreateDirectoryW(wide.as_ptr(), attributes)
        })?;
        if created == 0 {
            Err(error)
        } else {
            Ok(())
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        fs::create_dir(path)
    }
}

/// [`create_temp_managed`], but world-readable (`0o644` on unix; the directory's ACL on Windows) at
/// creation — for a signed repository object that the whole fleet fetches. The mode is set when
/// the file is created rather than repaired before the rename, so it is identical on the platform
/// where `set_permissions` is a no-op.
pub fn create_temp_published(dir: &Path, prefix: &str) -> io::Result<(File, PathBuf)> {
    create_temp_with(dir, prefix, |path| create(path, Visibility::Published))
}

#[cfg(unix)]
fn create(path: &Path, visibility: Visibility) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    let mode = match visibility {
        // The state directory's own ACL is a Windows concept; on unix a managed file is as
        // private as a secret, because only the privileged runtime is inside that tree.
        Visibility::Private | Visibility::Managed => 0o600,
        Visibility::Published => 0o644,
    };
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
}

/// Windows has no `mode`, and a file created without an explicit security descriptor INHERITS
/// its directory's ACL — the standard install location (`%ProgramData%\updated`) grants
/// `BUILTIN\Users` read, and `icacls /grant` in the installer only adds to that. Setting the
/// DACL after the fact would still leave a window in which any local user could open a handle
/// and read whatever is written through it afterwards, so for a [`Visibility::Private`] file the
/// descriptor is supplied at creation: it is never, at any instant, readable by anyone else.
/// `Managed` and `Published` files deliberately take the inherited ACL — that inheritance is how
/// the deployment preserves the state directory's intended access.
#[cfg(windows)]
fn create(path: &Path, visibility: Visibility) -> io::Result<File> {
    if visibility != Visibility::Private {
        return fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path);
    }
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::FromRawHandle;
    use windows_sys::Win32::Foundation::{GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };

    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let (handle, error) = with_owner_only_security(false, |attributes| unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    })?;
    if handle == INVALID_HANDLE_VALUE {
        Err(error)
    } else {
        // SAFETY: a successful `CreateFileW` returned an owned file handle, transferred exactly
        // once to `File` so Rust closes it.
        unsafe { Ok(File::from_raw_handle(handle as _)) }
    }
}

/// Call one Windows creation primitive with the protected owner-only security descriptor.
///
/// Full access goes to the owner, SYSTEM, and local Administrators, and nobody else. `P` protects
/// the DACL from inheriting the parent directory's entries. A private directory additionally makes
/// those same SYSTEM/Administrators ACEs object- and container-inheritable and adds an inherit-only
/// CREATOR OWNER ACE: files a reconciler creates for itself must grant their actual creator—not the
/// directory's original owner-rights pseudo-SID—and must not fall back to the process token's
/// default DACL. Both private files and private directories use this function so their principals
/// cannot drift.
#[cfg(windows)]
fn with_owner_only_security<T>(
    inheritable: bool,
    operation: impl FnOnce(*const windows_sys::Win32::Security::SECURITY_ATTRIBUTES) -> T,
) -> io::Result<(T, io::Error)> {
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;

    const OWNER_ONLY_SDDL: &str = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)";
    const OWNER_ONLY_INHERITABLE_SDDL: &str =
        "D:P(A;;FA;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;FA;;;CO)";
    let policy = if inheritable {
        OWNER_ONLY_INHERITABLE_SDDL
    } else {
        OWNER_ONLY_SDDL
    };
    let sddl: Vec<u16> = policy.encode_utf16().chain(Some(0)).collect();
    // SAFETY: `sddl` is live and NUL-terminated, the converted descriptor remains live through the
    // synchronous callback, and `LocalFree` releases it on every callback outcome.
    unsafe {
        let mut descriptor = std::ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let result = operation(&attributes);
        // Capture the creation error before `LocalFree` can overwrite it.
        let error = io::Error::last_os_error();
        LocalFree(descriptor as _);
        Ok((result, error))
    }
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

/// Durably replace `path` with `data`, readable by **the writing account alone** on every
/// platform (`0o600` at `open(2)` on unix, an explicit protected DACL passed to `CreateFileW` on
/// Windows): write a fresh sibling temp, fsync it, rename it into place,
/// then fsync the directory. The committed file inherits the temp's permissions, so callers never
/// chmod afterwards. This is the write secrets go through — an enrollment key, a minted TLS
/// private key.
///
/// `Err` means the file at `path` still holds its old content — except for the one failure that
/// happens after the rename, which says so ([`committed_unsynced`]).
///
/// Use [`atomic_write_managed`] for a non-secret file under the node's state directory.
pub fn atomic_write(path: &Path, prefix: &str, data: &[u8]) -> io::Result<()> {
    durable_write(path, prefix, data, Visibility::Private)
}

/// [`atomic_write`] for a non-secret file under the node's state directory: identical durability,
/// but the committed file keeps whatever access its directory confers (on Windows the deployment's
/// inheritable directory ACL; on unix still `0o600`). An agent pointer, a
/// launcher marker, a journal — anything a differently-privileged principal may legitimately have
/// to read or replace later.
pub fn atomic_write_managed(path: &Path, prefix: &str, data: &[u8]) -> io::Result<()> {
    durable_write(path, prefix, data, Visibility::Managed)
}

fn durable_write(path: &Path, prefix: &str, data: &[u8], visibility: Visibility) -> io::Result<()> {
    let dir = parent_dir(path);
    let (mut tmp, tmp_path) = create_temp_with(dir, prefix, |p| create(p, visibility))?;
    if let Err(e) = tmp.write_all(data).and_then(|_| tmp.sync_all()) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    drop(tmp);
    if let Err(e) = replace(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    sync_dir(dir).map_err(unsynced)
}

/// The failure of the directory fsync that follows an already-visible rename or unlink — the
/// one failure mode of these primitives where the effect landed anyway.
///
/// It is wrapped rather than returned bare so the two facts a caller needs — "the change is
/// there" and "its survival across a power loss is unproven" — travel in one `io::Result`
/// instead of forcing a second return type on every durable primitive and every caller of one.
/// [`committed_unsynced`] is how a caller asks.
///
/// The wrapped error is this type's `source`, and `io::Error`'s own `source` forwards to it, so
/// the original — **raw OS code included** — stays one `Error::source()` hop from the returned
/// error. That reachability is load-bearing: a `std::io::Error` carrying a payload cannot also
/// carry a raw code (the two are alternative representations), and a caller that classifies a
/// fault by its raw code rather than by `ErrorKind` — an fsync `EIO`, which has no `ErrorKind`
/// of its own — has nowhere else to read it from.
#[derive(Debug)]
struct Unsynced(io::Error);

impl std::fmt::Display for Unsynced {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (the change is already visible, not yet durable)",
            self.0
        )
    }
}

impl std::error::Error for Unsynced {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// Tag a post-commit failure, keeping the underlying `ErrorKind` so a caller that only matches
/// on the kind (`NotFound`, `PermissionDenied`, …) is unaffected by the wrapping, and keeping the
/// underlying error itself reachable as the returned error's `source` so a caller that classifies
/// by raw OS code (`EIO`, which arrives as an unmatchable `ErrorKind`) still finds it. Attaching a
/// payload to an `io::Error` necessarily replaces its raw-code representation, so the source hop
/// is the only place that code can live — see [`Unsynced`].
fn unsynced(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), Unsynced(error))
}

/// Whether `error` reports an operation whose effect ALREADY LANDED and that failed only to
/// prove that effect durable: the rename or unlink is visible to every reader, and the
/// directory fsync behind it is what failed (`EMFILE`, an fsync `EIO`).
///
/// The distinction exists for callers that undo their own state when a durable write fails.
/// The launcher rolls its committed-agent pointer back to the predecessor and records the
/// candidate rejected — which, for a pointer that actually moved, would leave a rejection
/// marker about the very binary the next boot launches as the committed agent. Every other
/// caller is right to treat this as the plain failure it also is.
pub fn committed_unsynced(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|inner| inner.is::<Unsynced>())
}

/// Copy a verified executable into a fresh sibling file, persist its final mode, and atomically
/// install it at `target`. A staged binary is not a secret: it is [`Visibility::Managed`], so on
/// Windows the state directory's inherited access still reaches it and a candidate staged by an
/// elevated installer step remains launchable by the service.
pub fn install_executable(target: &Path, source: &Path) -> io::Result<()> {
    let mut source = crate::file::open_regular(source, crate::file::FinalSymlink::Refuse)?;
    install_executable_from(target, &mut source)
}

/// Install an executable from one already-open, verified file handle.
///
/// TUF callers use this form so the bytes copied into the executable are read from the same inode
/// whose signed length and digest were checked, with no pathname reopen between verification and
/// activation.
pub fn install_executable_from(target: &Path, source: &mut File) -> io::Result<()> {
    use std::io::Seek as _;

    source.rewind()?;
    let dir = parent_dir(target);
    // Reap the leftover an earlier crash between the copy and the rename would have left HERE.
    // The prefix is private to this function, so no caller could ever sweep it; staging directories
    // are content-addressed and re-entered on every retry of the same candidate, so without this
    // the orphans accumulate one per crash and nothing prunes them.
    sweep_stale_temps(dir, EXECUTABLE_TEMP_PREFIX);
    let (mut tmp, tmp_path) = create_temp_managed(dir, EXECUTABLE_TEMP_PREFIX)?;
    let staged = io::copy(source, &mut tmp).and_then(|_| tmp.sync_all());
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
    sync_dir(dir).map_err(unsynced)?;
    // Also persist the directory entry OF `dir` itself. Executables are installed into a freshly
    // created content-addressed directory, and syncing only that directory leaves its own name
    // unpersisted in the parent: after a power loss the file is durable but the path to it is not,
    // so a committed pointer resolves to nothing. One extra fsync per install closes that.
    match dir.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => sync_dir(parent).map_err(unsynced),
        _ => Ok(()),
    }
}

/// Best-effort removal of stale staging leftovers — the ONE sweeper for every
/// `<prefix>…-….tmp` orphan this workspace can leave behind when a crash or power loss strikes
/// between staging and the rename that commits it: an [`atomic_write`], an [`install_executable`],
/// a bare [`create_temp_managed`], or a staged *directory* such as a signed metadata generation.
///
/// Sweeps `dir` for entries whose name starts with `prefix` and ends with `.tmp`, removing only
/// those whose age is known to have reached [`STALE_TEMP_AGE`]. Files are unlinked; directories are
/// removed whole, since a `.tmp` directory under a staging prefix is a half-built stage and nothing
/// else. Anything newer, and anything whose age cannot be determined, is spared, so a stage an
/// in-flight writer still owns is never yanked.
///
/// Purely hygiene: a directory-read or removal failure is ignored (a stray stage is inert —
/// the sequence/pid/nanos naming means it can never collide with a real committed path),
/// so this returns the count removed rather than a `Result`.
pub fn sweep_stale_temps(dir: &Path, prefix: &str) -> usize {
    let now = SystemTime::now();
    let Ok(entries) = fs::read_dir(dir) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(prefix) || !name.ends_with(".tmp") {
            continue;
        }
        // Only a *known* age past the threshold proves abandonment. An unreadable mtime, or
        // one in the future because the clock stepped backwards under an in-flight writer,
        // leaves the age unknown — spare the stage rather than yank one someone still owns.
        // A spared orphan is inert and the next sweep, once the clock settles, reaps it.
        let provably_stale = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age >= STALE_TEMP_AGE);
        if !provably_stale {
            continue;
        }
        let path = entry.path();
        let gone = if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            // A directory mtime records entry creation/removal, not writes to an existing child.
            // Require the stage's ownership lock as independent proof: WouldBlock means a live
            // writer, and a missing/unreadable ownership marker proves no abandonment, so we
            // safely spare it.
            let Some(_lease) = abandoned_temp_directory_lease(&path) else {
                continue;
            };
            fs::remove_dir_all(&path).is_ok()
        } else {
            fs::remove_file(&path).is_ok()
        };
        if gone {
            removed += 1;
        }
    }
    removed
}

/// Hold this value for the complete lifetime of a staged directory. Closing its file releases the
/// OS lock even after a crash; a later sweeper can then prove that no process owns the stage.
pub struct TempDirectoryLease {
    _file: File,
}

/// Mark a newly-created staged directory as actively owned.
pub fn lease_temp_directory(path: &Path) -> io::Result<TempDirectoryLease> {
    let file = crate::file::open_lock_file(
        &path.join(TEMP_DIRECTORY_LEASE_FILE),
        crate::file::LockFileDisposition::CreateNew,
    )?;
    file.lock()?;
    Ok(TempDirectoryLease { _file: file })
}

fn abandoned_temp_directory_lease(path: &Path) -> Option<File> {
    let file = crate::file::open_lock_file(
        &path.join(TEMP_DIRECTORY_LEASE_FILE),
        crate::file::LockFileDisposition::OpenExisting,
    )
    .ok()?;
    match file.try_lock() {
        Ok(()) => Some(file),
        Err(fs::TryLockError::WouldBlock | fs::TryLockError::Error(_)) => None,
    }
}

/// Durably unlink a file this tower wrote: the removal is persisted (the parent directory is
/// synced) before this returns, so a power loss cannot resurrect it. Removing something that is
/// already gone is success. The path must be a file — use [`remove_path`] for a path whose shape
/// is not ours to assume.
pub fn remove_file(path: &Path) -> io::Result<()> {
    let removed = retry_filesystem_contention(|| match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    })?;
    if !removed {
        return Ok(());
    }
    sync_dir(parent_dir(path)).map_err(unsynced)
}

/// Durably remove *whatever* is at `path` — a file, a symlink, or a whole directory tree — for
/// the one situation [`remove_file`] cannot serve: clearing garbage at a path this tower expects
/// to own but did not write, where anything at all may be sitting (an operator's stray `mkdir`,
/// a half-restored backup). `remove_file` would fail on a directory on every platform, which
/// turns "discard the garbage and carry on" into a warning repeated on every boot forever.
///
/// A symlink is removed as the link, never followed, so this can never delete a tree the link
/// merely pointed at. Removing something that is already gone is success.
pub fn remove_path(path: &Path) -> io::Result<()> {
    let removed = retry_filesystem_contention(|| match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => fs::remove_dir_all(path).map(|()| true),
        Ok(_) => match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    })?;
    if !removed {
        return Ok(());
    }
    sync_dir(parent_dir(path)).map_err(unsynced)
}

/// Replace `to` with `from`, tolerating the short-lived executable/file locks seen
/// during process teardown and antivirus scanning. Permanent errors surface at once.
pub fn replace(from: &Path, to: &Path) -> io::Result<()> {
    retry_filesystem_contention(|| fs::rename(from, to))
}

fn retry_filesystem_contention<T>(mut operation: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    let mut attempt = 0u32;
    loop {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error)
                if attempt < FILESYSTEM_CONTENTION_RETRIES
                    && is_transient_filesystem_contention(&error) =>
            {
                attempt += 1;
                std::thread::sleep(Duration::from_millis((20 * u64::from(attempt)).min(100)));
            }
            Err(error) => return Err(error),
        }
    }
}

/// Whether an OS error is the platform's answer to temporary filesystem contention.
///
/// This is the one raw-code policy shared by durable replacement and higher-level recovery.
/// Windows reports an incompatible open as any of ACCESS_DENIED, SHARING_VIOLATION, or
/// LOCK_VIOLATION depending on the filesystem and which operation detects the held handle.
/// Classifying ACCESS_DENIED here does not grant access or suppress a failure: every caller bounds
/// its retries and ultimately returns the original error if the denial is a permanent ACL issue.
pub fn is_transient_filesystem_contention(error: &io::Error) -> bool {
    match error.raw_os_error() {
        #[cfg(windows)]
        Some(5) | Some(32) | Some(33) => true,
        #[cfg(unix)]
        Some(16) | Some(26) => true,
        _ => false,
    }
}

/// fsync the file at `path` — the durable primitive for bytes some *earlier* step wrote and
/// closed, where the writing handle is gone but the rename that publishes them has not happened
/// yet.
///
/// The handle is opened for **writing**, and that is the whole point of routing this through one
/// primitive: on Windows `FlushFileBuffers` — what `File::sync_all` calls — requires write access
/// on the handle, so the POSIX habit of `File::open(path)?.sync_all()` fails there with
/// `ERROR_ACCESS_DENIED` (os error 5) on a file the caller owns and can write. Reading is
/// requested alongside it so the mode says "an existing file", never a truncation.
///
/// The file must exist: this proves bytes durable, it never creates them.
pub fn sync_file(path: &Path) -> io::Result<()> {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?
        .sync_all()
}

/// fsync a directory's dirents, so a rename or unlink already visible in it survives a power loss.
///
/// Unix only, by nature: a directory handle cannot be opened for writing, and Windows has no
/// directory-flush call at all (its `CreateFileW` backup-semantics handle does not accept
/// `FlushFileBuffers`), so there the metadata is ordered by the filesystem itself and this is a
/// no-op rather than a failure.
pub fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(dir)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// fsync `dir` and every directory beneath it, deepest first. [`sync_dir`] only flushes a
/// single directory's dirents; a freshly extracted tree with nested subdirectories (e.g.
/// `bin/`, `lib/`) needs each of those directories flushed too, or a power loss right after
/// an atomic rename can surface the release with unpersisted nested dirents. Children are
/// synced before their parent so the parent's link is never durable ahead of its contents.
/// Symlinks are not followed; only real subdirectories are descended.
pub fn sync_tree(dir: &Path) -> io::Result<()> {
    let mut subdirs = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            subdirs.push(entry.path());
        }
    }
    for subdir in subdirs {
        sync_tree(&subdir)?;
    }
    sync_dir(dir)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn dir(name: &str) -> (tempfile::TempDir, PathBuf) {
        let guard = tempfile::tempdir().unwrap();
        let d = guard.path().join(name);
        fs::create_dir_all(&d).unwrap();
        (guard, d)
    }

    /// Proving already-written bytes durable must work on every platform this tower publishes
    /// from, and the open mode is what decides that: a read-only handle cannot be flushed on
    /// Windows, so the primitive owns the mode rather than each caller re-deriving it.
    #[test]
    fn sync_file_flushes_a_closed_file_and_reports_a_missing_one() {
        let (_guard, d) = dir("sync-file");
        let path = d.join("published.json");
        fs::write(&path, b"{\"signed\":1}").unwrap();
        sync_file(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"{\"signed\":1}");
        assert_eq!(
            sync_file(&d.join("never-written"))
                .expect_err("fsync cannot prove bytes that do not exist")
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[test]
    fn atomic_write_replaces_the_whole_file() {
        let (_guard, d) = dir("replace");
        let p = d.join("state");
        atomic_write(&p, ".test-", b"first").unwrap();
        atomic_write(&p, ".test-", b"second-longer").unwrap();
        assert_eq!(fs::read(p).unwrap(), b"second-longer");
    }

    #[cfg(windows)]
    #[test]
    fn windows_filesystem_contention_has_one_raw_code_policy() {
        use windows_sys::Win32::Foundation::{
            ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, ERROR_LOCK_VIOLATION,
            ERROR_SHARING_VIOLATION,
        };

        for code in [
            ERROR_ACCESS_DENIED,
            ERROR_SHARING_VIOLATION,
            ERROR_LOCK_VIOLATION,
        ] {
            assert!(is_transient_filesystem_contention(
                &io::Error::from_raw_os_error(code as i32)
            ));
        }
        assert!(!is_transient_filesystem_contention(
            &io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER as i32)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn a_failure_after_the_rename_reports_the_write_as_committed() {
        // The rename is already visible when the directory fsync runs, so reporting that failure
        // as a plain Err claims the old content is still there while the new content is what
        // every reader sees. The launcher rolls its agent pointer back to the predecessor
        // on a failed commit; rolling back a pointer that moved rejects the binary the next boot
        // launches as the committed agent.
        use std::os::unix::fs::PermissionsExt;
        let (_guard, d) = dir("unsynced");
        let p = d.join("pointer");
        atomic_write_managed(&p, ".test-", b"old").unwrap();
        // Write and search but not read: creating and renaming the temp still works, opening the
        // directory itself — which is all `sync_dir` does — cannot. Root bypasses the check, so
        // there is nothing to prove there.
        let root = unsafe { libc::geteuid() } == 0;
        fs::set_permissions(&d, PermissionsExt::from_mode(0o300)).unwrap();
        let outcome = atomic_write_managed(&p, ".test-", b"new");
        fs::set_permissions(&d, PermissionsExt::from_mode(0o700)).unwrap();
        if root {
            return;
        }
        let error = outcome.expect_err("the directory fsync must fail");
        assert!(
            committed_unsynced(&error),
            "a post-rename failure must not read as a write that did not happen: {error}"
        );
        assert_eq!(
            fs::read(&p).unwrap(),
            b"new",
            "the rename is what committed"
        );
        assert!(
            !committed_unsynced(&io::Error::from(io::ErrorKind::PermissionDenied)),
            "an ordinary failure is still an ordinary failure"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_post_commit_failure_keeps_its_raw_os_code_reachable() {
        // An fsync EIO from a failing device is a node-local transient: the step that hit it earns
        // another attempt, and the release that hit it earns nothing. EIO has no `ErrorKind` of
        // its own — it arrives `Uncategorized`, which no caller can match — so the ONLY way to
        // recognise it is its raw code, and an `io::Error` that carries the `Unsynced` payload
        // cannot also carry that code. Whoever classifies must read it one `source()` hop down.
        // Lose that hop and a transient disk fault reads as a bad release: the candidate
        // agent is rejected by content hash and the node is stranded a release behind.
        use std::error::Error;
        let wrapped = unsynced(io::Error::from_raw_os_error(libc::EIO));

        assert!(committed_unsynced(&wrapped), "the change still landed");
        assert_eq!(
            wrapped.kind(),
            io::Error::from_raw_os_error(libc::EIO).kind(),
            "the kind a caller matches on is untouched by the wrapping"
        );
        let cause = wrapped
            .source()
            .and_then(|source| source.downcast_ref::<io::Error>())
            .expect("the wrapped error is the returned error's source");
        assert_eq!(
            cause.raw_os_error(),
            Some(libc::EIO),
            "the raw code must survive the wrapping, one source hop down"
        );
    }

    #[test]
    fn executable_install_uses_the_canonical_durable_path() {
        let (_guard, root) = dir("executable");
        let source = root.join("download");
        let target = root.join("agent");
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
    fn remove_path_clears_whatever_is_at_the_path() {
        // The point of `remove_path` is that the caller does not get to assume the shape of what
        // it is clearing: a plain unlink fails on a directory on every platform, which would turn
        // "discard this garbage and carry on" into a failure repeated on every attempt forever.
        let (_guard, d) = dir("remove-path");

        let file = d.join("garbage");
        fs::write(&file, b"not evidence").unwrap();
        remove_path(&file).unwrap();
        assert!(!file.exists());

        let nested = d.join("dir-garbage");
        fs::create_dir_all(nested.join("inner")).unwrap();
        fs::write(nested.join("inner").join("leaf"), b"deep").unwrap();
        remove_path(&nested).unwrap();
        assert!(!nested.exists(), "a non-empty directory is removed whole");

        // Idempotent: nothing there is the state the caller wanted.
        remove_path(&nested).unwrap();
        remove_path(&d.join("never-existed")).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn remove_path_unlinks_a_symlink_without_touching_its_target() {
        // Following the link would delete a tree that merely happened to be pointed at — the
        // garbage is the link itself.
        let (_guard, d) = dir("remove-symlink");
        let target = d.join("real");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("keep"), b"precious").unwrap();
        let link = d.join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        remove_path(&link).unwrap();
        assert!(!link.exists());
        assert!(
            target.join("keep").exists(),
            "the symlink's target must survive"
        );
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
        let (_guard, d) = dir("relative");
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

    /// Both entry kinds a writer stages, in one sweeper: individual temp files, and whole staged
    /// directories (a signed metadata generation is staged as one). A sweeper that only unlinks
    /// files leaves an abandoned staged directory behind forever, accumulating one per crash —
    /// which is why the publisher grew a second copy of this function once already.
    #[test]
    fn sweep_removes_stale_temps_of_both_kinds_but_spares_fresh_and_unrelated_entries() {
        let (_guard, d) = dir("sweep");
        // A committed file and an unrelated `.tmp` (wrong prefix) must survive.
        fs::write(d.join("state"), b"committed").unwrap();
        fs::write(d.join("other-9-9-9.tmp"), b"not ours").unwrap();
        // A fresh temp under our prefix is an in-flight write — spare it.
        fs::write(d.join(".launcher-1-2-3.tmp"), b"in flight").unwrap();
        let in_flight_stage = d.join(".launcher-generation-live.tmp");
        fs::create_dir(&in_flight_stage).unwrap();
        let in_flight_lease = lease_temp_directory(&in_flight_stage).unwrap();
        // An aged temp under our prefix is a crash leftover — reap it, file or directory.
        let aged = SystemTime::now() - (STALE_TEMP_AGE + Duration::from_secs(1));
        let stale = d.join(".launcher-4-5-6.tmp");
        fs::write(&stale, b"orphan").unwrap();
        filetime_set(&stale, aged);
        let stale_stage = d.join(".launcher-generation-dead.tmp");
        fs::create_dir(&stale_stage).unwrap();
        let stale_lease = lease_temp_directory(&stale_stage).unwrap();
        fs::write(stale_stage.join("timestamp.json"), b"{}").unwrap();
        // A crash closes the ownership handle without removing the marker.
        drop(stale_lease);
        filetime_set(&stale_stage, aged);

        // Freshness is stamped, not assumed. Everything above dates the entries that must be
        // REAPED explicitly, while the ones that must SURVIVE were left to inherit whatever the
        // clock said when they were created — so the test quietly depended on less than
        // `STALE_TEMP_AGE` of wall clock passing before the sweep, which is a thing a loaded
        // machine or a clock step can violate without the code being wrong.
        let fresh = SystemTime::now();
        filetime_set(&d.join(".launcher-1-2-3.tmp"), fresh);
        filetime_set(&in_flight_stage, fresh);

        // The count is asserted LAST, deliberately. It came first once and failed under a loaded
        // parallel run with nothing but `2 != n` to go on, while the four specific assertions that
        // would have named the survivor sat below it and never ran. Which entry the sweep got wrong
        // is the whole diagnosis; the total is a summary of it.
        let removed = sweep_stale_temps(&d, ".launcher-");
        assert!(d.join("state").exists(), "a committed file was swept");
        assert!(
            d.join("other-9-9-9.tmp").exists(),
            "a temp under someone else's prefix was swept"
        );
        assert!(
            d.join(".launcher-1-2-3.tmp").exists(),
            "a fresh in-flight temp file was swept"
        );
        assert!(in_flight_stage.exists(), "an in-flight stage was yanked");
        drop(in_flight_lease);
        assert!(!stale.exists(), "an aged orphan file survived the sweep");
        assert!(
            !stale_stage.exists(),
            "an abandoned staged directory survived the sweep"
        );
        assert_eq!(removed, 2, "exactly the aged file and the abandoned stage");
    }

    #[test]
    fn sweep_never_reaps_an_old_directory_while_its_owner_lock_is_held() {
        let (_guard, d) = dir("sweep-live-directory");
        let stage = d.join(".publish-generation-live.tmp");
        fs::create_dir(&stage).unwrap();
        let lease = lease_temp_directory(&stage).unwrap();
        fs::write(stage.join("targets.json"), b"still publishing").unwrap();
        filetime_set(
            &stage,
            SystemTime::now() - (STALE_TEMP_AGE + Duration::from_secs(1)),
        );

        assert_eq!(sweep_stale_temps(&d, ".publish-"), 0);
        assert!(stage.exists(), "the active staged generation was yanked");

        drop(lease);
        assert_eq!(sweep_stale_temps(&d, ".publish-"), 1);
        assert!(!stage.exists());
    }

    /// A node whose clock steps backwards (RTC ran fast, then NTP corrected it) leaves temps
    /// with mtimes in the future, so their age cannot be computed. That is not evidence of
    /// abandonment: sweeping must spare them, or a concurrent download gets its file unlinked
    /// out from under it and every retry fails the same way.
    #[test]
    fn sweep_spares_temps_whose_age_is_unknown() {
        let (_guard, d) = dir("sweep-future-mtime");
        let in_flight = d.join(".launcher-7-8-9.tmp");
        fs::write(&in_flight, b"in flight").unwrap();
        filetime_set(&in_flight, SystemTime::now() + Duration::from_secs(600));

        assert_eq!(sweep_stale_temps(&d, ".launcher-"), 0);
        assert!(in_flight.exists());
    }

    /// Backdate an entry's mtime without pulling in a dependency: reopening and rewriting
    /// would only refresh it, so set it directly through `File::set_times`. Windows requires a
    /// directory handle with `FILE_WRITE_ATTRIBUTES` and `FILE_FLAG_BACKUP_SEMANTICS`; a normal
    /// read handle can inspect a directory but cannot change its timestamps.
    fn filetime_set(path: &Path, when: SystemTime) {
        let times = fs::FileTimes::new().set_accessed(when).set_modified(when);
        if path.is_dir() {
            directory_handle_for_timestamp(path)
                .and_then(|handle| handle.set_times(times))
                .expect("backdate staged directory");
            return;
        }
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_times(times)
            .unwrap();
    }

    #[cfg(not(windows))]
    fn directory_handle_for_timestamp(path: &Path) -> io::Result<File> {
        File::open(path)
    }

    #[cfg(windows)]
    fn directory_handle_for_timestamp(path: &Path) -> io::Result<File> {
        use std::os::windows::fs::OpenOptionsExt as _;
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_FLAG_BACKUP_SEMANTICS, FILE_WRITE_ATTRIBUTES,
        };

        File::options()
            .access_mode(FILE_WRITE_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
    }

    #[test]
    fn temp_creation_only_retries_collisions() {
        let (_guard, d) = dir("collision");
        let mut attempts = 0;
        let _ = create_temp_with(&d, ".test-", |path| {
            attempts += 1;
            if attempts == 1 {
                return Err(io::Error::from(io::ErrorKind::AlreadyExists));
            }
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
        })
        .unwrap();
        assert_eq!(attempts, 2);
    }

    #[test]
    fn sync_tree_flushes_nested_directories() {
        // sync_tree must descend into every real subdirectory without erroring; a tree with
        // nested dirs (bin/, lib/sub/) exercises the recursive descent.
        let (_guard, d) = dir("sync-tree");
        fs::create_dir_all(d.join("bin")).unwrap();
        fs::create_dir_all(d.join("lib/sub")).unwrap();
        fs::write(d.join("bin/app"), b"exe").unwrap();
        fs::write(d.join("lib/sub/data"), b"payload").unwrap();
        sync_tree(&d).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn each_visibility_commits_its_mode_at_creation() {
        // A published artifact is world-readable the instant it exists; nothing repairs a mode
        // after the fact, so the unix and Windows paths agree on who may read what.
        use std::os::unix::fs::PermissionsExt;
        let (_guard, d) = dir("visibility");
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let (_f, managed) = create_temp_managed(&d, ".state-").unwrap();
        assert_eq!(mode(&managed), 0o600);
        let (_f, published) = create_temp_published(&d, ".publish-").unwrap();
        assert_eq!(mode(&published), 0o644);

        let secret = d.join("secret");
        atomic_write(&secret, ".key-", b"k").unwrap();
        assert_eq!(mode(&secret), 0o600);
        let state = d.join("state");
        atomic_write_managed(&state, ".launcher-", b"s").unwrap();
        assert_eq!(mode(&state), 0o600, "state stays owner-only on unix");
        let private_directory = d.join("private-directory");
        create_private_directory(&private_directory).unwrap();
        assert_eq!(mode(&private_directory), 0o700);
    }

    #[cfg(windows)]
    #[test]
    fn a_managed_file_keeps_its_directorys_inheritable_grant() {
        // A protected (`D:P`) DACL discards inherited ACEs. Managed state must preserve the
        // directory's intended access; only secrets receive a private descriptor.
        let (_guard, d) = dir("managed");
        let (_file, path) = create_temp_managed(&d, ".state-").unwrap();
        assert!(
            !dacl_sddl(&path).starts_with("D:P"),
            "a managed file must inherit the state directory's ACL"
        );
        let (_file, published) = create_temp_published(&d, ".publish-").unwrap();
        assert!(!dacl_sddl(&published).starts_with("D:P"));
        let state = d.join("state");
        atomic_write_managed(&state, ".launcher-", b"s").unwrap();
        assert!(!dacl_sddl(&state).starts_with("D:P"));
        let secret = d.join("secret");
        atomic_write(&secret, ".key-", b"k").unwrap();
        assert!(
            dacl_sddl(&secret).starts_with("D:P"),
            "a secret is still protected against directory inheritance"
        );
    }

    #[cfg(windows)]
    #[test]
    fn a_secret_is_owner_only_from_creation() {
        // The unix side gets this from `0o600`. On Windows the guarantee is a protected DACL
        // supplied at creation — to the temp, before any byte is written, and preserved by the
        // rename; without it the file inherits `%ProgramData%`'s `BUILTIN\Users: Read` and every
        // local user can read a node's private key.
        let (_guard, d) = dir("private");
        let path = d.join("secret");
        atomic_write(&path, ".key-", b"k").unwrap();
        let sddl = dacl_sddl(&path);
        assert!(
            sddl.starts_with("D:P"),
            "the DACL must be protected against directory inheritance: {sddl}"
        );
        for unprivileged in [";BU)", ";WD)", ";AU)", ";IU)"] {
            assert!(
                !sddl.contains(unprivileged),
                "{unprivileged} must not be granted access: {sddl}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn a_private_directory_is_owner_only_from_creation() {
        let (_guard, d) = dir("private-directory");
        let path = d.join("exchange");
        create_private_directory(&path).unwrap();
        let sddl = dacl_sddl(&path);
        assert!(
            sddl.starts_with("D:P"),
            "the directory DACL must be protected against inheritance: {sddl}"
        );
        let creator_ace = sddl
            .split('(')
            .find(|ace| ace.ends_with(";;;CO)"))
            .expect("the directory must give child objects to their creator owner");
        for flag in ["OI", "CI", "IO"] {
            assert!(
                creator_ace.contains(flag),
                "creator-owner ACE must be object/container inheritable and inherit-only: {sddl}"
            );
        }
        for unprivileged in [";BU)", ";WD)", ";AU)", ";IU)"] {
            assert!(
                !sddl.contains(unprivileged),
                "{unprivileged} must not be granted access: {sddl}"
            );
        }

        // The reconciler, not this module, creates output files. The directory is therefore only
        // a security boundary if an ordinary child creation inherits the same narrow principals.
        let child = path.join("credential");
        fs::write(&child, b"secret").unwrap();
        assert_eq!(fs::read(&child).unwrap(), b"secret");
        let child_sddl = dacl_sddl(&child);
        for principal in [";SY)", ";BA)"] {
            assert!(
                child_sddl.contains(principal),
                "{principal} must inherit full access: {child_sddl}"
            );
        }
        for unprivileged in [";BU)", ";WD)", ";AU)", ";IU)"] {
            assert!(
                !child_sddl.contains(unprivileged),
                "{unprivileged} must not inherit access: {child_sddl}"
            );
        }
    }

    /// `path`'s DACL rendered back as SDDL, for asserting on what it grants.
    #[cfg(windows)]
    fn dacl_sddl(path: &Path) -> String {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{
            ConvertSecurityDescriptorToStringSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::{GetFileSecurityW, DACL_SECURITY_INFORMATION};

        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        unsafe {
            let mut needed = 0u32;
            GetFileSecurityW(
                wide.as_ptr(),
                DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                0,
                &mut needed,
            );
            let mut buffer = vec![0u8; needed as usize];
            assert_ne!(
                GetFileSecurityW(
                    wide.as_ptr(),
                    DACL_SECURITY_INFORMATION,
                    buffer.as_mut_ptr() as _,
                    needed,
                    &mut needed,
                ),
                0,
                "reading the temp file's security descriptor: {}",
                io::Error::last_os_error()
            );
            let mut text = std::ptr::null_mut();
            assert_ne!(
                ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    buffer.as_ptr() as _,
                    SDDL_REVISION_1,
                    DACL_SECURITY_INFORMATION,
                    &mut text,
                    std::ptr::null_mut(),
                ),
                0,
                "rendering the DACL as SDDL: {}",
                io::Error::last_os_error()
            );
            let mut len = 0;
            while *text.add(len) != 0 {
                len += 1;
            }
            let sddl = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
            LocalFree(text as _);
            sddl
        }
    }
}
