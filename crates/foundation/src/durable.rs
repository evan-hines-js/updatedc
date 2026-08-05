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
    /// Whoever the containing directory's ACL grants — the node's state directory is granted to
    /// the service account by the installer, and that grant works purely by inheritance.
    Managed,
    /// Everybody. A signed repository artifact served to the whole fleet.
    Published,
}

/// Create a fresh, uniquely named temp file in `dir` that keeps the access its directory
/// confers: on Windows the directory's inheritable ACEs apply (the installer's
/// `icacls %STATEDIR% /grant "NT SERVICE\…:(OI)(CI)M"` grant reaches it), on unix it is `0o600`.
/// Every file under the node state directory that is not a secret goes through here: with a
/// protected DACL, a state file written by an elevated operator CLI or an installer step would
/// commit with no ACE for the service account, which could then neither read nor replace it, and
/// no `icacls` grant could repair it.
///
/// There is deliberately no owner-only counterpart to this: a secret is never streamed here — it
/// is always one in-memory buffer — so [`atomic_write`] is the single door to
/// [`Visibility::Private`], and there is no second one to keep in step with it.
pub fn create_temp_managed(dir: &Path, prefix: &str) -> io::Result<(File, PathBuf)> {
    create_temp_with(dir, prefix, |path| create(path, Visibility::Managed))
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
        // private as a secret, because only the service account is ever inside that tree.
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
/// the deployment grants the service account access to its own state directory.
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
    use windows_sys::Win32::Foundation::{LocalFree, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE,
    };

    // Full access to the file's owner, to SYSTEM and to the local Administrators group; to
    // nobody else. `P` marks the DACL protected, so the parent directory's inheritable entries
    // — the `BUILTIN\Users` read this exists to exclude — do not apply, and `fs::rename` keeps
    // it that way when the temp is committed.
    const OWNER_ONLY_SDDL: &str = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)";
    let sddl: Vec<u16> = OWNER_ONLY_SDDL.encode_utf16().chain(Some(0)).collect();
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: both wide buffers are live and NUL-terminated for the duration of the calls, the
    // converted descriptor is freed on every path, and the returned handle is either
    // INVALID_HANDLE_VALUE or handed to a `File` that owns and closes it.
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
        let handle = CreateFileW(
            wide.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        );
        // Capture the failure reason before LocalFree can overwrite it: `create_temp_with`
        // distinguishes an ALREADY_EXISTS collision (retry) from a real error (give up).
        let error = io::Error::last_os_error();
        LocalFree(descriptor as _);
        if handle == INVALID_HANDLE_VALUE {
            return Err(error);
        }
        Ok(File::from_raw_handle(handle as _))
    }
}

#[cfg(not(any(unix, windows)))]
fn create(path: &Path, _visibility: Visibility) -> io::Result<File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
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
/// inheritable grant to the service account; on unix still `0o600`). A supervisor pointer, a
/// guardian marker, a journal — anything a differently-privileged principal may legitimately have
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
/// on the kind (`NotFound`, `PermissionDenied`, …) is unaffected by the wrapping.
fn unsynced(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), Unsynced(error))
}

/// Whether `error` reports an operation whose effect ALREADY LANDED and that failed only to
/// prove that effect durable: the rename or unlink is visible to every reader, and the
/// directory fsync behind it is what failed (`EMFILE`, an fsync `EIO`).
///
/// The distinction exists for callers that undo their own state when a durable write fails.
/// The guardian rolls its committed-supervisor pointer back to the predecessor and records the
/// candidate rejected — which, for a pointer that actually moved, would leave a rejection
/// marker about the very binary the next boot launches as the committed supervisor. Every other
/// caller is right to treat this as the plain failure it also is.
pub fn committed_unsynced(error: &io::Error) -> bool {
    error.get_ref().is_some_and(|inner| inner.is::<Unsynced>())
}

/// Copy a verified executable into a fresh sibling file, persist its final mode, and atomically
/// install it at `target`. A staged binary is not a secret: it is [`Visibility::Managed`], so on
/// Windows the state directory's grant to the service account still reaches it and a candidate
/// staged by an elevated installer step remains launchable by the service.
pub fn install_executable(target: &Path, source: &Path) -> io::Result<()> {
    let dir = parent_dir(target);
    let (mut tmp, tmp_path) = create_temp_managed(dir, ".executable-")?;
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

/// Best-effort removal of stale temp files left behind when a crash or power loss struck
/// between an [`atomic_write`]/[`install_executable`]/[`create_temp_managed`] and its rename —
/// the `<prefix>…-….tmp` sibling is then an orphan no one will ever finish. Sweeps `dir`
/// for files whose name starts with `prefix` and ends with `.tmp`, removing only those whose
/// age is known to have reached [`STALE_TEMP_AGE`] — anything newer, and anything whose age
/// cannot be determined, is spared so a temp an in-flight writer still owns is never yanked.
///
/// Purely hygiene: a directory-read or unlink failure is ignored (a stray temp is inert —
/// the sequence/pid/nanos naming means it can never collide with a real committed file),
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
        // leaves the age unknown — spare the temp rather than yank a file someone still owns.
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
        if fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    removed
}

/// Durably unlink a file this tower wrote: the removal is persisted (the parent directory is
/// synced) before this returns, so a power loss cannot resurrect it. Removing something that is
/// already gone is success. The path must be a file — use [`remove_path`] for a path whose shape
/// is not ours to assume.
pub fn remove_file(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
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
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => fs::remove_dir_all(path)?,
        Ok(_) => return remove_file(path),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    }
    sync_dir(parent_dir(path)).map_err(unsynced)
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

fn is_transient_lock(error: &io::Error) -> bool {
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

    #[cfg(unix)]
    #[test]
    fn a_failure_after_the_rename_reports_the_write_as_committed() {
        // The rename is already visible when the directory fsync runs, so reporting that failure
        // as a plain Err claims the old content is still there while the new content is what
        // every reader sees. The guardian rolls its supervisor pointer back to the predecessor
        // on a failed commit; rolling back a pointer that moved rejects the binary the next boot
        // launches as the committed supervisor.
        use std::os::unix::fs::PermissionsExt;
        let d = dir("unsynced");
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
    fn remove_path_clears_whatever_is_at_the_path() {
        // The point of `remove_path` is that the caller does not get to assume the shape of what
        // it is clearing: a plain unlink fails on a directory on every platform, which would turn
        // "discard this garbage and carry on" into a failure repeated on every attempt forever.
        let d = dir("remove-path");

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
        let d = dir("remove-symlink");
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
    fn sweep_removes_stale_temps_but_spares_fresh_and_unrelated_files() {
        let d = dir("sweep");
        // A committed file and an unrelated `.tmp` (wrong prefix) must survive.
        fs::write(d.join("state"), b"committed").unwrap();
        fs::write(d.join("other-9-9-9.tmp"), b"not ours").unwrap();
        // A fresh temp under our prefix is an in-flight write — spare it.
        fs::write(d.join(".guardian-1-2-3.tmp"), b"in flight").unwrap();
        // An aged temp under our prefix is a crash leftover — reap it.
        let stale = d.join(".guardian-4-5-6.tmp");
        fs::write(&stale, b"orphan").unwrap();
        let aged = SystemTime::now() - (STALE_TEMP_AGE + Duration::from_secs(1));
        filetime_set(&stale, aged);

        assert_eq!(sweep_stale_temps(&d, ".guardian-"), 1);
        assert!(d.join("state").exists());
        assert!(d.join("other-9-9-9.tmp").exists());
        assert!(d.join(".guardian-1-2-3.tmp").exists());
        assert!(!stale.exists());
    }

    /// A node whose clock steps backwards (RTC ran fast, then NTP corrected it) leaves temps
    /// with mtimes in the future, so their age cannot be computed. That is not evidence of
    /// abandonment: sweeping must spare them, or a concurrent download gets its file unlinked
    /// out from under it and every retry fails the same way.
    #[test]
    fn sweep_spares_temps_whose_age_is_unknown() {
        let d = dir("sweep-future-mtime");
        let in_flight = d.join(".guardian-7-8-9.tmp");
        fs::write(&in_flight, b"in flight").unwrap();
        filetime_set(&in_flight, SystemTime::now() + Duration::from_secs(600));

        assert_eq!(sweep_stale_temps(&d, ".guardian-"), 0);
        assert!(in_flight.exists());
    }

    /// Backdate a file's mtime without pulling in a dependency: reopening and rewriting
    /// would only refresh it, so set it directly through `File::set_times`.
    fn filetime_set(path: &Path, when: SystemTime) {
        let times = fs::FileTimes::new().set_accessed(when).set_modified(when);
        File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_times(times)
            .unwrap();
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
        let d = dir("sync-tree");
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
        let d = dir("visibility");
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        let (_f, managed) = create_temp_managed(&d, ".state-").unwrap();
        assert_eq!(mode(&managed), 0o600);
        let (_f, published) = create_temp_published(&d, ".publish-").unwrap();
        assert_eq!(mode(&published), 0o644);

        let secret = d.join("secret");
        atomic_write(&secret, ".key-", b"k").unwrap();
        assert_eq!(mode(&secret), 0o600);
        let state = d.join("state");
        atomic_write_managed(&state, ".guardian-", b"s").unwrap();
        assert_eq!(mode(&state), 0o600, "state stays owner-only on unix");
    }

    #[cfg(windows)]
    #[test]
    fn a_managed_file_keeps_its_directorys_inheritable_grant() {
        // The state directory is granted to the service account by an installer `icacls` that
        // works purely by inheritance. A protected (`D:P`) DACL discards inherited ACEs, so a
        // state file written by an elevated operator CLI would be unreadable and unreplaceable
        // by the service, with no grant able to repair it. Only secrets are protected.
        let d = dir("managed");
        let (_file, path) = create_temp_managed(&d, ".state-").unwrap();
        assert!(
            !dacl_sddl(&path).starts_with("D:P"),
            "a managed file must inherit the state directory's ACL"
        );
        let (_file, published) = create_temp_published(&d, ".publish-").unwrap();
        assert!(!dacl_sddl(&published).starts_with("D:P"));
        let state = d.join("state");
        atomic_write_managed(&state, ".guardian-", b"s").unwrap();
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
        let d = dir("private");
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
