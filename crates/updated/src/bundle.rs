//! The sole application artifact format: an immutable, manifested tar.zst release.

use aws_lc_rs::digest::{Context, SHA256};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use crate::hash::{sha256_bytes, sha256_file};
use updated_contracts::is_sha256_hex;

pub(crate) const MANIFEST_FILE: &str = "manifest.json";
pub(crate) const MANIFEST_SCHEMA: u32 = 1;
const MANIFEST_BYTES_LIMIT: u64 = 4 << 20;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseId {
    pub version: String,
    pub manifest_sha256: String,
}

impl ReleaseId {
    pub(crate) fn directory_name(&self) -> String {
        format!("{}-{}", self.version, self.manifest_sha256)
    }

    fn validate(&self) -> io::Result<()> {
        semver::Version::parse(&self.version).map_err(invalid)?;
        validate_digest(&self.manifest_sha256)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BundleManifest {
    pub schema: u32,
    pub product: String,
    pub version: String,
    pub platform: String,
    pub entrypoint: String,
    pub files: Vec<ManifestFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManifestFile {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub executable: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct BundleLimits {
    pub archive_bytes: u64,
    pub expanded_bytes: u64,
    pub file_bytes: u64,
    pub files: usize,
    pub path_bytes: usize,
}

impl Default for BundleLimits {
    fn default() -> Self {
        Self {
            archive_bytes: 512 << 20,
            expanded_bytes: 1 << 30,
            file_bytes: 512 << 20,
            files: 16_384,
            path_bytes: 1024,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExpectedBundle<'a> {
    pub product: &'a str,
    pub version: &'a str,
    pub platform: &'a str,
}

#[derive(Debug)]
pub struct StagedRelease {
    pub id: ReleaseId,
    pub archive_sha256: String,
}

/// The one executable a bundle declares. A node reconciler receives every operation through this
/// entrypoint; phase-specific scripts are deliberately not part of the artifact protocol.
pub struct Entrypoints<'a> {
    pub entrypoint: &'a str,
}

impl<'a> Entrypoints<'a> {
    /// An application (or legacy single-script provider) bundle: just the forward entrypoint.
    pub fn new(entrypoint: &'a str) -> Self {
        Self { entrypoint }
    }
}

/// Build the canonical deterministic application archive from a prepared release tree.
/// `source` must not itself contain `manifest.json`; the publisher generates it from the
/// exact files that will be archived.
pub fn create_bundle(
    source: &Path,
    archive: &Path,
    product: &str,
    version: &str,
    platform: &str,
    entrypoints: &Entrypoints<'_>,
) -> io::Result<()> {
    semver::Version::parse(version).map_err(invalid)?;
    validate_relative(entrypoints.entrypoint, 1024)?;
    let metadata = fs::symlink_metadata(source)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("bundle source is not a regular directory"));
    }
    let mut paths = Vec::new();
    collect_files(source, source, &mut paths)?;
    paths.sort();
    let mut files = Vec::with_capacity(paths.len());
    for relative in &paths {
        let path = source.join(relative);
        let metadata = fs::symlink_metadata(&path)?;
        let executable = relative == entrypoints.entrypoint || is_executable(&metadata);
        files.push(ManifestFile {
            path: relative.clone(),
            sha256: sha256_file(&path)?,
            size: metadata.len(),
            executable,
        });
    }
    let manifest = BundleManifest {
        schema: MANIFEST_SCHEMA,
        product: product.to_string(),
        version: version.to_string(),
        platform: platform.to_string(),
        entrypoint: entrypoints.entrypoint.to_string(),
        files,
    };
    let expected = ExpectedBundle {
        product,
        version,
        platform,
    };
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(invalid)?;
    BundleManifest::parse(&manifest_bytes, &expected)?;

    if let Some(parent) = archive.parent().filter(|path| !path.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let output = File::create(archive)?;
    let encoder = zstd::stream::write::Encoder::new(output, 9)?;
    let mut tar = tar::Builder::new(encoder);
    tar.mode(tar::HeaderMode::Deterministic);
    append_bytes(&mut tar, MANIFEST_FILE, &manifest_bytes, false)?;
    for file in &manifest.files {
        append_file(&mut tar, source, file)?;
    }
    let encoder = tar.into_inner()?;
    encoder.finish()?.sync_all()?;
    Ok(())
}

/// Build the canonical archive from a `source` that is *either* a prepared directory tree or a
/// single executable file. A directory is bundled as-is; a lone file is first wrapped into a fresh
/// tree — the file placed at `entrypoints.entrypoint`, plus a generated `config/release.toml`
/// carrying the version — built inside `wrap_dir`, then bundled. This is the one definition of the
/// "wrap a lone binary" publishing shorthand, shared by every publish front end so the generated
/// tree layout (and its `release.toml`) cannot drift between them. `wrap_dir` is (re)created fresh,
/// so any stale contents from a previous build are removed first.
pub fn create_bundle_from_source(
    source: &Path,
    archive: &Path,
    wrap_dir: &Path,
    product: &str,
    version: &str,
    platform: &str,
    entrypoints: &Entrypoints<'_>,
) -> io::Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    if !metadata.is_file() {
        return create_bundle(source, archive, product, version, platform, entrypoints);
    }
    if wrap_dir.exists() {
        fs::remove_dir_all(wrap_dir)?;
    }
    let destination = wrap_dir.join(entrypoints.entrypoint);
    let parent = destination
        .parent()
        .ok_or_else(|| invalid("bundle entrypoint has no parent directory"))?;
    fs::create_dir_all(parent)?;
    fs::create_dir_all(wrap_dir.join("config"))?;
    fs::copy(source, &destination)?;
    fs::write(
        wrap_dir.join("config/release.toml"),
        format!("version = {version:?}\n"),
    )?;
    create_bundle(wrap_dir, archive, product, version, platform, entrypoints)
}

impl BundleManifest {
    pub(crate) fn parse(bytes: &[u8], expected: &ExpectedBundle<'_>) -> io::Result<Self> {
        let manifest: Self = serde_json::from_slice(bytes).map_err(invalid)?;
        if manifest.schema != MANIFEST_SCHEMA {
            return Err(invalid("unsupported bundle manifest schema"));
        }
        if manifest.product != expected.product
            || manifest.version != expected.version
            || manifest.platform != expected.platform
        {
            return Err(invalid(
                "bundle manifest disagrees with authenticated metadata",
            ));
        }
        manifest.validate_shape()?;
        Ok(manifest)
    }

    fn validate_shape(&self) -> io::Result<()> {
        if self.schema != MANIFEST_SCHEMA {
            return Err(invalid("unsupported bundle manifest schema"));
        }
        let valid_product = !self.product.is_empty()
            && self.product.len() <= 128
            && self.product.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
            });
        if !valid_product {
            return Err(invalid("bundle product is invalid"));
        }
        semver::Version::parse(&self.version).map_err(invalid)?;
        validate_relative(&self.entrypoint, 1024)?;
        let mut exact = BTreeSet::new();
        let mut folded = BTreeSet::new();
        for file in &self.files {
            validate_relative(&file.path, 1024)?;
            validate_digest(&file.sha256)?;
            if !exact.insert(file.path.clone()) || !folded.insert(file.path.to_lowercase()) {
                return Err(invalid("duplicate or case-colliding manifest path"));
            }
        }
        let file = self
            .files
            .iter()
            .find(|file| file.path == self.entrypoint)
            .ok_or_else(|| invalid("bundle entrypoint is not declared"))?;
        if !file.executable {
            return Err(invalid("bundle entrypoint is not executable"));
        }
        Ok(())
    }

    /// The release identity these exact manifest bytes name. Infallible by construction: the
    /// version was validated when the manifest parsed, and the digest is computed here.
    pub(crate) fn id(&self, bytes: &[u8]) -> ReleaseId {
        ReleaseId {
            version: self.version.clone(),
            manifest_sha256: sha256_bytes(bytes),
        }
    }
}

/// Resolve a committed release's manifest and entrypoint by identity, *without* re-hashing
/// the tree. The manifest's own bytes are bound to the release id (their digest must equal
/// `id.manifest_sha256`), so this proves we are pointing at the release we committed — it
/// trusts the already-verified tree rather than re-reading every file. Use on the
/// steady-state path (launching the committed release); use [`read_release`] where
/// untrusted or freshly written bytes must be fully re-verified.
pub(crate) fn read_manifest(root: &Path, id: &ReleaseId) -> io::Result<(BundleManifest, PathBuf)> {
    id.validate()?;
    let directory = root.join(id.directory_name());
    let directory_meta = fs::symlink_metadata(&directory)?;
    if !directory_meta.is_dir() || directory_meta.file_type().is_symlink() {
        return Err(invalid("release identity does not name a real directory"));
    }
    let bytes = fs::read(directory.join(MANIFEST_FILE))?;
    let manifest: BundleManifest = serde_json::from_slice(&bytes).map_err(invalid)?;
    manifest.validate_shape()?;
    if manifest.schema != MANIFEST_SCHEMA
        || manifest.version != id.version
        || !sha256_bytes(&bytes).eq_ignore_ascii_case(&id.manifest_sha256)
    {
        return Err(invalid("release identity does not match its manifest"));
    }
    let entrypoint = directory.join(&manifest.entrypoint);
    Ok((manifest, entrypoint))
}

/// Like [`read_manifest`], but also re-hashes every manifested file against the manifest.
/// This is the fail-closed check applied to bytes *entering* the trusted set — freshly
/// extracted downloads and a candidate at its activation/commit moment. A committed,
/// already-verified release is not re-hashed again on the steady-state launch path.
pub(crate) fn read_release(root: &Path, id: &ReleaseId) -> io::Result<(BundleManifest, PathBuf)> {
    let (manifest, entrypoint) = read_manifest(root, id)?;
    verify_tree(&root.join(id.directory_name()), &manifest)?;
    Ok((manifest, entrypoint))
}

/// Re-hash a committed release without exposing its manifest internals. Supervisors use
/// this before every network refresh so local tampering is detected while fully offline.
pub fn verify_release(root: &Path, id: &ReleaseId) -> io::Result<()> {
    read_release(root, id).map(|_| ())
}

pub fn read_active(path: &Path) -> io::Result<Option<ReleaseId>> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(invalid),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub fn write_active(path: &Path, release: &ReleaseId) -> io::Result<()> {
    foundation::durable::atomic_write_managed(
        path,
        ".active-release-",
        &serde_json::to_vec(release).map_err(invalid)?,
    )
}

/// Why materializing a downloaded archive failed — split by what the failure is *evidence about*.
///
/// This distinction is load-bearing and deliberately typed so it survives every crate boundary
/// between here and the supervisor's rejection set:
///
/// * [`Archive`](Self::Archive) is a verdict on the bytes. Only this may become a durable,
///   never-expiring rejection of a release, because only this is reproducible on every node and
///   on every retry — a manifest that disagrees with its signed metadata, a member whose digest
///   does not match, an archive over the size a target may be.
/// * [`Storage`](Self::Storage) is a verdict on *this node at this moment*: a full disk, a
///   revoked directory, a failing device, an already-committed tree that drifted locally. It says
///   nothing about the release and must always be retried.
///
/// A bare `io::Error` cannot express the difference, and when the two were collapsed a local
/// hiccup could be recorded as a permanent refusal to ever run a healthy release again. The
/// `From<io::Error>` impl deliberately yields `Storage`, so a filesystem call added later is
/// misfiled towards retrying rather than towards a permanent rejection; naming a failure as
/// evidence about the archive takes the explicit [`archive_verdict`] constructor.
#[derive(Debug)]
pub enum InstallError {
    /// The archive is bad. Rejectable.
    Archive(io::Error),
    /// This node could not materialize the archive right now. Never rejectable.
    Storage(io::Error),
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Archive(error) => write!(f, "bundle archive is invalid: {error}"),
            Self::Storage(error) => write!(f, "staging the bundle failed: {error}"),
        }
    }
}

impl std::error::Error for InstallError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Archive(error) | Self::Storage(error) => Some(error),
        }
    }
}

impl From<io::Error> for InstallError {
    fn from(error: io::Error) -> Self {
        Self::Storage(error)
    }
}

/// State a verdict about the archive's own bytes — the only failure that may be recorded durably.
fn archive_verdict(error: impl std::fmt::Display) -> InstallError {
    InstallError::Archive(invalid(error))
}

/// Classify a failure to materialize one archive member into a *freshly created, empty* staging
/// directory.
///
/// Because the destination tree starts empty and only this archive's own entries ever land in it,
/// anything already occupying a member's path was put there by an earlier entry of the same
/// archive — a repeated path, a path that collides case-insensitively on macOS/Windows, or an `a`
/// file followed by an `a/b` entry (which fails one level up, in `create_dir_all`). That is a
/// property of the bytes, reproducible on every node and every retry, so it is the one extraction
/// I/O failure that is [`Archive`](InstallError::Archive) evidence rather than
/// [`Storage`](InstallError::Storage): letting `From<io::Error>` file it as Storage would make a
/// malformed archive retry forever instead of falling back past it. Every other errno here — no
/// space, a revoked directory, a failing device — is still about this node right now.
fn classify_collision(error: io::Error) -> InstallError {
    // `create_dir_all` surfaces "a non-directory is already at this path" as the raw EEXIST from
    // `mkdir`, and `create_new` surfaces any occupant (file, directory or symlink) as EEXIST too.
    match error.kind() {
        io::ErrorKind::AlreadyExists | io::ErrorKind::NotADirectory => {
            archive_verdict("duplicate bundle member")
        }
        _ => InstallError::Storage(error),
    }
}

pub(crate) fn stage_bundle(
    archive: &Path,
    staging_root: &Path,
    versions_root: &Path,
    expected: &ExpectedBundle<'_>,
    limits: &BundleLimits,
) -> Result<StagedRelease, InstallError> {
    let archive_meta = fs::symlink_metadata(archive)?;
    if !archive_meta.is_file() {
        // The downloaded archive is written by this node, so anything but a regular file here is
        // local damage, not evidence about the release.
        return Err(InstallError::Storage(invalid(
            "the downloaded bundle archive is not a regular file",
        )));
    }
    if archive_meta.len() > limits.archive_bytes {
        return Err(archive_verdict(
            "bundle archive exceeds the target size limit",
        ));
    }
    ensure_real_directory(staging_root)?;
    ensure_real_directory(versions_root)?;
    let archive_sha256 = sha256_file(archive)?;
    let stage = Stage::create(staging_root)?;
    let (manifest, bytes) = extract(archive, stage.path(), expected, limits)?;
    let id = manifest.id(&bytes);
    let destination = versions_root.join(id.directory_name());
    if destination.exists() {
        // A content-addressed directory is only reusable while its complete tree still
        // matches the authenticated manifest. Do not let local drift become trusted just
        // because the same release is downloaded again.
        if read_release(versions_root, &id).is_ok() {
            return Ok(StagedRelease { id, archive_sha256 });
        }
        // It drifted. The archive is not to blame — the bytes in `stage` were just verified
        // member-by-member against the authenticated manifest — so this is never a rejection.
        // But it must also not be a dead end: refusing here and dropping the good tree would
        // leave the drifted directory in place forever, and every later attempt would
        // short-circuit on `destination.exists()` and fail identically, so the assigned release
        // could never install on this node again. Remove the invalid copy and republish the
        // verified one over it — the same repair a first install would have performed.
        //
        // `discard` rather than `remove_dir_all`, so whatever drifted into this name — a plain
        // file, a symlink pointing out of `versions/` — is removed without ever being followed.
        // If it cannot be removed, the rename below fails and the whole attempt is Storage.
        discard(&destination);
        foundation::durable::sync_dir(versions_root)?;
    }
    // Flush the entire staged tree — nested subdirectories (e.g. `bin/`, `lib/`) as well
    // as the top dir — so a power loss right after the rename cannot surface a release
    // whose nested dirents were never persisted.
    foundation::durable::sync_tree(stage.path())?;
    fs::rename(stage.path(), &destination)?;
    foundation::durable::sync_dir(versions_root)?;
    // Re-verify the freshly published tree against its manifest. Every member was hashed on the
    // way in, so a mismatch here is the device, not the release.
    read_release(versions_root, &id).map_err(InstallError::Storage)?;
    Ok(StagedRelease { id, archive_sha256 })
}

/// Attempt directories and their owner files share this prefix. Everything else in a staging root
/// — notably the `bundle.download` archive being staged from — belongs to someone else and is
/// never touched by the sweep.
const STAGE_PREFIX: &str = "stage-";

/// `<attempt>.owner`: the lock file guarding one attempt directory, kept beside it rather than
/// inside it so the directory can be renamed into `versions/` whole.
const OWNER_SUFFIX: &str = ".owner";

/// One staging attempt's private extraction directory.
///
/// Isolation is by construction, not by exclusion: the directory is named with a fresh random
/// token, so no two attempts — in this process, in another supervisor generation across a
/// self-update, or in a tool run by hand — can ever name the same path. There is no lock to
/// contend on, no heartbeat to miss and no staleness threshold to tune, so concurrent staging
/// cannot fail, cannot delete another attempt's tree, and cannot be refused.
///
/// What unique names alone do not give is cleanup: a kill between creating the directory and
/// renaming the tree into `versions/` leaves a fully expanded release behind, so a crash-looping
/// node would accumulate one copy per attempt until the disk fills. Each attempt therefore sweeps
/// the ones nobody owns any more, and ownership is answered by the OS rather than guessed from
/// elapsed time: every attempt holds an exclusive lock on its owner file for its whole life, and
/// the kernel releases that lock when the owning process exits, however it exits. A directory
/// whose owner lock can be taken has, by definition, no live owner.
///
/// The owner file is created *before* the directory it guards and removed *after* it, so a
/// sweeper that can see an attempt directory can always see (and fail to lock) its live owner.
struct Stage {
    dir: PathBuf,
    owner_path: PathBuf,
    /// `Option` only so the lock can be released inside `drop` *before* its file is unlinked:
    /// Windows refuses to unlink a file this process still holds open.
    owner: Option<crate::lock::InstanceLock>,
}

impl Stage {
    fn create(staging_root: &Path) -> io::Result<Stage> {
        // Sweep before claiming: leftovers are reclaimed even when this attempt goes on to fail,
        // and nothing this attempt owns exists yet, so the sweep cannot see it.
        sweep_abandoned(staging_root);
        let name = format!("{STAGE_PREFIX}{}", crate::rand::token()?);
        let owner_path = staging_root.join(format!("{name}{OWNER_SUFFIX}"));
        let owner = crate::lock::InstanceLock::acquire(&owner_path)?;
        let dir = staging_root.join(name);
        fs::create_dir(&dir)?;
        Ok(Stage {
            dir,
            owner_path,
            owner: Some(owner),
        })
    }

    fn path(&self) -> &Path {
        &self.dir
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        // A successful stage renamed the directory away; `NotFound` is then the normal case.
        let _ = fs::remove_dir_all(&self.dir);
        drop(self.owner.take());
        let _ = fs::remove_file(&self.owner_path);
    }
}

/// Remove every staging attempt whose owner is gone.
///
/// Best effort and order-independent on purpose: taking the owner lock is the entire test, and it
/// is atomic, so two sweepers can never both conclude that the same attempt is theirs to delete,
/// and a live attempt's lock is never available to either. Attempt names are one-shot random
/// tokens that are never reused, so nothing can claim a name between the moment it is found
/// abandoned and the moment it is removed. Anything that cannot be locked or removed is simply
/// left for the next sweep.
fn sweep_abandoned(staging_root: &Path) {
    let Ok(entries) = fs::read_dir(staging_root) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(STAGE_PREFIX) {
            continue;
        }
        let path = entry.path();
        let Some(attempt) = name.strip_suffix(OWNER_SUFFIX) else {
            // A directory with no owner file beside it: a previous sweep was interrupted between
            // unlinking the owner and removing the tree. A live attempt is never in this state.
            if !staging_root
                .join(format!("{name}{OWNER_SUFFIX}"))
                .try_exists()
                .unwrap_or(true)
            {
                discard(&path);
            }
            continue;
        };
        // A lock is only meaningful on a real file. Anything else planted under this name is
        // discarded without being opened, so a symlink is never followed or written through.
        if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
            discard(&path);
            continue;
        }
        match crate::lock::InstanceLock::acquire(&path) {
            // Released immediately: the removal below must not hold the file open on Windows.
            Ok(lock) => drop(lock),
            Err(_) => continue,
        }
        discard(&staging_root.join(attempt));
        let _ = fs::remove_file(&path);
    }
}

/// Remove a path of any type without ever following a symlink out of the staging root.
fn discard(path: &Path) {
    match fs::symlink_metadata(path) {
        // `symlink_metadata` reports a symlink-to-directory as a symlink, never a directory,
        // so this arm can only be a real directory.
        Ok(metadata) if metadata.is_dir() => {
            let _ = fs::remove_dir_all(path);
        }
        Ok(_) => {
            let _ = fs::remove_file(path);
        }
        Err(_) => {}
    }
}

fn ensure_real_directory(path: &Path) -> io::Result<()> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid("bundle storage root is not a real directory"));
    }
    Ok(())
}

/// Whether the last failure to come out of the decompress/untar stack originated at the device
/// rather than in the archive's structure.
///
/// The zstd and tar readers surface both as one `io::Error`, and telling them apart by
/// `ErrorKind` is guesswork — which is exactly how a failing disk could be recorded as a
/// permanently rejected release. So it is recorded as a fact instead: [`ArchiveSource`] wraps the
/// file the decoder reads from and sets this flag when, and only when, a read from the file
/// itself failed. Anything else the stack reports is a property of the bytes.
#[derive(Clone, Default)]
struct DeviceFault(std::rc::Rc<std::cell::Cell<bool>>);

impl DeviceFault {
    /// Classify a failure raised by the decompress/untar stack.
    fn classify(&self, error: io::Error) -> InstallError {
        if self.0.get() {
            InstallError::Storage(error)
        } else {
            InstallError::Archive(error)
        }
    }
}

struct ArchiveSource {
    file: File,
    fault: DeviceFault,
}

impl Read for ArchiveSource {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.file
            .read(buffer)
            .inspect_err(|_| self.fault.0.set(true))
    }
}

fn extract(
    archive: &Path,
    stage: &Path,
    expected: &ExpectedBundle<'_>,
    limits: &BundleLimits,
) -> Result<(BundleManifest, Vec<u8>), InstallError> {
    let fault = DeviceFault::default();
    let source = ArchiveSource {
        file: File::open(archive)?,
        fault: fault.clone(),
    };
    let decoder = zstd::stream::read::Decoder::new(source).map_err(|e| fault.classify(e))?;
    let mut tar = tar::Archive::new(decoder);
    let mut manifest_bytes = None;
    let mut extracted = BTreeMap::<String, (u64, String)>::new();
    let mut entries_seen = 0usize;
    let mut expanded = 0u64;
    for entry in tar.entries().map_err(|e| fault.classify(e))? {
        let mut entry = entry.map_err(|e| fault.classify(e))?;
        if !entry.header().entry_type().is_file() {
            return Err(archive_verdict(
                "bundle contains a non-regular archive entry",
            ));
        }
        let path = entry
            .path()
            .map_err(|e| fault.classify(e))?
            .to_string_lossy()
            .into_owned();
        validate_relative(&path, limits.path_bytes).map_err(InstallError::Archive)?;
        // Count entries seen, not entries recorded in `extracted` (which excludes the manifest), so
        // the limit bounds the archive's real entry count rather than that count plus one.
        entries_seen += 1;
        if entries_seen > limits.files {
            return Err(archive_verdict("bundle exceeds file-count limit"));
        }
        let size = entry.size();
        if size > limits.file_bytes {
            return Err(archive_verdict("bundle member exceeds file-size limit"));
        }
        expanded = expanded
            .checked_add(size)
            .ok_or_else(|| archive_verdict("bundle size overflow"))?;
        if expanded > limits.expanded_bytes {
            return Err(archive_verdict("bundle exceeds expanded-size limit"));
        }
        let destination = stage.join(&path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(classify_collision)?;
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)
            .map_err(classify_collision)?;
        let (bytes, digest) = if path == MANIFEST_FILE {
            if size > MANIFEST_BYTES_LIMIT {
                return Err(archive_verdict("bundle manifest exceeds size limit"));
            }
            let mut bytes = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
            entry
                .read_to_end(&mut bytes)
                .map_err(|e| fault.classify(e))?;
            if bytes.len() as u64 != size {
                return Err(archive_verdict("truncated bundle member"));
            }
            file.write_all(&bytes)?;
            let digest = sha256_bytes(&bytes);
            (Some(bytes), digest)
        } else {
            let mut context = Context::new(&SHA256);
            let mut written = 0u64;
            let mut buffer = [0u8; 64 * 1024];
            loop {
                let read = entry.read(&mut buffer).map_err(|e| fault.classify(e))?;
                if read == 0 {
                    break;
                }
                file.write_all(&buffer[..read])?;
                context.update(&buffer[..read]);
                written = written
                    .checked_add(read as u64)
                    .ok_or_else(|| archive_verdict("bundle member size overflow"))?;
            }
            if written != size {
                return Err(archive_verdict("truncated bundle member"));
            }
            (None, hex::encode(context.finish().as_ref()))
        };
        file.sync_all()?;
        if path == MANIFEST_FILE {
            manifest_bytes = bytes;
        } else {
            // Never an overwrite: `create_new` above is the single place a colliding member is
            // caught, and it already refused this entry if anything occupied the destination.
            extracted.insert(path, (size, digest));
        }
    }
    let bytes = manifest_bytes.ok_or_else(|| archive_verdict("bundle manifest is missing"))?;
    let manifest = BundleManifest::parse(&bytes, expected).map_err(InstallError::Archive)?;
    if extracted.len() != manifest.files.len() {
        return Err(archive_verdict(
            "bundle files do not exactly match the manifest",
        ));
    }
    for declared in &manifest.files {
        match extracted.get(&declared.path) {
            Some((size, digest))
                if *size == declared.size && digest.eq_ignore_ascii_case(&declared.sha256) => {}
            _ => return Err(archive_verdict("bundle member does not match its manifest")),
        }
        set_executable(&stage.join(&declared.path), declared.executable)?;
    }
    Ok((manifest, bytes))
}

fn collect_files(root: &Path, directory: &Path, out: &mut Vec<String>) -> io::Result<()> {
    let mut entries = fs::read_dir(directory)?.collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(invalid("bundle source contains a symlink"));
        }
        if metadata.is_dir() {
            collect_files(root, &path, out)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(invalid)?
                .to_str()
                .ok_or_else(|| invalid("bundle path is not UTF-8"))?
                .replace(std::path::MAIN_SEPARATOR, "/");
            if relative == MANIFEST_FILE {
                return Err(invalid("bundle source must not contain manifest.json"));
            }
            validate_relative(&relative, 1024)?;
            out.push(relative);
        } else {
            return Err(invalid("bundle source contains a non-regular file"));
        }
    }
    Ok(())
}

fn append_file(
    builder: &mut tar::Builder<zstd::stream::write::Encoder<'_, File>>,
    root: &Path,
    file: &ManifestFile,
) -> io::Result<()> {
    let mut input = File::open(root.join(&file.path))?;
    let mut header = deterministic_header(file.size, file.executable)?;
    builder.append_data(&mut header, &file.path, &mut input)
}

fn append_bytes(
    builder: &mut tar::Builder<zstd::stream::write::Encoder<'_, File>>,
    path: &str,
    bytes: &[u8],
    executable: bool,
) -> io::Result<()> {
    let mut header = deterministic_header(bytes.len() as u64, executable)?;
    builder.append_data(&mut header, path, bytes)
}

fn deterministic_header(size: u64, executable: bool) -> io::Result<tar::Header> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(size);
    header.set_mode(if executable { 0o555 } else { 0o444 });
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_cksum();
    Ok(header)
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    false
}

pub(crate) fn verify_tree(directory: &Path, manifest: &BundleManifest) -> io::Result<()> {
    let mut actual = Vec::new();
    collect_release_files(directory, directory, &mut actual)?;
    actual.sort();
    let mut expected = manifest
        .files
        .iter()
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    expected.push(MANIFEST_FILE.into());
    expected.sort();
    if actual != expected {
        return Err(invalid("release tree contains missing or unexpected files"));
    }
    for file in &manifest.files {
        let path = directory.join(&file.path);
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.is_file() || metadata.len() != file.size {
            return Err(invalid("release file type or size drifted"));
        }
        if !sha256_file(&path)?.eq_ignore_ascii_case(&file.sha256) {
            return Err(invalid("release file digest drifted"));
        }
        verify_executable(&metadata, file.executable)?;
    }
    Ok(())
}

#[cfg(unix)]
fn verify_executable(metadata: &fs::Metadata, expected: bool) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let actual = metadata.permissions().mode() & 0o111 != 0;
    if actual != expected {
        return Err(invalid("release executable permission drifted"));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_executable(_metadata: &fs::Metadata, _expected: bool) -> io::Result<()> {
    Ok(())
}

fn collect_release_files(root: &Path, directory: &Path, out: &mut Vec<String>) -> io::Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(invalid("release tree contains a symlink"));
        }
        if metadata.is_dir() {
            collect_release_files(root, &path, out)?;
        } else if metadata.is_file() {
            out.push(
                path.strip_prefix(root)
                    .map_err(invalid)?
                    .to_str()
                    .ok_or_else(|| invalid("release path is not UTF-8"))?
                    .replace(std::path::MAIN_SEPARATOR, "/"),
            );
        } else {
            return Err(invalid("release tree contains a non-regular file"));
        }
    }
    Ok(())
}

fn validate_relative(path: &str, max: usize) -> io::Result<()> {
    // The byte-length bound is bundle-specific (the archive's `path_bytes` limit); confinement —
    // the traversal-critical part — is the one shared decision in `crate::path`.
    if path.len() > max {
        return Err(invalid("invalid bundle path"));
    }
    if !updated_contracts::path::is_confined_relative(path) {
        return Err(invalid("bundle path is not a confined relative path"));
    }
    Ok(())
}

fn validate_digest(value: &str) -> io::Result<()> {
    if !is_sha256_hex(value) {
        return Err(invalid("invalid SHA-256 digest"));
    }
    Ok(())
}

#[cfg(unix)]
fn set_executable(path: &Path, executable: bool) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(
        path,
        fs::Permissions::from_mode(if executable { 0o555 } else { 0o444 }),
    )
}

#[cfg(not(unix))]
fn set_executable(path: &Path, _executable: bool) -> io::Result<()> {
    let mut permissions = fs::metadata(path)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions)
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("bundle-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn deterministic_bundle_round_trips_to_an_immutable_release() {
        let root = root("roundtrip");
        let source = root.join("source");
        fs::create_dir_all(source.join("bin")).unwrap();
        fs::create_dir_all(source.join("config")).unwrap();
        fs::write(source.join("bin/app"), b"same executable").unwrap();
        fs::write(source.join("config/release.toml"), b"version = \"2.0.0\"\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(source.join("bin/app"), fs::Permissions::from_mode(0o755)).unwrap();
        }
        let archive = root.join("bundle.tar.zst");
        create_bundle(
            &source,
            &archive,
            "app",
            "2.0.0",
            "test-platform",
            &Entrypoints::new("bin/app"),
        )
        .unwrap();
        let staged = stage_bundle(
            &archive,
            &root.join("staging"),
            &root.join("versions"),
            &ExpectedBundle {
                product: "app",
                version: "2.0.0",
                platform: "test-platform",
            },
            &BundleLimits::default(),
        )
        .unwrap();
        let dir = root.join("versions").join(staged.id.directory_name());
        assert_eq!(
            fs::read(dir.join("config/release.toml")).unwrap(),
            b"version = \"2.0.0\"\n"
        );
        let (_, entrypoint) = read_release(&root.join("versions"), &staged.id).unwrap();
        assert_eq!(entrypoint, dir.join("bin/app"));

        // The committed tree is only trusted while it still matches the authenticated manifest.
        fs::write(dir.join("undeclared"), b"drift").unwrap();
        assert!(read_release(&root.join("versions"), &staged.id).is_err());
    }

    fn sample_archive(root: &Path, version: &str) -> PathBuf {
        let source = root.join(format!("source-{version}"));
        fs::create_dir_all(source.join("bin")).unwrap();
        fs::write(source.join("bin/app"), b"executable").unwrap();
        let archive = root.join(format!("bundle-{version}.tar.zst"));
        create_bundle(
            &source,
            &archive,
            "app",
            version,
            "test-platform",
            &Entrypoints::new("bin/app"),
        )
        .unwrap();
        archive
    }

    fn stage(archive: &Path, staging: &Path, versions: &Path, version: &str) -> StagedRelease {
        stage_bundle(
            archive,
            staging,
            versions,
            &ExpectedBundle {
                product: "app",
                version,
                platform: "test-platform",
            },
            &BundleLimits::default(),
        )
        .unwrap()
    }

    /// A kill between creating the extraction directory and renaming it into `versions/` leaves
    /// a fully expanded release behind, and nothing else in the system sweeps `staging/`. The
    /// next attempt must reclaim it, so repeated interrupted stages cannot accumulate copies
    /// until the disk fills — and it must do so without any notion of how long ago the dead
    /// attempt last made progress.
    #[test]
    fn an_interrupted_stage_is_reclaimed_by_the_next_one() {
        let root = root("stage-leak");
        let staging = root.join("staging");
        let archive = sample_archive(&root, "1.0.0");

        // Two interrupted attempts: the leftovers of a killed extraction, twice over. A SIGKILL
        // leaves the expanded tree and its owner file behind, with the owner lock released by the
        // kernel as the process dies — which is exactly this on-disk state.
        fs::create_dir_all(&staging).unwrap();
        for token in ["aaaa", "bbbb"] {
            let dir = staging.join(format!("{STAGE_PREFIX}{token}"));
            fs::create_dir_all(dir.join("bin")).unwrap();
            fs::write(dir.join("bin/app"), vec![0u8; 4096]).unwrap();
            fs::write(
                staging.join(format!("{STAGE_PREFIX}{token}{OWNER_SUFFIX}")),
                b".",
            )
            .unwrap();
        }
        assert_eq!(fs::read_dir(&staging).unwrap().count(), 4);

        let staged = stage(&archive, &staging, &root.join("versions"), "1.0.0");
        assert!(root
            .join("versions")
            .join(staged.id.directory_name())
            .is_dir());
        // The successful stage renamed its directory away and no abandoned attempt survives it.
        assert_eq!(fs::read_dir(&staging).unwrap().count(), 0);
    }

    /// Two attempts staging into one staging root at the same time — two supervisor generations
    /// across a self-update, or a hand-run tool — must not interact at all: neither is refused,
    /// and neither's live tree is touched by the other's sweep.
    #[test]
    fn concurrent_attempts_are_isolated_rather_than_serialized() {
        let root = root("stage-concurrent");
        let staging = root.join("staging");
        let versions = root.join("versions");
        fs::create_dir_all(&staging).unwrap();

        let held = Stage::create(&staging).unwrap();
        fs::write(held.path().join("in-flight"), b"live extraction").unwrap();

        // A second attempt succeeds, and its sweep leaves the live one alone.
        let second = Stage::create(&staging).unwrap();
        assert_ne!(second.path(), held.path());
        assert!(
            held.path().join("in-flight").is_file(),
            "a live extraction tree must survive another attempt's sweep"
        );
        drop(second);

        // A whole staging run overlapping a live attempt likewise succeeds.
        let archive = sample_archive(&root, "1.0.0");
        let staged = stage(&archive, &staging, &versions, "1.0.0");
        assert!(versions.join(staged.id.directory_name()).is_dir());
        assert!(held.path().join("in-flight").is_file());

        // And the live attempt's leftovers go away once it is itself gone.
        drop(held);
        let staged = stage(&archive, &staging, &versions, "1.0.0");
        assert!(versions.join(staged.id.directory_name()).is_dir());
        assert_eq!(fs::read_dir(&staging).unwrap().count(), 0);
    }

    /// The sweep owns only the attempts it named; everything else in a staging root belongs to
    /// someone else. `bundle.download` — the archive being staged FROM — lives here.
    #[test]
    fn the_sweep_leaves_the_rest_of_the_staging_root_alone() {
        let root = root("stage-neighbours");
        let staging = root.join("staging");
        let versions = root.join("versions");
        fs::create_dir_all(&staging).unwrap();
        let archive = staging.join("bundle.download");
        fs::copy(sample_archive(&root, "1.0.0"), &archive).unwrap();

        let staged = stage(&archive, &staging, &versions, "1.0.0");
        assert!(versions.join(staged.id.directory_name()).is_dir());
        assert!(archive.is_file(), "the download being staged from survives");
    }

    /// Anything planted under an attempt name is discarded rather than opened, locked, or
    /// descended into — a symlink there must never be followed out of the staging root.
    #[test]
    fn hostile_entries_under_an_attempt_name_are_discarded_not_followed() {
        let root = root("stage-hostile");
        let staging = root.join("staging");
        fs::create_dir_all(&staging).unwrap();
        fs::write(staging.join("stage-stray.owner"), b"not a lock file").unwrap();
        fs::create_dir_all(staging.join("stage-stray")).unwrap();

        #[cfg(unix)]
        let elsewhere = {
            let elsewhere = root.join("elsewhere");
            fs::create_dir_all(&elsewhere).unwrap();
            fs::write(elsewhere.join("precious"), b"do not touch").unwrap();
            std::os::unix::fs::symlink(&elsewhere, staging.join("stage-link.owner")).unwrap();
            elsewhere
        };

        drop(Stage::create(&staging).unwrap());
        assert!(!staging.join("stage-stray").exists());
        assert!(!staging.join("stage-stray.owner").exists());
        #[cfg(unix)]
        {
            assert!(!staging.join("stage-link.owner").exists());
            assert!(
                elsewhere.join("precious").is_file(),
                "a symlink under an attempt name is never followed"
            );
        }
    }

    /// The whole point of the typed [`InstallError`]: a staging failure must be structurally
    /// incapable of being read as a verdict on the release bytes, because a verdict is recorded
    /// durably and never expires. Only evidence about the archive itself is `Archive`.
    #[test]
    fn staging_failures_are_never_a_verdict_on_the_release_bytes() {
        let root = root("stage-verdict");
        let staging = root.join("staging");
        let versions = root.join("versions");
        let archive = sample_archive(&root, "1.0.0");

        // A staging root that cannot be used at all: local, so retryable, never rejectable.
        fs::write(&staging, b"not a directory").unwrap();
        let error = stage_bundle(
            &archive,
            &staging,
            &versions,
            &ExpectedBundle {
                product: "app",
                version: "1.0.0",
                platform: "test-platform",
            },
            &BundleLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(error, InstallError::Storage(_)), "{error}");
        fs::remove_file(&staging).unwrap();

        // A manifest that disagrees with the authenticated metadata IS a verdict on the bytes.
        let error = stage_bundle(
            &archive,
            &staging,
            &versions,
            &ExpectedBundle {
                product: "app",
                version: "2.0.0",
                platform: "test-platform",
            },
            &BundleLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(error, InstallError::Archive(_)), "{error}");

        // So is an archive over the size a target may be.
        let error = stage_bundle(
            &archive,
            &staging,
            &versions,
            &ExpectedBundle {
                product: "app",
                version: "1.0.0",
                platform: "test-platform",
            },
            &BundleLimits {
                archive_bytes: 1,
                ..BundleLimits::default()
            },
        )
        .unwrap_err();
        assert!(matches!(error, InstallError::Archive(_)), "{error}");

        // Bytes that are not an archive at all are also a verdict on the bytes.
        let garbage = root.join("garbage.tar.zst");
        fs::write(&garbage, b"this is not zstd").unwrap();
        let error = stage_bundle(
            &garbage,
            &staging,
            &versions,
            &ExpectedBundle {
                product: "app",
                version: "1.0.0",
                platform: "test-platform",
            },
            &BundleLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(error, InstallError::Archive(_)), "{error}");

        // A committed tree that drifted locally is the node's problem, not the release's — and
        // staging repairs it rather than failing, so see
        // `a_drifted_committed_release_is_repaired_by_the_next_stage` for that path. What must
        // never happen is either outcome being an `Archive` verdict.
    }

    /// A `versions/<id>` tree that drifted after it was committed used to be a dead end: staging
    /// short-circuited on `destination.exists()`, refused, and dropped the freshly extracted tree,
    /// so every later attempt failed identically and the assigned release could never install on
    /// that node again. The bytes in staging were verified member-by-member against the
    /// authenticated manifest, so they are exactly the repair.
    #[test]
    fn a_drifted_committed_release_is_repaired_by_the_next_stage() {
        let root = root("stage-repair");
        let staging = root.join("staging");
        let versions = root.join("versions");
        let archive = sample_archive(&root, "1.0.0");

        let staged = stage(&archive, &staging, &versions, "1.0.0");
        let committed = versions.join(staged.id.directory_name());
        // Two shapes of drift: an undeclared extra file, and a declared member whose bytes
        // changed. Both make `read_release` refuse the committed tree.
        fs::write(committed.join("undeclared"), b"planted").unwrap();
        // The committed member is mode 0o555, so replace it rather than write through it.
        fs::remove_file(committed.join("bin/app")).unwrap();
        fs::write(committed.join("bin/app"), b"tampered").unwrap();
        assert!(read_release(&versions, &staged.id).is_err());

        let repaired = stage(&archive, &staging, &versions, "1.0.0");
        assert_eq!(repaired.id, staged.id, "same content address");
        read_release(&versions, &repaired.id).expect("the drifted tree was replaced, not trusted");
        assert!(!committed.join("undeclared").exists());
        assert_eq!(fs::read(committed.join("bin/app")).unwrap(), b"executable");
        // Nothing of the repairing attempt is left behind in staging.
        assert_eq!(fs::read_dir(&staging).unwrap().count(), 0);
    }

    /// Build an archive whose entries are written verbatim, so a caller can plant the path
    /// collisions `create_bundle` makes unrepresentable.
    fn raw_archive(path: &Path, entries: &[(&str, &[u8])]) {
        let encoder = zstd::stream::write::Encoder::new(File::create(path).unwrap(), 1).unwrap();
        let mut tar = tar::Builder::new(encoder);
        tar.mode(tar::HeaderMode::Deterministic);
        for (name, bytes) in entries {
            append_bytes(&mut tar, name, bytes, false).unwrap();
        }
        tar.into_inner()
            .unwrap()
            .finish()
            .unwrap()
            .sync_all()
            .unwrap();
    }

    /// An archive whose entries collide on a destination path is malformed *bytes* — reproducible
    /// on every node and every retry — so it must be an `Archive` verdict the supervisor can
    /// reject and descend past. Classified as `Storage` (which is what a bare `?` on
    /// `create_new`/`create_dir_all` yields) the same bad version is retried on every boot forever
    /// and the ordered fallback never runs.
    #[test]
    fn colliding_archive_entries_are_a_verdict_on_the_bytes() {
        let root = root("collision");
        let staging = root.join("staging");
        let versions = root.join("versions");
        let expected = ExpectedBundle {
            product: "app",
            version: "1.0.0",
            platform: "test-platform",
        };

        // A repeated path, and a file whose name a later entry needs to be a directory.
        for (name, entries) in [
            (
                "duplicate.tar.zst",
                vec![("bin/app", &b"first"[..]), ("bin/app", &b"second"[..])],
            ),
            (
                "file-then-dir.tar.zst",
                vec![("a", &b"file"[..]), ("a/b", &b"under a file"[..])],
            ),
        ] {
            let archive = root.join(name);
            raw_archive(&archive, &entries);
            let error = stage_bundle(
                &archive,
                &staging,
                &versions,
                &expected,
                &BundleLimits::default(),
            )
            .unwrap_err();
            assert!(matches!(error, InstallError::Archive(_)), "{name}: {error}");
            assert!(
                error.to_string().contains("duplicate bundle member"),
                "{name}: the collision must be named, not inferred: {error}"
            );
        }

        // The classification is about collisions specifically: a well-formed archive that merely
        // lacks its manifest is still a verdict on the bytes, and no other errno is swept in.
        let archive = root.join("no-manifest.tar.zst");
        raw_archive(&archive, &[("bin/app", &b"only member"[..])]);
        let error = stage_bundle(
            &archive,
            &staging,
            &versions,
            &expected,
            &BundleLimits::default(),
        )
        .unwrap_err();
        assert!(matches!(error, InstallError::Archive(_)), "{error}");
    }

    #[test]
    fn manifest_rejects_unknown_fields_and_escaping_paths() {
        let expected = ExpectedBundle {
            product: "app",
            version: "1.0.0",
            platform: "test",
        };
        let unknown = br#"{"schema":1,"product":"app","version":"1.0.0","platform":"test","entrypoint":"bin/app","files":[],"legacy":true}"#;
        assert!(BundleManifest::parse(unknown, &expected).is_err());
        let escaping = br#"{"schema":1,"product":"app","version":"1.0.0","platform":"test","entrypoint":"../app","files":[]}"#;
        assert!(BundleManifest::parse(escaping, &expected).is_err());
    }
}
