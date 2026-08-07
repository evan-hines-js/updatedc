//! Offline TUF repository authoring: key generation, minting/signing the initial
//! root, and publishing releases. Used by the dev/mock server and tests — never
//! by a deployed client. Single top-level `targets` role (delegations are a
//! documented production extension).

use std::collections::HashMap;
use std::io::Write;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::Ed25519KeyPair;
use tough::editor::signed::{SignedRepository, SignedRole};
use tough::editor::RepositoryEditor;
use tough::key_source::{KeySource, LocalKeySource};
use tough::schema::decoded::{Decoded, Hex};
use tough::schema::key::Key;
use tough::schema::{KeyHolder, RoleKeys, RoleType, Root, Signed, Target};
use tough::sign::{parse_keypair, Sign};
use tough::{FilesystemTransport, RepositoryLoader, TargetName};
use url::Url;

/// An authoring error.
#[derive(Debug)]
pub struct RepoError(String);

impl std::fmt::Display for RepoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for RepoError {}

type Result<T> = std::result::Result<T, RepoError>;

fn err(context: &str, e: impl std::fmt::Display) -> RepoError {
    RepoError(format!("{context}: {e}"))
}

/// Paths to the TUF role signing keys (ed25519 pkcs8). The root role carries **two keys
/// side-by-side** (an active key and a pre-provisioned successor) so the root can be
/// rotated without a flag day: a new root version is co-signed by a retained key and a
/// fresh one, and clients follow the version chain. The online roles have one key each.
pub struct Keys {
    /// Root-role keys, `roots[0]` active and any remainder pre-provisioned successors.
    pub roots: Vec<PathBuf>,
    pub targets: PathBuf,
    pub snapshot: PathBuf,
    pub timestamp: PathBuf,
}

impl Keys {
    /// The standard key file layout under `dir`: `root.pk8` (active) and, when present,
    /// `root.next.pk8` (the side-by-side successor). A repository minted single-key (e.g.
    /// the operator's assignment repo) simply has no `root.next.pk8`.
    pub fn in_dir(dir: &Path) -> Self {
        let mut roots = vec![dir.join("root.pk8")];
        let successor = dir.join("root.next.pk8");
        if successor.exists() {
            roots.push(successor);
        }
        Keys {
            roots,
            targets: dir.join("targets.pk8"),
            snapshot: dir.join("snapshot.pk8"),
            timestamp: dir.join("timestamp.pk8"),
        }
    }

    /// The single-key online roles (targets, snapshot, timestamp).
    fn online(&self) -> [(RoleType, &PathBuf); 3] {
        [
            (RoleType::Targets, &self.targets),
            (RoleType::Snapshot, &self.snapshot),
            (RoleType::Timestamp, &self.timestamp),
        ]
    }
}

/// A target to publish: its logical TUF path, the source artifact, and the signed
/// custom metadata (product/version/channel/os/arch/executable).
pub struct PublishTarget {
    pub name: String,
    pub source: PathBuf,
    pub custom: HashMap<String, serde_json::Value>,
}

impl PublishTarget {
    /// Build a target using the standard path convention
    /// `products/<product>/<channel>/<version>/<os>-<arch>/<component>` and the
    /// matching signed custom metadata.
    pub fn application(
        product: &str,
        channel: &str,
        version: &str,
        os: &str,
        arch: &str,
        component: &str,
        source: PathBuf,
    ) -> Self {
        let name = format!("products/{product}/{channel}/{version}/{os}-{arch}/{component}");
        let mut custom = HashMap::new();
        custom.insert("product".into(), product.into());
        custom.insert("channel".into(), channel.into());
        custom.insert("version".into(), version.into());
        custom.insert("os".into(), os.into());
        custom.insert("arch".into(), arch.into());
        custom.insert("executable".into(), serde_json::Value::Bool(true));
        PublishTarget {
            name,
            source,
            custom,
        }
    }

    /// Bind the provider set this application version was published with into the target's
    /// signed custom metadata. When an ordered-fallback descent selects this older app
    /// version, it re-selects exactly these providers — so the app and its providers roll
    /// back as one signed unit, never pairing an old app with the head's newer providers.
    /// The assignment's own `provider_set` still governs the assigned *head*, so providers
    /// remain independently revisable there without republishing the app.
    pub fn with_provider_set(mut self, path: &str, sha256: &str) -> Self {
        self.custom.insert(
            "provider_set".into(),
            serde_json::json!({ "path": path, "sha256": sha256 }),
        );
        self
    }
}

/// Where every byte destined for the published repository is staged: `<repo>/.publish/`.
///
/// Deliberately NOT inside `metadata/` or `targets/`. Those two directories *are* the published
/// repository: a mirror walks them whole and uploads every file below them verbatim (see
/// `updatec::publisher::upload_order`), with no notion of which names are internal. A staging
/// temp orphaned there by a crash would therefore be uploaded as a repository object and stay
/// one forever. Staging one level up, in a directory no mirror walks, makes that unrepresentable
/// rather than something a filter has to keep catching.
///
/// `.publish/` and the published directories share a filesystem, so committing a staged file is
/// still a rename, never a copy.
#[derive(Clone)]
struct Scratch(PathBuf);

impl Scratch {
    /// Open (creating if needed) the scratch for one repository, sweeping leftovers that no
    /// in-flight publish can still own.
    async fn open(repo_dir: &Path) -> Result<Self> {
        let dir = repo_dir.join(".publish");
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| err("creating publish staging directory", e))?;
        let swept = dir.clone();
        tokio::task::spawn_blocking(move || sweep_stale_staging(&swept))
            .await
            .map_err(|e| err("sweeping publish staging", e))?;
        Ok(Self(dir))
    }

    fn dir(&self) -> &Path {
        &self.0
    }
}

/// The one prefix every publish staging temp carries, so the sweep can recognize its own.
const STAGE_PREFIX: &str = ".publish-";

/// A staging entry untouched for at least this long is an abandoned crash leftover, not one a
/// publish is mid-way through — [`sweep_stale_staging`] spares anything newer, so it can run at
/// the start of a publish without racing one already in flight.
const STALE_STAGE_AGE: std::time::Duration = std::time::Duration::from_secs(60);

/// Discard every `<STAGE_PREFIX>*.tmp` leftover in `.publish/` that no live publish can still own.
///
/// This is the only sweep `.publish/` gets, and it must handle both entry kinds a publish stages:
/// individual files (one per repository object) and the whole signed metadata *generation*, which
/// is staged as a directory. `foundation::durable::sweep_stale_temps` only unlinks files, so a
/// crashed publish's generation directory would survive it forever and accumulate one per crash.
///
/// Purely hygiene, like the sweep it replaces: every failure is ignored, since the unique naming
/// means a stray staging entry can never collide with a published path.
fn sweep_stale_staging(dir: &Path) {
    let now = std::time::SystemTime::now();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(STAGE_PREFIX) || !name.ends_with(".tmp") {
            continue;
        }
        // A directory's mtime advances as roles are written into it, so an in-flight generation
        // reads as fresh for exactly as long as it is being filled.
        let recently_written = entry
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age < STALE_STAGE_AGE);
        if recently_written {
            continue;
        }
        let path = entry.path();
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            let _ = std::fs::remove_dir_all(&path);
        } else {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Stage a file that is destined for the published repository.
///
/// Every file this module commits is a signed, world-readable artifact served to the whole fleet,
/// which is the opposite of what `foundation::durable::create_temp_managed` exists for — that door
/// is for a node's own private state. The access a published object grants is therefore decided in
/// exactly one place — here, at creation, by
/// `create_temp_published` — and never repaired afterwards. A `set_permissions` fix-up would be a
/// unix-only half-measure: on Windows it is a no-op, so a protected DACL stamped at creation would
/// survive the rename and every metadata file and target object would commit unreadable to the
/// account that serves the repository.
fn stage_published(scratch: &Scratch) -> Result<(std::fs::File, PathBuf)> {
    foundation::durable::create_temp_published(scratch.dir(), STAGE_PREFIX)
        .map_err(|e| err("creating publish staging file", e))
}

/// Commit a file staged by [`stage_published`] to its published path.
///
/// The bytes are fsynced *before* the rename: a rename publishes the directory entry atomically
/// but flushes none of the file's data, so without this a power loss commits a name that resolves
/// to unwritten blocks — and neither metadata nor a content-addressed target object is ever
/// rewritten afterwards, so the damage is permanent. Callers fsync the destination directory once
/// they have committed every file of a generation.
///
/// Blocking: run it under [`blocking`], never directly on a runtime worker.
fn commit_published(staged: &Path, destination: &Path) -> Result<()> {
    std::fs::File::open(staged)
        .and_then(|file| file.sync_all())
        .map_err(|e| err("syncing published file", e))?;
    foundation::durable::replace(staged, destination)
        .map_err(|e| err("committing published file", e))
}

/// Run the filesystem work of a publish step off the runtime.
///
/// Publication is fsync-heavy — a metadata generation is one `sync_all` per role plus the
/// directory, and a release adds one per multi-hundred-megabyte target object. On a cold page
/// cache each of those parks the calling thread in the kernel for as long as the device takes,
/// and in `updatec` the publisher shares its runtime with the gateway listener, so doing it
/// inline stalls unrelated request handling. Every blocking publish step goes through here.
async fn blocking<T, F>(work: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| err("publish task", e))?
}

/// Durably place `data` at `destination`, including the fsync of the destination directory.
///
/// This is the one way bytes this process produced enter the published repository: signed roots,
/// and every role of a metadata generation. (Target objects take the other door — they are
/// already staged as whole files and are committed by rename rather than re-written.)
async fn publish_file(scratch: &Scratch, destination: &Path, data: Vec<u8>) -> Result<()> {
    let destination = destination.to_path_buf();
    let scratch = scratch.clone();
    blocking(move || publish_file_blocking(&scratch, &destination, &data)).await
}

fn publish_file_blocking(scratch: &Scratch, destination: &Path, data: &[u8]) -> Result<()> {
    let (mut file, staged) = stage_published(scratch)?;
    let written = file.write_all(data);
    drop(file);
    let result = written
        .map_err(|e| err("writing published file", e))
        .and_then(|()| commit_published(&staged, destination));
    if result.is_err() {
        let _ = std::fs::remove_file(&staged);
        return result;
    }
    foundation::durable::sync_dir(foundation::durable::parent_dir(destination))
        .map_err(|e| err("syncing published directory", e))
}

/// fsync `leaf` and every directory between it and `root` inclusive, deepest first. A
/// consistent-snapshot target name is path-like, so its object lands in a freshly created
/// nested directory whose own dirent is otherwise never persisted.
fn sync_published_dirs(root: &Path, leaf: &Path) -> Result<()> {
    let mut dir = Some(leaf);
    while let Some(current) = dir {
        foundation::durable::sync_dir(current)
            .map_err(|e| err("syncing published directory", e))?;
        if current == root {
            break;
        }
        dir = current.parent();
    }
    Ok(())
}

/// Generate the five ed25519 role keys under `keys_dir`.
///
/// Every key is created exclusively at mode 0600, so a file already standing at one of the
/// names is a hard error rather than an adoption. Minting a role key set is minting a *fresh*
/// one: a pre-existing file is of unknown provenance — a leftover from a retired root, or a
/// key planted by another local principal — and signing it into a new trust root would pin it
/// for the whole fleet while reporting success. Callers that want to keep existing keys must
/// say so by not calling this.
pub async fn generate_keys(keys_dir: &Path) -> Result<Keys> {
    tokio::fs::create_dir_all(keys_dir)
        .await
        .map_err(|e| err("creating key dir", e))?;
    let rng = SystemRandom::new();
    // Two root keys side-by-side (active + successor) so the root is rotatable from day one.
    for name in [
        "root.pk8",
        "root.next.pk8",
        "targets.pk8",
        "snapshot.pk8",
        "timestamp.pk8",
    ] {
        let pkcs8 =
            Ed25519KeyPair::generate_pkcs8(&rng).map_err(|e| err("generating ed25519 key", e))?;
        create_key_file(&keys_dir.join(name), pkcs8.as_ref())?;
    }
    Ok(Keys::in_dir(keys_dir))
}

/// Mint a single fresh ed25519 root key at `path` (mode 0600). Used to provision the new
/// successor when rotating the root. Fails if `path` already exists.
pub async fn generate_root_key(path: &Path) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| err("creating key dir", e))?;
    }
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|e| err("generating ed25519 key", e))?;
    create_key_file(path, pkcs8.as_ref())
}

/// Mint the key file itself: created exclusively (an existing key is never replaced) and
/// owner-only on every platform, because the permissions are supplied at creation by
/// [`foundation::durable::create_private_new`] — the same descriptor every other secret this
/// repository writes gets, rather than a second `OpenOptions` call site that would have to keep
/// the Windows DACL in step by hand.
fn create_key_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = foundation::durable::create_private_new(path)
        .map_err(|e| err("exclusively creating signing key", e))?;
    if let Err(e) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(err("durably writing signing key", e));
    }
    validate_key_file(path)
}

fn validate_key_file(path: &Path) -> Result<()> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| err("inspecting signing key", e))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RepoError(format!(
            "signing key {} must be a regular, non-symlink file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(RepoError(format!(
                "signing key {} must have mode 0600, found {mode:04o}",
                path.display()
            )));
        }
    }
    // Off Unix there is no mode to read back. A key this process minted is still owner-only —
    // [`create_key_file`] hands the protected descriptor to the file at creation — but a key that
    // was already on disk was created by something else, and its ACL is not inspected here. Say so
    // rather than let a reused key look as checked as a freshly minted one.
    #[cfg(not(unix))]
    {
        foundation::log::warn(
            "updated-tuf",
            &format!(
                "cannot verify the permissions of the existing signing key {} on this platform; \
                 keys minted here are owner-only at creation, one created elsewhere may not be",
                path.display()
            ),
        );
    }
    Ok(())
}

/// Initialize an empty TUF repository under `repo_dir`: mint and sign `root.json`,
/// then sign empty targets/snapshot/timestamp. Creates `metadata/` and `targets/`.
/// Build a fresh signed repository whose metadata starts at version 1.
pub async fn init(repo_dir: &Path, keys: &Keys, expiry_days: i64) -> Result<()> {
    init_from_version(repo_dir, keys, expiry_days, 1).await
}

/// Build a fresh signed repository whose root, targets, snapshot, and timestamp all start at
/// `start_version`.
///
/// Starting above 1 is what makes REPLACING a live repository usable. TUF clients remember the
/// highest metadata version they have accepted and refuse anything lower — correctly, that is
/// rollback protection — so a replacement republished at version 1 over a repository that has
/// reached version 40 is rejected by every node that ever saw the old one, forever, with no error
/// the operator would recognize as "the repository was re-initialized".
pub async fn init_from_version(
    repo_dir: &Path,
    keys: &Keys,
    expiry_days: i64,
    start_version: u64,
) -> Result<()> {
    let start = nz(start_version.max(1));
    let metadata_dir = repo_dir.join("metadata");
    let targets_dir = repo_dir.join("targets");
    tokio::fs::create_dir_all(&metadata_dir)
        .await
        .map_err(|e| err("creating metadata dir", e))?;
    tokio::fs::create_dir_all(&targets_dir)
        .await
        .map_err(|e| err("creating targets dir", e))?;
    let scratch = Scratch::open(repo_dir).await?;

    let expires = expiry(expiry_days)?;

    // Build root.json. The root role lists every provided root key (threshold 1, so any one
    // can sign a rotation); each online role has a single key.
    let mut root_keys: HashMap<Decoded<Hex>, Key> = HashMap::new();
    let mut roles: HashMap<RoleType, RoleKeys> = HashMap::new();
    let mut root_keyids = Vec::new();
    for path in &keys.roots {
        let key = load_signer(path)?.tuf_key();
        let keyid = key.key_id().map_err(|e| err("computing key id", e))?;
        root_keys.insert(keyid.clone(), key);
        root_keyids.push(keyid);
    }
    roles.insert(
        RoleType::Root,
        RoleKeys {
            keyids: root_keyids,
            threshold: nz(1),
            _extra: HashMap::new(),
        },
    );
    for (role, path) in keys.online() {
        let key = load_signer(path)?.tuf_key();
        let keyid = key.key_id().map_err(|e| err("computing key id", e))?;
        root_keys.insert(keyid.clone(), key);
        roles.insert(
            role,
            RoleKeys {
                keyids: vec![keyid],
                threshold: nz(1),
                _extra: HashMap::new(),
            },
        );
    }
    let root = Root {
        spec_version: "1.0.0".to_string(),
        // Mutable logical target names cannot be published atomically with metadata:
        // an old client may otherwise fetch newly replaced bytes and fail their hash.
        // Consistent snapshots make every client-visible target content-addressed.
        consistent_snapshot: true,
        version: start,
        expires,
        keys: root_keys,
        roles,
        _extra: HashMap::new(),
    };
    let rng = SystemRandom::new();
    let root_sources: Vec<Box<dyn KeySource>> = keys.roots.iter().map(|p| local(p)).collect();
    let signed_root = SignedRole::new(root.clone(), &KeyHolder::Root(root), &root_sources, &rng)
        .await
        .map_err(|e| err("signing root", e))?;
    // The versioned root the client fetches to walk the rotation chain, then the pinned
    // anchor that points at it.
    publish_file(
        &scratch,
        &metadata_dir.join(format!("{start}.root.json")),
        signed_root.buffer().to_vec(),
    )
    .await?;
    publish_file(
        &scratch,
        &metadata_dir.join("root.json"),
        signed_root.buffer().to_vec(),
    )
    .await?;

    // Sign empty targets/snapshot/timestamp at the starting version.
    let mut editor = RepositoryEditor::new(metadata_dir.join("root.json"))
        .await
        .map_err(|e| err("creating editor", e))?;
    editor
        .targets_version(start)
        .map_err(|e| err("targets version", e))?
        .targets_expires(expires)
        .map_err(|e| err("targets expiry", e))?
        .snapshot_version(start)
        .snapshot_expires(expires)
        .timestamp_version(start)
        .timestamp_expires(expires);
    let signed = editor
        .sign(&[
            local(&keys.targets),
            local(&keys.snapshot),
            local(&keys.timestamp),
        ])
        .await
        .map_err(|e| err("signing initial metadata", e))?;
    publish_metadata(&scratch, &signed, &metadata_dir).await?;
    Ok(())
}

/// Rotate the root role: publish a new root version whose key set is the `retained` keys
/// (which must already be in the current root, providing continuity) plus the freshly
/// minted `new_root_key`. The new version is co-signed by the retained keys — which
/// authorizes the change under the *current* root — and the new key, so clients that trust
/// any prior version follow the chain (`tough` does this automatically on load).
///
/// This is a root-key-only ceremony: the online roles (targets/snapshot/timestamp) are
/// carried forward from the current root untouched, so their keys are never needed here and
/// their signed metadata stays valid. Only `metadata/root.json` and the new versioned
/// `metadata/<n>.root.json` are written; nothing else changes.
pub async fn rotate_root(
    repo_dir: &Path,
    retained: &[PathBuf],
    new_root_key: &Path,
    expiry_days: i64,
) -> Result<()> {
    if retained.is_empty() {
        return Err(RepoError(
            "root rotation needs at least one retained key for continuity".into(),
        ));
    }
    let metadata_dir = repo_dir.join("metadata");
    let root_path = metadata_dir.join("root.json");
    let scratch = Scratch::open(repo_dir).await?;
    let bytes = tokio::fs::read(&root_path)
        .await
        .map_err(|e| err("reading root.json", e))?;
    let current: Signed<Root> =
        serde_json::from_slice(&bytes).map_err(|e| err("parsing root.json", e))?;
    let old = &current.signed;
    let old_root_role = old
        .roles
        .get(&RoleType::Root)
        .ok_or_else(|| RepoError("current root omits the root role".into()))?;

    // Carry the online roles forward from the current root, unchanged.
    let mut keys: HashMap<Decoded<Hex>, Key> = HashMap::new();
    let mut roles: HashMap<RoleType, RoleKeys> = HashMap::new();
    for role in [RoleType::Targets, RoleType::Snapshot, RoleType::Timestamp] {
        let role_keys = old
            .roles
            .get(&role)
            .ok_or_else(|| RepoError(format!("current root omits the {role:?} role")))?
            .clone();
        for keyid in &role_keys.keyids {
            let key = old
                .keys
                .get(keyid)
                .ok_or_else(|| RepoError(format!("current root omits a {role:?} key")))?
                .clone();
            keys.insert(keyid.clone(), key);
        }
        roles.insert(role, role_keys);
    }

    // New root role = retained continuity keys + the fresh successor.
    let mut root_keyids = Vec::new();
    let mut sources: Vec<Box<dyn KeySource>> = Vec::new();
    for path in retained {
        let key = load_signer(path)?.tuf_key();
        let keyid = key.key_id().map_err(|e| err("computing key id", e))?;
        if !old_root_role.keyids.contains(&keyid) {
            return Err(RepoError(format!(
                "retained key {} is not in the current root, so it cannot authorize a rotation",
                path.display()
            )));
        }
        keys.insert(keyid.clone(), key);
        root_keyids.push(keyid);
        sources.push(local(path));
    }
    let new_key = load_signer(new_root_key)?.tuf_key();
    let new_keyid = new_key.key_id().map_err(|e| err("computing key id", e))?;
    if old_root_role.keyids.contains(&new_keyid) {
        return Err(RepoError(
            "the new root key already belongs to the current root; provide a fresh key".into(),
        ));
    }
    keys.insert(new_keyid.clone(), new_key);
    root_keyids.push(new_keyid);
    sources.push(local(new_root_key));
    // The root role's threshold is repository state, not a constant: a root minted for
    // multi-party signing must not be silently downgraded to a single signature by a rotation,
    // which every node would accept because the new root is validly co-signed under the old one.
    roles.insert(
        RoleType::Root,
        RoleKeys {
            keyids: root_keyids,
            threshold: old_root_role.threshold,
            _extra: old_root_role._extra.clone(),
        },
    );

    let next_version = nz(old.version.get() + 1);
    let new_root = Root {
        spec_version: old.spec_version.clone(),
        consistent_snapshot: old.consistent_snapshot,
        version: next_version,
        expires: expiry(expiry_days)?,
        keys,
        roles,
        _extra: HashMap::new(),
    };
    let rng = SystemRandom::new();
    let signed_root = SignedRole::new(new_root.clone(), &KeyHolder::Root(new_root), &sources, &rng)
        .await
        .map_err(|e| err("signing rotated root", e))?;
    // The versioned root is what clients fetch to walk the rotation chain; the unversioned
    // pointer is the anchor for new enrollments, so it is committed second — a crash between
    // the two leaves the anchor on a root whose successor is already durable.
    publish_file(
        &scratch,
        &metadata_dir.join(format!("{next_version}.root.json")),
        signed_root.buffer().to_vec(),
    )
    .await?;
    publish_file(&scratch, &root_path, signed_root.buffer().to_vec()).await
}

/// Renew the root role: publish the CURRENT key set again, at the next version and a fresh
/// expiry, signed by whichever of `root_keys` the current root already trusts.
///
/// Renewal, not rotation: nothing about the trust in the repository changes, only how long the
/// document is valid for. That is what makes it safe to run unattended on a timer — a client
/// pinned to any earlier root follows the version chain to this one exactly as it would a
/// rotation, and no key has to be minted, distributed, or persisted anywhere. Root metadata is
/// the one document `replace_release` never touches, so without this a repository that keeps
/// publishing still hard-expires at its original root's expiry and every client stops loading it.
///
/// Like [`rotate_root`], only `metadata/root.json` and the new versioned `metadata/<n>.root.json`
/// are written; the online roles are carried forward untouched and their signed metadata stays
/// valid.
pub async fn renew_root(repo_dir: &Path, root_keys: &[PathBuf], expiry_days: i64) -> Result<()> {
    let metadata_dir = repo_dir.join("metadata");
    let root_path = metadata_dir.join("root.json");
    let scratch = Scratch::open(repo_dir).await?;
    let bytes = tokio::fs::read(&root_path)
        .await
        .map_err(|e| err("reading root.json", e))?;
    let current: Signed<Root> =
        serde_json::from_slice(&bytes).map_err(|e| err("parsing root.json", e))?;
    let old = &current.signed;
    let old_root_role = old
        .roles
        .get(&RoleType::Root)
        .ok_or_else(|| RepoError("current root omits the root role".into()))?;

    // Sign with whatever of the supplied set the current root actually lists, and let the role's
    // own threshold decide whether that is enough. Key-set drift is normal — a rotation retires a
    // key the operator's directory still holds, and the caller hands the whole directory over — and
    // refusing the renewal outright for one stray key made every reconcile a hard failure at
    // exactly the moment the root is closest to expiring.
    let mut sources: Vec<Box<dyn KeySource>> = Vec::new();
    for path in root_keys {
        let key = load_signer(path)?.tuf_key();
        let keyid = key.key_id().map_err(|e| err("computing key id", e))?;
        if old_root_role.keyids.contains(&keyid) {
            sources.push(local(path));
        }
    }
    if (sources.len() as u64) < old_root_role.threshold.get() {
        return Err(RepoError(format!(
            "root renewal needs {} of the current root's keys, but only {} of the {} supplied are \
             in it",
            old_root_role.threshold,
            sources.len(),
            root_keys.len()
        )));
    }

    let next_version = nz(old.version.get() + 1);
    let renewed = Root {
        spec_version: old.spec_version.clone(),
        consistent_snapshot: old.consistent_snapshot,
        version: next_version,
        expires: expiry(expiry_days)?,
        keys: old.keys.clone(),
        roles: old.roles.clone(),
        _extra: old._extra.clone(),
    };
    let rng = SystemRandom::new();
    let signed_root = SignedRole::new(renewed.clone(), &KeyHolder::Root(renewed), &sources, &rng)
        .await
        .map_err(|e| err("signing renewed root", e))?;
    // Same commit order as a rotation: the versioned document first, so a crash between the two
    // leaves the anchor pointing at a root whose successor is already durable.
    publish_file(
        &scratch,
        &metadata_dir.join(format!("{next_version}.root.json")),
        signed_root.buffer().to_vec(),
    )
    .await?;
    publish_file(&scratch, &root_path, signed_root.buffer().to_vec()).await
}

/// Publish a release: register `targets`, bump targets/snapshot/timestamp, and
/// re-sign. The target artifacts are copied into `targets/`.
pub async fn add_release(
    repo_dir: &Path,
    keys: &Keys,
    targets: Vec<PublishTarget>,
    expiry_days: i64,
) -> Result<()> {
    publish_release(repo_dir, keys, targets, expiry_days, false).await
}

/// Publish an exact target set, removing every target that is not in `targets` from
/// the new metadata generation. Immutable target objects remain on disk for readers
/// pinned to an older metadata snapshot.
pub async fn replace_release(
    repo_dir: &Path,
    keys: &Keys,
    targets: Vec<PublishTarget>,
    expiry_days: i64,
) -> Result<()> {
    publish_release(repo_dir, keys, targets, expiry_days, true).await
}

async fn publish_release(
    repo_dir: &Path,
    keys: &Keys,
    targets: Vec<PublishTarget>,
    expiry_days: i64,
    replace_targets: bool,
) -> Result<()> {
    let metadata_dir = repo_dir.join("metadata");
    let targets_dir = repo_dir.join("targets");
    let root_path = metadata_dir.join("root.json");
    let scratch = Scratch::open(repo_dir).await?;

    // Validate every filesystem-bound name before hashing, signing, or copying anything.
    for pt in &targets {
        validate_target_name(&pt.name)?;
    }

    // Snapshot each caller-owned artifact once into exclusive repository staging. The
    // signed hash and the eventually published bytes are both read from this immutable
    // copy, so a concurrent build/cleanup process cannot change the source between hash
    // and publication.
    let mut staged = StagedArtifacts::default();
    for pt in &targets {
        // Staged with the access the *published* object needs, because this staging copy is the
        // object: it is committed by rename, never re-created at its final path.
        let (file, path) = stage_published(&scratch)?;
        let mut dst = tokio::fs::File::from_std(file);
        let mut src = tokio::fs::File::open(&pt.source)
            .await
            .map_err(|e| err("opening target artifact", e))?;
        tokio::io::copy(&mut src, &mut dst)
            .await
            .map_err(|e| err("staging target artifact", e))?;
        dst.sync_all()
            .await
            .map_err(|e| err("syncing target artifact", e))?;
        drop(dst);
        staged.0.push(path);
    }

    // Load the current repository to learn its metadata versions (bump = +1).
    let root = tokio::fs::read(&root_path)
        .await
        .map_err(|e| err("reading root.json", e))?;
    let repo = RepositoryLoader::new(&root, dir_url(&metadata_dir)?, dir_url(&targets_dir)?)
        .transport(FilesystemTransport)
        .expiration_enforcement(tough::ExpirationEnforcement::Unsafe)
        .load()
        .await
        .map_err(|e| err("loading repository to edit", e))?;
    let next_targets = nz(repo.targets().signed.version.get() + 1);
    let next_snapshot = nz(repo.snapshot().signed.version.get() + 1);
    let next_timestamp = nz(repo.timestamp().signed.version.get() + 1);

    let expires = expiry(expiry_days)?;
    let mut editor = RepositoryEditor::from_repo(&root_path, repo)
        .await
        .map_err(|e| err("opening editor from repo", e))?;
    editor
        .targets_version(next_targets)
        .map_err(|e| err("targets version", e))?
        .targets_expires(expires)
        .map_err(|e| err("targets expiry", e))?
        .snapshot_version(next_snapshot)
        .snapshot_expires(expires)
        .timestamp_version(next_timestamp)
        .timestamp_expires(expires);

    if replace_targets {
        editor
            .clear_targets()
            .map_err(|e| err("clearing previous targets", e))?;
    }

    // The digest signed into metadata is also the object's published name, so both are taken
    // from this one hash of the staged bytes — the published path can never disagree with what
    // the metadata says the bytes hash to.
    let mut digests = Vec::with_capacity(targets.len());
    for (pt, staged_path) in targets.iter().zip(&staged.0) {
        let mut target = Target::from_path(staged_path)
            .await
            .map_err(|e| err("hashing target", e))?;
        digests.push(hex::encode(&target.hashes.sha256));
        for (k, v) in &pt.custom {
            target.custom.insert(k.clone(), v.clone());
        }
        editor
            .add_target(pt.name.as_str(), target)
            .map_err(|e| err("adding target", e))?;
    }

    let signed = editor
        .sign(&[
            local(&keys.targets),
            local(&keys.snapshot),
            local(&keys.timestamp),
        ])
        .await
        .map_err(|e| err("signing release", e))?;

    // Publish immutable, digest-prefixed target objects before metadata can reference
    // them. An old metadata snapshot continues fetching its old digest while a new one
    // fetches the new digest, so concurrent readers never observe mixed generations.
    //
    // The staged copy IS the published object: its bytes were fsynced when it was staged and
    // hashed into the metadata just signed, so committing it is a rename, never a second copy
    // that could be interrupted half-written. The commit is unconditional — a destination left
    // truncated by an earlier kill is repaired rather than skipped, and rewriting a
    // content-addressed path with identical bytes is invisible to a concurrent reader.
    let mut commits = Vec::with_capacity(targets.len());
    for ((pt, staged_path), digest) in targets.iter().zip(&staged.0).zip(&digests) {
        let name = TargetName::new(&pt.name).map_err(|e| err("parsing target name", e))?;
        commits.push((
            staged_path.clone(),
            targets_dir.join(format!("{digest}.{}", name.resolved())),
        ));
    }
    let objects_dir = targets_dir.clone();
    blocking(move || {
        for (staged_path, destination) in &commits {
            let parent = foundation::durable::parent_dir(destination);
            std::fs::create_dir_all(parent)
                .map_err(|e| err("creating target object directory", e))?;
            commit_published(staged_path, destination)?;
            sync_published_dirs(&objects_dir, parent)?;
        }
        Ok(())
    })
    .await?;

    publish_metadata(&scratch, &signed, &metadata_dir).await?;
    Ok(())
}

/// A name no other publish can ever pick, for one publish's staged signed metadata generation.
///
/// Keyed on fresh randomness rather than the process id: two publishes inside one process would
/// otherwise stage into the same directory, and each would delete and republish the other's signed
/// generation. It carries [`STAGE_PREFIX`] and the `.tmp` suffix so [`sweep_stale_staging`]
/// reclaims it if this process dies before it can be removed.
fn generation_stage(scratch: &Scratch) -> Result<PathBuf> {
    let token = updated::rand::token().map_err(|e| err("naming metadata staging", e))?;
    Ok(scratch
        .dir()
        .join(format!("{STAGE_PREFIX}generation-{token}.tmp")))
}

/// Stage a complete signed metadata generation, publish immutable/versioned roles first,
/// and atomically replace `timestamp.json` last as the sole visibility commit.
async fn publish_metadata(
    scratch: &Scratch,
    signed: &SignedRepository,
    metadata_dir: &Path,
) -> Result<()> {
    let stage = generation_stage(scratch)?;
    // `create_dir`, not `create_dir_all`: the directory is this publish's by construction, so a
    // name that somehow already exists is a failure rather than something to clear out from under
    // whoever owns it.
    tokio::fs::create_dir(&stage)
        .await
        .map_err(|e| err("creating metadata staging", e))?;
    if let Err(error) = signed.write(&stage).await {
        let _ = tokio::fs::remove_dir_all(&stage).await;
        return Err(err("staging signed metadata", error));
    }

    let staged_dir = stage.clone();
    let metadata_dir = metadata_dir.to_path_buf();
    let scratch = scratch.clone();
    let result = blocking(move || {
        let mut files = std::fs::read_dir(&staged_dir)
            .map_err(|e| err("reading metadata staging", e))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| err("reading staged metadata entry", e))?;
        files.sort_by_key(|entry| entry.file_name());
        // The signer wrote these staged files with neither the access a published object needs
        // nor a flush, so each is re-staged and committed through `publish_file_blocking` —
        // `timestamp.json` last, as the sole visibility commit for the generation.
        let publish = |entry: &std::fs::DirEntry| -> Result<()> {
            let bytes =
                std::fs::read(entry.path()).map_err(|e| err("reading staged metadata role", e))?;
            publish_file_blocking(&scratch, &metadata_dir.join(entry.file_name()), &bytes)
        };
        for entry in files
            .iter()
            .filter(|entry| entry.file_name() != "timestamp.json")
        {
            publish(entry)?;
        }
        let timestamp = files
            .iter()
            .find(|entry| entry.file_name() == "timestamp.json")
            .ok_or_else(|| RepoError("signed generation has no timestamp.json".into()))?;
        publish(timestamp)
    })
    .await;
    let _ = tokio::fs::remove_dir_all(&stage).await;
    result
}

/// Read the authenticated SHA-256 for a logical target name from the current repository.
/// Authoring tools use metadata as the single source of truth; targets exist only under
/// their consistent-snapshot digest-prefixed paths.
pub async fn target_sha256(repo_dir: &Path, name: &str) -> Result<String> {
    validate_target_name(name)?;
    let metadata_dir = repo_dir.join("metadata");
    let targets_dir = repo_dir.join("targets");
    let root = tokio::fs::read(metadata_dir.join("root.json"))
        .await
        .map_err(|e| err("reading root.json", e))?;
    let repo = RepositoryLoader::new(&root, dir_url(&metadata_dir)?, dir_url(&targets_dir)?)
        .transport(FilesystemTransport)
        .expiration_enforcement(tough::ExpirationEnforcement::Unsafe)
        .load()
        .await
        .map_err(|e| err("loading repository", e))?;
    let name = TargetName::new(name).map_err(|e| err("parsing target name", e))?;
    let target = repo
        .targets()
        .signed
        .targets
        .get(&name)
        .ok_or_else(|| RepoError(format!("target {:?} is absent from metadata", name.raw())))?;
    Ok(hex::encode(&target.hashes.sha256))
}

/// Resolve a provider set's reconciler artifact against the signed metadata a publisher already
/// holds, before the set itself is signed.
///
/// `ProviderSet::validate` is syntactic: a stale copy-paste that pairs one artifact's path with a
/// previous build's digest passes every check it makes and is signed into an immutable target. It
/// then fails once, much later and fleet-wide, when `stage_providers` calls `exact_target` on a
/// node — a cold install walks ordered fallback down past the version, and an update returns
/// `Unchanged`, so the group stalls with nothing to correct in place. The repository in hand is
/// the same signed targets metadata every agent verifies against, so resolving it here turns that
/// into a publish-time refusal with nothing signed.
///
/// One definition for every publisher (`updatectl publish-provider-set` over S3, the dev server's
/// local repository): a front end that skipped the check would sign exactly the immutable target
/// the other one refuses.
pub async fn verify_provider_set_reconciler(
    repo_dir: &Path,
    set: &updated_contracts::artifact::ProviderSet,
) -> Result<()> {
    let reference = &set.reconciler.artifact;
    let signed = target_sha256(repo_dir, &reference.path)
        .await
        .map_err(|error| {
            RepoError(format!(
                "--provider-path {:?} does not resolve in this repository's signed metadata: \
                 {error}. Publish the reconciler with `publish-provider-artifact` against this \
                 same repository first, and pass the path and digest it prints. Nothing was signed.",
                reference.path
            ))
        })?;
    if signed != reference.sha256 {
        return Err(RepoError(format!(
            "--provider-sha256 {} does not match the signed digest of --provider-path {:?}, which \
             is {signed}: the two flags name different reconciler builds. Nothing was signed.",
            reference.sha256, reference.path
        )));
    }
    Ok(())
}

/// The current generation number of the published repository: the TUF `timestamp` version, bumped
/// once per [`replace_release`]. It is the monotonic id of "what the fleet is pointed at right now",
/// the value change-tracking subscribers watermark against.
pub async fn current_version(repo_dir: &Path) -> Result<u64> {
    let metadata_dir = repo_dir.join("metadata");
    let targets_dir = repo_dir.join("targets");
    let root = tokio::fs::read(metadata_dir.join("root.json"))
        .await
        .map_err(|e| err("reading root.json", e))?;
    let repo = RepositoryLoader::new(&root, dir_url(&metadata_dir)?, dir_url(&targets_dir)?)
        .transport(FilesystemTransport)
        .expiration_enforcement(tough::ExpirationEnforcement::Unsafe)
        .load()
        .await
        .map_err(|e| err("loading repository to read version", e))?;
    Ok(repo.timestamp().signed.version.get())
}

#[derive(Default)]
struct StagedArtifacts(Vec<PathBuf>);

impl Drop for StagedArtifacts {
    fn drop(&mut self) {
        for path in &self.0 {
            if let Err(e) = std::fs::remove_file(path) {
                if e.kind() != std::io::ErrorKind::NotFound {
                    eprintln!(
                        "warning: removing publish staging file {}: {e}",
                        path.display()
                    );
                }
            }
        }
    }
}

fn load_signer(path: &Path) -> Result<impl Sign> {
    let bytes = std::fs::read(path).map_err(|e| err("reading key", e))?;
    parse_keypair(&bytes).map_err(|e| err("parsing key", e))
}

fn local(path: &Path) -> Box<dyn KeySource> {
    Box::new(LocalKeySource {
        path: path.to_path_buf(),
    })
}

fn nz(n: u64) -> NonZeroU64 {
    NonZeroU64::new(n).expect("version/threshold is non-zero")
}

fn validate_target_name(name: &str) -> Result<()> {
    let parts: Vec<_> = name.split('/').collect();
    let known_layout = (parts.len() == 6 && parts[0] == "products")
        || (parts.len() == 2 && parts[0] == "provider-sets" && parts[1].ends_with(".json"))
        || (parts.len() == 3
            && parts[0] == "assignments"
            && matches!(parts[1], "agents" | "configs")
            && parts[2].ends_with(".json"));
    // Every segment must be a confined path component — the one shared traversal guard, so a target
    // name can never escape the repository key space regardless of this layout check.
    if !known_layout
        || !parts
            .iter()
            .all(|p| updated_contracts::path::is_safe_component(p))
    {
        return Err(RepoError(format!("unsafe target path {name:?}")));
    }
    Ok(())
}

fn expiry(days: i64) -> Result<jiff::Timestamp> {
    if days <= 0 {
        return Err(RepoError("expiry days must be greater than zero".into()));
    }
    let span = days
        .checked_mul(24)
        // `try_from_hours` is the only non-panicking constructor: `from_hours` aborts once
        // hours*3600 overflows i64, which `checked_mul(24)` alone does not catch.
        .and_then(jiff::SignedDuration::try_from_hours)
        .ok_or_else(|| RepoError("expiry days overflow".into()))?;
    jiff::Timestamp::now()
        .checked_add(span)
        .map_err(|e| err("expiry is outside the supported timestamp range", e))
}

fn dir_url(dir: &Path) -> Result<Url> {
    let abs = std::fs::canonicalize(dir).map_err(|e| err("canonicalizing repo dir", e))?;
    Url::from_directory_path(&abs)
        .map_err(|()| RepoError(format!("cannot form file URL for {}", abs.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_error_displays_its_message() {
        assert_eq!(RepoError("boom".into()).to_string(), "boom");
        assert_eq!(err("context", "why").to_string(), "context: why");
    }

    #[test]
    fn nz_preserves_the_value() {
        // The metadata version bump relies on this returning n, not a fixed 1.
        assert_eq!(nz(5).get(), 5);
        assert_eq!(nz(1).get(), 1);
    }

    #[test]
    fn expiry_is_days_out_in_whole_days() {
        // `days` is converted to hours as days*24 — not days+24 (~16 days) or days/24.
        let now = jiff::Timestamp::now();
        let e = expiry(365).unwrap();
        let low = now
            .checked_add(jiff::SignedDuration::from_hours(364 * 24))
            .unwrap();
        let high = now
            .checked_add(jiff::SignedDuration::from_hours(366 * 24))
            .unwrap();
        assert!(e > low && e < high, "expiry ~365 days out, got {e}");
    }

    #[test]
    fn expiry_rejects_non_positive_and_overflowing_values() {
        assert!(expiry(0).is_err());
        assert!(expiry(-1).is_err());
        assert!(expiry(i64::MAX).is_err());
        // days*24 fits in i64 but the resulting hours exceed what a SignedDuration can hold —
        // this must be an error, not a panic.
        assert!(expiry(2_562_047_788_015_216).is_err());
        assert!(expiry(384_307_168_202_282_325).is_err());
        // The largest hour count a SignedDuration accepts is still far beyond the timestamp range,
        // so it fails on the add rather than aborting.
        assert!(expiry(2_562_047_788_015_215 / 24).is_err());
    }

    #[test]
    fn target_names_are_confined_to_known_layouts() {
        assert!(validate_target_name("products/app/stable/1.0.0/linux-x86_64/app").is_ok());
        assert!(validate_target_name("assignments/agents/agent-123.json").is_ok());
        assert!(validate_target_name("assignments/node-123.json").is_err());
        assert!(validate_target_name("provider-sets/web.json").is_ok());
        assert!(validate_target_name("assignments/group/node.json").is_err());
        assert!(validate_target_name("products/../../outside/stable/1.0/app").is_err());
        assert!(validate_target_name("products/app/stable/1.0/linux/app/extra").is_err());
        assert!(validate_target_name("products/app/stable/1.0/linux/app\\evil").is_err());
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "updated-tuf-{name}-{}-{}",
            std::process::id(),
            updated::rand::token().unwrap()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn a_published_file_is_world_readable_and_leaves_no_staging_behind() {
        let repo = scratch("publish-file");
        let dir = repo.join("metadata");
        std::fs::create_dir_all(&dir).unwrap();
        let staging = Scratch::open(&repo).await.unwrap();
        let destination = dir.join("root.json");
        publish_file(&staging, &destination, b"first".to_vec())
            .await
            .unwrap();
        publish_file(&staging, &destination, b"second-and-longer".to_vec())
            .await
            .unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"second-and-longer");
        // Nothing but the published object is left in the published tree, and the staging
        // area it went through is outside that tree entirely.
        assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 1);
        assert_eq!(std::fs::read_dir(staging.dir()).unwrap().count(), 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&destination)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o644,
                "a published artifact is world-readable"
            );
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Regression: nothing a publish stages may ever appear inside the published tree.
    ///
    /// A mirror uploads every file below `metadata/` and `targets/` verbatim, so a `.publish-*.tmp`
    /// orphaned there by a crash would become a permanent repository object. Staging happens in
    /// `<repo>/.publish/`, which no mirror walks — and a leftover there, planted here as a crash
    /// would leave it, is swept by the next publish instead of being published.
    #[tokio::test]
    async fn publish_staging_never_lands_inside_the_published_tree() {
        let root = scratch("publish-staging-outside");
        let repo_dir = root.join("repo");
        let keys = generate_keys(&root.join("keys")).await.unwrap();
        init(&repo_dir, &keys, 365).await.unwrap();

        // A crash leftover, aged past the sweep's in-flight guard.
        let orphan = repo_dir.join(".publish").join(".publish-999-1-1.tmp");
        std::fs::write(&orphan, b"interrupted publish").unwrap();
        let stale = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        std::fs::File::options()
            .write(true)
            .open(&orphan)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(stale))
            .unwrap();

        let artifact = root.join("app-bin");
        std::fs::write(&artifact, b"release bytes").unwrap();
        add_release(
            &repo_dir,
            &keys,
            vec![PublishTarget::application(
                "app", "stable", "1.0.0", "linux", "x86_64", "app", artifact,
            )],
            365,
        )
        .await
        .unwrap();

        fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, out);
                } else {
                    out.push(path);
                }
            }
        }
        for published in ["metadata", "targets"] {
            let mut files = Vec::new();
            walk(&repo_dir.join(published), &mut files);
            for file in files {
                let name = file.file_name().unwrap().to_string_lossy().into_owned();
                assert!(
                    !name.starts_with('.') && !name.ends_with(".tmp"),
                    "{name} is staging state inside the published tree"
                );
            }
        }
        assert!(!orphan.exists(), "an abandoned staging temp must be swept");
        let _ = std::fs::remove_dir_all(root);
    }

    /// Two publishes in one process must not share a staging directory. Keyed on the process id
    /// they did: the second's `create_dir` would land on the first's staged generation, and
    /// whichever finished first would delete the other's roles out from under it.
    #[tokio::test]
    async fn each_publish_stages_its_generation_under_a_name_no_other_can_pick() {
        let root = scratch("generation-stage-name");
        let scratch_dir = Scratch::open(&root).await.unwrap();
        let first = generation_stage(&scratch_dir).unwrap();
        let second = generation_stage(&scratch_dir).unwrap();
        assert_ne!(first, second);
        let name = first.file_name().unwrap().to_string_lossy().into_owned();
        assert!(
            !name.contains(&std::process::id().to_string()),
            "the name must not be process-keyed: {name}"
        );
        assert!(name.starts_with(STAGE_PREFIX) && name.ends_with(".tmp"));
        let _ = std::fs::remove_dir_all(root);
    }

    /// A publish stages individual objects as files *and* a whole signed generation as a
    /// directory. `foundation::durable::sweep_stale_temps` only unlinks files, so the crash
    /// leftover the sweep exists for — an abandoned generation — would otherwise survive every
    /// later publish and accumulate one copy per crash.
    #[test]
    fn the_publish_sweep_reclaims_abandoned_generations_as_well_as_files() {
        let root = scratch("publish-sweep-kinds");
        let dir = root.join(".publish");
        std::fs::create_dir_all(&dir).unwrap();

        let aged =
            std::time::SystemTime::now() - (STALE_STAGE_AGE + std::time::Duration::from_secs(60));
        let backdate = |path: &Path| {
            // A directory cannot be opened for writing; `set_times` works on a read handle.
            let file = if path.is_dir() {
                std::fs::File::open(path).unwrap()
            } else {
                std::fs::File::options().write(true).open(path).unwrap()
            };
            file.set_times(std::fs::FileTimes::new().set_modified(aged))
                .unwrap();
        };

        // Abandoned: a staged object and a whole staged generation.
        let stale_file = dir.join(format!("{STAGE_PREFIX}1-2-3.tmp"));
        std::fs::write(&stale_file, b"orphan").unwrap();
        backdate(&stale_file);
        let stale_generation = dir.join(format!("{STAGE_PREFIX}generation-dead.tmp"));
        std::fs::create_dir(&stale_generation).unwrap();
        std::fs::write(stale_generation.join("timestamp.json"), b"{}").unwrap();
        backdate(&stale_generation);

        // In flight (fresh), and not ours (wrong prefix) — both must survive.
        let live_generation = dir.join(format!("{STAGE_PREFIX}generation-live.tmp"));
        std::fs::create_dir(&live_generation).unwrap();
        let unrelated = dir.join("keys-9-9-9.tmp");
        std::fs::write(&unrelated, b"not ours").unwrap();
        backdate(&unrelated);

        sweep_stale_staging(&dir);

        assert!(!stale_file.exists(), "an abandoned staged object survived");
        assert!(
            !stale_generation.exists(),
            "an abandoned staged generation survived the sweep"
        );
        assert!(
            live_generation.exists(),
            "an in-flight generation was yanked"
        );
        assert!(unrelated.exists());
        let _ = std::fs::remove_dir_all(root);
    }

    /// Regression: a published object's access is decided once, by the staging primitive it is
    /// created through, and never repaired afterwards — a repair would be a unix-only half of the
    /// rule and would leave every Windows publisher committing metadata and target objects that
    /// the account serving the repository cannot open. Every file of a real generation must be
    /// world-readable: the roots this module writes itself, the roles the signer writes into
    /// staging, and the content-addressed target objects.
    #[cfg(unix)]
    #[tokio::test]
    async fn every_published_metadata_role_and_target_object_is_world_readable() {
        use std::os::unix::fs::PermissionsExt;

        let root = scratch("published-modes");
        let repo_dir = root.join("repo");
        let keys = generate_keys(&root.join("keys")).await.unwrap();
        init(&repo_dir, &keys, 365).await.unwrap();
        let artifact = root.join("app-bin");
        std::fs::write(&artifact, b"release bytes").unwrap();
        add_release(
            &repo_dir,
            &keys,
            vec![PublishTarget::application(
                "app", "stable", "1.0.0", "linux", "x86_64", "app", artifact,
            )],
            365,
        )
        .await
        .unwrap();

        // A consistent-snapshot target name is path-like, so objects sit in nested directories.
        fn files(dir: &Path, out: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    files(&path, out);
                } else {
                    out.push(path);
                }
            }
        }
        for dir in ["metadata", "targets"] {
            let dir = repo_dir.join(dir);
            let mut published = Vec::new();
            files(&dir, &mut published);
            assert!(!published.is_empty(), "{} published nothing", dir.display());
            for path in published {
                assert_eq!(
                    std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                    0o644,
                    "{} must be readable by whoever serves the repository",
                    path.display()
                );
            }
        }
        let _ = std::fs::remove_dir_all(root);
    }

    /// A kill during publication can leave a target object truncated at its content-addressed
    /// path. Republishing the same release must rewrite it: skipping an existing path would
    /// make the damaged bytes permanent, since the path is derived from the digest the metadata
    /// signs and every retry lands on it again.
    #[tokio::test]
    async fn republishing_repairs_a_truncated_target_object() {
        let root = scratch("truncated-target");
        let repo_dir = root.join("repo");
        let keys = generate_keys(&root.join("keys")).await.unwrap();
        init(&repo_dir, &keys, 365).await.unwrap();

        let artifact = root.join("app-bin");
        std::fs::write(&artifact, b"complete release bytes").unwrap();
        let target = || {
            PublishTarget::application(
                "app",
                "stable",
                "1.0.0",
                "linux",
                "x86_64",
                "app",
                artifact.clone(),
            )
        };
        add_release(&repo_dir, &keys, vec![target()], 365)
            .await
            .unwrap();

        let name = target().name;
        let digest = target_sha256(&repo_dir, &name).await.unwrap();
        let object = repo_dir.join("targets").join(format!("{digest}.{name}"));
        assert_eq!(
            std::fs::read(&object).unwrap(),
            b"complete release bytes",
            "the published object is the staged artifact"
        );

        std::fs::write(&object, b"trunc").unwrap();
        add_release(&repo_dir, &keys, vec![target()], 365)
            .await
            .unwrap();
        assert_eq!(std::fs::read(&object).unwrap(), b"complete release bytes");
        let _ = std::fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn signing_keys_must_be_owner_only_regular_files() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("updated-key-check-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("root.pk8");
        std::fs::write(&key, b"key").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(validate_key_file(&key).is_err());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(validate_key_file(&key).is_ok());
        let link = dir.join("link.pk8");
        std::os::unix::fs::symlink(&key, &link).unwrap();
        assert!(validate_key_file(&link).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
