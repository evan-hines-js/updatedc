//! Offline TUF repository authoring: key generation, minting/signing the initial
//! root, and publishing releases. Used by the dev/mock server and tests — never
//! by a deployed client. Single top-level `targets` role (delegations are a
//! documented production extension).

use std::collections::HashMap;
use std::io::Write;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::Ed25519KeyPair;
use tough::editor::signed::{SignedRepository, SignedRole};
use tough::editor::RepositoryEditor;
use tough::key_source::KeySource;
use tough::schema::decoded::{Decoded, Hex};
use tough::schema::key::Key;
use tough::schema::{KeyHolder, RoleKeys, RoleType, Root, Signed, Target};
use tough::sign::{parse_keypair, Sign};
use tough::{FilesystemTransport, Repository, RepositoryLoader, TargetName};
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

/// The complete private-key set for a rotatable repository. Provisioning and controller
/// materialization both iterate this constant, so a newly minted standby root cannot be dropped
/// between the key generator and the signer.
pub const KEY_FILE_NAMES: [&str; 5] = [
    "root.pk8",
    "root.next.pk8",
    "targets.pk8",
    "snapshot.pk8",
    "timestamp.pk8",
];

/// Authoring metadata has the same fleet-scale ceiling as the routing client. This is deliberately
/// independent of artifact size: release archives stream and may be large, while every role file
/// is a bounded JSON trust document.
const AUTHORING_METADATA_MAX_BYTES: usize = 64 * 1024 * 1024;
const SIGNING_KEY_MAX_BYTES: usize = 1024 * 1024;

/// Read the current authoring root through the one bounded, no-follow trust-material path.
pub async fn root_bytes(repo_dir: &Path) -> Result<Vec<u8>> {
    crate::read_local_trust_material(
        &repo_dir.join("metadata/root.json"),
        AUTHORING_METADATA_MAX_BYTES as u64,
    )
    .await
    .map_err(|e| err("reading root.json", e))
}

/// One immutable, bounded snapshot of a local signing key.
///
/// `tough::LocalKeySource` reopens its path when signing. Reading once here makes the public key
/// placed in metadata and the private key that signs it the same bytes, closes the check/use race,
/// and keeps the no-follow/size policy in this crate rather than delegating it to an unbounded
/// convenience read.
#[derive(Clone)]
struct BoundedKeySource {
    bytes: Arc<[u8]>,
}

impl std::fmt::Debug for BoundedKeySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BoundedKeySource").finish_non_exhaustive()
    }
}

impl BoundedKeySource {
    fn load(path: &Path) -> Result<Self> {
        let bytes = foundation::file::read_bounded_private_regular(path, SIGNING_KEY_MAX_BYTES)
            .map_err(|e| err("reading key", e))?;
        // Validate eagerly so a malformed key fails at the named path boundary, before an editor
        // is mutated. `as_sign` parses the same immutable bytes again for tough's owned signer.
        validate_signing_key_bytes(&bytes)?;
        Ok(Self {
            bytes: Arc::from(bytes),
        })
    }

    fn tuf_key(&self) -> Result<Key> {
        Ok(parse_keypair(&self.bytes)
            .map_err(|e| err("parsing key", e))?
            .tuf_key())
    }

    fn boxed(&self) -> Box<dyn KeySource> {
        Box::new(self.clone())
    }
}

/// Validate one in-memory role key through the same parser and size policy used for key files.
///
/// Kubernetes Secret consumers cannot apply the local-file checks in `BoundedKeySource`, but they
/// must not invent a weaker "non-empty bytes" definition of a signing key. This is the one shared
/// cryptographic boundary for projected and file-backed authoring keys.
pub fn validate_signing_key_bytes(bytes: &[u8]) -> Result<()> {
    signing_key_id(bytes).map(|_| ())
}

/// Read and validate one file-backed signing key through the authoring boundary.
///
/// Callers that need the bytes themselves (for example, to project them into a Kubernetes Secret)
/// must not read the path first and rely on [`validate_signing_key_bytes`] to reject it afterwards:
/// by then an oversized or redirected file has already bypassed the bound and no-follow policy.
/// This is the sole file-to-bytes path for signing keys.
pub fn read_signing_key_bytes(path: &Path) -> Result<Vec<u8>> {
    let source = BoundedKeySource::load(path)?;
    Ok(source.bytes.as_ref().to_vec())
}

/// Return the canonical TUF key ID for one bounded PKCS#8 role key.
pub fn signing_key_id(bytes: &[u8]) -> Result<String> {
    if bytes.len() > SIGNING_KEY_MAX_BYTES {
        return Err(RepoError(format!(
            "signing key is {} bytes; maximum is {SIGNING_KEY_MAX_BYTES}",
            bytes.len()
        )));
    }
    let key = parse_keypair(bytes)
        .map_err(|error| err("parsing key", error))?
        .tuf_key();
    let id = key
        .key_id()
        .map_err(|error| err("calculating key ID", error))?;
    Ok(hex::encode(id.as_ref()))
}

/// The one role-separation gate for a set of signing-key snapshots.
///
/// Parsing each file is insufficient: copying one valid private key into several role slots
/// collapses TUF's compromise boundaries, while supplying one threshold key more than once must
/// never count as several signers. Callers name each slot so a duplicate reports the two pieces of
/// configuration that collapsed. File-backed authoring and projected Kubernetes Secrets both use
/// this accumulator on the exact bytes they will subsequently sign with or persist.
#[derive(Default)]
struct DistinctSigningKeys {
    slots_by_id: HashMap<String, String>,
}

impl DistinctSigningKeys {
    fn insert(&mut self, slot: &str, bytes: &[u8]) -> Result<()> {
        let id =
            signing_key_id(bytes).map_err(|error| RepoError(format!("invalid {slot}: {error}")))?;
        self.insert_id(slot, id)
    }

    fn insert_id(&mut self, slot: &str, id: String) -> Result<()> {
        if let Some(existing) = self.slots_by_id.get(&id) {
            return Err(RepoError(format!(
                "signing-key slots {existing} and {slot} contain the same public key"
            )));
        }
        self.slots_by_id.insert(id, slot.to_string());
        Ok(())
    }
}

/// Validate that every supplied signing-key snapshot is cryptographically valid and distinct.
pub fn validate_distinct_signing_keys<'a>(
    keys: impl IntoIterator<Item = (&'a str, &'a [u8])>,
) -> Result<()> {
    let mut distinct = DistinctSigningKeys::default();
    for (slot, bytes) in keys {
        distinct.insert(slot, bytes)?;
    }
    Ok(())
}

/// Validate the one complete rotatable repository-key document.
///
/// This is the Kubernetes Secret boundary: missing slots, obsolete/unknown slots, malformed keys,
/// and role-collapsed keys are all one invalid document. File-backed authoring may deliberately
/// omit the standby root for a single-key repository, so it consumes the distinct-key primitive
/// above directly instead of weakening this closed shape.
pub fn validate_complete_signing_key_set<'a>(
    keys: impl IntoIterator<Item = (&'a str, &'a [u8])>,
) -> Result<()> {
    let mut supplied = HashMap::new();
    for (slot, bytes) in keys {
        if supplied.insert(slot, bytes).is_some() {
            return Err(RepoError(format!(
                "complete signing-key set contains duplicate slot {slot}"
            )));
        }
    }
    let mut material = Vec::with_capacity(KEY_FILE_NAMES.len());
    for slot in KEY_FILE_NAMES {
        let bytes = supplied
            .remove(slot)
            .ok_or_else(|| RepoError(format!("complete signing-key set is missing {slot}")))?;
        material.push((slot, bytes));
    }
    if !supplied.is_empty() {
        let mut unexpected = supplied.keys().copied().collect::<Vec<_>>();
        unexpected.sort_unstable();
        return Err(RepoError(format!(
            "complete signing-key set contains unexpected slot(s): {}",
            unexpected.join(", ")
        )));
    }
    validate_distinct_signing_keys(material)
}

#[async_trait::async_trait]
impl KeySource for BoundedKeySource {
    async fn as_sign(
        &self,
    ) -> std::result::Result<Box<dyn Sign>, Box<dyn std::error::Error + Send + Sync + 'static>>
    {
        Ok(Box::new(parse_keypair(&self.bytes)?))
    }

    async fn write(
        &self,
        _value: &str,
        _key_id_hex: &str,
    ) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "bounded signing-key snapshots are read-only",
        )
        .into())
    }
}

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
    pub fn in_dir(dir: &Path) -> Result<Self> {
        let mut roots = vec![dir.join("root.pk8")];
        let successor = dir.join("root.next.pk8");
        if foundation::file::path_entry_exists(&successor)
            .map_err(|error| err("checking for the standby root key", error))?
        {
            // Optional means genuinely absent, not occupied-but-unusable. Validate through the
            // sole signing-key file boundary now, so discovery cannot silently downgrade a
            // two-root directory and cannot defer a symlink/mode/format failure to a later role.
            read_signing_key_bytes(&successor)?;
            roots.push(successor);
        }
        Ok(Keys {
            roots,
            targets: dir.join("targets.pk8"),
            snapshot: dir.join("snapshot.pk8"),
            timestamp: dir.join("timestamp.pk8"),
        })
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
    /// The canonical logical name used by publication and consumers referring to its target.
    pub fn application_name(
        product: &str,
        channel: &str,
        version: &str,
        os: &str,
        arch: &str,
        component: &str,
    ) -> String {
        format!("products/{product}/{channel}/{version}/{os}-{arch}/{component}")
    }

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
        let name = Self::application_name(product, channel, version, os, arch, component);
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
}

/// Where every byte destined for the published repository is staged: `<repo>/.publish/`.
///
/// Deliberately NOT inside `metadata/` or `targets/`. Those two directories *are* the published
/// repository: publication resolves its active closure below them (see
/// `updatec::publisher::publication_plan`), with no notion of which names are staging internals. A
/// staging temp orphaned there could therefore become a repository object. Staging one level up,
/// in a directory publication never considers, makes that unrepresentable rather than something a
/// filter has to keep catching.
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
        tokio::task::spawn_blocking(move || {
            foundation::durable::sweep_stale_temps(&swept, STAGE_PREFIX)
        })
        .await
        .map_err(|e| err("sweeping publish staging", e))?;
        Ok(Self(dir))
    }

    fn dir(&self) -> &Path {
        &self.0
    }
}

/// The one prefix every publish staging entry carries — files (one per repository object) and the
/// whole signed metadata *generation*, which is staged as a directory — so the shared sweep
/// recognizes its own.
const STAGE_PREFIX: &str = ".publish-";

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
/// The fsync goes through `foundation::durable::sync_file`, which opens the staged file for
/// writing: `File::open` alone yields a read-only handle, which Windows refuses to flush
/// (`ERROR_ACCESS_DENIED`).
///
/// Blocking: run it under [`blocking`], never directly on a runtime worker.
fn commit_published(staged: &Path, destination: &Path) -> Result<()> {
    foundation::durable::sync_file(staged).map_err(|e| err("syncing published file", e))?;
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
    for name in KEY_FILE_NAMES {
        let pkcs8 =
            Ed25519KeyPair::generate_pkcs8(&rng).map_err(|e| err("generating ed25519 key", e))?;
        create_key_file(&keys_dir.join(name), pkcs8.as_ref())?;
    }
    Keys::in_dir(keys_dir)
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
    BoundedKeySource::load(path).map(|_| ())
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
    let mut root_sources = Vec::new();
    let mut distinct = DistinctSigningKeys::default();
    for path in &keys.roots {
        let source = BoundedKeySource::load(path)?;
        distinct.insert(&path.display().to_string(), &source.bytes)?;
        let key = source.tuf_key()?;
        let keyid = key.key_id().map_err(|e| err("computing key id", e))?;
        root_keys.insert(keyid.clone(), key);
        root_keyids.push(keyid);
        root_sources.push(source.boxed());
    }
    roles.insert(
        RoleType::Root,
        RoleKeys {
            keyids: root_keyids,
            threshold: nz(1),
            _extra: HashMap::new(),
        },
    );
    let mut online_sources = Vec::new();
    for (role, path) in keys.online() {
        let source = BoundedKeySource::load(path)?;
        distinct.insert(&path.display().to_string(), &source.bytes)?;
        let key = source.tuf_key()?;
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
        online_sources.push(source.boxed());
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
        .sign(&online_sources)
        .await
        .map_err(|e| err("signing initial metadata", e))?;
    publish_metadata(&scratch, &signed, &metadata_dir).await?;
    Ok(())
}

/// Republish the root role: read the current root, build its successor at the next version with a
/// fresh expiry, sign it, and commit the versioned document before the unversioned anchor.
///
/// A renewal is a rotation with an unchanged key set and role map, so this is the whole of both
/// ceremonies except the one thing they genuinely differ in: `plan` receives the current root and
/// its root role, and answers with the key set, the role map, and the keys that sign. Everything
/// else — the version bump, carrying `spec_version` / `consistent_snapshot` / `_extra` forward, the
/// expiry, and the commit order — lives here once, so a change to any of it moves both ceremonies
/// together instead of drifting between two copies (which is how one of them came to drop the
/// root's `_extra` while the other kept it).
async fn republish_root(
    repo_dir: &Path,
    expiry_days: i64,
    plan: impl FnOnce(
        &Root,
        &RoleKeys,
    ) -> Result<(
        HashMap<Decoded<Hex>, Key>,
        HashMap<RoleType, RoleKeys>,
        Vec<Box<dyn KeySource>>,
    )>,
) -> Result<()> {
    let metadata_dir = repo_dir.join("metadata");
    let root_path = metadata_dir.join("root.json");
    let scratch = Scratch::open(repo_dir).await?;
    let bytes = root_bytes(repo_dir).await?;
    let current: Signed<Root> =
        serde_json::from_slice(&bytes).map_err(|e| err("parsing root.json", e))?;
    let old = &current.signed;
    let old_root_role = old
        .roles
        .get(&RoleType::Root)
        .ok_or_else(|| RepoError("current root omits the root role".into()))?;
    let (keys, roles, sources) = plan(old, old_root_role)?;

    let next_version = next_version(old.version, "root")?;
    let next = Root {
        spec_version: old.spec_version.clone(),
        consistent_snapshot: old.consistent_snapshot,
        version: next_version,
        expires: expiry(expiry_days)?,
        keys,
        roles,
        _extra: old._extra.clone(),
    };
    let rng = SystemRandom::new();
    let signed_root = SignedRole::new(next.clone(), &KeyHolder::Root(next), &sources, &rng)
        .await
        .map_err(|e| err("signing republished root", e))?;
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
    republish_root(repo_dir, expiry_days, |old, old_root_role| {
        // Carry the online roles forward from the current root, unchanged.
        let mut keys: HashMap<Decoded<Hex>, Key> = HashMap::new();
        let mut roles: HashMap<RoleType, RoleKeys> = HashMap::new();
        let mut distinct = DistinctSigningKeys::default();
        for role in [RoleType::Targets, RoleType::Snapshot, RoleType::Timestamp] {
            let role_keys = old
                .roles
                .get(&role)
                .ok_or_else(|| RepoError(format!("current root omits the {role:?} role")))?
                .clone();
            for (index, keyid) in role_keys.keyids.iter().enumerate() {
                let key = old
                    .keys
                    .get(keyid)
                    .ok_or_else(|| RepoError(format!("current root omits a {role:?} key")))?
                    .clone();
                distinct.insert_id(
                    &format!("current {role:?}[{index}]"),
                    hex::encode(keyid.as_ref()),
                )?;
                keys.insert(keyid.clone(), key);
            }
            roles.insert(role, role_keys);
        }

        // New root role = retained continuity keys + the fresh successor.
        let mut root_keyids = Vec::new();
        let mut sources: Vec<Box<dyn KeySource>> = Vec::new();
        for path in retained {
            let source = BoundedKeySource::load(path)?;
            distinct.insert(&path.display().to_string(), &source.bytes)?;
            let key = source.tuf_key()?;
            let keyid = key.key_id().map_err(|e| err("computing key id", e))?;
            if !old_root_role.keyids.contains(&keyid) {
                return Err(RepoError(format!(
                    "retained key {} is not in the current root, so it cannot authorize a rotation",
                    path.display()
                )));
            }
            keys.insert(keyid.clone(), key);
            root_keyids.push(keyid);
            sources.push(source.boxed());
        }
        let new_source = BoundedKeySource::load(new_root_key)?;
        distinct.insert(&new_root_key.display().to_string(), &new_source.bytes)?;
        let new_key = new_source.tuf_key()?;
        let new_keyid = new_key.key_id().map_err(|e| err("computing key id", e))?;
        if old_root_role.keyids.contains(&new_keyid) {
            return Err(RepoError(
                "the new root key already belongs to the current root; provide a fresh key".into(),
            ));
        }
        keys.insert(new_keyid.clone(), new_key);
        root_keyids.push(new_keyid);
        sources.push(new_source.boxed());
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
        Ok((keys, roles, sources))
    })
    .await
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
    republish_root(repo_dir, expiry_days, |old, old_root_role| {
        // Sign with whatever of the supplied set the current root actually lists, and let the
        // role's own threshold decide whether that is enough. Key-set drift is normal — a rotation
        // retires a key the operator's directory still holds, and the caller hands the whole
        // directory over — and refusing the renewal outright for one stray key made every reconcile
        // a hard failure at exactly the moment the root is closest to expiring.
        let mut sources: Vec<Box<dyn KeySource>> = Vec::new();
        let mut distinct = DistinctSigningKeys::default();
        for role in [RoleType::Targets, RoleType::Snapshot, RoleType::Timestamp] {
            let role_keys = old
                .roles
                .get(&role)
                .ok_or_else(|| RepoError(format!("current root omits the {role:?} role")))?;
            for (index, keyid) in role_keys.keyids.iter().enumerate() {
                distinct.insert_id(
                    &format!("current {role:?}[{index}]"),
                    hex::encode(keyid.as_ref()),
                )?;
            }
        }
        for path in root_keys {
            let source = BoundedKeySource::load(path)?;
            let key = source.tuf_key()?;
            let keyid = key.key_id().map_err(|e| err("computing key id", e))?;
            if old_root_role.keyids.contains(&keyid) {
                distinct.insert_id(&path.display().to_string(), hex::encode(keyid.as_ref()))?;
                sources.push(source.boxed());
            }
        }
        if (sources.len() as u64) < old_root_role.threshold.get() {
            return Err(RepoError(format!(
                "root renewal needs {} of the current root's keys, but only {} of the {} supplied \
                 are in it",
                old_root_role.threshold,
                sources.len(),
                root_keys.len()
            )));
        }
        // Nothing about the trust changes: the same keys under the same roles, at a later expiry.
        Ok((old.keys.clone(), old.roles.clone(), sources))
    })
    .await
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
        let source = pt.source.clone();
        let source_display = source.display().to_string();
        let opened = tokio::task::spawn_blocking(move || {
            foundation::file::open_regular(&source, foundation::file::FinalSymlink::Refuse)
        })
        .await
        .map_err(|e| err("opening target artifact task", e))?
        .map_err(|e| err(&format!("opening target artifact {source_display}"), e))?;
        let mut src = tokio::fs::File::from_std(opened);
        tokio::io::copy(&mut src, &mut dst)
            .await
            .map_err(|e| err("staging target artifact", e))?;
        dst.sync_all()
            .await
            .map_err(|e| err("syncing target artifact", e))?;
        drop(dst);
        staged.0.push(path);
    }

    // Load the current repository and advance every role through the one checked version gate.
    // A repository at u64::MAX is exhausted, not permission to panic or wrap rollback protection.
    let repo = load_local(repo_dir, "loading repository to edit").await?;
    let next_targets = next_version(repo.targets().signed.version, "targets")?;
    let next_snapshot = next_version(repo.snapshot().signed.version, "snapshot")?;
    let next_timestamp = next_version(repo.timestamp().signed.version, "timestamp")?;

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

    let online = [
        ("targets.pk8", BoundedKeySource::load(&keys.targets)?),
        ("snapshot.pk8", BoundedKeySource::load(&keys.snapshot)?),
        ("timestamp.pk8", BoundedKeySource::load(&keys.timestamp)?),
    ];
    validate_distinct_signing_keys(
        online
            .iter()
            .map(|(slot, source)| (*slot, source.bytes.as_ref())),
    )?;
    let online_sources = online.map(|(_, source)| source.boxed());
    let signed = editor
        .sign(&online_sources)
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
/// generation. It carries [`STAGE_PREFIX`] and the `.tmp` suffix so the shared
/// `foundation::durable::sweep_stale_temps` reclaims it — directory and all — if this process
/// dies before it can be removed.
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
    // Directory mtime cannot distinguish a stalled writer from an orphan: writes to children do
    // not refresh it. Hold an OS lock until every staged role has been published, so a concurrent
    // Scratch::open can reclaim crash leftovers without ever deleting this live generation.
    let stage_lease = match foundation::durable::lease_temp_directory(&stage) {
        Ok(lease) => lease,
        Err(error) => {
            let _ = tokio::fs::remove_dir_all(&stage).await;
            return Err(err("leasing metadata staging", error));
        }
    };
    if let Err(error) = signed.write(&stage).await {
        drop(stage_lease);
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
        files.retain(|entry| entry.file_name() != foundation::durable::TEMP_DIRECTORY_LEASE_FILE);
        files.sort_by_key(|entry| entry.file_name());
        // The signer wrote these staged files with neither the access a published object needs
        // nor a flush, so each is re-staged and committed through `publish_file_blocking` —
        // `timestamp.json` last, as the sole visibility commit for the generation.
        let publish = |entry: &std::fs::DirEntry| -> Result<()> {
            let bytes = foundation::file::read_bounded_regular(
                &entry.path(),
                AUTHORING_METADATA_MAX_BYTES,
                foundation::file::FinalSymlink::Refuse,
            )
            .map_err(|e| err("reading staged metadata role", e))?;
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
    drop(stage_lease);
    let _ = tokio::fs::remove_dir_all(&stage).await;
    result
}

/// Read the authenticated SHA-256 for a logical target name from the current repository.
/// Authoring tools use metadata as the single source of truth; targets exist only under
/// their consistent-snapshot digest-prefixed paths.
pub async fn target_sha256(repo_dir: &Path, name: &str) -> Result<String> {
    target_sha256_if_present(repo_dir, name)
        .await?
        .ok_or_else(|| RepoError(format!("target {name:?} is absent from metadata")))
}

/// Read an authenticated target digest when the target exists.
///
/// Absence is the only condition represented by `None`: malformed names, unreadable repositories,
/// and invalid metadata remain errors. Callers that publish idempotently must use this instead of
/// turning every lookup failure into "not published", which would hide repository corruption and
/// attempt a write through a broken trust boundary.
pub async fn target_sha256_if_present(repo_dir: &Path, name: &str) -> Result<Option<String>> {
    validate_target_name(name)?;
    let repo = load_local(repo_dir, "loading repository").await?;
    let name = TargetName::new(name).map_err(|e| err("parsing target name", e))?;
    Ok(repo
        .targets()
        .signed
        .targets
        .get(&name)
        .map(|target| hex::encode(&target.hashes.sha256)))
}

/// Resolve one signed target reference — a `path` + `sha256` flag pair — against this
/// repository's checked-out signed metadata, refusing at publish time what a node could only
/// discover mid-rollout: a reference every syntactic check accepts but that resolves to nothing,
/// or to different bytes than its digest names. The ONE implementation for every publisher-side
/// reference (the provider-set reconciler above, `updatectl deploy`'s provider set), so the
/// resolve-and-compare contract cannot drift between tools. `path_flag`/`sha_flag` name the
/// operator's actual arguments and `names_differ`/`remedy` carry the call-site-specific operator
/// text. Digests are compared as given, which is safe because there is only one spelling to
/// compare: operator input is parsed through `digest::parse_canonical_sha256` at the flag, and
/// every other digest reaching here was produced by `hex::encode`. This used to say that callers
/// lowercase operator input first, and no caller did.
pub async fn verify_target_reference(
    repo_dir: &Path,
    path: &str,
    sha256: &str,
    path_flag: &str,
    sha_flag: &str,
    names_differ: &str,
    remedy: &str,
) -> Result<()> {
    let signed = target_sha256(repo_dir, path).await.map_err(|error| {
        RepoError(format!(
            "{path_flag} {path:?} does not resolve in this repository's signed metadata: \
             {error}. {remedy}"
        ))
    })?;
    if signed != sha256 {
        return Err(RepoError(format!(
            "{sha_flag} {sha256} does not match the signed digest of {path_flag} {path:?}, which \
             is {signed}: the two flags name different {names_differ}. {remedy}"
        )));
    }
    Ok(())
}

/// The current generation number of the published repository: the TUF `timestamp` version, bumped
/// once per [`replace_release`]. It is the monotonic id of "what the fleet is pointed at right now",
/// the value change-tracking subscribers watermark against.
pub async fn current_version(repo_dir: &Path) -> Result<u64> {
    let repo = load_local(repo_dir, "loading repository to read version").await?;
    Ok(repo.timestamp().signed.version.get())
}

/// The repository's current publication delta.
///
/// `uploads` are local files in commit order. `retained_targets` are content-addressed targets
/// still named by the new metadata but absent from this checkout; each carries its signed length so
/// the publisher can prove the object already exists intact enough to be the same target before
/// committing metadata. This is what lets a metadata-only remote checkout add one release without
/// downloading and re-uploading every older artifact.
/// The root rotation chain is always uploaded so an older pinned client can walk forward, and
/// `timestamp.json` is always last because it is the sole visibility commit.
pub struct PublicationPlan {
    pub uploads: Vec<PathBuf>,
    pub retained_targets: Vec<RetainedTarget>,
}

/// One immutable target body retained at the publication destination rather than present in a
/// metadata-only checkout.
pub struct RetainedTarget {
    pub path: PathBuf,
    pub length: u64,
}

pub async fn current_publication_plan(repo_dir: &Path) -> Result<PublicationPlan> {
    const MAX_ROOT_CHAIN_FILES: usize = 1025; // root.json + tough's 1024-update client ceiling.

    let repository = load_local(repo_dir, "resolving current publication closure").await?;
    let metadata_dir = repo_dir.join("metadata");
    let targets_dir = repo_dir.join("targets");

    let mut targets = Vec::with_capacity(repository.targets().signed.targets.len());
    let mut retained_targets = Vec::new();
    for (name, target) in &repository.targets().signed.targets {
        validate_target_name(name.raw())?;
        let digest = hex::encode(&target.hashes.sha256);
        let path = targets_dir.join(format!("{digest}.{}", name.resolved()));
        match std::fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
                targets.push(path)
            }
            Ok(_) => {
                return Err(RepoError(format!(
                    "publication path {} is not a regular, non-symlink file",
                    path.display()
                )));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                retained_targets.push(RetainedTarget {
                    path,
                    length: target.length,
                })
            }
            Err(error) => {
                return Err(err(
                    &format!("inspecting publication file {}", path.display()),
                    error,
                ));
            }
        }
    }
    targets.sort();
    retained_targets.sort_by(|left, right| left.path.cmp(&right.path));

    let roots_dir = metadata_dir.clone();
    let mut roots = blocking(move || {
        let mut roots = Vec::new();
        for entry in
            std::fs::read_dir(&roots_dir).map_err(|e| err("reading metadata directory", e))?
        {
            let entry = entry.map_err(|e| err("reading metadata entry", e))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            let is_root = name == "root.json"
                || name
                    .strip_suffix(".root.json")
                    .and_then(|version| version.parse::<u64>().ok())
                    .is_some_and(|version| version > 0);
            if is_root {
                roots.push(require_publication_file(entry.path())?);
                if roots.len() > MAX_ROOT_CHAIN_FILES {
                    return Err(RepoError(format!(
                        "root chain contains more than {} files",
                        MAX_ROOT_CHAIN_FILES - 1
                    )));
                }
            }
        }
        roots.sort();
        Ok(roots)
    })
    .await?;
    if !roots.iter().any(|path| path.ends_with("root.json")) {
        return Err(RepoError("current publication has no root.json".into()));
    }

    let current_targets = require_publication_file(metadata_dir.join(format!(
        "{}.targets.json",
        repository.targets().signed.version
    )))?;
    let current_snapshot = require_publication_file(metadata_dir.join(format!(
        "{}.snapshot.json",
        repository.snapshot().signed.version
    )))?;
    let timestamp = require_publication_file(metadata_dir.join("timestamp.json"))?;

    targets.append(&mut roots);
    targets.push(current_targets);
    targets.push(current_snapshot);
    targets.push(timestamp);
    Ok(PublicationPlan {
        uploads: targets,
        retained_targets,
    })
}

fn require_publication_file(path: PathBuf) -> Result<PathBuf> {
    let metadata = std::fs::symlink_metadata(&path).map_err(|e| {
        err(
            &format!("inspecting publication file {}", path.display()),
            e,
        )
    })?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(RepoError(format!(
            "publication path {} is not a regular, non-symlink file",
            path.display()
        )));
    }
    Ok(path)
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

fn nz(n: u64) -> NonZeroU64 {
    NonZeroU64::new(n).expect("version/threshold is non-zero")
}

/// Advance a TUF metadata version without weakening rollback protection at the integer boundary.
///
/// Root renewal and release publication share this transition so no role can grow a private
/// overflow behavior. Reaching the wire format's maximum version permanently exhausts that role;
/// the operator must create a new repository lineage rather than wrap it to an older version.
fn next_version(current: NonZeroU64, role: &str) -> Result<NonZeroU64> {
    current
        .get()
        .checked_add(1)
        .and_then(NonZeroU64::new)
        .ok_or_else(|| RepoError(format!("{role} metadata version is exhausted")))
}

fn validate_target_name(name: &str) -> Result<()> {
    let parts: Vec<_> = name.split('/').collect();
    let known_layout = (parts.len() == 6 && parts[0] == "products")
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

/// Load the repository sitting in `repo_dir` for authoring — the single home of what that means.
///
/// `context` names the operation, so a failure still reads as "loading repository to edit" or "to
/// read version". Expiration is deliberately unenforced: these are the publisher's own queries
/// against its own metadata, and a repository whose timestamp has lapsed is exactly the one an
/// operator is running a tool against to fix. That is a trust-relevant choice, so it is made here
/// once rather than restated at every authoring query.
async fn load_local(repo_dir: &Path, context: &str) -> Result<Repository> {
    let metadata_dir = repo_dir.join("metadata");
    let targets_dir = repo_dir.join("targets");
    let root = root_bytes(repo_dir).await?;
    RepositoryLoader::new(&root, dir_url(&metadata_dir)?, dir_url(&targets_dir)?)
        .transport(FilesystemTransport)
        .expiration_enforcement(tough::ExpirationEnforcement::Unsafe)
        .load()
        .await
        .map_err(|e| err(context, e))
}

fn dir_url(dir: &Path) -> Result<Url> {
    let abs = std::fs::canonicalize(dir).map_err(|e| err("canonicalizing repo dir", e))?;
    Url::from_directory_path(&abs)
        .map_err(|()| RepoError(format!("cannot form file URL for {}", abs.display())))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn repo_error_displays_its_message() {
        assert_eq!(RepoError("boom".into()).to_string(), "boom");
        assert_eq!(err("context", "why").to_string(), "context: why");
    }

    #[test]
    fn nz_preserves_the_value() {
        // Repository initialization relies on this returning n, not a fixed 1.
        assert_eq!(nz(5).get(), 5);
        assert_eq!(nz(1).get(), 1);
    }

    #[test]
    fn metadata_versions_advance_once_and_never_wrap() {
        assert_eq!(next_version(nz(41), "targets").unwrap(), nz(42));
        assert_eq!(
            next_version(NonZeroU64::MAX, "root")
                .unwrap_err()
                .to_string(),
            "root metadata version is exhausted"
        );
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
        assert!(validate_target_name("provider-sets/web.json").is_err());
        assert!(validate_target_name("assignments/group/node.json").is_err());
        assert!(validate_target_name("products/../../outside/stable/1.0/app").is_err());
        assert!(validate_target_name("products/app/stable/1.0/linux/app/extra").is_err());
        assert!(validate_target_name("products/app/stable/1.0/linux/app\\evil").is_err());
    }

    fn scratch(name: &str) -> (tempfile::TempDir, PathBuf) {
        let guard = tempfile::tempdir().unwrap();
        let dir = guard.path().join(name);
        std::fs::create_dir_all(&dir).unwrap();
        (guard, dir)
    }

    #[tokio::test]
    async fn a_published_file_is_world_readable_and_leaves_no_staging_behind() {
        let (_tmp, repo) = scratch("publish-file");
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
        let (_tmp, root) = scratch("publish-staging-outside");
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
    }

    /// Two publishes in one process must not share a staging directory. Keyed on the process id
    /// they did: the second's `create_dir` would land on the first's staged generation, and
    /// whichever finished first would delete the other's roles out from under it.
    #[tokio::test]
    async fn each_publish_stages_its_generation_under_a_name_no_other_can_pick() {
        let (_tmp, root) = scratch("generation-stage-name");
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

        let (_tmp, root) = scratch("published-modes");
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
    }

    /// A kill during publication can leave a target object truncated at its content-addressed
    /// path. Republishing the same release must rewrite it: skipping an existing path would
    /// make the damaged bytes permanent, since the path is derived from the digest the metadata
    /// signs and every retry lands on it again.
    #[tokio::test]
    async fn republishing_repairs_a_truncated_target_object() {
        let (_tmp, root) = scratch("truncated-target");
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
        assert_eq!(
            target_sha256_if_present(&repo_dir, &target().name)
                .await
                .unwrap(),
            None,
            "an absent target is distinct from an unreadable repository"
        );
        add_release(&repo_dir, &keys, vec![target()], 365)
            .await
            .unwrap();

        let name = target().name;
        let digest = target_sha256(&repo_dir, &name).await.unwrap();
        assert_eq!(
            target_sha256_if_present(&repo_dir, &name).await.unwrap(),
            Some(digest.clone())
        );
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
    }

    #[cfg(unix)]
    #[test]
    fn key_discovery_never_treats_an_uninspectable_successor_as_absent() {
        let guard = tempfile::tempdir().unwrap();
        let successor = guard.path().join("root.next.pk8");
        std::os::unix::fs::symlink("root.next.pk8", &successor).unwrap();
        assert!(
            Keys::in_dir(guard.path()).is_err(),
            "a symlink loop must be an error, not a silent single-root downgrade"
        );
    }

    #[test]
    fn signing_key_roles_cannot_collapse_onto_one_public_key() {
        let first = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let second = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        validate_distinct_signing_keys([
            ("root.pk8", first.as_ref()),
            ("root.next.pk8", second.as_ref()),
        ])
        .unwrap();

        let error = validate_distinct_signing_keys([
            ("root.pk8", first.as_ref()),
            ("targets.pk8", first.as_ref()),
        ])
        .unwrap_err()
        .to_string();
        assert!(error.contains("root.pk8"), "{error}");
        assert!(error.contains("targets.pk8"), "{error}");
        assert!(error.contains("same public key"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn signing_keys_must_be_owner_only_regular_files() {
        use std::os::unix::fs::PermissionsExt;
        let guard = tempfile::tempdir().unwrap();
        let dir = guard.path().to_path_buf();
        let key = dir.join("root.pk8");
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        std::fs::write(&key, pkcs8.as_ref()).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_signing_key_bytes(&key).is_err());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_signing_key_bytes(&key).unwrap(), pkcs8.as_ref());
        let link = dir.join("link.pk8");
        std::os::unix::fs::symlink(&key, &link).unwrap();
        assert!(read_signing_key_bytes(&link).is_err());
        std::fs::write(&key, vec![0; SIGNING_KEY_MAX_BYTES + 1]).unwrap();
        assert!(read_signing_key_bytes(&key).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
