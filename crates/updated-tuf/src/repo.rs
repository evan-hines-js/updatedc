//! Offline TUF repository authoring: key generation, minting/signing the initial
//! root, and publishing releases. Used by the dev/mock server and tests — never
//! by a deployed client. Single top-level `targets` role (delegations are a
//! documented production extension).

use std::collections::HashMap;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::Ed25519KeyPair;
use tough::editor::signed::SignedRole;
use tough::editor::RepositoryEditor;
use tough::key_source::{KeySource, LocalKeySource};
use tough::schema::decoded::{Decoded, Hex};
use tough::schema::key::Key;
use tough::schema::{KeyHolder, RoleKeys, RoleType, Root, Target};
use tough::sign::{parse_keypair, Sign};
use tough::{FilesystemTransport, RepositoryLoader};
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

/// Paths to the four TUF role signing keys (ed25519 pkcs8).
pub struct Keys {
    pub root: PathBuf,
    pub targets: PathBuf,
    pub snapshot: PathBuf,
    pub timestamp: PathBuf,
}

impl Keys {
    /// The standard key file layout under `dir`.
    pub fn in_dir(dir: &Path) -> Self {
        Keys {
            root: dir.join("root.pk8"),
            targets: dir.join("targets.pk8"),
            snapshot: dir.join("snapshot.pk8"),
            timestamp: dir.join("timestamp.pk8"),
        }
    }
    fn all(&self) -> [(RoleType, &PathBuf); 4] {
        [
            (RoleType::Root, &self.root),
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
}

/// Generate the four ed25519 role keys under `keys_dir` if they are not present.
pub async fn generate_keys(keys_dir: &Path) -> Result<Keys> {
    tokio::fs::create_dir_all(keys_dir)
        .await
        .map_err(|e| err("creating key dir", e))?;
    let keys = Keys::in_dir(keys_dir);
    let rng = SystemRandom::new();
    for (_role, path) in keys.all() {
        if tokio::fs::try_exists(path).await.unwrap_or(false) {
            continue;
        }
        let pkcs8 =
            Ed25519KeyPair::generate_pkcs8(&rng).map_err(|e| err("generating ed25519 key", e))?;
        tokio::fs::write(path, pkcs8.as_ref())
            .await
            .map_err(|e| err("writing key", e))?;
        restrict(path).await;
    }
    Ok(keys)
}

#[cfg(unix)]
async fn restrict(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await;
}
#[cfg(not(unix))]
async fn restrict(_path: &Path) {}

/// Initialize an empty TUF repository under `repo_dir`: mint and sign `root.json`,
/// then sign empty targets/snapshot/timestamp. Creates `metadata/` and `targets/`.
pub async fn init(repo_dir: &Path, keys: &Keys, expiry_days: i64) -> Result<()> {
    let metadata_dir = repo_dir.join("metadata");
    let targets_dir = repo_dir.join("targets");
    tokio::fs::create_dir_all(&metadata_dir)
        .await
        .map_err(|e| err("creating metadata dir", e))?;
    tokio::fs::create_dir_all(&targets_dir)
        .await
        .map_err(|e| err("creating targets dir", e))?;

    let expires = expiry(expiry_days);

    // Build root.json: one ed25519 key per role, threshold 1.
    let mut root_keys: HashMap<Decoded<Hex>, Key> = HashMap::new();
    let mut roles: HashMap<RoleType, RoleKeys> = HashMap::new();
    for (role, path) in keys.all() {
        let signer = load_signer(path)?;
        let key = signer.tuf_key();
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
        consistent_snapshot: false,
        version: nz(1),
        expires,
        keys: root_keys,
        roles,
        _extra: HashMap::new(),
    };
    let rng = SystemRandom::new();
    let signed_root = SignedRole::new(
        root.clone(),
        &KeyHolder::Root(root),
        &[local(&keys.root)],
        &rng,
    )
    .await
    .map_err(|e| err("signing root", e))?;
    // The pinned root and the versioned root the client fetches for rotation.
    tokio::fs::write(metadata_dir.join("root.json"), signed_root.buffer())
        .await
        .map_err(|e| err("writing root.json", e))?;
    tokio::fs::write(metadata_dir.join("1.root.json"), signed_root.buffer())
        .await
        .map_err(|e| err("writing 1.root.json", e))?;

    // Sign empty targets/snapshot/timestamp (version 1).
    let mut editor = RepositoryEditor::new(metadata_dir.join("root.json"))
        .await
        .map_err(|e| err("creating editor", e))?;
    editor
        .targets_version(nz(1))
        .map_err(|e| err("targets version", e))?
        .targets_expires(expires)
        .map_err(|e| err("targets expiry", e))?
        .snapshot_version(nz(1))
        .snapshot_expires(expires)
        .timestamp_version(nz(1))
        .timestamp_expires(expires);
    let signed = editor
        .sign(&[
            local(&keys.targets),
            local(&keys.snapshot),
            local(&keys.timestamp),
        ])
        .await
        .map_err(|e| err("signing initial metadata", e))?;
    signed
        .write(&metadata_dir)
        .await
        .map_err(|e| err("writing initial metadata", e))?;
    Ok(())
}

/// Publish a release: register `targets`, bump targets/snapshot/timestamp, and
/// re-sign. The target artifacts are copied into `targets/`.
pub async fn add_release(
    repo_dir: &Path,
    keys: &Keys,
    targets: Vec<PublishTarget>,
    expiry_days: i64,
) -> Result<()> {
    let metadata_dir = repo_dir.join("metadata");
    let targets_dir = repo_dir.join("targets");
    let root_path = metadata_dir.join("root.json");

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

    let expires = expiry(expiry_days);
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

    for pt in &targets {
        let mut target = Target::from_path(&pt.source)
            .await
            .map_err(|e| err("hashing target", e))?;
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

    // Place artifacts, then write metadata (timestamp is the visibility commit).
    for pt in &targets {
        let dest = targets_dir.join(&pt.name);
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| err("creating target dir", e))?;
        }
        tokio::fs::copy(&pt.source, &dest)
            .await
            .map_err(|e| err("copying target artifact", e))?;
    }
    signed
        .write(&metadata_dir)
        .await
        .map_err(|e| err("writing release metadata", e))?;
    Ok(())
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

fn expiry(days: i64) -> jiff::Timestamp {
    jiff::Timestamp::now()
        .checked_add(jiff::SignedDuration::from_hours(days * 24))
        .unwrap_or(jiff::Timestamp::MAX)
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
        let e = expiry(365);
        let low = now
            .checked_add(jiff::SignedDuration::from_hours(364 * 24))
            .unwrap();
        let high = now
            .checked_add(jiff::SignedDuration::from_hours(366 * 24))
            .unwrap();
        assert!(e > low && e < high, "expiry ~365 days out, got {e}");
    }
}
