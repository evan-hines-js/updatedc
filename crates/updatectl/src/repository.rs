//! Checking a release repository out of its object store, reading its signed metadata, and
//! writing a new generation back.

use crate::*;

/// Wire up the S3 object store for the release repository. Credentials come from the
/// standard AWS environment (empty for anonymous/dev stores such as public MinIO).
pub(crate) fn build_store(
    backend: &Backend,
) -> Result<(S3Destination, Arc<dyn ObjectStore>), Error> {
    let destination = S3Destination {
        bucket: backend.bucket.clone(),
        prefix: backend.prefix.clone(),
        region: backend.region.clone(),
        credentials_secret_ref: None,
        endpoint: backend.endpoint.clone(),
        public_endpoint: None,
    };
    let access = std::env::var("AWS_ACCESS_KEY_ID").ok();
    let secret = std::env::var("AWS_SECRET_ACCESS_KEY").ok();
    // Temporary credentials (STS AssumeRole, SSO, IRSA) are only valid with their session token.
    let token = std::env::var("AWS_SESSION_TOKEN").ok();
    let store = updatec::runtime::repository_object_store(
        &destination,
        updatec::runtime::S3Credentials {
            access_key: access.as_deref(),
            secret_key: secret.as_deref(),
            session_token: token.as_deref(),
        },
    )?;
    Ok((destination, store))
}

/// Resolve the signing keys from a mounted directory. `deploy` signs only the online roles
/// (targets/snapshot/timestamp), so the root keys are deliberately **not** required here —
/// a release pipeline never needs the root private keys, only `trust-root`/`rotate-root` do.
pub(crate) fn open_keys(dir: &Path) -> Result<repo::Keys, Error> {
    let keys = repo::Keys::in_dir(dir)?;
    for path in [&keys.targets, &keys.snapshot, &keys.timestamp] {
        if !foundation::file::path_entry_exists(path)? {
            return Err(format!(
                "--keys-dir {} is missing {}",
                dir.display(),
                path.file_name().unwrap_or_default().to_string_lossy()
            )
            .into());
        }
    }
    Ok(keys)
}

/// The four top-level TUF roles, the documents whose versions a publish bumps.
pub(crate) const TOP_LEVEL_METADATA: [&str; 4] = [
    "root.json",
    "timestamp.json",
    "snapshot.json",
    "targets.json",
];

/// The version each top-level TUF role currently declares, held per role rather than collapsed
/// into one number.
///
/// A single maximum cannot serve as the concurrent-publish measure: the roles advance
/// independently. `repo::publish_release` bumps targets/snapshot/timestamp and leaves root alone,
/// while `repo::rotate_root` and `repo::renew_root` bump only root, so one root rotation would
/// park a single maximum above the timestamp and mask the next publisher's commit entirely.
/// Comparing role by role means every publish path advances a role the guard is watching.
///
/// Every role is read from BOTH its unversioned document and its versioned copies. Under
/// `consistent_snapshot` (what `repo::init_from_version` writes) the snapshot and targets roles
/// exist ONLY at `<N>.<role>.json`, so reading unversioned names alone left those two slots empty
/// forever and collapsed the floor below to `max(root, timestamp)` — losing `metadata/timestamp.json`
/// while fifty versioned targets stood then re-initialized the repository at version 2, which every
/// node that had accepted targets v51 refuses as a rollback, permanently and with no publisher error.
///
/// A role is `None` when its document is absent, distinct from a document that declares version
/// 0: this one reading is also the answer to "is anything published here", and a repository is
/// live if ANY top-level role stands, not only if `root.json` does. Deriving liveness from a
/// single object and the version floor from all four is how a half-deleted prefix — root.json
/// gone, timestamp still at 47 — gets re-initialized at version 1 and wedges every node.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct RoleVersions(pub(crate) [Option<u64>; TOP_LEVEL_METADATA.len()]);

impl RoleVersions {
    /// Read the live repository's role versions from S3. An absent document is `None`; an
    /// unreadable one is present at version 0 — the guard only cares that a role's document is
    /// byte-for-byte the generation this process saw.
    pub(crate) async fn live(
        store: &dyn ObjectStore,
        destination: &S3Destination,
    ) -> Result<Self, Error> {
        let mut versions = Self::default();
        for (slot, name) in TOP_LEVEL_METADATA.iter().enumerate() {
            let key = updatec::object_key(&destination.prefix, &format!("metadata/{name}"));
            let bytes = match updatec::read_object_bounded(store, &key, updatec::OBJECT_BYTES_LIMIT)
                .await
            {
                Ok(bytes) => bytes,
                Err(object_store::Error::NotFound { .. }) => continue,
                Err(error) => return Err(error.into()),
            };
            versions.0[slot] = Some(updatec::runtime::signed_version(&bytes).unwrap_or(0));
        }
        // The versioned copies carry their version in the object name, so the floor is read from
        // the listing without fetching any of them.
        let prefix = updatec::object_key(&destination.prefix, "metadata");
        let mut listing = store.list(Some(&prefix));
        while let Some(entry) = listing.next().await {
            if let Some(filename) = entry?.location.filename() {
                versions.note_versioned(filename);
            }
        }
        Ok(versions)
    }

    /// Raise a role's version from a versioned metadata name, `<N>.<role>.json`. Anything else —
    /// a delegated role, a stray object — names no top-level role and is ignored.
    pub(crate) fn note_versioned(&mut self, filename: &str) {
        let Some((version, role)) = filename.split_once('.') else {
            return;
        };
        let Ok(version) = version.parse::<u64>() else {
            return;
        };
        let Some(slot) = TOP_LEVEL_METADATA.iter().position(|name| *name == role) else {
            return;
        };
        self.0[slot] = Some(self.0[slot].unwrap_or(0).max(version));
    }

    /// Whether the repository is live: any top-level role document is present. Nodes pin
    /// versioned roots and follow `timestamp.json`, so a prefix that still serves a timestamp is
    /// serving a fleet whether or not the unversioned `root.json` survived.
    pub(crate) fn is_initialized(&self) -> bool {
        self.0.iter().any(Option::is_some)
    }

    /// The highest version any role has published — the floor a replacement repository must
    /// start above, because a TUF client refuses any role document below the version it last
    /// accepted for that role. Zero when nothing is published.
    pub(crate) fn highest(&self) -> u64 {
        self.0.iter().flatten().copied().max().unwrap_or(0)
    }

    /// The roles that are actually present, named with their versions, for a diagnostic that has
    /// to tell an operator what is standing at a prefix they are about to replace.
    pub(crate) fn describe_present(&self) -> String {
        let present: Vec<String> = TOP_LEVEL_METADATA
            .iter()
            .enumerate()
            .filter_map(|(slot, name)| {
                self.0[slot].map(|version| format!("{name} at version {version}"))
            })
            .collect();
        present.join(", ")
    }

    /// The first role whose version differs from `base`, described for an operator, or `None`
    /// when every role still stands where `base` saw it.
    pub(crate) fn moved_since(&self, base: &Self) -> Option<String> {
        TOP_LEVEL_METADATA
            .iter()
            .enumerate()
            .find(|(slot, _)| self.0[*slot] != base.0[*slot])
            .map(|(slot, name)| {
                format!(
                    "{name} from {} to {}",
                    describe_version(base.0[slot]),
                    describe_version(self.0[slot])
                )
            })
    }
}

/// One role's standing, for operator-facing text: a version, or the absence of the document.
pub(crate) fn describe_version(version: Option<u64>) -> String {
    match version {
        Some(version) => format!("version {version}"),
        None => "absent".to_string(),
    }
}

/// Fetch the one active, consistent-snapshot metadata closure into `metadata_dir` so the TUF
/// editor can load the current generation and bump from it.
///
/// Historical versioned documents remain immutable in S3 and are not inputs to a new signature.
/// Mirroring the whole prefix made every stray/nested object a publication input and let an
/// untrusted bucket exhaust local memory or disk. The active closure is exactly five bounded
/// objects: the root anchor and its matching versioned copy, timestamp, and the snapshot and
/// targets versions those signed documents name.
pub(crate) async fn download_metadata(
    store: &dyn ObjectStore,
    destination: &S3Destination,
    metadata_dir: &Path,
) -> Result<(), Error> {
    let root = download_metadata_object(store, destination, metadata_dir, "root.json").await?;
    let root_version = signed_metadata_version(&root, "root.json")?;
    let root_value: serde_json::Value = serde_json::from_slice(&root)
        .map_err(|error| format!("root.json is not valid signed JSON: {error}"))?;
    if root_value
        .pointer("/signed/consistent_snapshot")
        .and_then(serde_json::Value::as_bool)
        != Some(true)
    {
        return Err("root.json does not require consistent snapshots; this repository layout is unsupported".into());
    }

    let versioned_root_name = format!("{root_version}.root.json");
    let versioned_root =
        download_metadata_object(store, destination, metadata_dir, &versioned_root_name).await?;
    if versioned_root != root {
        return Err(format!(
            "root.json does not match its active versioned copy {versioned_root_name}"
        )
        .into());
    }

    let timestamp =
        download_metadata_object(store, destination, metadata_dir, "timestamp.json").await?;
    let snapshot_version =
        referenced_metadata_version(&timestamp, "timestamp.json", "snapshot.json")?;
    let snapshot_name = format!("{snapshot_version}.snapshot.json");
    let snapshot =
        download_metadata_object(store, destination, metadata_dir, &snapshot_name).await?;
    let targets_version = referenced_metadata_version(&snapshot, &snapshot_name, "targets.json")?;
    let targets_name = format!("{targets_version}.targets.json");
    download_metadata_object(store, destination, metadata_dir, &targets_name).await?;
    Ok(())
}

pub(crate) async fn download_metadata_object(
    store: &dyn ObjectStore,
    destination: &S3Destination,
    metadata_dir: &Path,
    name: &str,
) -> Result<Vec<u8>, Error> {
    let key = updatec::object_key(&destination.prefix, &format!("metadata/{name}"));
    let bytes = updatec::read_object_bounded(store, &key, updatec::OBJECT_BYTES_LIMIT).await?;
    tokio::fs::write(metadata_dir.join(name), &bytes).await?;
    Ok(bytes)
}

pub(crate) fn signed_metadata_version(bytes: &[u8], document: &str) -> Result<u64, Error> {
    updatec::runtime::signed_version(bytes)
        .filter(|version| *version != 0)
        .ok_or_else(|| format!("{document} has no positive signed.version").into())
}

pub(crate) fn referenced_metadata_version(
    bytes: &[u8],
    document: &str,
    referenced: &str,
) -> Result<u64, Error> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("{document} is not valid signed JSON: {error}"))?;
    value
        .pointer(&format!("/signed/meta/{referenced}/version"))
        .and_then(serde_json::Value::as_u64)
        .filter(|version| *version != 0)
        .ok_or_else(|| {
            format!("{document} has no positive signed.meta[{referenced:?}].version").into()
        })
}

/// Build an opaque payload bundle from a prepared directory tree.
pub(crate) fn build_payload_bundle(
    source: &Path,
    archive: &Path,
    product: &str,
    version: &str,
    platform: &str,
) -> Result<(), Error> {
    updated::bundle::create_bundle(source, archive, product, version, platform)
        .map_err(|error| format!("building bundle: {error}"))?;
    Ok(())
}
