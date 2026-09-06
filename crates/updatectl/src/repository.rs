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

/// Resolve mounted online signing keys. A release pipeline never needs root private keys.
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

/// The two mutable documents that select the active repository. Their exact bytes identify the
/// checkout; signed version numbers alone do not detect replacement within the same version.
/// Historical and unrelated objects are never inputs to this bounded preflight. The shared
/// repository publisher owns immutable-object checks and conditional commits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MetadataGeneration {
    root: String,
    timestamp: String,
}

impl MetadataGeneration {
    pub(crate) async fn live(
        store: &dyn ObjectStore,
        destination: &S3Destination,
    ) -> Result<Self, Error> {
        let mut digests = [String::new(), String::new()];
        for (digest, name) in digests.iter_mut().zip(["root.json", "timestamp.json"]) {
            let key = updatec::object_key(&destination.prefix, &format!("metadata/{name}"));
            let bytes =
                updatec::read_object_bounded(store, &key, updatec::OBJECT_BYTES_LIMIT).await?;
            *digest = updated_contracts::digest::sha256_bytes(&bytes);
        }
        let [root, timestamp] = digests;
        Ok(Self { root, timestamp })
    }

    pub(crate) fn changed_document(&self, base: &Self) -> Option<&'static str> {
        if self.root != base.root {
            Some("root.json")
        } else if self.timestamp != base.timestamp {
            Some("timestamp.json")
        } else {
            None
        }
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
