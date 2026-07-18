//! Async TUF client and repository builder, wrapping [`tough`].
//!
//! The client ([`TrustedRepository`]) loads an installer-pinned root, performs the
//! full TUF refresh (root rotation, timestamp/snapshot/targets verification,
//! version-rollback and expiration checks — all done by `tough` on load), and
//! exposes *verified* targets. A [`VerifiedTarget`] is a capability: it exists
//! only after the metadata chain verified, so download code never accepts an
//! unauthenticated URL, size, or digest from a caller.
//!
//! [`repo`] is the offline side: minting a TUF repository (four ed25519 roles) and
//! publishing releases. The dev/mock server uses it; a client never does.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use aws_lc_rs::digest::{digest, SHA256};
use futures::StreamExt;
use tokio::io::AsyncWriteExt;
use tokio::time::{timeout, Duration};
use tough::schema::Target;
use tough::{ExpirationEnforcement, Limits, Repository, RepositoryLoader, TargetName};
use url::Url;

pub mod policy;
pub mod repo;
pub mod select;

pub use policy::{DefaultPolicy, PolicyError};

/// Bound every wait on a repository origin. Target downloads may take longer than
/// this in total, but must continue making progress.
const TRANSPORT_TIMEOUT: Duration = Duration::from_secs(30);

/// A TUF client error, classified so callers can tell a *retryable* network
/// problem from a *fail-closed* trust failure that must never be retried blindly
/// or worked around.
#[derive(Debug)]
pub enum Error {
    /// A transport/network problem reaching the repository. Retryable.
    Transport(String),
    /// A TUF trust failure — bad signature, version rollback, expired metadata,
    /// hash/length mismatch, or corrupt local state. Fail closed; never fall back.
    Trust(String),
    /// A local I/O or configuration error.
    Local(String),
}

impl Error {
    /// Whether retrying later could succeed. Trust and local errors never can.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Error::Transport(_))
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Transport(m) => write!(f, "repository transport error: {m}"),
            Error::Trust(m) => write!(f, "TUF trust failure: {m}"),
            Error::Local(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for Error {}

/// Map a `tough` error to our classification. Only a transport error is
/// retryable; everything else (signature, rollback, expiry, hash/length, corrupt
/// state) fails closed.
fn classify(e: tough::error::Error) -> Error {
    match e {
        tough::error::Error::Transport { .. } => Error::Transport(e.to_string()),
        other => Error::Trust(other.to_string()),
    }
}

#[cfg(test)]
mod error_tests {
    use super::{assignment_identity, transport_timeout, validate_release_url, Error};
    use updated::config::RepositoryAssignment;

    #[test]
    fn only_transport_is_retryable() {
        // The fail-closed contract: a transport blip may be retried, but a trust
        // failure (bad signature, rollback, expiry, hash/length mismatch, corrupt
        // state) or a local error must never be retried or worked around.
        assert!(Error::Transport("connection reset".into()).is_retryable());
        assert!(!Error::Trust("signature threshold not met".into()).is_retryable());
        assert!(!Error::Local("datastore unwritable".into()).is_retryable());
    }

    #[test]
    fn display_classifies_the_failure() {
        // The classification is visible in the message, and a local error passes its
        // reason through verbatim — a Display that emitted nothing would erase it.
        assert_eq!(
            Error::Transport("connection reset".into()).to_string(),
            "repository transport error: connection reset"
        );
        assert_eq!(
            Error::Trust("rollback".into()).to_string(),
            "TUF trust failure: rollback"
        );
        assert_eq!(Error::Local("bad path".into()).to_string(), "bad path");
    }

    #[test]
    fn timeout_is_a_retryable_transport_failure() {
        let error = transport_timeout("refreshing metadata");
        assert!(error.is_retryable());
        assert!(error.to_string().contains("timed out after 30s"));
    }

    #[test]
    fn assigned_repositories_have_independent_stable_datastores() {
        let assignment = |metadata: &str, targets: &str| RepositoryAssignment {
            schema: 1,
            metadata_url: metadata.into(),
            targets_url: targets.into(),
        };
        let a = assignment("https://cdn/a/metadata/", "https://cdn/a/targets/");
        let b = assignment("https://cdn/b/metadata/", "https://cdn/b/targets/");
        assert_eq!(assignment_identity(&a), assignment_identity(&a));
        assert_ne!(assignment_identity(&a), assignment_identity(&b));
        assert_eq!(assignment_identity(&a).len(), 64);
    }

    #[test]
    fn assigned_endpoints_are_bounded_http_base_urls() {
        assert!(validate_release_url("metadata_url", "https://cdn.example/metadata/").is_ok());
        for invalid in [
            "file:///tmp/metadata/",
            "https://user:pass@cdn.example/metadata/",
            "https://cdn.example/metadata/#fragment",
            "https://cdn.example/metadata",
        ] {
            assert!(
                validate_release_url("metadata_url", invalid).is_err(),
                "{invalid}"
            );
        }
    }
}

/// A target whose existence, length, and hashes are authenticated by the current
/// trusted TUF metadata chain. Produced only by [`TrustedRepository`].
#[derive(Debug, Clone)]
pub struct VerifiedTarget {
    /// The logical TUF target path.
    pub path: String,
    pub length: u64,
    /// Hash algorithm -> digest bytes (currently `sha256`).
    pub hashes: BTreeMap<String, Vec<u8>>,
    /// Signed, opaque custom metadata (product/version/os/arch/...).
    pub custom: serde_json::Value,
}

/// A loaded, verified TUF repository. Each [`load`](Self::load) /
/// [`refresh`](Self::refresh) performs the complete TUF refresh workflow.
pub struct TrustedRepository {
    config: updated::config::RepositorySource,
    datastore: PathBuf,
    repo: Repository,
}

impl TrustedRepository {
    /// Resolve the node's exact, TUF-verified routing assignment and then load the
    /// selected release repository. Repeating this operation is how a running node
    /// observes control-plane group changes without restart.
    pub async fn assigned(
        routing_config: &updated::config::Routing,
        repository_config: &updated::config::Repository,
        paths: &updated::config::Paths,
    ) -> Result<Self, Error> {
        if !routing_config.base_url.ends_with('/') {
            return Err(Error::Local(
                "routing.base_url must end with '/' so metadata/ and targets/ are children".into(),
            ));
        }
        let base = Url::parse(&routing_config.base_url)
            .map_err(|e| Error::Local(format!("routing.base_url: {e}")))?;
        if !matches!(base.scheme(), "http" | "https")
            || base.cannot_be_a_base()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.fragment().is_some()
        {
            return Err(Error::Local(
                "routing.base_url must be an HTTP(S) base URL without credentials or a fragment"
                    .into(),
            ));
        }
        let metadata_url = base
            .join("metadata/")
            .map_err(|e| Error::Local(format!("routing metadata URL: {e}")))?;
        let targets_url = base
            .join("targets/")
            .map_err(|e| Error::Local(format!("routing targets URL: {e}")))?;
        let routing = updated::config::RepositorySource {
            root: routing_config.root.clone(),
            metadata_url: metadata_url.to_string(),
            targets_url: targets_url.to_string(),
            metadata_limit: routing_config.metadata_limit,
            target_limit: 64 * 1024,
        };
        let routing = Self::load(&routing, &paths.routing_datastore).await?;
        let target = routing
            .all_targets()
            .into_iter()
            .find(|target| target.path == routing_config.assignment)
            .ok_or_else(|| {
                Error::Trust(format!(
                    "routing assignment {} is absent from verified metadata",
                    routing_config.assignment
                ))
            })?;
        routing.download_target(&target, &paths.assignment).await?;
        let bytes = tokio::fs::read(&paths.assignment)
            .await
            .map_err(|e| Error::Local(format!("reading verified routing assignment: {e}")))?;
        let assignment: updated::config::RepositoryAssignment = serde_json::from_slice(&bytes)
            .map_err(|e| Error::Trust(format!("invalid repository assignment: {e}")))?;
        let assignment_store = paths.datastore.join(assignment_identity(&assignment));
        let source = repository_config
            .resolve(assignment)
            .map_err(Error::Trust)?;
        validate_release_url("metadata_url", &source.metadata_url)?;
        validate_release_url("targets_url", &source.targets_url)?;
        Self::load(&source, &assignment_store).await
    }
    /// Load the pinned root and refresh the full metadata chain.
    pub async fn load(
        config: &updated::config::RepositorySource,
        datastore: &Path,
    ) -> Result<Self, Error> {
        let repo = Self::load_repo(config, datastore).await?;
        Ok(Self {
            config: config.clone(),
            datastore: datastore.to_owned(),
            repo,
        })
    }

    /// Re-run the TUF refresh, picking up newer signed metadata (and rotated
    /// roots) while enforcing rollback and expiration.
    pub async fn refresh(&mut self) -> Result<(), Error> {
        self.repo = Self::load_repo(&self.config, &self.datastore).await?;
        Ok(())
    }

    async fn load_repo(
        config: &updated::config::RepositorySource,
        datastore: &Path,
    ) -> Result<Repository, Error> {
        let root = tokio::fs::read(&config.root).await.map_err(|e| {
            Error::Local(format!(
                "reading pinned root {}: {e}",
                config.root.display()
            ))
        })?;
        let metadata_url = Url::parse(&config.metadata_url)
            .map_err(|e| Error::Local(format!("metadata base url: {e}")))?;
        let targets_url = Url::parse(&config.targets_url)
            .map_err(|e| Error::Local(format!("targets base url: {e}")))?;
        tokio::fs::create_dir_all(datastore)
            .await
            .map_err(|e| Error::Local(format!("creating datastore: {e}")))?;
        let load = RepositoryLoader::new(&root, metadata_url, targets_url)
            .datastore(datastore.to_owned())
            .limits(Limits {
                max_root_size: config.metadata_limit,
                max_targets_size: config.metadata_limit,
                max_timestamp_size: config.metadata_limit,
                max_snapshot_size: config.metadata_limit,
                max_root_updates: 1024,
            })
            .expiration_enforcement(ExpirationEnforcement::Safe)
            .load();
        timeout(TRANSPORT_TIMEOUT, load)
            .await
            .map_err(|_| transport_timeout("refreshing metadata"))?
            .map_err(classify)
    }

    /// Every verified target in the trusted metadata.
    pub fn all_targets(&self) -> Vec<VerifiedTarget> {
        self.repo
            .all_targets()
            .map(|(name, target)| to_verified(name.raw(), target))
            .collect()
    }

    /// Stream a verified target to `destination`. `tough` verifies length and
    /// hashes against the trusted metadata while streaming; if the stream yields
    /// an error the partial file is unusable and is removed.
    pub async fn download_target(
        &self,
        target: &VerifiedTarget,
        destination: &Path,
    ) -> Result<(), Error> {
        let name = TargetName::new(target.path.as_str())
            .map_err(|e| Error::Local(format!("bad target name {}: {e}", target.path)))?;
        let stream = timeout(TRANSPORT_TIMEOUT, self.repo.read_target(&name))
            .await
            .map_err(|_| transport_timeout("opening target stream"))?
            .map_err(classify)?
            .ok_or_else(|| {
                Error::Trust(format!(
                    "target {} is not present in verified metadata",
                    target.path
                ))
            })?;

        if target.length > self.config.target_limit {
            return Err(Error::Trust(format!(
                "target {} exceeded the {} byte limit",
                target.path, self.config.target_limit
            )));
        }
        let dir = foundation::durable::parent_dir(destination);
        let (file, temporary) = foundation::durable::create_temp(dir, ".target-")
            .map_err(|e| Error::Local(format!("creating target staging file: {e}")))?;
        let mut file = tokio::fs::File::from_std(file);
        let mut written = 0u64;
        tokio::pin!(stream);
        let result = async {
            while let Some(chunk) = timeout(TRANSPORT_TIMEOUT, stream.next())
                .await
                .map_err(|_| transport_timeout("waiting for target data"))?
            {
                // A stream error means a size/hash check failed: do NOT use the data.
                let chunk = chunk.map_err(classify)?;
                written += chunk.len() as u64;
                if written > self.config.target_limit {
                    return Err(Error::Trust(format!(
                        "target {} exceeded the {} byte limit",
                        target.path, self.config.target_limit
                    )));
                }
                file.write_all(&chunk)
                    .await
                    .map_err(|e| Error::Local(format!("writing target: {e}")))?;
            }
            file.flush()
                .await
                .map_err(|e| Error::Local(format!("flushing target: {e}")))?;
            file.sync_all()
                .await
                .map_err(|e| Error::Local(format!("syncing target: {e}")))?;
            Ok(())
        }
        .await;
        if result.is_err() {
            drop(file);
            if let Err(cleanup) = tokio::fs::remove_file(&temporary).await {
                if cleanup.kind() != std::io::ErrorKind::NotFound {
                    return Err(Error::Local(format!(
                        "{result:?}; also removing partial target {} failed: {cleanup}",
                        temporary.display()
                    )));
                }
            }
            return result;
        }
        drop(file);
        foundation::durable::replace(&temporary, destination).map_err(|e| {
            let _ = std::fs::remove_file(&temporary);
            Error::Local(format!(
                "installing staged target {}: {e}",
                destination.display()
            ))
        })?;
        foundation::durable::sync_dir(dir)
            .map_err(|e| Error::Local(format!("syncing target directory: {e}")))?;
        Ok(())
    }
}

fn assignment_identity(assignment: &updated::config::RepositoryAssignment) -> String {
    // Length-prefix the fields so different endpoint pairs cannot have an ambiguous
    // concatenation. The digest is only a private directory name; the signed assignment
    // and TUF metadata remain the authority.
    let mut bytes = Vec::with_capacity(
        assignment.metadata_url.len() + assignment.targets_url.len() + 2 * size_of::<u64>(),
    );
    bytes.extend_from_slice(&(assignment.metadata_url.len() as u64).to_be_bytes());
    bytes.extend_from_slice(assignment.metadata_url.as_bytes());
    bytes.extend_from_slice(&(assignment.targets_url.len() as u64).to_be_bytes());
    bytes.extend_from_slice(assignment.targets_url.as_bytes());
    hex::encode(digest(&SHA256, &bytes).as_ref())
}

fn validate_release_url(name: &str, raw: &str) -> Result<(), Error> {
    let url = Url::parse(raw).map_err(|e| Error::Trust(format!("assignment {name}: {e}")))?;
    if !raw.ends_with('/') || !matches!(url.scheme(), "http" | "https") || url.cannot_be_a_base() {
        return Err(Error::Trust(format!(
            "assignment {name} must be an HTTP(S) base URL ending with '/'"
        )));
    }
    if !url.username().is_empty() || url.password().is_some() || url.fragment().is_some() {
        return Err(Error::Trust(format!(
            "assignment {name} must not contain credentials or a fragment"
        )));
    }
    Ok(())
}

fn transport_timeout(operation: &str) -> Error {
    Error::Transport(format!(
        "timed out after {}s while {operation}",
        TRANSPORT_TIMEOUT.as_secs()
    ))
}

fn to_verified(path: &str, target: &Target) -> VerifiedTarget {
    let mut hashes = BTreeMap::new();
    hashes.insert("sha256".to_string(), target.hashes.sha256.to_vec());
    VerifiedTarget {
        path: path.to_string(),
        length: target.length,
        hashes,
        custom: serde_json::to_value(&target.custom).unwrap_or(serde_json::Value::Null),
    }
}
