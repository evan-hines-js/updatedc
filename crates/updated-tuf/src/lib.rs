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
use std::path::Path;

use aws_lc_rs::digest::{digest, SHA256};
use futures::StreamExt;
use tokio::io::AsyncWriteExt;
use tokio::time::{timeout, Duration};
use tough::schema::{Role, Root, Signed, Snapshot, Target, Targets, Timestamp};
use tough::{ExpirationEnforcement, Limits, Repository, RepositoryLoader, TargetName};
use url::Url;

pub mod policy;
pub mod repo;
pub mod select;
mod transport;

pub use policy::{DefaultPolicy, PolicyError};

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

    fn runtime() -> updated::config::ManagedRuntime {
        updated::config::ManagedRuntime {
            product: "app".into(),
            channel: "stable".into(),
            install_root: "/app".into(),
            args: vec![],
            health_checks: vec![],
            repository: updated::config::ManagedRepositoryLimits {
                metadata_limit: 1,
                target_limit: 1,
                transport_timeout_seconds: 1,
            },
            storage: updated::config::ManagedStorage {
                inactive_releases: 1,
                inactive_providers: 1,
                inactive_supervisors: 1,
                inactive_bytes: 1,
                inactive_repository_caches: 1,
            },
            timeouts: updated::config::ManagedTimeouts {
                check_interval_seconds: 1,
                health_grace_seconds: 1,
                health_successes: 1,
                health_interval_seconds: 1,
                retry_after_seconds: 1,
                refresh_retry_seconds: 1,
                confirmation_window_seconds: 1,
                supervisor_check_interval_seconds: 1,
                drain_hold_seconds: Some(0),
            },
        }
    }

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
        let error = transport_timeout(std::time::Duration::from_secs(30), "refreshing metadata");
        assert!(error.is_retryable());
        assert!(error.to_string().contains("timed out after 30s"));
    }

    #[test]
    fn assigned_repositories_have_independent_stable_datastores() {
        let runtime = || updated::config::ManagedRuntime {
            product: "app".into(),
            channel: "stable".into(),
            install_root: "/app".into(),
            args: vec![],
            health_checks: vec![],
            repository: updated::config::ManagedRepositoryLimits {
                metadata_limit: 1,
                target_limit: 1,
                transport_timeout_seconds: 1,
            },
            storage: updated::config::ManagedStorage {
                inactive_releases: 1,
                inactive_providers: 1,
                inactive_supervisors: 1,
                inactive_bytes: 1,
                inactive_repository_caches: 1,
            },
            timeouts: updated::config::ManagedTimeouts {
                check_interval_seconds: 1,
                health_grace_seconds: 1,
                health_successes: 1,
                health_interval_seconds: 1,
                retry_after_seconds: 1,
                refresh_retry_seconds: 1,
                confirmation_window_seconds: 1,
                supervisor_check_interval_seconds: 1,
                drain_hold_seconds: Some(0),
            },
        };
        let assignment = |metadata: &str, targets: &str| RepositoryAssignment {
            schema: 2,
            deployment: "deployment".into(),
            metadata_url: metadata.into(),
            targets_url: targets.into(),
            report_url: None,
            application: updated::config::TargetReference {
                path: "app".into(),
                sha256: "aa".into(),
            },
            ordered_install_fallback: false,
            provider_set: updated::config::TargetReference {
                path: "providers".into(),
                sha256: "bb".into(),
            },
            release_root: serde_json::json!({}),
            runtime: runtime(),
        };
        let a = assignment("https://cdn/a/metadata/", "https://cdn/a/targets/");
        let b = assignment("https://cdn/b/metadata/", "https://cdn/b/targets/");
        assert_eq!(assignment_identity(&a), assignment_identity(&a));
        assert_ne!(assignment_identity(&a), assignment_identity(&b));
        assert_eq!(assignment_identity(&a).len(), 64);
    }

    #[test]
    fn deployment_changes_do_not_reset_the_tuf_rollback_history() {
        let mut first = RepositoryAssignment {
            schema: 2,
            deployment: "deploy-1".into(),
            metadata_url: "https://cdn/group/metadata/".into(),
            targets_url: "https://cdn/group/targets/".into(),
            report_url: None,
            application: updated::config::TargetReference {
                path: "products/app/stable/1/linux-x86_64/app".into(),
                sha256: "a".repeat(64),
            },
            ordered_install_fallback: false,
            provider_set: updated::config::TargetReference {
                path: "provider-sets/1.json".into(),
                sha256: "b".repeat(64),
            },
            release_root: serde_json::json!({}),
            runtime: updated::config::ManagedRuntime {
                product: "app".into(),
                channel: "stable".into(),
                install_root: "/app".into(),
                args: vec![],
                health_checks: vec![],
                repository: updated::config::ManagedRepositoryLimits {
                    metadata_limit: 1,
                    target_limit: 1,
                    transport_timeout_seconds: 1,
                },
                storage: updated::config::ManagedStorage {
                    inactive_releases: 1,
                    inactive_providers: 1,
                    inactive_supervisors: 1,
                    inactive_bytes: 1,
                    inactive_repository_caches: 1,
                },
                timeouts: updated::config::ManagedTimeouts {
                    check_interval_seconds: 1,
                    health_grace_seconds: 1,
                    health_successes: 1,
                    health_interval_seconds: 1,
                    retry_after_seconds: 1,
                    refresh_retry_seconds: 1,
                    confirmation_window_seconds: 1,
                    supervisor_check_interval_seconds: 1,
                    drain_hold_seconds: Some(0),
                },
            },
        };
        let datastore = assignment_identity(&first);
        first.deployment = "deploy-2".into();
        first.application.sha256 = "c".repeat(64);
        first.provider_set.sha256 = "d".repeat(64);
        assert_eq!(datastore, assignment_identity(&first));
    }

    #[test]
    fn prune_retains_the_active_assignments_datastore_and_removes_a_stale_one() {
        // Mirror the exact protected-set construction in `assigned`: the active assignment's
        // identity is the one directory that must survive pruning, because it carries tough's
        // anti-rollback floor. A stale inactive assignment's cache is fair game.
        let active = assignment_identity(&RepositoryAssignment {
            schema: 2,
            deployment: "active".into(),
            metadata_url: "https://cdn/active/metadata/".into(),
            targets_url: "https://cdn/active/targets/".into(),
            report_url: None,
            application: updated::config::TargetReference {
                path: "app".into(),
                sha256: "aa".into(),
            },
            ordered_install_fallback: false,
            provider_set: updated::config::TargetReference {
                path: "providers".into(),
                sha256: "bb".into(),
            },
            release_root: serde_json::json!({}),
            runtime: runtime(),
        });
        let stale = assignment_identity(&RepositoryAssignment {
            schema: 2,
            deployment: "stale".into(),
            metadata_url: "https://cdn/stale/metadata/".into(),
            targets_url: "https://cdn/stale/targets/".into(),
            report_url: None,
            application: updated::config::TargetReference {
                path: "app".into(),
                sha256: "aa".into(),
            },
            ordered_install_fallback: false,
            provider_set: updated::config::TargetReference {
                path: "providers".into(),
                sha256: "bb".into(),
            },
            release_root: serde_json::json!({}),
            runtime: runtime(),
        });
        assert_ne!(active, stale);

        let datastore = std::env::temp_dir().join(format!(
            "updated-tuf-prune-{}-{}",
            std::process::id(),
            updated::rand::token().unwrap()
        ));
        for identity in [&active, &stale] {
            let dir = datastore.join(identity);
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("timestamp.json"), b"floor").unwrap();
        }

        // The active identity is excluded from the prune set exactly as in `assigned`.
        let protected = std::iter::once(std::ffi::OsString::from(active.clone())).collect();
        // Zero inactive retention: without protection, both directories would be eligible.
        let removed =
            updated::gc::prune_directories(&datastore, &protected, 0, 0).expect("prune succeeds");

        assert_eq!(
            removed, 1,
            "only the stale inactive cache should be removed"
        );
        assert!(
            datastore.join(&active).is_dir(),
            "the active assignment's datastore (and its rollback floor) must survive pruning"
        );
        assert!(
            !datastore.join(&stale).exists(),
            "a stale inactive assignment's cache is eligible for GC"
        );
        let _ = std::fs::remove_dir_all(&datastore);
    }

    #[test]
    fn assigned_endpoints_are_bounded_http_base_urls() {
        assert!(validate_release_url("metadata_url", "https://cdn.example/metadata/").is_ok());
        assert!(validate_release_url("metadata_url", "file:///opt/update/metadata/").is_ok());
        assert!(validate_release_url("metadata_url", "/opt/update/metadata/").is_ok());
        for invalid in [
            "relative/metadata/",
            "ftp://cdn.example/metadata/",
            "https://user:pass@cdn.example/metadata/",
            "https://cdn.example/metadata/?generation=1",
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

/// A loaded, verified TUF repository. [`load`](Self::load) — and [`assigned`](Self::assigned),
/// which resolves the routing assignment first — performs the complete TUF refresh workflow.
pub struct TrustedRepository {
    config: updated::config::RepositorySource,
    repo: Repository,
    assignment: Option<updated::config::RepositoryAssignment>,
}

/// Enroll (or load the one-way preplaced enrollment bundle), verify the current
/// routing assignment, and materialize the complete managed configuration it signs.
/// The caller supplies a durable enrollment state directory; no managed install path
/// is consulted until after the assignment has passed TUF verification.
pub async fn resolve_managed_config(
    bootstrap_path: &Path,
    enrollment_state: &Path,
) -> Result<updated::config::Config, Error> {
    let bootstrap = updated::enrollment::BootstrapConfig::load(bootstrap_path)
        .map_err(|error| Error::Local(format!("loading bootstrap config: {error}")))?;
    let bundle = updated::enrollment::load_or_enroll_http(&bootstrap, enrollment_state)
        .await
        .map_err(|error| Error::Local(format!("loading enrollment bundle: {error}")))?;
    let routing_root = enrollment_state.join("routing-root.json");
    foundation::durable::atomic_write(
        &routing_root,
        ".routing-root-",
        bundle.routing_root.as_bytes(),
    )
    .map_err(|error| Error::Local(format!("materializing routing root: {error}")))?;
    // The gateway that serves routing and release metadata is the same externally-exposed listener
    // the agent enrolled through, so ongoing fetches present the same mTLS identity: the per-node
    // certificate the node minted at `/enroll`.
    let mtls = bootstrap
        .enrollment
        .steady_identity(enrollment_state)
        .map_err(|error| Error::Local(format!("resolving steady-state mTLS identity: {error}")))?;
    let routing = updated::config::Routing {
        root: routing_root,
        base_url: bundle.routing_base_url.clone(),
        assignment: bundle.assignment.clone(),
        datastore: None,
        metadata_limit: 1024 * 1024,
        transport_timeout: std::time::Duration::from_secs(30),
        mtls,
    };
    // The enrollment bundle carries the assignment as of enrollment. Once the node has resolved a
    // live routing assignment (persisted by the update loop), THAT is the current managed config:
    // a control-plane reassignment changes the launch spec, health checks, cadence, and retention,
    // and the running supervisor must boot on those, not the enrollment-frozen values. The embedded
    // assignment seeds only the very first boot, before any live resolution — and the loop still
    // re-verifies and reconciles the live assignment every cycle, so a stale or tampered persisted
    // file is corrected within one tick. Any read/parse/validate failure falls back to embedded.
    let embedded = verify_embedded_assignment(&bundle)?;
    let assignment = persisted_assignment(&embedded.runtime.install_root).unwrap_or(embedded);
    assignment
        .runtime
        .materialize(routing, &assignment.release_root, enrollment_state)
        .map_err(Error::Trust)
}

/// The last live routing assignment this node resolved, which the update loop persists to
/// `<install_root>/state/repository-assignment.json` (see [`updated::config::Paths::resolve_paths`],
/// which derives the same path). Returned only when it parses and structurally validates, so any
/// failure leaves the caller on the enrollment-embedded assignment.
fn persisted_assignment(install_root: &Path) -> Option<updated::config::RepositoryAssignment> {
    // Mirrors `resolve_paths`: state_dir = <install_root>/state, assignment = state_dir/…json.
    let path = install_root
        .join("state")
        .join("repository-assignment.json");
    let bytes = std::fs::read(path).ok()?;
    let assignment: updated::config::RepositoryAssignment = serde_json::from_slice(&bytes).ok()?;
    assignment.validate().ok()?;
    Some(assignment)
}

/// Verify the complete initial TUF chain carried by an enrollment bundle and return
/// the exact managed assignment it authenticates. This is the offline installer path:
/// no network operation is permitted or required.
fn verify_embedded_assignment(
    bundle: &updated::enrollment::EnrollmentBundle,
) -> Result<updated::config::RepositoryAssignment, Error> {
    let root_bytes = bundle.routing_root.as_bytes();
    let timestamp_bytes = bundle.initial.timestamp.as_bytes();
    let snapshot_bytes = bundle.initial.snapshot.as_bytes();
    let targets_bytes = bundle.initial.targets.as_bytes();
    let agent_bytes = bundle.initial.agent_document.as_bytes();
    let config_bytes = bundle.initial.managed_configuration.as_bytes();

    let root: Signed<Root> = parse_embedded(root_bytes, "root")?;
    let timestamp: Signed<Timestamp> = parse_embedded(timestamp_bytes, "timestamp")?;
    let snapshot: Signed<Snapshot> = parse_embedded(snapshot_bytes, "snapshot")?;
    let targets: Signed<Targets> = parse_embedded(targets_bytes, "targets")?;
    root.signed
        .verify_role(&root)
        .map_err(|error| Error::Trust(format!("embedded root signature: {error}")))?;
    root.signed
        .verify_role(&timestamp)
        .map_err(|error| Error::Trust(format!("embedded timestamp signature: {error}")))?;
    root.signed
        .verify_role(&snapshot)
        .map_err(|error| Error::Trust(format!("embedded snapshot signature: {error}")))?;
    root.signed
        .verify_role(&targets)
        .map_err(|error| Error::Trust(format!("embedded targets signature: {error}")))?;
    let now = jiff::Timestamp::now();
    for (name, expires) in [
        ("root", root.signed.expires()),
        ("timestamp", timestamp.signed.expires()),
        ("snapshot", snapshot.signed.expires()),
        ("targets", targets.signed.expires()),
    ] {
        if expires <= now {
            return Err(Error::Trust(format!("embedded {name} metadata is expired")));
        }
    }
    if timestamp.signed.meta.len() != 1 {
        return Err(Error::Trust(
            "embedded timestamp must describe exactly snapshot.json".into(),
        ));
    }
    let snapshot_meta = timestamp
        .signed
        .meta
        .get("snapshot.json")
        .ok_or_else(|| Error::Trust("embedded timestamp omits snapshot.json".into()))?;
    verify_metafile("snapshot", snapshot_meta, snapshot_bytes)?;
    if snapshot.signed.version != snapshot_meta.version {
        return Err(Error::Trust(
            "embedded snapshot version does not match timestamp".into(),
        ));
    }
    let targets_meta = snapshot
        .signed
        .meta
        .get("targets.json")
        .ok_or_else(|| Error::Trust("embedded snapshot omits targets.json".into()))?;
    verify_metafile("targets", targets_meta, targets_bytes)?;
    if targets.signed.version != targets_meta.version {
        return Err(Error::Trust(
            "embedded targets version does not match snapshot".into(),
        ));
    }
    verify_embedded_target(&targets, &bundle.assignment, agent_bytes, "agent document")?;
    let agent: updated::config::AgentDocument = parse_embedded(agent_bytes, "agent document")?;
    agent.validate().map_err(Error::Trust)?;
    verify_embedded_target(
        &targets,
        &agent.config.path,
        config_bytes,
        "managed configuration",
    )?;
    let actual_config = updated::hash::sha256_bytes(config_bytes);
    if actual_config != agent.config.sha256 {
        return Err(Error::Trust(
            "embedded managed configuration digest does not match agent document".into(),
        ));
    }
    let assignment: updated::config::RepositoryAssignment =
        parse_embedded(config_bytes, "managed configuration")?;
    assignment.validate().map_err(Error::Trust)?;
    Ok(assignment)
}

fn parse_embedded<T: serde::de::DeserializeOwned>(bytes: &[u8], name: &str) -> Result<T, Error> {
    serde_json::from_slice(bytes)
        .map_err(|error| Error::Trust(format!("invalid embedded {name}: {error}")))
}

fn verify_metafile(name: &str, meta: &tough::schema::Metafile, bytes: &[u8]) -> Result<(), Error> {
    if meta
        .length
        .is_some_and(|length| length != bytes.len() as u64)
    {
        return Err(Error::Trust(format!("embedded {name} length mismatch")));
    }
    if let Some(hashes) = &meta.hashes {
        let actual = digest(&SHA256, bytes);
        if hashes.sha256.as_ref() != actual.as_ref() {
            return Err(Error::Trust(format!("embedded {name} digest mismatch")));
        }
    }
    Ok(())
}

fn verify_embedded_target(
    targets: &Signed<Targets>,
    path: &str,
    bytes: &[u8],
    name: &str,
) -> Result<(), Error> {
    let target_name = TargetName::new(path)
        .map_err(|error| Error::Trust(format!("invalid embedded {name} path: {error}")))?;
    let target = targets
        .signed
        .targets
        .get(&target_name)
        .ok_or_else(|| Error::Trust(format!("embedded targets omit {name} {path}")))?;
    if target.length != bytes.len() as u64
        || target.hashes.sha256.as_ref() != digest(&SHA256, bytes).as_ref()
    {
        return Err(Error::Trust(format!(
            "embedded {name} length or digest mismatch"
        )));
    }
    Ok(())
}

impl TrustedRepository {
    /// Resolve only the signed routing document. This deliberately does not touch the
    /// selected release repository: callers can use the verified managed runtime to
    /// derive its install paths and resource limits first.
    pub async fn resolve_assignment(
        routing_config: &updated::config::Routing,
        routing_datastore: &Path,
        assignment_staging: &Path,
    ) -> Result<updated::config::RepositoryAssignment, Error> {
        if !routing_config.base_url.ends_with('/') {
            return Err(Error::Local(
                "routing.base_url must end with '/' so metadata/ and targets/ are children".into(),
            ));
        }
        let base = repository_base("routing.base_url", &routing_config.base_url)
            .map_err(|error| Error::Local(error.to_string()))?;
        let metadata_url = base
            .join("metadata/")
            .map_err(|e| Error::Local(format!("routing metadata URL: {e}")))?;
        let targets_url = base
            .join("targets/")
            .map_err(|e| Error::Local(format!("routing targets URL: {e}")))?;
        let source = updated::config::RepositorySource {
            root: routing_config.root.clone(),
            metadata_url: metadata_url.to_string(),
            targets_url: targets_url.to_string(),
            metadata_limit: routing_config.metadata_limit,
            target_limit: 64 * 1024,
            transport_timeout: routing_config.transport_timeout,
            mtls: routing_config.mtls.clone(),
        };
        let routing = Self::load(&source, routing_datastore).await?;
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
        routing.download_target(&target, assignment_staging).await?;
        let bytes = tokio::fs::read(assignment_staging)
            .await
            .map_err(|e| Error::Local(format!("reading verified agent document: {e}")))?;
        let agent: updated::config::AgentDocument = serde_json::from_slice(&bytes)
            .map_err(|e| Error::Trust(format!("invalid agent document: {e}")))?;
        agent.validate().map_err(Error::Trust)?;
        let config = routing.exact_target(&agent.config)?;
        routing.download_target(&config, assignment_staging).await?;
        let bytes = tokio::fs::read(assignment_staging)
            .await
            .map_err(|e| Error::Local(format!("reading verified config bundle: {e}")))?;
        let assignment: updated::config::RepositoryAssignment = serde_json::from_slice(&bytes)
            .map_err(|e| Error::Trust(format!("invalid config bundle: {e}")))?;
        assignment.validate().map_err(Error::Trust)?;
        Ok(assignment)
    }

    /// Resolve the agent's exact, TUF-verified document and then load the
    /// selected release repository. Repeating this operation is how a running node
    /// observes control-plane group changes without restart.
    pub async fn assigned(
        routing_config: &updated::config::Routing,
        repository_config: &updated::config::Repository,
        storage: &updated::config::Storage,
        paths: &updated::config::Paths,
    ) -> Result<Self, Error> {
        let assignment =
            Self::resolve_assignment(routing_config, &paths.routing_datastore, &paths.assignment)
                .await?;
        let assignment_key = assignment_identity(&assignment);
        let assignment_store = paths.datastore.join(&assignment_key);
        std::fs::create_dir_all(&assignment_store).map_err(|error| {
            Error::Local(format!("creating assigned repository state: {error}"))
        })?;
        let release_root = assignment_store.join("release-root.json");
        foundation::durable::atomic_write(
            &release_root,
            ".release-root-",
            &serde_json::to_vec(&assignment.release_root)
                .map_err(|error| Error::Trust(format!("encoding signed release root: {error}")))?,
        )
        .map_err(|error| Error::Local(format!("materializing signed release root: {error}")))?;
        let source = updated::config::RepositorySource {
            root: release_root,
            metadata_url: assignment.metadata_url.clone(),
            targets_url: assignment.targets_url.clone(),
            metadata_limit: repository_config.metadata_limit,
            target_limit: repository_config.target_limit,
            transport_timeout: repository_config.transport_timeout,
            // The release repository is the same externally-exposed gateway as routing.
            mtls: routing_config.mtls.clone(),
        };
        validate_release_url("metadata_url", &source.metadata_url)?;
        validate_release_url("targets_url", &source.targets_url)?;
        let mut repository = Self::load(&source, &assignment_store).await?;
        repository.assignment = Some(assignment);
        // The active assignment's datastore holds tough's version-monotonicity floor
        // (the highest timestamp/snapshot version this node has ever accepted). Pruning it
        // would let the next load restart with no floor and accept an older validly-signed,
        // non-expired metadata set — a rollback attack. So the active identity is always in
        // `protected` and can never be GC'd, regardless of retention limits.
        //
        // Residual: with the persisted floor gone we would still refuse *expired* metadata,
        // so the anti-rollback window collapses to the timestamp/snapshot expiry horizon.
        // Keeping that horizon short is a publishing-side concern, not enforced here; the
        // floor below is the durable defense and must not be discarded.
        let protected = std::iter::once(assignment_key.into()).collect();
        if let Err(error) = updated::gc::prune_directories(
            &paths.datastore,
            &protected,
            storage.inactive_repository_caches,
            storage.inactive_bytes,
        ) {
            foundation::log::warn(
                "tuf",
                &format!("could not prune inactive repository metadata caches: {error}"),
            );
        }
        Ok(repository)
    }
    /// Load the pinned root and refresh the full metadata chain.
    pub async fn load(
        config: &updated::config::RepositorySource,
        datastore: &Path,
    ) -> Result<Self, Error> {
        let repo = Self::load_repo(config, datastore).await?;
        Ok(Self {
            config: config.clone(),
            repo,
            assignment: None,
        })
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
        let metadata_url = repository_base("metadata base", &config.metadata_url)?;
        let targets_url = repository_base("targets base", &config.targets_url)?;
        tokio::fs::create_dir_all(datastore)
            .await
            .map_err(|e| Error::Local(format!("creating datastore: {e}")))?;
        let load = RepositoryLoader::new(&root, metadata_url, targets_url)
            .transport(transport::transport(&config.mtls))
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
        timeout(config.transport_timeout, load)
            .await
            .map_err(|_| transport_timeout(config.transport_timeout, "refreshing metadata"))?
            .map_err(classify)
    }

    /// Every verified target in the trusted metadata.
    pub fn all_targets(&self) -> Vec<VerifiedTarget> {
        self.repo
            .all_targets()
            .map(|(name, target)| to_verified(name.raw(), target))
            .collect()
    }

    /// The exact desired deployment authenticated by the routing repository.
    pub fn assignment(&self) -> Option<&updated::config::RepositoryAssignment> {
        self.assignment.as_ref()
    }

    /// Resolve an exact target reference without version or "latest" selection.
    pub fn exact_target(
        &self,
        reference: &updated::config::TargetReference,
    ) -> Result<VerifiedTarget, Error> {
        let target = self
            .all_targets()
            .into_iter()
            .find(|target| target.path == reference.path)
            .ok_or_else(|| {
                Error::Trust(format!(
                    "desired target {} is absent from verified metadata",
                    reference.path
                ))
            })?;
        let actual = target
            .hashes
            .get("sha256")
            .map(hex::encode)
            .ok_or_else(|| Error::Trust(format!("target {} has no sha256", target.path)))?;
        // Case-insensitive, matching `hash::verify_file` and `bundle.rs`: a signed assignment may
        // carry an upper- or mixed-case digest, and `actual` is lowercase `hex::encode`. A
        // case-sensitive `!=` here would spuriously reject a valid uppercase-digest assignment.
        if !actual.eq_ignore_ascii_case(&reference.sha256) {
            return Err(Error::Trust(format!(
                "desired target {} has sha256 {}, expected {}",
                target.path, actual, reference.sha256
            )));
        }
        Ok(target)
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
        let stream = timeout(self.config.transport_timeout, self.repo.read_target(&name))
            .await
            .map_err(|_| transport_timeout(self.config.transport_timeout, "opening target stream"))?
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
            while let Some(chunk) = timeout(self.config.transport_timeout, stream.next())
                .await
                .map_err(|_| {
                    transport_timeout(self.config.transport_timeout, "waiting for target data")
                })?
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
    // Metadata rollback history belongs to a repository endpoint, not a deployment.
    // Changing exact desired targets must reuse the same datastore or every rollout
    // would accidentally reset TUF's remembered version floor.
    let mut bytes = Vec::new();
    for endpoint in [&assignment.metadata_url, &assignment.targets_url] {
        bytes.extend_from_slice(&(endpoint.len() as u64).to_be_bytes());
        bytes.extend_from_slice(endpoint.as_bytes());
    }
    hex::encode(digest(&SHA256, &bytes).as_ref())
}

fn validate_release_url(name: &str, raw: &str) -> Result<(), Error> {
    repository_base(&format!("assignment {name}"), raw).map(|_| ())
}

/// One location grammar for automatic and manual deployments. HTTP(S) and file URLs
/// are accepted directly; an absolute directory path is the shorthand used by a
/// manually placed assignment. All forms resolve to the same TUF transport.
fn repository_base(name: &str, raw: &str) -> Result<Url, Error> {
    let parsed = Url::parse(raw).ok();
    let url = match parsed {
        Some(url) if matches!(url.scheme(), "http" | "https" | "file") => url,
        Some(url) if !url.scheme().is_empty() => {
            return Err(Error::Trust(format!(
                "{name} uses unsupported {} scheme",
                url.scheme()
            )))
        }
        _ => Url::from_directory_path(Path::new(raw)).map_err(|_| {
            Error::Trust(format!(
                "{name} must be an HTTP(S)/file base URL or an absolute directory path"
            ))
        })?,
    };
    if url.cannot_be_a_base() || !url.path().ends_with('/') {
        return Err(Error::Trust(format!(
            "{name} must identify a base directory ending with '/'"
        )));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Trust(format!(
            "{name} must not contain credentials, a query, or a fragment"
        )));
    }
    Ok(url)
}

fn transport_timeout(timeout: Duration, operation: &str) -> Error {
    let timeout = if timeout.subsec_nanos() == 0 {
        format!("{}s", timeout.as_secs())
    } else {
        format!("{:.3}s", timeout.as_secs_f64())
    };
    Error::Transport(format!("timed out after {timeout} while {operation}"))
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
