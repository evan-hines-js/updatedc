#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

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

use std::io::Seek as _;
use std::path::{Path, PathBuf};

use futures::StreamExt;
use tokio::io::AsyncWriteExt;
use tokio::time::{timeout, Duration};
use tough::schema::{Role, Root, Signed, Snapshot, Target, Targets, Timestamp};
use tough::{ExpirationEnforcement, Limits, Repository, RepositoryLoader, TargetName};
use url::Url;

pub mod policy;
pub mod repo;
pub mod select;
pub mod testing;
mod transport;

pub use policy::{DefaultPolicy, PolicyError};
/// Re-exported so a consumer of a selection result names the reference type through the crate that
/// produced it, without depending on the wire-contract crate directly.
pub use updated_contracts::artifact::TargetReference;

/// Read node-owned TUF trust material through the repository's one local-file policy.
///
/// Roots and materialized metadata are durable state, never projected Kubernetes files: the final
/// component must be a regular file rather than a symlink/reparse point, and the caller's wire
/// limit is also the allocation limit. Blocking file I/O stays off the async transport runtime.
pub(crate) async fn read_local_trust_material(path: &Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let limit = usize::try_from(limit).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TUF material limit does not fit this platform",
        )
    })?;
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        foundation::file::read_bounded_regular(&path, limit, foundation::file::FinalSymlink::Refuse)
    })
    .await
    .map_err(std::io::Error::other)?
}

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
    match &e {
        // `tough` verifies content integrity *inside* the fetch stream (a SHA-256
        // digest adapter and a size cap), so a hash mismatch or an oversize body
        // surfaces as a transport error carrying the real cause. Those are trust
        // failures — the bytes were tampered with, and retrying the same mirror is
        // not a fix.
        tough::error::Error::Transport { source, .. } if is_integrity_failure(source) => {
            Error::Trust(e.to_string())
        }
        tough::error::Error::Transport { .. } => Error::Transport(e.to_string()),
        _ => Error::Trust(e.to_string()),
    }
}

/// Whether a `tough` transport error actually reports a content-integrity failure
/// (SHA-256 mismatch or size overrun) raised by the fetch stream's adapters.
fn is_integrity_failure(source: &tough::TransportError) -> bool {
    let mut cause = std::error::Error::source(source);
    while let Some(error) = cause {
        if matches!(
            error.downcast_ref::<tough::error::Error>(),
            Some(tough::error::Error::HashMismatch { .. })
                | Some(tough::error::Error::MaxSizeExceeded { .. })
        ) {
            return true;
        }
        cause = error.source();
    }
    false
}

/// The one `ManagedRuntime`/`RepositoryAssignment` fixture this crate's tests build on.
///
/// Repository ceilings must also admit the fixture's pinned root; the remaining scalar values use
/// the smallest valid filler. A derived `Default` cannot stand in for this, and a per-test copy is
/// thirty lines of noise a reader has to diff against its neighbours to find the one field the test
/// is actually about. Tests state their subject with `..assignment(name)` and leave the rest here.
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod fixture {
    use updated_contracts::assignment::RepositoryAssignment;

    pub(crate) fn runtime() -> updated_contracts::assignment::ManagedRuntime {
        updated_contracts::assignment::testing::minimal_runtime()
    }

    /// A contract-valid assignment, named so a test can tell which of two documents it got back.
    pub(crate) fn assignment(deployment: &str) -> RepositoryAssignment {
        RepositoryAssignment {
            schema: RepositoryAssignment::SCHEMA,
            deployment: deployment.into(),
            metadata_url: "https://cdn/metadata/".into(),
            targets_url: "https://cdn/targets/".into(),
            application: updated_contracts::artifact::TargetReference {
                path: "app".into(),
                sha256: "a".repeat(64),
            },
            cold_install_fallback: false,
            provider_set: updated_contracts::artifact::TargetReference {
                path: "providers".into(),
                sha256: "b".repeat(64),
            },
            release_root: serde_json::json!({}),
            runtime: runtime(),
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod error_tests {
    use super::{transport_timeout, Error};
    use crate::fixture::{assignment, runtime};
    use updated_contracts::assignment::RepositoryAssignment;

    fn lineage(assignment: &RepositoryAssignment) -> updated::state::RepositoryLineage {
        updated::state::RepositoryLineage::from_metadata_url(&assignment.metadata_url)
            .expect("fixture metadata URL is valid")
    }

    /// Every way of not having a usable persisted assignment changes whether a transport outage can
    /// be survived, so each must be distinguishable. An `Option` would collapse ordinary first boot
    /// and a planted document that attempts to move `install_root` into the same silence.
    #[test]
    fn each_way_of_lacking_a_live_assignment_is_reported_distinctly() {
        use super::{persisted_assignment, LiveAssignment};

        let guard = tempfile::tempdir().unwrap();
        let dir = guard.path().to_path_buf();
        // The signed fixture is portable, but its node-local root must match the platform running
        // this boot-config test. Derive both sides from the same enrollment/runtime fixture so the
        // test exercises persisted-assignment identity rather than a Unix path assumption.
        let install_root = runtime().install_root;
        let path = updated::config::persisted_assignment_path(&dir);
        let usable = || assignment("deployment");
        let plant = |value: serde_json::Value| {
            std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        };

        // Absent — the ordinary first boot, and the only case that is not a fault.
        assert!(matches!(
            persisted_assignment(&dir, &install_root),
            LiveAssignment::Absent
        ));

        plant(serde_json::to_value(usable()).unwrap());
        let persisted_bytes = std::fs::read(&path).unwrap();
        let resolved = persisted_assignment(&dir, &install_root)
            .usable()
            .unwrap_or_else(|reason| panic!("a valid persisted assignment is usable: {reason}"));
        assert_eq!(
            resolved.sha256,
            updated_contracts::digest::sha256_bytes(&persisted_bytes),
            "offline boot retains the exact assignment identity its input request must name"
        );

        type Corrupt = fn(&mut serde_json::Value);
        let cases: [(&str, Corrupt); 3] = [
            ("would move installRoot", |v| {
                v["runtime"]["installRoot"] = serde_json::json!("/elsewhere");
            }),
            ("metadataUrl is invalid", |v| {
                v["metadataUrl"] = serde_json::json!("ftp://cdn/metadata/");
            }),
            ("deployment identity is invalid", |v| {
                v["deployment"] = serde_json::json!("");
            }),
        ];
        for (expected, mutate) in cases {
            let mut value = serde_json::to_value(usable()).unwrap();
            mutate(&mut value);
            plant(value);
            let reason = persisted_assignment(&dir, &install_root)
                .usable()
                .err()
                .unwrap_or_else(|| panic!("{expected} must not be usable as a boot config"))
                .to_string();
            assert!(
                reason.contains(expected),
                "the reason must name the fault, got: {reason}"
            );
        }

        std::fs::write(&path, b"{not json").unwrap();
        let reason = persisted_assignment(&dir, &install_root)
            .usable()
            .expect_err("malformed JSON is never usable")
            .to_string();
        assert!(reason.contains("is malformed"));
        let _ = std::fs::remove_dir_all(dir);
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
        // The repository URLs are the whole subject: the datastore identity must follow them.
        let at = |metadata: &str, targets: &str| RepositoryAssignment {
            metadata_url: metadata.into(),
            targets_url: targets.into(),
            ..assignment("deployment")
        };
        let a = at("https://cdn/a/metadata/", "https://cdn/a/targets/");
        let b = at("https://cdn/b/metadata/", "https://cdn/b/targets/");
        assert_eq!(lineage(&a), lineage(&a));
        assert_ne!(lineage(&a), lineage(&b));
        assert_eq!(lineage(&a).as_str().len(), 64);
    }

    #[test]
    fn deployment_changes_do_not_reset_the_tuf_rollback_history() {
        let mut first = RepositoryAssignment {
            metadata_url: "https://cdn/group/metadata/".into(),
            targets_url: "https://cdn/group/targets/".into(),
            application: updated_contracts::artifact::TargetReference {
                path: "products/app/stable/1/linux-x86_64/app".into(),
                sha256: "a".repeat(64),
            },
            ..assignment("deploy-1")
        };
        let datastore = lineage(&first);
        first.deployment = "deploy-2".into();
        first.application.sha256 = "c".repeat(64);
        assert_eq!(datastore, lineage(&first));
    }

    #[test]
    fn changing_only_the_targets_mirror_keeps_the_tuf_rollback_history() {
        let first = assignment("deployment");
        let mirrored = RepositoryAssignment {
            targets_url: "https://mirror/targets/".into(),
            ..first.clone()
        };

        assert_eq!(lineage(&first), lineage(&mirrored));
    }

    #[test]
    fn prune_retains_the_active_assignments_datastore_and_removes_a_stale_one() {
        // Mirror the exact protected-set construction in `assigned`: the active assignment's
        // identity is the one directory that must survive pruning, because it carries tough's
        // anti-rollback floor. A stale inactive assignment's cache is fair game.
        let active = lineage(&RepositoryAssignment {
            metadata_url: "https://cdn/active/metadata/".into(),
            targets_url: "https://cdn/active/targets/".into(),
            ..assignment("active")
        });
        let stale = lineage(&RepositoryAssignment {
            metadata_url: "https://cdn/stale/metadata/".into(),
            targets_url: "https://cdn/stale/targets/".into(),
            ..assignment("stale")
        });
        assert_ne!(active, stale);

        let guard = tempfile::tempdir().unwrap();
        let datastore = guard.path().to_path_buf();
        for identity in [&active, &stale] {
            let dir = datastore.join(identity.as_str());
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("timestamp.json"), b"floor").unwrap();
        }

        // The active identity is excluded from the prune set exactly as in `assigned`.
        let protected = std::iter::once(std::ffi::OsString::from(active.as_str())).collect();
        // Zero inactive retention: without protection, both directories would be eligible.
        let removed =
            updated::gc::prune_directories(&datastore, &protected, 0, 0).expect("prune succeeds");

        assert_eq!(
            removed, 1,
            "only the stale inactive cache should be removed"
        );
        assert!(
            datastore.join(active.as_str()).is_dir(),
            "the active assignment's datastore (and its rollback floor) must survive pruning"
        );
        assert!(
            !datastore.join(stale.as_str()).exists(),
            "a stale inactive assignment's cache is eligible for GC"
        );
        let _ = std::fs::remove_dir_all(&datastore);
    }

    fn routing() -> updated::config::Routing {
        updated::config::Routing {
            root: "/state/routing-root.json".into(),
            base_url: "https://gateway.example/routing/".into(),
            assignment: "assignments/agents/node.json".into(),
            transport_timeout: std::time::Duration::from_secs(30),
            mtls: updated::tls::Identity::new(
                "/state/client.crt",
                "/state/client.key",
                "/state/ca.crt",
            ),
        }
    }

    /// The routing limits are the only ones no signed assignment and no operator setting can
    /// raise, and both fail the node closed and non-retryably when they bite — so they are
    /// decided here, above every shape the control plane may publish, not by the caller.
    #[test]
    fn routing_limits_are_fixed_regardless_of_what_the_caller_configured() {
        use super::{routing_source, ROUTING_METADATA_FLOOR, ROUTING_TARGET_LIMIT};

        let source = routing_source(&routing()).unwrap();
        assert_eq!(
            source.metadata_url,
            "https://gateway.example/routing/metadata/"
        );
        assert_eq!(
            source.targets_url,
            "https://gateway.example/routing/targets/"
        );
        assert_eq!(source.metadata_limit, ROUTING_METADATA_FLOOR);
        assert_eq!(source.target_limit, ROUTING_TARGET_LIMIT);

        let mut bad = routing();
        bad.base_url = "https://gateway.example/routing".into();
        assert!(routing_source(&bad).is_err(), "the base must end in '/'");
    }

    /// The routing target limit must sit above the largest config bundle the signed contract
    /// permits: a document the control plane may legitimately publish and the node then refuses
    /// as `Error::Trust` is unfetchable forever, since that error is not retryable and no knob
    /// raises this limit.
    #[test]
    fn the_routing_target_limit_admits_the_largest_bounded_input_selection() {
        use super::ROUTING_TARGET_LIMIT;
        use updated_contracts::dataflow::InputSelection;

        let mut runtime = runtime();
        runtime.inputs = InputSelection {
            generation: "a".repeat(64),
            object_sha256: "b".repeat(64),
            files: (0..updated_contracts::dataflow::FileSnapshot::MAX_FILES)
                .map(|index| format!("{index:02}{}", "i".repeat(126)))
                .collect(),
        };
        let assignment = RepositoryAssignment {
            schema: RepositoryAssignment::SCHEMA,
            deployment: "deployment".into(),
            metadata_url: "https://cdn/metadata/".into(),
            targets_url: "https://cdn/targets/".into(),
            application: updated_contracts::artifact::TargetReference {
                path: "products/app/stable/1.0.0/linux-x86_64/app".into(),
                sha256: "a".repeat(64),
            },
            cold_install_fallback: false,
            provider_set: updated_contracts::artifact::TargetReference {
                path: "provider-sets/web.json".into(),
                sha256: "b".repeat(64),
            },
            release_root: serde_json::json!({}),
            runtime,
        };
        assignment
            .validate()
            .expect("this is the maximal shape the contract accepts, not an invalid one");
        let encoded = serde_json::to_vec(&assignment).unwrap().len() as u64;
        assert!(
            encoded < ROUTING_TARGET_LIMIT,
            "a contract-valid config bundle of {encoded} bytes must not exceed the \
             {ROUTING_TARGET_LIMIT} byte routing limit"
        );
        assert_eq!(
            assignment.runtime.inputs.files.len(),
            updated_contracts::dataflow::FileSnapshot::MAX_FILES
        );
    }
}

/// A target whose existence, length, and hashes are authenticated by the current
/// trusted TUF metadata chain. Produced only by [`TrustedRepository`].
#[derive(Debug, Clone)]
pub struct VerifiedTarget {
    /// The logical TUF target path.
    pub path: String,
    pub length: u64,
    /// The sha256 digest bytes the metadata signs. Always present: TUF targets metadata carries it
    /// for every target, so there is no "unhashed target" case for a caller to handle.
    pub sha256: Vec<u8>,
    /// Signed, opaque custom metadata (product/version/os/arch/...).
    pub custom: serde_json::Value,
}

/// One downloaded target held open on the exact inode whose signed length and digest were checked.
///
/// Consumers deliberately do not receive the pathname. Small documents are collected through
/// [`read_bounded`](Self::read_bounded), bundles through [`install_bundle`](Self::install_bundle),
/// and agent binaries through [`install_executable`](Self::install_executable). Each operation
/// rechecks the held handle immediately before consuming it, so verification can never be separated
/// from use by reopening a replaceable path.
#[must_use = "a downloaded TUF target must be consumed through its verified handle"]
#[derive(Debug)]
pub struct DownloadedTarget {
    file: std::fs::File,
    destination: PathBuf,
    expected_length: u64,
    expected_sha256: String,
}

impl DownloadedTarget {
    fn verify_handle(&mut self) -> std::io::Result<()> {
        let (actual_sha256, actual_length) = updated::hash::sha256_file_handle(&mut self.file)?;
        if actual_length != self.expected_length
            || !updated_contracts::digest::digests_match(&actual_sha256, &self.expected_sha256)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "downloaded target {} no longer matches its signed length and digest",
                    self.destination.display()
                ),
            ));
        }
        Ok(())
    }

    /// Read a small target into memory under both the caller's allocation bound and the target's
    /// signed length/digest. The digest is computed from the returned bytes themselves.
    pub fn read_bounded(&mut self, limit: usize) -> Result<Vec<u8>, Error> {
        if self.expected_length > limit as u64 {
            return Err(Error::Trust(format!(
                "downloaded target is {} bytes, over its {limit}-byte document limit",
                self.expected_length
            )));
        }
        self.file
            .rewind()
            .map_err(|error| Error::Local(format!("rewinding downloaded target: {error}")))?;
        let bytes = foundation::file::read_opened_bounded(&mut self.file, limit)
            .map_err(|error| Error::Local(format!("reading downloaded target: {error}")))?;
        let actual_sha256 = updated_contracts::digest::sha256_bytes(&bytes);
        if bytes.len() as u64 != self.expected_length
            || !updated_contracts::digest::digests_match(&actual_sha256, &self.expected_sha256)
        {
            return Err(Error::Local(format!(
                "downloaded target {} changed after TUF verification",
                self.destination.display()
            )));
        }
        Ok(bytes)
    }

    /// Install a bundle from this exact verified handle.
    pub fn install_bundle(
        &mut self,
        store: &updated::provider::BundleStore,
        expected: &updated::bundle::ExpectedBundle<'_>,
    ) -> Result<updated::bundle::ReleaseId, updated::bundle::InstallError> {
        self.verify_handle()
            .map_err(updated::bundle::InstallError::Storage)?;
        store.install_file(&mut self.file, expected)
    }

    /// Atomically install an agent executable from this exact verified handle.
    pub fn install_executable(&mut self, target: &Path) -> std::io::Result<()> {
        self.verify_handle()?;
        foundation::durable::install_executable_from(target, &mut self.file)
    }
}

/// A loaded, verified TUF repository. [`load`](Self::load) — and [`assigned`](Self::assigned),
/// which resolves the routing assignment first — performs the complete TUF refresh workflow.
pub struct TrustedRepository {
    config: updated::config::RepositorySource,
    repo: Repository,
    assignment: Option<AssignmentContext>,
}

/// The three identities authenticated together when the routing repository resolves an assignment.
///
/// Keeping the document, its exact-byte digest, and its repository lineage in one immutable value
/// prevents downstream code from recomputing or accidentally pairing facts from different
/// assignments. A plain [`TrustedRepository::load`] has no context; only
/// [`TrustedRepository::assigned`] can construct one.
pub struct AssignmentContext {
    document: updated_contracts::assignment::RepositoryAssignment,
    sha256: String,
    repository_lineage: updated::state::RepositoryLineage,
}

impl AssignmentContext {
    pub fn document(&self) -> &updated_contracts::assignment::RepositoryAssignment {
        &self.document
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn repository_lineage(&self) -> &updated::state::RepositoryLineage {
        &self.repository_lineage
    }
}

/// Enroll (or load the one-way preplaced enrollment bundle), verify the current
/// routing assignment, and materialize the complete managed configuration it signs.
/// The caller supplies a durable enrollment state directory; no managed install path
/// is consulted until after the assignment has passed TUF verification.
pub async fn resolve_managed_config(
    config_path: &Path,
    enrollment_state: &Path,
) -> Result<updated::config::Config, Error> {
    let config = updated::enrollment::NodeConfig::load(config_path)
        .map_err(|error| Error::Local(format!("loading the node config: {error}")))?;
    // The private routing gateway is the listener the agent enrolled through, so ongoing routing
    // fetches present the same per-node mTLS identity minted at `/enroll`. The assignment selected
    // from that repository names a separate release-object origin; its client deliberately carries
    // no node identity (though it may reuse the fleet CA bundle as ordinary server trust).
    let mtls = config
        .enrollment
        .steady_identity(enrollment_state)
        .map_err(|error| Error::Local(format!("resolving steady-state mTLS identity: {error}")))?;
    let bundle = updated::enrollment::load_or_enroll_http(&config, enrollment_state)
        .await
        .map_err(|error| Error::Local(format!("loading enrollment bundle: {error}")))?;
    let routing_root = enrollment_state.join("routing-root.json");
    foundation::durable::atomic_write_managed(
        &routing_root,
        ".routing-root-",
        bundle.routing_root.as_bytes(),
    )
    .map_err(|error| Error::Local(format!("materializing routing root: {error}")))?;
    let routing = updated::config::Routing {
        root: routing_root,
        base_url: bundle.routing_base_url.clone(),
        assignment: bundle.assignment.clone(),
        transport_timeout: std::time::Duration::from_secs(30),
        mtls,
    };
    // First boot and every later update resolve the same live TUF/S3 path. The small enrollment
    // object pins only the root, routing identity, assignment path, and immutable install root;
    // copying timestamp/targets/config into every node's object was a second configuration path
    // and quadratic object-store growth. A transport outage may use the last assignment this same
    // verifier durably committed; a trust failure never falls back.
    let assignment_path = updated::config::persisted_assignment_path(enrollment_state);
    let routing_datastore = enrollment_state.join("routing-tuf");
    let live = persisted_assignment(enrollment_state, &bundle.install_root);
    let resolved = match TrustedRepository::resolve_assignment_at(
        &routing,
        &routing_datastore,
        &assignment_path,
        &bundle.install_root,
    )
    .await
    {
        Ok(resolved) => resolved,
        Err(error @ Error::Transport(_)) => match live.usable() {
            Ok(live) => {
                foundation::log::warn(
                    "updated",
                    &format!(
                        "live routing refresh failed; booting the last TUF-verified assignment: {error}"
                    ),
                );
                *live
            }
            Err(reason) => {
                return Err(Error::Transport(format!(
                    "{error}; {reason}, so this node has no verified configuration to boot"
                )))
            }
        },
        Err(error) => return Err(error),
    };
    updated::config::Config::materialize(
        &resolved.assignment.runtime,
        &resolved.assignment.deployment,
        &resolved.sha256,
        routing,
    )
    .map_err(Error::Trust)
}

/// What the node-local copy of the live routing assignment turned out to be.
///
/// Not an `Option`: every way of not having one is a distinct operator situation — a first boot,
/// an unreachable state directory, a corrupted file, a document that would relocate the node — and
/// the caller must be able to say which when the live repository is temporarily unreachable.
enum LiveAssignment {
    // Boxed: the assignment dwarfs the two failure variants, and this is constructed once per
    // boot, so the indirection costs nothing and keeps the enum a pointer wide.
    Usable(Box<ResolvedAssignment>),
    /// No file yet: the ordinary state of a node that has not completed its first update cycle.
    Absent,
    /// Present but not usable as a boot config, for the stated reason.
    Rejected(String),
}

/// Why a boot cannot fall back to a last TUF-verified assignment. Its own type rather than a method
/// on [`LiveAssignment`]: only the two non-usable cases have a reason, and narrowing them out of the
/// enum makes "the live assignment is usable" impossible to print as a failure reason.
enum NoLiveAssignment {
    Absent,
    Rejected(String),
}

impl std::fmt::Display for NoLiveAssignment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Absent => f.write_str("no live routing assignment has been persisted yet"),
            Self::Rejected(reason) => {
                write!(f, "ignoring the persisted routing assignment: {reason}")
            }
        }
    }
}

impl LiveAssignment {
    /// The assignment if it can be booted on, or the reason it cannot.
    fn usable(self) -> Result<Box<ResolvedAssignment>, NoLiveAssignment> {
        match self {
            LiveAssignment::Usable(assignment) => Ok(assignment),
            LiveAssignment::Absent => Err(NoLiveAssignment::Absent),
            LiveAssignment::Rejected(reason) => Err(NoLiveAssignment::Rejected(reason)),
        }
    }
}

/// The last live routing assignment this node resolved, which the update loop persists beside the
/// enrollment material through [`updated::config::persisted_assignment_path`] — the same helper
/// [`updated::config::Paths::resolve`] derives the writer's `assignment` path from, so reader and
/// writer cannot drift.
///
/// Usable only when it parses, structurally validates, carries repository URLs this build can
/// actually fetch from, and leaves the node where the enrollment bundle put it. The persisted file
/// is local state this boot cannot re-verify, so it may refine the assignment the enrollment
/// bundle authenticated but never relocate the node: an `install_root` read out of it would move
/// the binary, state, journal, and rejection set the launcher and agent operate on.
fn persisted_assignment(enrollment_state: &Path, install_root: &Path) -> LiveAssignment {
    let path = updated::config::persisted_assignment_path(enrollment_state);
    let bytes = match foundation::file::read_bounded_regular(
        &path,
        updated_contracts::assignment::RepositoryAssignment::MAX_DOCUMENT_BYTES,
        foundation::file::FinalSymlink::Refuse,
    ) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return LiveAssignment::Absent
        }
        Err(error) => {
            return LiveAssignment::Rejected(format!("{} is unreadable ({error})", path.display()))
        }
    };
    let assignment =
        match updated_contracts::assignment::RepositoryAssignment::from_bounded_json(&bytes) {
            Ok(assignment) => assignment,
            Err(error) => {
                return LiveAssignment::Rejected(format!(
                    "{} is malformed ({error})",
                    path.display()
                ))
            }
        };
    if let Err(reason) = usable_as_boot_config(&assignment, install_root) {
        return LiveAssignment::Rejected(format!("{} {reason}", path.display()));
    }
    LiveAssignment::Usable(Box::new(ResolvedAssignment {
        assignment,
        sha256: updated_contracts::digest::sha256_bytes(&bytes),
    }))
}

/// Whether a routing document may serve as this node's live boot config, or why it may not.
///
/// The signed contract's own `validate` covers its shape and repository transport grammar. The
/// remaining fact that decides whether this node can boot on it is node-local and no publisher can
/// check it: whether the assignment leaves the node where the enrollment bundle put it. An
/// `install_root` taken out of such a document would move the binary, state, journal and rejection
/// set the launcher and agent operate on.
///
/// The writer that commits a freshly resolved document and the reader that boots on the committed
/// one both come through here, so no document can become the live config by a route that skips a
/// check. The reason is phrased as a predicate of the document ("is invalid …") so each caller
/// prefixes its own subject.
fn usable_as_boot_config(
    assignment: &updated_contracts::assignment::RepositoryAssignment,
    install_root: &Path,
) -> Result<(), String> {
    if let Err(error) = assignment.validate() {
        return Err(format!("is invalid ({error})"));
    }
    if assignment.runtime.install_root != install_root {
        return Err(format!(
            "would move installRoot away from the enrollment-verified {}",
            install_root.display()
        ));
    }
    Ok(())
}

/// Verify the exact routing publication used to mint one small enrollment object.
///
/// The object itself carries only the pinned root and immutable node boundary. Before publishing
/// it, the controller proves that the current timestamp/snapshot/targets chain authenticates this
/// agent document and managed assignment, and returns that parsed assignment so the object can pin
/// its install root. These documents remain ordinary shared S3 repository objects; they are never
/// copied into every node's enrollment object.
pub fn verify_enrollment_publication(
    root_bytes: &[u8],
    timestamp_bytes: &[u8],
    snapshot_bytes: &[u8],
    targets_bytes: &[u8],
    assignment_path: &str,
    agent_bytes: &[u8],
    config_bytes: &[u8],
) -> Result<updated_contracts::assignment::RepositoryAssignment, Error> {
    let root: Signed<Root> = parse_enrollment_document(root_bytes, "root")?;
    let timestamp: Signed<Timestamp> = parse_enrollment_document(timestamp_bytes, "timestamp")?;
    let snapshot: Signed<Snapshot> = parse_enrollment_document(snapshot_bytes, "snapshot")?;
    let targets: Signed<Targets> = parse_enrollment_document(targets_bytes, "targets")?;
    root.signed
        .verify_role(&root)
        .map_err(|error| Error::Trust(format!("enrollment root signature: {error}")))?;
    root.signed
        .verify_role(&timestamp)
        .map_err(|error| Error::Trust(format!("enrollment timestamp signature: {error}")))?;
    root.signed
        .verify_role(&snapshot)
        .map_err(|error| Error::Trust(format!("enrollment snapshot signature: {error}")))?;
    root.signed
        .verify_role(&targets)
        .map_err(|error| Error::Trust(format!("enrollment targets signature: {error}")))?;

    let now = jiff::Timestamp::now();
    for (role, expires) in [
        ("root", root.signed.expires()),
        ("timestamp", timestamp.signed.expires()),
        ("snapshot", snapshot.signed.expires()),
        ("targets", targets.signed.expires()),
    ] {
        if expires <= now {
            return Err(Error::Trust(format!(
                "enrollment {role} metadata is expired"
            )));
        }
    }
    if timestamp.signed.meta.len() != 1 {
        return Err(Error::Trust(
            "enrollment timestamp must describe exactly snapshot.json".into(),
        ));
    }
    let snapshot_meta = timestamp
        .signed
        .meta
        .get("snapshot.json")
        .ok_or_else(|| Error::Trust("enrollment timestamp omits snapshot.json".into()))?;
    verify_enrollment_metafile("snapshot", snapshot_meta, snapshot_bytes)?;
    if snapshot.signed.version != snapshot_meta.version {
        return Err(Error::Trust(
            "enrollment snapshot version does not match timestamp".into(),
        ));
    }
    let targets_meta = snapshot
        .signed
        .meta
        .get("targets.json")
        .ok_or_else(|| Error::Trust("enrollment snapshot omits targets.json".into()))?;
    verify_enrollment_metafile("targets", targets_meta, targets_bytes)?;
    if targets.signed.version != targets_meta.version {
        return Err(Error::Trust(
            "enrollment targets version does not match snapshot".into(),
        ));
    }
    verify_enrollment_target(&targets, assignment_path, agent_bytes, "agent document")?;
    let agent = updated_contracts::artifact::AgentDocument::from_bounded_json(agent_bytes)
        .map_err(Error::Trust)?;
    verify_enrollment_target(
        &targets,
        &agent.config.path,
        config_bytes,
        "managed configuration",
    )?;
    updated_contracts::assignment::RepositoryAssignment::from_bounded_json(config_bytes)
        .map_err(Error::Trust)
}

fn parse_enrollment_document<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    name: &str,
) -> Result<T, Error> {
    serde_json::from_slice(bytes)
        .map_err(|error| Error::Trust(format!("invalid enrollment {name}: {error}")))
}

fn verify_enrollment_metafile(
    name: &str,
    meta: &tough::schema::Metafile,
    bytes: &[u8],
) -> Result<(), Error> {
    if meta
        .length
        .is_some_and(|length| length != bytes.len() as u64)
    {
        return Err(Error::Trust(format!("enrollment {name} length mismatch")));
    }
    if let Some(hashes) = &meta.hashes {
        if !updated_contracts::digest::digests_match(
            &updated_contracts::digest::sha256_bytes(bytes),
            &hex::encode(&hashes.sha256),
        ) {
            return Err(Error::Trust(format!("enrollment {name} digest mismatch")));
        }
    }
    Ok(())
}

fn verify_enrollment_target(
    targets: &Signed<Targets>,
    path: &str,
    bytes: &[u8],
    name: &str,
) -> Result<(), Error> {
    let target_name = TargetName::new(path)
        .map_err(|error| Error::Trust(format!("invalid enrollment {name} path: {error}")))?;
    let target = targets
        .signed
        .targets
        .get(&target_name)
        .ok_or_else(|| Error::Trust(format!("enrollment targets omit {name} {path}")))?;
    if target.length != bytes.len() as u64
        || !updated_contracts::digest::digests_match(
            &updated_contracts::digest::sha256_bytes(bytes),
            &hex::encode(&target.hashes.sha256),
        )
    {
        return Err(Error::Trust(format!(
            "enrollment {name} length or digest mismatch"
        )));
    }
    Ok(())
}
/// A verified routing assignment together with the digest of the exact document it came from.
#[derive(Debug)]
pub struct ResolvedAssignment {
    pub assignment: updated_contracts::assignment::RepositoryAssignment,
    /// SHA-256 (hex) of the signed assignment bytes — the content identity the node reports so the
    /// control plane can distinguish two revisions of one deployment name.
    pub sha256: String,
}

/// Byte ceiling for a routing target — the agent document and the config bundle it names.
///
/// Derived from the contract rather than picked, because a routing target that exceeds it is
/// rejected as [`Error::Trust`], which is not retryable: the node stops updating entirely, points
/// the operator at a tampering event that never happened, and no signed or operator-settable knob
/// can raise the limit (the assignment's own `repository.target_limit` governs the *release*
/// repository). So the ceiling must sit above the largest document the control plane is allowed to
/// publish. A config bundle is a signed `RepositoryAssignment`; its bounded file selection is much
/// smaller than a full dataflow snapshot, so reserving one complete snapshot ceiling covers it with
/// ample JSON-escaping overhead.
const ROUTING_TARGET_LIMIT: u64 =
    updated_contracts::assignment::RepositoryAssignment::MAX_DOCUMENT_BYTES as u64;

/// Floor for the routing repository's metadata limit, applied to whatever the caller configured.
///
/// The routing `targets.json` carries one entry per enrolled node plus one per deployment, so it
/// grows linearly with the fleet — roughly 200 bytes each. It is the one metadata document whose
/// size is a property of the fleet rather than of any one node's configuration, and, unlike the
/// release repository's limit, no signed assignment or operator setting can raise it once it is
/// too low. Exceeding it does not degrade one node: it aborts the `targets.json` fetch on every
/// node at once, so the whole fleet stops resolving assignments simultaneously and the fix — a new
/// agent binary — can no longer be delivered through the update path it broke. This floor
/// puts that cliff past a hundred thousand nodes; a caller that wants more may still ask for more.
const ROUTING_METADATA_FLOOR: u64 = 64 * 1024 * 1024;

/// Name prefix of the staging temp a target is streamed into before it is renamed over its
/// destination. Named once because it is both what [`TrustedRepository::download_target`]
/// creates and what it sweeps: a rename that never happened leaves this behind, and the sweep is
/// the only thing that reclaims it.
const TARGET_STAGING_PREFIX: &str = ".target-";

/// The repository source the routing repository is loaded through — the one place routing
/// metadata and target limits are decided, so both the fleet-scale floor and the contract-derived
/// target ceiling apply to every caller regardless of what it configured.
fn routing_source(
    routing_config: &updated::config::Routing,
) -> Result<updated::config::RepositorySource, Error> {
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
    Ok(updated::config::RepositorySource {
        root: routing_config.root.clone(),
        metadata_url: metadata_url.to_string(),
        targets_url: targets_url.to_string(),
        metadata_limit: ROUTING_METADATA_FLOOR,
        target_limit: ROUTING_TARGET_LIMIT,
        transport_timeout: routing_config.transport_timeout,
        access: updated::config::RepositoryAccess::GatewayCapability,
        mtls: routing_config.mtls.clone(),
    })
}

impl TrustedRepository {
    /// Resolve only the signed routing document. This deliberately does not touch the
    /// selected release repository: callers can use the verified managed runtime to
    /// derive its install paths and resource limits first.
    pub async fn resolve_assignment(
        routing_config: &updated::config::Routing,
        paths: &updated::config::Paths,
    ) -> Result<ResolvedAssignment, Error> {
        Self::resolve_assignment_at(
            routing_config,
            &paths.routing_datastore,
            &paths.assignment,
            &paths.install_root,
        )
        .await
    }

    /// The one routing-resolution implementation, parameterized only by its durable locations and
    /// immutable install-root pin. Boot uses it before `Paths` can be derived; the running update
    /// loop passes those exact same locations back through [`Self::resolve_assignment`].
    async fn resolve_assignment_at(
        routing_config: &updated::config::Routing,
        routing_datastore: &Path,
        assignment_path: &Path,
        install_root: &Path,
    ) -> Result<ResolvedAssignment, Error> {
        let source = routing_source(routing_config)?;
        let routing = Self::load(&source, routing_datastore).await?;
        let target = routing.target(&routing_config.assignment).ok_or_else(|| {
            Error::Trust(format!(
                "routing assignment {} is absent from verified metadata",
                routing_config.assignment
            ))
        })?;
        // Download into scratch, never over the live assignment file. That file IS this node's
        // persisted managed configuration: writing the intermediate agent document into it, or
        // failing between the two downloads, would leave the node's own config replaced by a
        // half-resolved document — and the next boot could otherwise fall back to a document that
        // was never fully resolved or durably committed.
        let staging = updated::config::with_suffix(assignment_path, ".resolving");
        let staged = async {
            let mut downloaded = routing.download_target(&target, &staging).await?;
            let bytes = downloaded
                .read_bounded(updated_contracts::artifact::AgentDocument::MAX_DOCUMENT_BYTES)?;
            let agent = updated_contracts::artifact::AgentDocument::from_bounded_json(&bytes)
                .map_err(|e| Error::Trust(format!("invalid agent document: {e}")))?;
            let config = routing.exact_target(&agent.config)?;
            let mut downloaded = routing.download_target(&config, &staging).await?;
            let bytes = downloaded.read_bounded(
                updated_contracts::assignment::RepositoryAssignment::MAX_DOCUMENT_BYTES,
            )?;
            let assignment =
                updated_contracts::assignment::RepositoryAssignment::from_bounded_json(&bytes)
                    .map_err(|e| Error::Trust(format!("invalid config bundle: {e}")))?;
            Ok::<_, Error>((assignment, bytes))
        }
        .await;
        // The staging file is scratch on every path out of here, failures included: an agent
        // document whose config target is absent from metadata fails on every poll, and each one
        // would otherwise leave a file named like the live assignment holding the intermediate
        // document. Nothing sweeps it — `download_target` reclaims only its own prefix.
        let _ = std::fs::remove_file(&staging);
        let (assignment, bytes) = staged?;
        // This write REPLACES the node's live boot config — the document the next boot launches the
        // managed application from, before any network. So everything that decides whether a node
        // can boot on it is proven here, ahead of the write, through the same check the reader
        // applies: afterwards the last good assignment is already gone, and a document rejected
        // later fails non-retryably with nothing to roll back to.
        //
        // Rejecting here is deliberately loud, and wider than it looks: this is the one refresh both
        // the application check and the self-update ride on, so an unusable published assignment now
        // stops the node updating at all until an operator republishes. That is the direction to
        // fail — a document the node cannot boot on must never become the document it boots on — but
        // it is a real escalation from persisting it and ignoring it at the next boot, which kept
        // updates flowing while quietly running an assignment nobody had checked.
        usable_as_boot_config(&assignment, install_root)
            .map_err(|reason| Error::Trust(format!("the resolved assignment {reason}")))?;
        write_if_changed(assignment_path, ".assignment-", &bytes)
            .map_err(|e| Error::Local(format!("persisting the resolved assignment: {e}")))?;
        Ok(ResolvedAssignment {
            // The digest TUF just verified these exact bytes against — the same value the control
            // plane published this configuration under, and the node's content identity for it.
            sha256: updated_contracts::digest::sha256_bytes(&bytes),
            assignment,
        })
    }

    /// Resolve the agent's exact, TUF-verified document and then load the
    /// selected release repository. Repeating this operation is how a running node
    /// observes control-plane group changes without restart.
    ///
    /// The repository's own limits and timeout come from the assignment that was just verified —
    /// the same document that names the repository — so a control-plane change to them takes
    /// effect on the next cycle like every other runtime field, with no node-local copy to drift
    /// from it or to pin the process to its boot-time values.
    pub async fn assigned(
        routing_config: &updated::config::Routing,
        storage: &updated_contracts::assignment::ManagedStorage,
        paths: &updated::config::Paths,
    ) -> Result<Self, Error> {
        let resolved = Self::resolve_assignment(routing_config, paths).await?;
        let ResolvedAssignment {
            assignment,
            sha256: assignment_sha256,
        } = resolved;
        let limits = &assignment.runtime.repository;
        // The TUF rollback floor, installed-version ordering, and rejection policy are one
        // repository-lineage fact. They all key exclusively on the authenticated metadata origin;
        // moving the target-object mirror must not manufacture a blank rollback history.
        let repository_lineage =
            updated::state::RepositoryLineage::from_metadata_url(&assignment.metadata_url)
                .map_err(|error| {
                    Error::Trust(format!("assignment metadataUrl is invalid: {error}"))
                })?;
        let assignment_store = paths.datastore.join(repository_lineage.as_str());
        std::fs::create_dir_all(&assignment_store).map_err(|error| {
            Error::Local(format!("creating assigned repository state: {error}"))
        })?;
        let release_root = assignment_store.join("release-root.json");
        write_if_changed(
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
            metadata_limit: limits.metadata_limit,
            target_limit: limits.target_limit,
            transport_timeout: Duration::from_secs(limits.transport_timeout_seconds),
            // A release repository is signed desired state, not the routing capability origin.
            // It is fetched without presenting the node's control-plane identity.
            access: updated::config::RepositoryAccess::Direct,
            mtls: routing_config.mtls.clone(),
        };
        let mut repository = Self::load(&source, &assignment_store).await?;
        repository.assignment = Some(AssignmentContext {
            document: assignment,
            sha256: assignment_sha256,
            repository_lineage: repository_lineage.clone(),
        });
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
        let protected =
            std::iter::once(std::ffi::OsString::from(repository_lineage.as_str())).collect();
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
        let root = read_local_trust_material(&config.root, config.metadata_limit)
            .await
            .map_err(|e| {
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
            .transport(transport::transport(&config.mtls, config.access))
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

    /// Every verified target in the trusted metadata. For callers that genuinely enumerate —
    /// version selection and its diagnostics; a lookup by name uses `target` instead.
    pub fn all_targets(&self) -> Vec<VerifiedTarget> {
        self.repo
            .all_targets()
            .map(|(name, target)| to_verified(name.raw(), target))
            .collect()
    }

    /// The one verified target published under `path`, or `None` if the trusted metadata does not
    /// name it.
    ///
    /// Indexed, not a scan of [`Self::all_targets`]: the routing `targets.json` carries one entry
    /// per enrolled node plus one per deployment (see [`ROUTING_METADATA_FLOOR`]), and every check
    /// cycle resolves targets by name, so scanning would make a per-node operation cost the whole
    /// fleet. Reading the top-level `targets` map is the same set the scan saw because this crate
    /// mints a single top-level `targets` role and no delegations (see [`repo`]); a delegated
    /// repository would need this to consult them too.
    fn target(&self, path: &str) -> Option<VerifiedTarget> {
        let name = TargetName::new(path).ok()?;
        self.repo
            .targets()
            .signed
            .targets
            .get(&name)
            .map(|target| to_verified(path, target))
    }

    /// The exact desired deployment, exact-byte digest, and repository lineage authenticated by
    /// the routing repository, exposed only as the unit they were resolved as.
    pub fn assignment_context(&self) -> Option<&AssignmentContext> {
        self.assignment.as_ref()
    }

    /// The largest target this repository will fetch — for [`assigned`](Self::assigned), the
    /// ceiling the resolved assignment signs. Callers that bound what they do with a downloaded
    /// target (bundle extraction, say) read it here rather than from a node-local copy, so one
    /// signed value governs the whole acquisition.
    pub fn target_limit(&self) -> u64 {
        self.config.target_limit
    }

    /// Resolve an exact target reference without version or "latest" selection.
    pub fn exact_target(
        &self,
        reference: &updated_contracts::artifact::TargetReference,
    ) -> Result<VerifiedTarget, Error> {
        let target = self.target(&reference.path).ok_or_else(|| {
            Error::Trust(format!(
                "desired target {} is absent from verified metadata",
                reference.path
            ))
        })?;
        let actual = hex::encode(&target.sha256);
        if !updated_contracts::digest::digests_match(&actual, &reference.sha256) {
            return Err(Error::Trust(format!(
                "desired target {} has sha256 {}, expected {}",
                target.path, actual, reference.sha256
            )));
        }
        Ok(target)
    }

    /// Stream a verified target to `destination`. `tough` verifies length and
    /// hashes against the trusted metadata while streaming; if the stream yields
    /// an error the partial file is unusable and is removed. Staging temps abandoned by an
    /// earlier interrupted download in the same directory are swept first — see
    /// [`TARGET_STAGING_PREFIX`].
    pub async fn download_target(
        &self,
        target: &VerifiedTarget,
        destination: &Path,
    ) -> Result<DownloadedTarget, Error> {
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
        // Reclaim staging temps orphaned by an abrupt death mid-stream. The error paths below
        // remove their own partial file, but a SIGKILL, a power loss or a reboot between the
        // create and the rename leaves a full-size `.target-*.tmp` that nothing else sweeps —
        // the staging roots we download into hold fixed destination files, not per-attempt
        // directories, so neither the bundle sweep nor directory pruning ever sees them. A
        // crash-looping node would otherwise accumulate one bundle-sized orphan per attempt
        // until the install root fills. `sweep_stale_temps` skips anything written recently,
        // so a download in flight beside this one is never yanked.
        foundation::durable::sweep_stale_temps(dir, TARGET_STAGING_PREFIX);
        // A downloaded target is node-local state, not a secret and not something this node
        // serves: it lands in the install root's staging area and is read back by this service
        // only. `create_temp_managed` keeps the deployment's own grant on that tree governing it,
        // rather than committing a protected DACL that an operator CLI or installer step running
        // as a different principal could then neither read nor replace.
        let (file, temporary) =
            foundation::durable::create_temp_managed(dir, TARGET_STAGING_PREFIX)
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
        if let Err(error) = result {
            drop(file);
            if let Err(cleanup) = tokio::fs::remove_file(&temporary).await {
                if cleanup.kind() != std::io::ErrorKind::NotFound {
                    return Err(Error::Local(format!(
                        "{error}; also removing partial target {} failed: {cleanup}",
                        temporary.display()
                    )));
                }
            }
            return Err(error);
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
        let destination = destination.to_path_buf();
        let expected_length = target.length;
        let expected_sha256 = hex::encode(&target.sha256);
        tokio::task::spawn_blocking(move || {
            let file = foundation::file::open_regular(
                &destination,
                foundation::file::FinalSymlink::Refuse,
            )?;
            let mut downloaded = DownloadedTarget {
                file,
                destination,
                expected_length,
                expected_sha256,
            };
            downloaded.verify_handle()?;
            Ok::<_, std::io::Error>(downloaded)
        })
        .await
        .map_err(|error| Error::Local(format!("joining target verification task: {error}")))?
        .map_err(|error| Error::Local(format!("verifying downloaded target file: {error}")))
    }
}

/// Turn the contracts crate's one repository grammar into the URL used by the transport. Keeping
/// no local parser here is important: a location cannot pass the signed-contract boundary and then
/// acquire a different meaning when TUF constructs its transport.
fn repository_base(name: &str, raw: &str) -> Result<Url, Error> {
    updated_contracts::assignment::canonical_repository_base(raw)
        .map_err(|error| Error::Trust(format!("{name} is invalid: {error}")))
}

fn transport_timeout(timeout: Duration, operation: &str) -> Error {
    let timeout = if timeout.subsec_nanos() == 0 {
        format!("{}s", timeout.as_secs())
    } else {
        format!("{:.3}s", timeout.as_secs_f64())
    };
    Error::Transport(format!("timed out after {timeout} while {operation}"))
}

/// Durably write `bytes` to `path` unless it already holds exactly those bytes.
///
/// Both callers sit on the per-cycle refresh ([`TrustedRepository::assigned`], run every
/// `check_interval`), and both write content that is byte-identical from one cycle to the next
/// almost always — while [`foundation::durable::atomic_write_managed`] is a temp write, an fsync,
/// a rename and a directory fsync. Nothing depends on the rewrite happening when the content is
/// unchanged: both files are read back only as content, and the anti-rollback floor lives in the
/// tough datastore, not here. Bytes that differ — a truncated or tampered file included — still
/// take the write, so the self-healing property is unchanged.
fn write_if_changed(path: &Path, prefix: &str, bytes: &[u8]) -> std::io::Result<()> {
    if foundation::file::read_bounded_regular(
        path,
        bytes.len(),
        foundation::file::FinalSymlink::Refuse,
    )
    .ok()
    .as_deref()
        == Some(bytes)
    {
        return Ok(());
    }
    foundation::durable::atomic_write_managed(path, prefix, bytes)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod write_if_changed_tests {
    use super::write_if_changed;

    #[test]
    fn oversized_existing_content_is_replaced_without_an_unbounded_read() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("assignment.json");
        std::fs::write(&path, vec![b'x'; 1024 * 1024]).unwrap();

        write_if_changed(&path, ".assignment-", b"bounded").unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), b"bounded");
    }

    #[cfg(unix)]
    #[test]
    fn a_matching_symlink_is_replaced_instead_of_being_accepted() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        let path = directory.path().join("assignment.json");
        std::fs::write(&target, b"same").unwrap();
        symlink(&target, &path).unwrap();

        write_if_changed(&path, ".assignment-", b"same").unwrap();

        assert!(!std::fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read(&path).unwrap(), b"same");
    }
}

fn to_verified(path: &str, target: &Target) -> VerifiedTarget {
    VerifiedTarget {
        path: path.to_string(),
        length: target.length,
        sha256: target.hashes.sha256.to_vec(),
        custom: serde_json::to_value(&target.custom).unwrap_or(serde_json::Value::Null),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod integrity_tests {
    use super::{classify, repository_base, Error};
    use crate::repo;
    use std::path::{Path, PathBuf};
    use tough::{ExpirationEnforcement, FilesystemTransport, Limits, RepositoryLoader};

    fn scratch(label: &str) -> (tempfile::TempDir, PathBuf) {
        let guard = tempfile::tempdir().unwrap();
        let dir = guard.path().join(label);
        std::fs::create_dir_all(&dir).unwrap();
        (guard, dir)
    }

    async fn minted(tmp: &Path) -> PathBuf {
        let repo_dir = tmp.join("repo");
        let keys = repo::generate_keys(&tmp.join("keys")).await.unwrap();
        repo::init(&repo_dir, &keys, 365).await.unwrap();
        repo_dir
    }

    /// Load a minted repository off the filesystem, the way a node loads it over the wire.
    async fn load(repo_dir: &Path, datastore: &Path, snapshot_limit: u64) -> Result<(), Error> {
        let root = std::fs::read(repo_dir.join("metadata/root.json")).unwrap();
        let metadata_url = repository_base(
            "metadata base",
            &format!("{}/", repo_dir.join("metadata").display()),
        )
        .unwrap();
        let targets_url = repository_base(
            "targets base",
            &format!("{}/", repo_dir.join("targets").display()),
        )
        .unwrap();
        std::fs::create_dir_all(datastore).unwrap();
        RepositoryLoader::new(&root, metadata_url, targets_url)
            .transport(FilesystemTransport)
            .datastore(datastore.to_owned())
            .limits(Limits {
                max_root_size: 1024 * 1024,
                max_targets_size: 1024 * 1024,
                max_timestamp_size: 1024 * 1024,
                max_snapshot_size: snapshot_limit,
                max_root_updates: 1024,
            })
            .expiration_enforcement(ExpirationEnforcement::Safe)
            .load()
            .await
            .map(|_| ())
            .map_err(classify)
    }

    /// The newest published copy of a versioned role document.
    fn newest(metadata: &Path, file: &str) -> PathBuf {
        std::fs::read_dir(metadata)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                let name = entry.file_name().into_string().ok()?;
                let version: u64 = name.strip_suffix(&format!(".{file}"))?.parse().ok()?;
                Some((version, entry.path()))
            })
            .max_by_key(|(version, _)| *version)
            .unwrap_or_else(|| panic!("no published {file} in {}", metadata.display()))
            .1
    }

    /// `tough` checks content integrity inside the fetch stream, so a hash mismatch and a size
    /// overrun both arrive wrapped in its transport variant. They are tampering, not a flaky link:
    /// classifying them as retryable would retry a compromised mirror on the fast cadence and
    /// raise no trust alarm.
    #[tokio::test]
    async fn tampered_metadata_is_a_trust_failure_not_a_retryable_transport_blip() {
        let (_tmp, tmp) = scratch("integrity");
        let repo_dir = minted(&tmp).await;

        // A clean repository loads, so the failures below are about the tampering only.
        load(&repo_dir, &tmp.join("clean"), 1024 * 1024)
            .await
            .expect("a freshly minted repository verifies");

        // A missing file is a genuine transport problem and stays retryable.
        let empty = tmp.join("empty/metadata");
        std::fs::create_dir_all(&empty).unwrap();
        std::fs::copy(repo_dir.join("metadata/root.json"), empty.join("root.json")).unwrap();
        let missing = load(&tmp.join("empty"), &tmp.join("missing-store"), 1024 * 1024)
            .await
            .unwrap_err();
        assert!(
            missing.is_retryable(),
            "an absent file is a transport problem, got: {missing}"
        );

        // One flipped byte in signed metadata: the digest adapter fails the stream.
        let snapshot = newest(&repo_dir.join("metadata"), "snapshot.json");
        let mut bytes = std::fs::read(&snapshot).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        std::fs::write(&snapshot, &bytes).unwrap();
        let tampered = load(&repo_dir, &tmp.join("tampered-store"), 1024 * 1024)
            .await
            .unwrap_err();
        assert!(
            matches!(tampered, Error::Trust(_)) && !tampered.is_retryable(),
            "a hash mismatch must fail closed, got: {tampered}"
        );

        // An oversize role document is the other in-stream integrity check.
        std::fs::write(&snapshot, &bytes[..last]).unwrap();
        let oversize = load(&repo_dir, &tmp.join("oversize-store"), 8)
            .await
            .unwrap_err();
        assert!(
            matches!(oversize, Error::Trust(_)) && !oversize.is_retryable(),
            "a length overrun must fail closed, got: {oversize}"
        );
        let _ = std::fs::remove_dir_all(tmp);
    }

    /// An absolute directory path is a documented location form. On Windows it carries a drive
    /// letter, which `Url::parse` happily reads as a one-letter scheme — so the path form has to be
    /// recognised before parsing, or an offline deployment is refused as a tampering event.
    #[test]
    fn an_absolute_directory_path_is_a_location_not_a_scheme() {
        let base = if cfg!(windows) {
            r"C:\ProgramData\updated\release\metadata\"
        } else {
            "/opt/update/metadata/"
        };
        let url = repository_base("metadata base", base).expect("an absolute path is a location");
        assert_eq!(url.scheme(), "file");
        // A real unsupported scheme is still refused.
        assert!(repository_base("metadata base", "ftp://cdn.example/metadata/").is_err());
    }
}
