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
/// Re-exported so a consumer of a selection result names the reference type through the crate that
/// produced it, without depending on the wire-contract crate directly.
pub use updated_contracts::artifact::TargetReference;

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

#[cfg(test)]
mod error_tests {
    use super::{assignment_identity, transport_timeout, validate_release_url, Error};
    use updated_contracts::assignment::RepositoryAssignment;

    fn runtime() -> updated_contracts::assignment::ManagedRuntime {
        updated_contracts::assignment::ManagedRuntime {
            mode: updated_contracts::assignment::RuntimeMode::Managed,
            product: "app".into(),
            channel: "stable".into(),
            install_root: "/app".into(),
            args: vec![],
            secrets: vec![],
            inputs: std::collections::BTreeMap::new(),
            repository: updated_contracts::assignment::ManagedRepositoryLimits {
                metadata_limit: 1,
                target_limit: 1,
                transport_timeout_seconds: 1,
            },
            storage: updated_contracts::assignment::ManagedStorage {
                inactive_releases: 1,
                inactive_providers: 1,
                inactive_supervisors: 1,
                inactive_bytes: 1,
                inactive_repository_caches: 1,
            },
            timeouts: updated_contracts::assignment::ManagedTimeouts {
                check_interval_seconds: 1,
                health_grace_seconds: 1,
                health_successes: 1,
                health_interval_seconds: 1,
                refresh_retry_seconds: 1,
                confirmation_window_seconds: 1,
                supervisor_check_interval_seconds: 1,
                drain_hold_seconds: Some(0),
            },
        }
    }

    /// A contract-valid assignment, named so a test can tell which of two documents it got back.
    fn assignment(deployment: &str) -> RepositoryAssignment {
        RepositoryAssignment {
            schema: RepositoryAssignment::SCHEMA,
            deployment: deployment.into(),
            metadata_url: "https://cdn/metadata/".into(),
            targets_url: "https://cdn/targets/".into(),
            report_url: None,
            application: updated_contracts::artifact::TargetReference {
                path: "app".into(),
                sha256: "a".repeat(64),
            },
            ordered_install_fallback: false,
            provider_set: updated_contracts::artifact::TargetReference {
                path: "providers".into(),
                sha256: "b".repeat(64),
            },
            release_root: serde_json::json!({}),
            runtime: runtime(),
        }
    }

    /// Every way of not having a usable live assignment costs the node one launch of the managed
    /// application on enrollment-frozen configuration, so each must be distinguishable — an
    /// `Option` here would collapse "first boot" and "someone planted a document that would move
    /// install_root" into the same silence.
    #[test]
    fn each_way_of_lacking_a_live_assignment_is_reported_distinctly() {
        use super::{persisted_assignment, LiveAssignment};

        let guard = tempfile::tempdir().unwrap();
        let dir = guard.path().to_path_buf();
        let install_root = std::path::Path::new("/app");
        let path = updated::config::persisted_assignment_path(&dir);
        let usable = || assignment("deployment");
        let plant = |value: serde_json::Value| {
            std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        };

        // Absent — the ordinary first boot, and the only case that is not a fault.
        assert!(matches!(
            persisted_assignment(&dir, install_root),
            LiveAssignment::Absent
        ));

        plant(serde_json::to_value(usable()).unwrap());
        assert!(matches!(
            persisted_assignment(&dir, install_root),
            LiveAssignment::Usable(_)
        ));

        type Corrupt = fn(&mut serde_json::Value);
        let cases: [(&str, Corrupt); 3] = [
            ("would move install_root", |v| {
                v["runtime"]["install_root"] = serde_json::json!("/elsewhere");
            }),
            ("has a bad metadata_url", |v| {
                v["metadata_url"] = serde_json::json!("ftp://cdn/metadata/");
            }),
            ("is invalid", |v| {
                v["deployment"] = serde_json::json!("");
            }),
        ];
        for (expected, mutate) in cases {
            let mut value = serde_json::to_value(usable()).unwrap();
            mutate(&mut value);
            plant(value);
            let reason = persisted_assignment(&dir, install_root)
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
        let reason = persisted_assignment(&dir, install_root)
            .usable()
            .expect_err("malformed JSON is never usable")
            .to_string();
        assert!(reason.contains("is malformed"));
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The enrollment bundle is written once and never rewritten, so every long-lived node
    /// eventually holds an expired embedded chain. A node that has since resolved and persisted a
    /// live routing assignment must still boot on it: the alternative — the state this replaces —
    /// was a hard trust failure out of option parsing, a crash-looping supervisor, a stopped
    /// application, and no update loop to ever fix it.
    #[test]
    fn an_expired_enrollment_bundle_still_boots_a_node_that_has_live_state() {
        use super::{boot_assignment, Generation, LiveAssignment, VerifiedEmbedded};

        let embedded = |expired_role| VerifiedEmbedded {
            assignment: assignment("enrollment-frozen"),
            expired_role,
            generation: Generation {
                timestamp: 1,
                snapshot: 1,
                targets: 1,
            },
        };
        let live = || LiveAssignment::Usable(Box::new(assignment("live")));

        let booted = boot_assignment(embedded(Some("timestamp")), live())
            .expect("an expired bundle must not stop a node that holds verified newer state");
        assert_eq!(booted.deployment, "live");

        // And the pin is not what was relaxed: with nothing newer to boot on, the expired chain is
        // still the current repository state and is still refused, naming the role that expired.
        let reason = boot_assignment(embedded(Some("timestamp")), LiveAssignment::Absent)
            .expect_err("first use of an expired chain has no verified state to fall back to")
            .to_string();
        assert!(
            reason.contains("embedded timestamp metadata is expired"),
            "the refusal must name the expired role, got: {reason}"
        );
        // A live document that exists but cannot be booted on is not verified newer state either.
        assert!(boot_assignment(
            embedded(Some("root")),
            LiveAssignment::Rejected("would move install_root".into())
        )
        .is_err());

        // Unexpired, no live state: the ordinary first boot still runs on the embedded assignment.
        let booted = boot_assignment(embedded(None), LiveAssignment::Absent)
            .expect("a fresh bundle is the whole configuration a first boot has");
        assert_eq!(booted.deployment, "enrollment-frozen");
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
        let runtime = || updated_contracts::assignment::ManagedRuntime {
            mode: updated_contracts::assignment::RuntimeMode::Managed,
            product: "app".into(),
            channel: "stable".into(),
            install_root: "/app".into(),
            args: vec![],
            secrets: vec![],
            inputs: std::collections::BTreeMap::new(),
            repository: updated_contracts::assignment::ManagedRepositoryLimits {
                metadata_limit: 1,
                target_limit: 1,
                transport_timeout_seconds: 1,
            },
            storage: updated_contracts::assignment::ManagedStorage {
                inactive_releases: 1,
                inactive_providers: 1,
                inactive_supervisors: 1,
                inactive_bytes: 1,
                inactive_repository_caches: 1,
            },
            timeouts: updated_contracts::assignment::ManagedTimeouts {
                check_interval_seconds: 1,
                health_grace_seconds: 1,
                health_successes: 1,
                health_interval_seconds: 1,
                refresh_retry_seconds: 1,
                confirmation_window_seconds: 1,
                supervisor_check_interval_seconds: 1,
                drain_hold_seconds: Some(0),
            },
        };
        let assignment = |metadata: &str, targets: &str| RepositoryAssignment {
            schema: updated_contracts::assignment::RepositoryAssignment::SCHEMA,
            deployment: "deployment".into(),
            metadata_url: metadata.into(),
            targets_url: targets.into(),
            report_url: None,
            application: updated_contracts::artifact::TargetReference {
                path: "app".into(),
                sha256: "aa".into(),
            },
            ordered_install_fallback: false,
            provider_set: updated_contracts::artifact::TargetReference {
                path: "providers".into(),
                sha256: "b".repeat(64),
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
            schema: RepositoryAssignment::SCHEMA,
            deployment: "deploy-1".into(),
            metadata_url: "https://cdn/group/metadata/".into(),
            targets_url: "https://cdn/group/targets/".into(),
            report_url: None,
            application: updated_contracts::artifact::TargetReference {
                path: "products/app/stable/1/linux-x86_64/app".into(),
                sha256: "a".repeat(64),
            },
            ordered_install_fallback: false,
            provider_set: updated_contracts::artifact::TargetReference {
                path: "providers".into(),
                sha256: "b".repeat(64),
            },
            release_root: serde_json::json!({}),
            runtime: updated_contracts::assignment::ManagedRuntime {
                mode: updated_contracts::assignment::RuntimeMode::Managed,
                product: "app".into(),
                channel: "stable".into(),
                install_root: "/app".into(),
                args: vec![],
                secrets: vec![],
                inputs: std::collections::BTreeMap::new(),
                repository: updated_contracts::assignment::ManagedRepositoryLimits {
                    metadata_limit: 1,
                    target_limit: 1,
                    transport_timeout_seconds: 1,
                },
                storage: updated_contracts::assignment::ManagedStorage {
                    inactive_releases: 1,
                    inactive_providers: 1,
                    inactive_supervisors: 1,
                    inactive_bytes: 1,
                    inactive_repository_caches: 1,
                },
                timeouts: updated_contracts::assignment::ManagedTimeouts {
                    check_interval_seconds: 1,
                    health_grace_seconds: 1,
                    health_successes: 1,
                    health_interval_seconds: 1,
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
        assert_eq!(datastore, assignment_identity(&first));
    }

    #[test]
    fn prune_retains_the_active_assignments_datastore_and_removes_a_stale_one() {
        // Mirror the exact protected-set construction in `assigned`: the active assignment's
        // identity is the one directory that must survive pruning, because it carries tough's
        // anti-rollback floor. A stale inactive assignment's cache is fair game.
        let active = assignment_identity(&RepositoryAssignment {
            schema: RepositoryAssignment::SCHEMA,
            deployment: "active".into(),
            metadata_url: "https://cdn/active/metadata/".into(),
            targets_url: "https://cdn/active/targets/".into(),
            report_url: None,
            application: updated_contracts::artifact::TargetReference {
                path: "app".into(),
                sha256: "aa".into(),
            },
            ordered_install_fallback: false,
            provider_set: updated_contracts::artifact::TargetReference {
                path: "providers".into(),
                sha256: "b".repeat(64),
            },
            release_root: serde_json::json!({}),
            runtime: runtime(),
        });
        let stale = assignment_identity(&RepositoryAssignment {
            schema: RepositoryAssignment::SCHEMA,
            deployment: "stale".into(),
            metadata_url: "https://cdn/stale/metadata/".into(),
            targets_url: "https://cdn/stale/targets/".into(),
            report_url: None,
            application: updated_contracts::artifact::TargetReference {
                path: "app".into(),
                sha256: "aa".into(),
            },
            ordered_install_fallback: false,
            provider_set: updated_contracts::artifact::TargetReference {
                path: "providers".into(),
                sha256: "b".repeat(64),
            },
            release_root: serde_json::json!({}),
            runtime: runtime(),
        });
        assert_ne!(active, stale);

        let guard = tempfile::tempdir().unwrap();
        let datastore = guard.path().to_path_buf();
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
    fn the_routing_target_limit_admits_the_largest_contract_valid_assignment() {
        use super::ROUTING_TARGET_LIMIT;
        use updated_contracts::telemetry::{OutputManifest, OutputValue};

        let mut runtime = runtime();
        runtime.inputs = (0..OutputManifest::MAX_VALUES)
            .map(|i| {
                (
                    format!("{i:0>128}"),
                    OutputValue::String {
                        value: "v".repeat(OutputManifest::MAX_STRING_BYTES),
                    },
                )
            })
            .collect();
        runtime.secrets = (0..64)
            .map(|i| updated_contracts::assignment::SecretReference {
                environment: format!("SECRET_{i}"),
                secret: "s".repeat(253),
                key: "k".repeat(253),
            })
            .collect();
        let assignment = RepositoryAssignment {
            schema: RepositoryAssignment::SCHEMA,
            deployment: "deployment".into(),
            metadata_url: "https://cdn/metadata/".into(),
            targets_url: "https://cdn/targets/".into(),
            report_url: None,
            application: updated_contracts::artifact::TargetReference {
                path: "products/app/stable/1.0.0/linux-x86_64/app".into(),
                sha256: "a".repeat(64),
            },
            ordered_install_fallback: false,
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
        // The old 64 KiB limit is the regression this guards: it sat below the contract.
        assert!(encoded > 64 * 1024);
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

/// A loaded, verified TUF repository. [`load`](Self::load) — and [`assigned`](Self::assigned),
/// which resolves the routing assignment first — performs the complete TUF refresh workflow.
pub struct TrustedRepository {
    config: updated::config::RepositorySource,
    repo: Repository,
    assignment: Option<updated_contracts::assignment::RepositoryAssignment>,
    assignment_sha256: Option<String>,
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
    // The gateway that serves routing and release metadata is the same externally-exposed listener
    // the agent enrolled through, so ongoing fetches present the same mTLS identity: the per-node
    // certificate the node minted at `/enroll`. The refresh policy is given it too, since catching a
    // lagging pin up means reading the repository's published versioned roots.
    let mtls = bootstrap
        .enrollment
        .steady_identity(enrollment_state)
        .map_err(|error| Error::Local(format!("resolving steady-state mTLS identity: {error}")))?;
    let bundle = updated::enrollment::load_or_enroll_http(
        &bootstrap,
        enrollment_state,
        &EmbeddedChainPolicy::new(mtls.clone()),
    )
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
    // The enrollment bundle carries the assignment as of enrollment. Once the node has resolved a
    // live routing assignment (persisted by the update loop), THAT is the current managed config:
    // a control-plane reassignment changes the launch spec, health checks, cadence, and retention,
    // and the running supervisor must boot on those, not the enrollment-frozen values. The embedded
    // assignment seeds only the very first boot, before any live resolution — and the loop still
    // re-verifies and reconciles the live assignment every cycle, so a stale or tampered persisted
    // file is corrected within one tick. Any read/parse/validate failure falls back to embedded,
    // which [`boot_assignment`] then requires to be fresh — the whole decision lives there.
    let embedded = verify_embedded_chain(&bundle)?;
    let live = persisted_assignment(enrollment_state, &embedded.assignment.runtime.install_root);
    let assignment = boot_assignment(embedded, live)?;
    updated::config::Config::materialize(&assignment.runtime, &assignment.deployment, routing)
        .map_err(Error::Trust)
}

/// Which assignment this boot launches the managed application on, or why it cannot boot at all.
///
/// This is where the enrollment bundle's freshness matters and the only place it may be waived.
/// The embedded chain's expiry bounds how long it may stand in for *the current state of the
/// repository*, and that is exactly the job it holds until the node resolves a live assignment of
/// its own. Once one is persisted, the embedded copy has a different and permanent job — it is the
/// enrollment-time root of trust that pinned `install_root` and authenticated the chain, and none
/// of that decays. Requiring it to be fresh anyway is what turned a frozen bundle into a node that
/// hard-fails at boot forever: the bundle is written once at enrollment and never refreshed, so
/// every node outlives its embedded metadata, and the update loop that would fix it never starts.
///
/// Nothing here is relaxed but the clock. Every signature, threshold, digest and the `install_root`
/// pin have already been checked by [`verify_embedded_chain`] and are checked identically whether
/// the chain is expired or not; a node with no verified newer state still refuses to boot on an
/// expired one.
fn boot_assignment(
    embedded: VerifiedEmbedded,
    live: LiveAssignment,
) -> Result<updated_contracts::assignment::RepositoryAssignment, Error> {
    match live.usable() {
        Ok(live) => {
            // Worth saying even though the boot succeeds: the node is running on newer state than
            // its enrollment material, and the material it would fall back to is no longer usable.
            if let Some(role) = embedded.expired_role {
                foundation::log::warn(
                    "updated",
                    &format!(
                        "the enrollment bundle's embedded {role} metadata is expired; this boot \
                         uses the persisted live routing assignment, but the node has no usable \
                         fallback configuration left and must be re-enrolled"
                    ),
                );
            }
            Ok(*live)
        }
        // Booting on the enrollment-frozen assignment is normal exactly once, on a node's first
        // ever boot. Any later occurrence means THIS launch of the managed application uses the
        // product, channel, arguments and secret mapping as of enrollment rather than whatever the
        // control plane has since assigned — one launch on stale configuration, which the update
        // loop then corrects a tick later. That correction is invisible, so the boot that needed
        // it is stated outright, with the reason the live assignment was not usable.
        Err(reason) => {
            foundation::log::warn(
                "updated",
                &format!(
                    "{reason}; this boot launches the managed application on the \
                     enrollment-frozen assignment until the update loop resolves the current one"
                ),
            );
            embedded.fresh()
        }
    }
}

/// What the node-local copy of the live routing assignment turned out to be.
///
/// Not an `Option`: every way of not having one is a distinct operator situation — a first boot,
/// an unreachable state directory, a corrupted file, a document that would relocate the node — and
/// the caller must be able to say which, because the only symptom otherwise is one silent launch
/// on enrollment-frozen configuration.
enum LiveAssignment {
    // Boxed: the assignment dwarfs the two failure variants, and this is constructed once per
    // boot, so the indirection costs nothing and keeps the enum a pointer wide.
    Usable(Box<updated_contracts::assignment::RepositoryAssignment>),
    /// No file yet: the ordinary state of a node that has not completed its first update cycle.
    Absent,
    /// Present but not usable as a boot config, for the stated reason.
    Rejected(String),
}

/// Why a boot fell back to the enrollment-frozen assignment. Its own type rather than a method on
/// [`LiveAssignment`]: only the two non-usable cases have a reason, and narrowing them out of the
/// enum is what makes "the live assignment is usable" impossible to print as a fallback reason.
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
    fn usable(
        self,
    ) -> Result<Box<updated_contracts::assignment::RepositoryAssignment>, NoLiveAssignment> {
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
/// the binary, state, journal, and rejection set the guardian and supervisor operate on.
fn persisted_assignment(enrollment_state: &Path, install_root: &Path) -> LiveAssignment {
    let path = updated::config::persisted_assignment_path(enrollment_state);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return LiveAssignment::Absent
        }
        Err(error) => {
            return LiveAssignment::Rejected(format!("{} is unreadable ({error})", path.display()))
        }
    };
    let assignment: updated_contracts::assignment::RepositoryAssignment =
        match serde_json::from_slice(&bytes) {
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
    LiveAssignment::Usable(Box::new(assignment))
}

/// Whether a routing document may serve as this node's live boot config, or why it may not.
///
/// The signed contract's own `validate` covers its shape, but two of the facts that decide whether
/// a node can boot on it are node-local and no publisher can check them: whether this build can
/// fetch from the endpoints it names, and whether it leaves the node where the enrollment bundle
/// put it. An `install_root` taken out of such a document would move the binary, state, journal and
/// rejection set the guardian and supervisor operate on.
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
    for (field, url) in [
        ("metadata_url", &assignment.metadata_url),
        ("targets_url", &assignment.targets_url),
    ] {
        if let Err(error) = validate_release_url(field, url) {
            return Err(format!("has a bad {field}: {error}"));
        }
    }
    if assignment.runtime.install_root != install_root {
        return Err(format!(
            "would move install_root away from the enrollment-verified {}",
            install_root.display()
        ));
    }
    Ok(())
}

/// Verify the complete initial TUF chain carried by an enrollment bundle and return
/// the exact managed assignment it authenticates: every role signature and threshold against the
/// bundle's own root, every expiry, each metafile digest, and each target digest.
///
/// Self-consistency only — it proves the documents belong together under THAT root. A verifier
/// that did not obtain the root from a trusted source must additionally pin it (see the gateway,
/// which compares it against the digest the controller recorded in etcd); otherwise a substituted
/// root and a matching chain verify perfectly.
///
/// No network operation is permitted or required, so the offline installer path and the gateway's
/// live `/enroll` response are checked by exactly the same code.
pub fn verify_embedded_assignment(
    bundle: &updated_contracts::enrollment::EnrollmentBundle,
) -> Result<updated_contracts::assignment::RepositoryAssignment, Error> {
    verify_embedded_chain(bundle)?.fresh()
}

/// How near expiry an enrollment bundle's embedded chain must be before a node spends a
/// control-plane request replacing it.
///
/// Generous on purpose. The material is checked on the boot path and then every 12 hours by the
/// supervisor's identity tick, so a window of days means an ordinary node replaces its chain long
/// before it matters and a node that is offline, or whose gateway is down, gets many attempts before
/// its bundle stops counting as current. Nothing breaks the moment it lapses — an expired bundle
/// still pins the root of trust and the install root, and a node with live state boots on it — so
/// there is no reason to fetch aggressively.
const BUNDLE_REFRESH_LEAD: jiff::SignedDuration = jiff::SignedDuration::from_hours(72);

/// The trust half of [`updated::enrollment::BundlePolicy`]: when a persisted enrollment bundle is
/// aging, and whether a replacement the gateway offers may be adopted.
///
/// The enrollment module owns the transport and the durability; this owns what the bytes mean,
/// because deciding it needs the same TUF verification the boot path uses — and the refresh path
/// must not have a second, weaker copy of it.
///
/// It carries the node's steady-state mTLS identity for one reason: adopting a root the node was
/// offline several rotations for needs the intermediate versioned roots, and those are fetched from
/// the same routing repository, over the same transport, that every other metadata fetch uses.
pub struct EmbeddedChainPolicy {
    mtls: updated::tls::Identity,
}

/// How long a single versioned-root fetch may take.
///
/// This bounds *progress*, not elapsed time — it is reset by every chunk, exactly like the
/// `read_timeout` on the underlying client — so on its own it does not bound the walk at all. The
/// total bound is [`ROOT_CATCH_UP_DEADLINE`]; this one just fails a single obviously-dead fetch
/// early so a walk with one bad version left in it can still finish.
const ROOT_FETCH_TIMEOUT: Duration = Duration::from_secs(30);

/// The total wall-clock budget for one whole rotation walk, however many versions it covers.
///
/// [`ROOT_FETCH_TIMEOUT`] resets on every byte, so a gateway that trickles one byte just under it
/// holds a single fetch open until the 64 MiB metadata floor is reached — and the walk is up to
/// [`MAX_ROOT_CATCH_UP`] such fetches, run in sequence, awaited inline on the boot path and in the
/// supervisor's single control loop. Without one deadline over the whole walk a node stops probing
/// and reporting health while still looking alive, which is the failure the control-plane deadline
/// on the other two gateway calls exists to prevent.
///
/// Thirty seconds is set by the health path, not by the work: the healthproxy drains a node whose
/// report is older than `REPORT_FRESHNESS` (60s), and the heartbeat runs on the same loop this walk
/// blocks, so the stall this deadline permits must stay well inside that window or the walk itself
/// causes the drain it exists to prevent. The work still fits: a versioned root is a few kilobytes
/// of JSON, so even at the [`MAX_ROOT_CATCH_UP`] ceiling of 64 versions this leaves ~0.4s per
/// fetch, and a real catch-up is one to three versions — which gets the whole budget and can still
/// spend the full [`ROOT_FETCH_TIMEOUT`] on a single slow fetch. It is also invisible against the
/// 12h identity tick that drives the refresh, and short enough that a boot behind a dead gateway
/// proceeds rather than hangs.
///
/// Fail-closed on expiry: the walk is abandoned, the candidate is refused, and the node keeps the
/// root it has — the same outcome an unreachable repository already gets. A genuinely slow but
/// honest origin loses nothing permanent: the walk holds no partial state (the pin only moves when
/// a whole bundle is adopted), and the next tick simply retries against a hopefully quicker origin.
const ROOT_CATCH_UP_DEADLINE: Duration = Duration::from_secs(30);

/// How many root versions one catch-up may walk.
///
/// This is what keeps the bound on the walk a property of the node rather than of the candidate: a
/// bundle claiming version `u64::MAX` would otherwise ask the node to attempt that many fetches.
///
/// 64, not the `max_root_updates` ceiling `tough` uses for its own walk. The two are not the same
/// question: `tough` bounds a walk against a repository it is already talking to, while this bounds
/// how much sequential network work an *unauthenticated* candidate document can conscript the node's
/// control loop into. Roots are renewed about yearly and rotated only on a key ceremony, so even a
/// pessimistic four version bumps a year makes 64 more than fifteen years of lag — far past the
/// point where a node's own certificates have expired and re-enrollment is the answer anyway. The
/// smaller ceiling shrinks the worst case a hostile or hung origin can impose by sixteen times at no
/// cost to any node that can still be recovered by refresh.
const MAX_ROOT_CATCH_UP: u64 = 64;

impl EmbeddedChainPolicy {
    /// The policy as this node's own: `mtls` is the per-node steady-state identity the routing
    /// repository is read through, used only to fetch intermediate versioned roots.
    pub fn new(mtls: updated::tls::Identity) -> Self {
        Self { mtls }
    }

    /// The versioned roots `versions` names, in ascending order, as far as they could be fetched.
    ///
    /// Best-effort by design, and safe to be: nothing here decides anything. Whatever comes back is
    /// handed to [`root_chains_from`], which verifies every step and refuses the candidate outright
    /// if the chain it was given does not reach it. So a repository that is unreachable, a version
    /// the operator never published, or a gateway serving garbage all end the same way the old
    /// behaviour did — the node keeps the root it has — while a genuine multi-version rotation is
    /// walked one signed step at a time.
    ///
    /// The range is [`catch_up_range`]'s, computed and bounded by the caller before a single byte is
    /// fetched, and the roots come from the CURRENT bundle's `routing_base_url`, the origin this node
    /// has been pinned to since enrollment, never from anything the candidate names: a candidate that
    /// could choose where its own predecessors are fetched from would supply the whole chain itself.
    ///
    /// This is the only part of [`Self::accept`] that touches the network, which is why the caller
    /// can put a single [`ROOT_CATCH_UP_DEADLINE`] over the whole of it.
    async fn rotation_chain(
        &self,
        base_url: &str,
        versions: std::ops::RangeInclusive<u64>,
    ) -> Vec<String> {
        let metadata = match repository_base("routing.base_url", base_url).and_then(|base| {
            base.join("metadata/")
                .map_err(|e| Error::Local(e.to_string()))
        }) {
            Ok(metadata) => metadata,
            Err(error) => {
                foundation::log::warn(
                    "updated",
                    &format!("cannot locate the published rotation chain: {error}"),
                );
                return Vec::new();
            }
        };
        let mut chain = Vec::new();
        for version in versions {
            match self.versioned_root(&metadata, version).await {
                Ok(root) => chain.push(root),
                Err(error) => {
                    foundation::log::warn(
                        "updated",
                        &format!(
                            "stopping the root catch-up at version {version}: {error}; the node \
                             keeps the root it has"
                        ),
                    );
                    break;
                }
            }
        }
        chain
    }

    /// Fetch `<metadata>/<version>.root.json` — the copy a TUF repository publishes precisely so a
    /// client can walk the rotation chain — bounded by the routing metadata size floor so an
    /// unbounded response cannot be read into memory.
    async fn versioned_root(&self, metadata: &Url, version: u64) -> Result<String, Error> {
        let url = metadata
            .join(&format!("{version}.root.json"))
            .map_err(|error| Error::Local(format!("versioned root URL: {error}")))?;
        let stream = timeout(
            ROOT_FETCH_TIMEOUT,
            tough::Transport::fetch(&transport::transport(&self.mtls), url.clone()),
        )
        .await
        .map_err(|_| transport_timeout(ROOT_FETCH_TIMEOUT, "fetching a versioned root"))?
        .map_err(|error| Error::Transport(format!("fetching {url}: {error}")))?;
        let mut bytes = Vec::new();
        tokio::pin!(stream);
        while let Some(chunk) = timeout(ROOT_FETCH_TIMEOUT, stream.next())
            .await
            .map_err(|_| transport_timeout(ROOT_FETCH_TIMEOUT, "reading a versioned root"))?
        {
            let chunk =
                chunk.map_err(|error| Error::Transport(format!("reading {url}: {error}")))?;
            bytes.extend_from_slice(&chunk);
            if bytes.len() as u64 > ROUTING_METADATA_FLOOR {
                return Err(Error::Trust(format!(
                    "{url} exceeded the {ROUTING_METADATA_FLOOR} byte metadata limit"
                )));
            }
        }
        String::from_utf8(bytes)
            .map_err(|error| Error::Trust(format!("{url} is not UTF-8: {error}")))
    }
}

#[async_trait::async_trait]
impl updated::enrollment::BundlePolicy for EmbeddedChainPolicy {
    /// A bundle is due for replacement once any role in its embedded chain is within
    /// [`BUNDLE_REFRESH_LEAD`] of expiry — or once the chain can no longer be read at all, which is
    /// the one case where a node cannot prove its material is current and should ask for material it
    /// can.
    fn needs_refresh(&self, current: &updated_contracts::enrollment::EnrollmentBundle) -> bool {
        match earliest_expiry(current) {
            Ok(expiry) => expiry.duration_since(jiff::Timestamp::now()) <= BUNDLE_REFRESH_LEAD,
            Err(_) => true,
        }
    }

    /// Adopt a candidate only if it verifies completely on its own terms AND continues this node's
    /// enrollment-time root of trust.
    ///
    /// The chain check is [`verify_embedded_chain`] — the identical signature, threshold and digest
    /// verification first use gets — plus [`VerifiedEmbedded::fresh`], since replacing aging
    /// material with material that is already expired buys nothing.
    ///
    /// The root check is what makes the swap safe at all. A verified chain proves only that the
    /// documents belong together under *whatever root came with them*, so on its own it would accept
    /// a wholly attacker-minted bundle from a gateway that had been taken over, and the node's
    /// enrollment-time pin would be worth nothing. [`root_chains_from`] requires the candidate's root
    /// to be reachable from the pinned root by verified single-version steps — the same rule a TUF
    /// client applies walking root versions forward, and the reason [`Self::rotation_chain`] fetches
    /// the intermediate versioned roots first: a node that was offline across two root renewals is
    /// two versions behind, and each of those versions is checkable only against the one before it.
    ///
    /// The three pins are the rest of it. A refresh exists to replace *aging metadata* and may do
    /// nothing else: it must not move where the node's configuration comes from, nor where its
    /// state lives. So the candidate must name the same assignment target and the same
    /// `routing_base_url` as the bundle it replaces, and the assignment it embeds must keep the
    /// same `install_root` — all checked against the CURRENT persisted bundle, exactly as
    /// [`updated::enrollment::adopt_bundle`] pins `agent_id`, because the pin these boots derive is
    /// read out of whatever bundle is persisted. Without them a refresh carrying another agent's
    /// genuinely-signed assignment, or the same agent's assignment with an edited `installRoot`,
    /// verifies perfectly and is adopted — and the next boot resolves someone else's configuration,
    /// or repoints `versions/`, the transaction journal and the rejected-hash set at an empty
    /// directory while the fail-closed [`usable_as_boot_config`] guard rejects the node's own live
    /// assignment for having the *old* root.
    ///
    /// `routing_base_url` is the same class of move and the worst of the three, because it is the
    /// one that disables the correction path. It is plaintext the gateway chooses and no TUF
    /// signature covers it, so a refresh may carry the node's own bundle byte-identical but for a
    /// `file:` or absolute-path base. That verifies trivially, and afterwards
    /// `updated::enrollment`'s `can_reach_gateway` classifies the node as a local/offline
    /// deployment: it stops asking for bundles at all, so no later refresh — not even from a
    /// restored gateway — can undo it, and routing resolution fails as a retryable transport error
    /// forever. Pinning it means a genuine gateway relocation is not adoptable by refresh, which is
    /// correct: the refresh endpoint itself is reached through the node's bootstrap configuration,
    /// not this field, so moving the fleet's routing origin is a re-enrollment, not a metadata
    /// rotation.
    ///
    /// Order matters as much as the checks do. EVERY check that can be made from the two documents
    /// alone runs before the first byte is fetched — the roots parse, the candidate's root version is
    /// in [`catch_up_range`]'s window, the three pins hold, both chains verify, and neither of the
    /// non-root roles goes backwards. Only then is the rotation chain walked, because the walk takes
    /// its version range from `candidate.routing_root`, a document nothing has authenticated yet:
    /// deciding locally first means a candidate a compromised gateway made up costs the node one
    /// parse rather than up to [`MAX_ROOT_CATCH_UP`] sequential network round trips on the same task
    /// that drives health probes and self-update. The walk that does happen is bounded as a whole by
    /// [`ROOT_CATCH_UP_DEADLINE`], so no response — however slowly trickled — can hold that task
    /// open indefinitely.
    async fn accept(
        &self,
        candidate: &updated_contracts::enrollment::EnrollmentBundle,
        current: &updated_contracts::enrollment::EnrollmentBundle,
    ) -> std::io::Result<()> {
        let pinned_root: Signed<Root> =
            parse_embedded(current.routing_root.as_bytes(), "pinned root").map_err(refusal)?;
        let candidate_root: Signed<Root> =
            parse_embedded(candidate.routing_root.as_bytes(), "candidate root").map_err(refusal)?;
        let walk = catch_up_range(
            &pinned_root,
            &candidate_root,
            current.routing_root == candidate.routing_root,
        )
        .map_err(refusal)?;
        if candidate.assignment != current.assignment {
            return Err(refusal(Error::Trust(format!(
                "refreshed enrollment bundle names the assignment {:?}, moving this node off the \
                 enrollment-verified {:?}",
                candidate.assignment, current.assignment
            ))));
        }
        if candidate.routing_base_url != current.routing_base_url {
            return Err(refusal(Error::Trust(format!(
                "refreshed enrollment bundle would read routing from {:?}, moving this node off \
                 the enrollment-verified {:?}",
                candidate.routing_base_url, current.routing_base_url
            ))));
        }
        let offered = verify_embedded_chain(candidate).map_err(refusal)?;
        // The current bundle is deliberately verified WITHOUT the freshness requirement: it is the
        // material being replaced precisely because it is aging, and an expired chain still pins
        // this node's install root (see [`boot_assignment`]).
        let held = verify_embedded_chain(current).map_err(refusal)?;
        no_generation_rollback(current, candidate, &held.generation, &offered.generation)
            .map_err(refusal)?;
        let pinned = held.assignment.runtime.install_root;
        let offered_assignment = offered.fresh().map_err(refusal)?;
        if offered_assignment.runtime.install_root != pinned {
            return Err(refusal(Error::Trust(format!(
                "refreshed enrollment bundle would move install_root to {} from the \
                 enrollment-verified {}",
                offered_assignment.runtime.install_root.display(),
                pinned.display()
            ))));
        }
        // Last, because it is the only step that touches the network, and under one deadline for
        // the whole walk rather than one per fetch.
        let chain = match walk {
            None => Vec::new(),
            Some(versions) => timeout(
                ROOT_CATCH_UP_DEADLINE,
                self.rotation_chain(&current.routing_base_url, versions),
            )
            .await
            .map_err(|_| {
                refusal(transport_timeout(
                    ROOT_CATCH_UP_DEADLINE,
                    "walking the published rotation chain; the node keeps the root it has",
                ))
            })?,
        };
        root_chains_from(&current.routing_root, &candidate.routing_root, &chain)
            .map_err(refusal)?;
        Ok(())
    }
}

/// The versioned roots that must be fetched to check `candidate` against `pinned`, or `None` when
/// nothing lies in between and [`root_chains_from`] can decide with no network at all.
///
/// This is the whole of the local pre-flight on the root, and it exists so the *candidate* cannot
/// choose how much work the node does. `identical` is the byte equality [`root_chains_from`] treats
/// as trivially chaining, passed in rather than recomputed so the two agree by construction.
///
/// Three outcomes short-circuit before any fetch: a candidate below the pin is a rollback, a
/// candidate at the pin that is not the same bytes is a substitution, and a candidate more than
/// [`MAX_ROOT_CATCH_UP`] ahead is a fast-forward. All three are refusals the one-step rule would
/// reach anyway — the point of reaching them here is that they cost nothing.
fn catch_up_range(
    pinned: &Signed<Root>,
    candidate: &Signed<Root>,
    identical: bool,
) -> Result<Option<std::ops::RangeInclusive<u64>>, Error> {
    let (held, offered) = (pinned.signed.version.get(), candidate.signed.version.get());
    if identical {
        return Ok(None);
    }
    if offered <= held {
        return Err(Error::Trust(format!(
            "the refreshed root is version {offered}, not ahead of the pinned root {held}: an \
             older or substituted root is a rollback however well it verifies"
        )));
    }
    if offered - held > MAX_ROOT_CATCH_UP {
        return Err(Error::Trust(format!(
            "the refreshed root is version {offered}, more than the {MAX_ROOT_CATCH_UP} versions \
             ahead of the pinned root {held} that a catch-up may walk, so it is refused as a \
             fast-forward"
        )));
    }
    // Adjacent: the one-step rule decides it with nothing in between.
    Ok((offered - held > 1).then(|| held + 1..=offered - 1))
}

/// Rollback protection for the three roles the root check does not cover.
///
/// The root is held to "never backwards" by [`chains_one_step`], but a bundle carries a whole
/// generation of the routing repository, and until this ran nothing stopped a gateway from replying
/// with the SAME root and an OLDER — still genuinely signed, still unexpired — timestamp, snapshot
/// and targets. Everything verifies, so the node durably adopts the withdrawn managed configuration
/// those targets sign, and the next boot that falls back to its enrollment material launches the
/// application on it. That is precisely the rollback the TUF client rules forbid, applied to the
/// same adoption path that already forbids it for the root.
///
/// The rule is TUF's own: a role's version may never decrease, and equal versions must mean equal
/// bytes, since a repository that changes a role's content without bumping its version has
/// republished under an identity it already used. Equal-and-identical is the case that must keep
/// passing — a same-generation re-fetch is what an ordinary refresh returns when nothing has been
/// published since, and refusing it would break refresh idempotence.
fn no_generation_rollback(
    current: &updated_contracts::enrollment::EnrollmentBundle,
    candidate: &updated_contracts::enrollment::EnrollmentBundle,
    held: &Generation,
    offered: &Generation,
) -> Result<(), Error> {
    for (role, held, offered, held_bytes, offered_bytes) in [
        (
            "timestamp",
            held.timestamp,
            offered.timestamp,
            &current.initial.timestamp,
            &candidate.initial.timestamp,
        ),
        (
            "snapshot",
            held.snapshot,
            offered.snapshot,
            &current.initial.snapshot,
            &candidate.initial.snapshot,
        ),
        (
            "targets",
            held.targets,
            offered.targets,
            &current.initial.targets,
            &candidate.initial.targets,
        ),
    ] {
        if offered < held {
            return Err(Error::Trust(format!(
                "refreshed enrollment bundle carries {role} version {offered}, below the \
                 {held} this node already holds: an older generation is a rollback however well \
                 it verifies"
            )));
        }
        if offered == held && held_bytes != offered_bytes {
            return Err(Error::Trust(format!(
                "refreshed enrollment bundle carries a different {role} document at the same \
                 version {offered} this node already holds"
            )));
        }
    }
    Ok(())
}

fn refusal(error: Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string())
}

/// The soonest any role of a bundle's embedded chain stops being usable as current state.
///
/// Signatures are deliberately NOT checked here: this answers "is it worth asking for newer
/// material?", and a bundle whose chain does not verify is handled by refusing to boot on it, not by
/// declining to refresh it.
fn earliest_expiry(
    bundle: &updated_contracts::enrollment::EnrollmentBundle,
) -> Result<jiff::Timestamp, Error> {
    let root: Signed<Root> = parse_embedded(bundle.routing_root.as_bytes(), "root")?;
    let timestamp: Signed<Timestamp> =
        parse_embedded(bundle.initial.timestamp.as_bytes(), "timestamp")?;
    let snapshot: Signed<Snapshot> =
        parse_embedded(bundle.initial.snapshot.as_bytes(), "snapshot")?;
    let targets: Signed<Targets> = parse_embedded(bundle.initial.targets.as_bytes(), "targets")?;
    // The four roles are fixed, so the soonest of them is total — there is no "no roles" case to
    // fail closed on.
    Ok(root
        .signed
        .expires()
        .min(timestamp.signed.expires())
        .min(snapshot.signed.expires())
        .min(targets.signed.expires()))
}

/// Whether `candidate` may stand in for the root this node pinned at enrollment: byte-identical, or
/// reachable from the pinned root through `intermediates` by verified single-version steps.
///
/// This is the TUF root rotation walk. Each document is checked against the one before it — a
/// threshold of signatures from the PREVIOUS root's root role, and a version exactly one higher —
/// and every verified step advances the pin, so the last intermediate is what the candidate itself
/// must chain from. Nothing here trusts a version number on its own: an attacker picks those freely,
/// which is why authority is checked first at every link and the version rule second.
///
/// The one-step rule in both directions is what the walk buys. Backwards, a rotation deliberately
/// retains a continuity key, so an OLD root still verifies under the current one and replaying it
/// would move the node's root of trust onto keys the operator has retired. Forwards, a root minted
/// at an arbitrary version by one leaked key would pin the node above every genuine root the
/// operator will ever publish, and each of those is then refused as a rollback — a node bricked
/// past re-enrolment. Neither is possible when no accepted step may skip a version.
///
/// A bundle carries exactly one root document (`routing_root`), so the intermediates are not in it:
/// [`EmbeddedChainPolicy::rotation_chain`] fetches the `<n>.root.json` copies the repository
/// publishes for exactly this purpose. That is what lets a node that was offline across two root
/// renewals catch up — without it the pin advanced only by adoption, adoption allowed only one
/// step, and a node two versions behind could never accept another bundle again. Fail-closed
/// throughout: a missing, unfetchable or non-consecutive intermediate leaves the chain short of the
/// candidate, the candidate is refused, and the node keeps the root it has.
fn root_chains_from(pinned: &str, candidate: &str, intermediates: &[String]) -> Result<(), Error> {
    if pinned == candidate {
        return Ok(());
    }
    let mut held: Signed<Root> = parse_embedded(pinned.as_bytes(), "pinned root")?;
    for step in intermediates {
        let next: Signed<Root> = parse_embedded(step.as_bytes(), "intermediate root")?;
        let version = next.signed.version;
        chains_one_step(&held, &next, &format!("published root version {version}"))?;
        held = next;
    }
    let candidate: Signed<Root> = parse_embedded(candidate.as_bytes(), "candidate root")?;
    chains_one_step(&held, &candidate, "the refreshed root")
}

/// One link of the rotation walk: `next` must carry a threshold of signatures from `previous`'s root
/// role and be exactly one version ahead of it. `subject` names the document so a refusal says which
/// link broke; `previous` is always the node's pin, since every verified link becomes it.
fn chains_one_step(
    previous: &Signed<Root>,
    next: &Signed<Root>,
    subject: &str,
) -> Result<(), Error> {
    // Authority first: whether the root the node holds vouches for this document at all. A root it
    // did not sign is a substitution, and saying so is more use to an operator than a version
    // complaint — an attacker picks the version number, so that check can always be satisfied.
    previous.signed.verify_role(next).map_err(|error| {
        Error::Trust(format!(
            "{subject} is not signed by the pinned root: {error}"
        ))
    })?;
    // A pinned root at `u64::MAX` has no successor at all, so every candidate is refused rather
    // than wrapping onto — or re-accepting — the version the node already holds.
    let expected = previous.signed.version.checked_add(1).ok_or_else(|| {
        Error::Trust(format!(
            "pinned root is version {}, which has no successor",
            previous.signed.version
        ))
    })?;
    if next.signed.version != expected {
        return Err(Error::Trust(format!(
            "{subject} is version {}, not the pinned root's successor {expected}",
            next.signed.version
        )));
    }
    Ok(())
}

/// A fully verified embedded chain together with whether it is still within its own expiry window.
///
/// The two are separated because they answer different questions and only one of them decays.
/// Signatures, thresholds and digests prove the documents belong together under the bundle's root —
/// that is what pins this node's root of trust, and it is mandatory on every path. Expiry says only
/// how long the chain may be taken for the repository's *current* state. [`boot_assignment`] is the
/// one caller allowed to make that distinction, and only when it has verified newer state to use
/// instead; every other caller goes through [`verify_embedded_assignment`], which demands both.
struct VerifiedEmbedded {
    assignment: updated_contracts::assignment::RepositoryAssignment,
    /// The first role whose `expires` has passed, if any.
    expired_role: Option<&'static str>,
    /// Which generation of the routing repository the chain is, for [`no_generation_rollback`].
    generation: Generation,
}

/// The version each non-root role of an embedded chain carries.
///
/// [`verify_embedded_chain`] already proves these three are consistent with each other — snapshot's
/// against timestamp's metafile, targets' against snapshot's — so one of them moving is the whole
/// generation moving. They are surfaced separately from the assignment because they answer the
/// question the assignment cannot: not "do these documents belong together?" but "are they newer
/// than what this node already had?".
struct Generation {
    timestamp: u64,
    snapshot: u64,
    targets: u64,
}

impl VerifiedEmbedded {
    /// The assignment if the chain is also still fresh enough to be treated as current.
    fn fresh(self) -> Result<updated_contracts::assignment::RepositoryAssignment, Error> {
        match self.expired_role {
            Some(role) => Err(Error::Trust(format!("embedded {role} metadata is expired"))),
            None => Ok(self.assignment),
        }
    }
}

fn verify_embedded_chain(
    bundle: &updated_contracts::enrollment::EnrollmentBundle,
) -> Result<VerifiedEmbedded, Error> {
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
    let expired_role = [
        ("root", root.signed.expires()),
        ("timestamp", timestamp.signed.expires()),
        ("snapshot", snapshot.signed.expires()),
        ("targets", targets.signed.expires()),
    ]
    .into_iter()
    .find_map(|(name, expires)| (expires <= now).then_some(name));
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
    let agent: updated_contracts::artifact::AgentDocument =
        parse_embedded(agent_bytes, "agent document")?;
    agent.validate().map_err(Error::Trust)?;
    verify_embedded_target(
        &targets,
        &agent.config.path,
        config_bytes,
        "managed configuration",
    )?;
    let assignment: updated_contracts::assignment::RepositoryAssignment =
        parse_embedded(config_bytes, "managed configuration")?;
    assignment.validate().map_err(Error::Trust)?;
    Ok(VerifiedEmbedded {
        assignment,
        expired_role,
        generation: Generation {
            timestamp: timestamp.signed.version.get(),
            snapshot: snapshot.signed.version.get(),
            targets: targets.signed.version.get(),
        },
    })
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

/// A verified routing assignment together with the digest of the exact document it came from.
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
/// publish. A config bundle is a signed `RepositoryAssignment`, and everything the contract bounds
/// in it is bounded here: `runtime.inputs` at `OutputManifest::MAX_VALUES` entries of a 128-byte
/// name and a `MAX_STRING_BYTES` value, and 64 secret references of three ~253-byte fields. Both
/// are counted at six bytes per source byte, the worst case for JSON string escaping (`\u00XX`).
const ROUTING_TARGET_LIMIT: u64 = {
    const ESCAPED: u64 = 6;
    let inputs = updated_contracts::telemetry::OutputManifest::MAX_VALUES as u64
        * ((128 + updated_contracts::telemetry::OutputManifest::MAX_STRING_BYTES as u64) * ESCAPED
            + 64);
    let secrets = 64 * (3 * 253 * ESCAPED + 64);
    // The fields the contract leaves unbounded — `args`, and the embedded `release_root`, whose
    // size follows the number of signing keys — get one flat megabyte between them. Nothing can
    // make that provably sufficient; what it can do is put the failure far outside the shapes a
    // control plane produces, instead of below them.
    inputs + secrets + (1024 * 1024)
};

/// Floor for the routing repository's metadata limit, applied to whatever the caller configured.
///
/// The routing `targets.json` carries one entry per enrolled node plus one per deployment, so it
/// grows linearly with the fleet — roughly 200 bytes each. It is the one metadata document whose
/// size is a property of the fleet rather than of any one node's configuration, and, unlike the
/// release repository's limit, no signed assignment or operator setting can raise it once it is
/// too low. Exceeding it does not degrade one node: it aborts the `targets.json` fetch on every
/// node at once, so the whole fleet stops resolving assignments simultaneously and the fix — a new
/// supervisor binary — can no longer be delivered through the update path it broke. This floor
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
        let source = routing_source(routing_config)?;
        let routing = Self::load(&source, &paths.routing_datastore).await?;
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
        // Download into scratch, never over the live assignment file. That file IS this node's
        // persisted managed configuration: writing the intermediate agent document into it, or
        // failing between the two downloads, would leave the node's own config replaced by a
        // half-resolved document — and the next boot would silently fall back to the
        // enrollment-frozen assignment instead of the one it is actually running.
        let staging = updated::config::with_suffix(&paths.assignment, ".resolving");
        let staged = async {
            routing.download_target(&target, &staging).await?;
            let bytes = tokio::fs::read(&staging)
                .await
                .map_err(|e| Error::Local(format!("reading verified agent document: {e}")))?;
            let agent: updated_contracts::artifact::AgentDocument = serde_json::from_slice(&bytes)
                .map_err(|e| Error::Trust(format!("invalid agent document: {e}")))?;
            agent.validate().map_err(Error::Trust)?;
            let config = routing.exact_target(&agent.config)?;
            routing.download_target(&config, &staging).await?;
            let bytes = tokio::fs::read(&staging)
                .await
                .map_err(|e| Error::Local(format!("reading verified config bundle: {e}")))?;
            let assignment: updated_contracts::assignment::RepositoryAssignment =
                serde_json::from_slice(&bytes)
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
        usable_as_boot_config(&assignment, &paths.install_root)
            .map_err(|reason| Error::Trust(format!("the resolved assignment {reason}")))?;
        foundation::durable::atomic_write_managed(&paths.assignment, ".assignment-", &bytes)
            .map_err(|e| Error::Local(format!("persisting the resolved assignment: {e}")))?;
        Ok(ResolvedAssignment {
            // The digest TUF just verified these exact bytes against — the same value the control
            // plane published this configuration under, and the node's content identity for it.
            sha256: updated::hash::sha256_bytes(&bytes),
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
        storage: &updated::config::Storage,
        paths: &updated::config::Paths,
    ) -> Result<Self, Error> {
        let resolved = Self::resolve_assignment(routing_config, paths).await?;
        let ResolvedAssignment {
            assignment,
            sha256: assignment_sha256,
        } = resolved;
        let limits = &assignment.runtime.repository;
        let assignment_key = assignment_identity(&assignment);
        let assignment_store = paths.datastore.join(&assignment_key);
        std::fs::create_dir_all(&assignment_store).map_err(|error| {
            Error::Local(format!("creating assigned repository state: {error}"))
        })?;
        let release_root = assignment_store.join("release-root.json");
        foundation::durable::atomic_write_managed(
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
            // The release repository is the same externally-exposed gateway as routing.
            mtls: routing_config.mtls.clone(),
        };
        let mut repository = Self::load(&source, &assignment_store).await?;
        repository.assignment = Some(assignment);
        repository.assignment_sha256 = Some(assignment_sha256);
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
            assignment_sha256: None,
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
    pub fn assignment(&self) -> Option<&updated_contracts::assignment::RepositoryAssignment> {
        self.assignment.as_ref()
    }

    /// The content digest of the assignment document this repository was resolved from — what the
    /// node reports so the control plane can tell which exact configuration it is acting on.
    pub fn assignment_sha256(&self) -> Option<&str> {
        self.assignment_sha256.as_deref()
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
        let actual = hex::encode(&target.sha256);
        if !updated::hash::digests_match(&actual, &reference.sha256) {
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

fn assignment_identity(assignment: &updated_contracts::assignment::RepositoryAssignment) -> String {
    // Metadata rollback history belongs to a repository endpoint, not a deployment.
    // Changing exact desired targets must reuse the same datastore or every rollout
    // would accidentally reset TUF's remembered version floor.
    let mut bytes = Vec::new();
    for endpoint in [&assignment.metadata_url, &assignment.targets_url] {
        bytes.extend_from_slice(&(endpoint.len() as u64).to_be_bytes());
        bytes.extend_from_slice(endpoint.as_bytes());
    }
    updated::hash::sha256_bytes(&bytes)
}

fn validate_release_url(name: &str, raw: &str) -> Result<(), Error> {
    repository_base(&format!("assignment {name}"), raw).map(|_| ())
}

/// One location grammar for automatic and manual deployments. HTTP(S) and file URLs
/// are accepted directly; an absolute directory path is the shorthand used by a
/// manually placed assignment. All forms resolve to the same TUF transport.
fn repository_base(name: &str, raw: &str) -> Result<Url, Error> {
    // An absolute path is decided by the platform, not by URL syntax: a Windows
    // drive-letter path parses as a URL whose scheme is the drive letter, so it
    // must be recognised as a directory before `Url::parse` sees it. This is the
    // same rule `updated::config::base_url_is_local` applies to the same string.
    let parsed = if Path::new(raw).is_absolute() {
        None
    } else {
        Url::parse(raw).ok()
    };
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
    VerifiedTarget {
        path: path.to_string(),
        length: target.length,
        sha256: target.hashes.sha256.to_vec(),
        custom: serde_json::to_value(&target.custom).unwrap_or(serde_json::Value::Null),
    }
}

#[cfg(test)]
mod bundle_refresh_tests {
    use super::{earliest_expiry, root_chains_from, EmbeddedChainPolicy, BUNDLE_REFRESH_LEAD};
    use crate::repo;
    use std::path::{Path, PathBuf};
    use updated::enrollment::BundlePolicy;
    use updated_contracts::enrollment::{EnrollmentBundle, InitialSignedConfiguration};

    fn scratch(label: &str) -> (tempfile::TempDir, PathBuf) {
        let guard = tempfile::tempdir().unwrap();
        let dir = guard.path().join(label);
        std::fs::create_dir_all(&dir).unwrap();
        (guard, dir)
    }

    /// Mint a repository whose metadata expires in `expiry_days`, and return its directory.
    async fn minted(tmp: &Path, expiry_days: i64) -> PathBuf {
        std::fs::create_dir_all(tmp).unwrap();
        let repo_dir = tmp.join("repo");
        let keys = repo::generate_keys(&tmp.join("keys")).await.unwrap();
        repo::init(&repo_dir, &keys, expiry_days).await.unwrap();
        repo_dir
    }

    /// The newest published copy of a role document. A consistent-snapshot repository writes the
    /// version-prefixed name (`1.snapshot.json`) for everything but `timestamp.json`, so a test
    /// asking for "snapshot.json" wants the highest version it finds.
    fn role(repo_dir: &Path, file: &str) -> String {
        let metadata = repo_dir.join("metadata");
        if let Ok(bytes) = std::fs::read_to_string(metadata.join(file)) {
            return bytes;
        }
        let newest = std::fs::read_dir(&metadata)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                let name = entry.file_name().into_string().ok()?;
                let version: u64 = name.strip_suffix(&format!(".{file}"))?.parse().ok()?;
                Some((version, entry.path()))
            })
            .max_by_key(|(version, _)| *version)
            .unwrap_or_else(|| panic!("no published {file} in {}", metadata.display()));
        std::fs::read_to_string(newest.1).unwrap()
    }

    /// The policy as a node holds it. The identity is only ever presented when a versioned root is
    /// fetched over the network, which none of these cases reaches, so the paths need not exist.
    fn policy() -> EmbeddedChainPolicy {
        EmbeddedChainPolicy::new(updated::tls::Identity::new(
            "/nonexistent/agent.crt",
            "/nonexistent/agent.key",
            "/nonexistent/ca.crt",
        ))
    }

    /// A bundle carrying a real repository's signed chain. Only the four role documents matter here:
    /// expiry is read from them, and nothing in this module verifies the targets they sign.
    fn bundle_from(repo_dir: &Path) -> EnrollmentBundle {
        EnrollmentBundle {
            schema: 1,
            agent_id: "agent-a".into(),
            routing_base_url: "https://updates.example/".into(),
            assignment: "assignments/agents/agent-a.json".into(),
            routing_root: role(repo_dir, "root.json"),
            initial: InitialSignedConfiguration {
                timestamp: role(repo_dir, "timestamp.json"),
                snapshot: role(repo_dir, "snapshot.json"),
                targets: role(repo_dir, "targets.json"),
                agent_document: "{}".into(),
                managed_configuration: "{}".into(),
            },
        }
    }

    /// The refresh exists to replace signed material before it stops counting as current, so the
    /// trigger must be the chain's own expiry — read from the documents themselves, never assumed
    /// from when the bundle was written.
    #[tokio::test]
    async fn a_chain_is_due_for_replacement_once_any_role_nears_its_expiry() {
        let (_tmp, tmp) = scratch("bundle-expiry");
        let fresh = minted(&tmp.join("fresh"), 365).await;
        let fresh = bundle_from(&fresh);
        assert!(
            !policy().needs_refresh(&fresh),
            "a year of validity is not worth a control-plane request"
        );
        let due = minted(&tmp.join("due"), 1).await;
        let due = bundle_from(&due);
        assert!(
            policy().needs_refresh(&due),
            "a chain inside the {BUNDLE_REFRESH_LEAD:?} lead must be replaced while it is still valid"
        );

        // The earliest role governs, and an unreadable chain cannot be shown to be current — the one
        // case where a node should ask for material it can actually read.
        let mut mixed = fresh.clone();
        mixed.initial.timestamp = due.initial.timestamp.clone();
        assert!(earliest_expiry(&mixed).unwrap() < earliest_expiry(&fresh).unwrap());
        assert!(policy().needs_refresh(&mixed));
        let mut unreadable = fresh.clone();
        unreadable.initial.snapshot = "{}".into();
        assert!(policy().needs_refresh(&unreadable));
        let _ = std::fs::remove_dir_all(tmp);
    }

    /// A verified chain proves only that its documents agree under whatever root arrived with them,
    /// so the refresh would otherwise accept a wholly attacker-minted bundle from a gateway that had
    /// been taken over — and the enrollment-time pin would be worth nothing. The candidate root must
    /// be the pinned root, or a rotation the pinned root itself signed.
    #[tokio::test]
    async fn a_refreshed_root_must_be_the_pinned_root_or_a_rotation_it_signed() {
        let (_tmp, tmp) = scratch("bundle-root");
        let repo_dir = tmp.join("repo");
        let keys = repo::generate_keys(&tmp.join("keys")).await.unwrap();
        repo::init(&repo_dir, &keys, 365).await.unwrap();
        let v1 = role(&repo_dir, "root.json");

        // An unrelated repository: a perfectly valid root, signed by keys this node never pinned.
        let foreign_root = role(&minted(&tmp.join("foreign"), 365).await, "root.json");
        let refusal = root_chains_from(&v1, &foreign_root, &[])
            .unwrap_err()
            .to_string();
        assert!(
            refusal.contains("not signed by the pinned root"),
            "a substituted root must be refused by name, got: {refusal}"
        );

        // The same bytes are trivially the same root of trust.
        root_chains_from(&v1, &v1, &[]).expect("the pinned root is itself");

        // One rotation, co-signed by the pinned root, is the case this must allow — otherwise a
        // fleet could never refresh again after an operator rotates.
        let successor = tmp.join("successor.pk8");
        repo::generate_root_key(&successor).await.unwrap();
        repo::rotate_root(&repo_dir, &keys.roots[1..], &successor, 365)
            .await
            .unwrap();
        let v2 = role(&repo_dir, "root.json");
        root_chains_from(&v1, &v2, &[]).expect("a rotation the pinned root signed is adoptable");

        // Never backwards: an older root is a rollback however well it verifies.
        let rollback = root_chains_from(&v2, &v1, &[]).unwrap_err().to_string();
        assert!(
            rollback.contains("not the pinned root's successor"),
            "a rollback must be refused by name, got: {rollback}"
        );

        // Never forwards past one step either, even when the pinned root's own keys signed the
        // candidate: a root minted at an arbitrarily high version is a fast-forward, and adopting
        // it would leave the node pinned above every genuine root the operator will ever publish —
        // an unrecoverable state, since each of those is then refused as a rollback.
        let ahead_dir = tmp.join("ahead");
        repo::init_from_version(&ahead_dir, &keys, 365, u64::MAX)
            .await
            .unwrap();
        let ahead = role(&ahead_dir, "root.json");
        let fast_forward = root_chains_from(&v1, &ahead, &[]).unwrap_err().to_string();
        assert!(
            fast_forward.contains("not the pinned root's successor"),
            "a version fast-forward must be refused by name, got: {fast_forward}"
        );

        // A second rotation cannot be checked against v1 alone — but it is exactly what a node that
        // was offline across two ceremonies comes back to, so it is adoptable once the root in
        // between is supplied. The pin advances through the walk: v2 verifies under v1, v3 under v2.
        let third = tmp.join("third.pk8");
        repo::generate_root_key(&third).await.unwrap();
        repo::rotate_root(&repo_dir, std::slice::from_ref(&successor), &third, 365)
            .await
            .unwrap();
        let v3 = role(&repo_dir, "root.json");
        assert!(root_chains_from(&v1, &v3, &[]).is_err());
        root_chains_from(&v2, &v3, &[]).expect("each single step still chains");
        root_chains_from(&v1, &v3, std::slice::from_ref(&v2))
            .expect("a two-version rotation chains once the root in between is walked");

        // What the walk must not become: a way to pass off a chain that skips. Handing the walk the
        // candidate itself in place of the missing v2 is a chain with a hole in it, and v1 never
        // signed v3, so it fails at the link that cannot be verified rather than at the version
        // count — the fast-forward stays blocked no matter how the intermediates are supplied.
        let skipped = root_chains_from(&v1, &v3, std::slice::from_ref(&v3))
            .unwrap_err()
            .to_string();
        assert!(
            skipped.contains("published root version 3")
                && skipped.contains("not signed by the pinned root"),
            "a chain that skips a version must be refused by name, got: {skipped}"
        );
        let _ = std::fs::remove_dir_all(tmp);
    }
}

#[cfg(test)]
mod integrity_tests {
    use super::{classify, repository_base, validate_release_url, Error};
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
        assert!(validate_release_url("metadata_url", base).is_ok());
        // A real unsupported scheme is still refused.
        assert!(validate_release_url("metadata_url", "ftp://cdn.example/metadata/").is_err());
    }
}
