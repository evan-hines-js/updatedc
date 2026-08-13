//! What a `/bundle` refresh is allowed to change.
//!
//! A refresh replaces *aging signed metadata* and nothing else. These tests author a real routing
//! repository, publish two agents' assignments through it, and then offer a node genuinely signed
//! bundles that move its identity's assignment or its install root — the two moves a gateway that
//! had been taken over can make without forging a single signature, since it chooses `agentId` and
//! `assignment` in plaintext and TUF covers only the roles and the documents themselves.

use std::path::{Path, PathBuf};

use updated::enrollment::BundlePolicy;
use updated_contracts::enrollment::{EnrollmentBundle, InitialSignedConfiguration};
use updated_tuf::{repo, EmbeddedChainPolicy};

fn scratch(label: &str) -> (tempfile::TempDir, PathBuf) {
    let guard = tempfile::tempdir().unwrap();
    let dir = guard.path().join(label);
    std::fs::create_dir_all(&dir).unwrap();
    (guard, dir)
}

/// The newest published copy of a role document; a consistent-snapshot repository writes the
/// version-prefixed name for every role but `timestamp.json`.
fn role(repo_dir: &Path, file: &str) -> String {
    let metadata = repo_dir.join("metadata");
    if file == "timestamp.json" {
        return std::fs::read_to_string(metadata.join(file)).unwrap();
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
        .unwrap();
    std::fs::read_to_string(newest.1).unwrap()
}

fn assignment(install_root: &Path) -> updated_contracts::assignment::RepositoryAssignment {
    updated_contracts::assignment::RepositoryAssignment {
        schema: updated_contracts::assignment::RepositoryAssignment::SCHEMA,
        deployment: "commit".into(),
        metadata_url: "http://127.0.0.1:9/release/metadata/".into(),
        targets_url: "http://127.0.0.1:9/release/targets/".into(),
        report_url: None,
        application: updated_contracts::artifact::TargetReference {
            path: "products/app/stable/1/linux-x86_64/app".into(),
            sha256: "a".repeat(64),
        },
        ordered_install_fallback: false,
        provider_set: updated_contracts::artifact::TargetReference {
            path: "provider-sets/default.json".into(),
            sha256: "b".repeat(64),
        },
        release_root: serde_json::json!({}),
        runtime: updated_contracts::assignment::ManagedRuntime {
            product: "app".into(),
            channel: "stable".into(),
            install_root: install_root.to_path_buf(),
            secrets: vec![],
            inputs: std::collections::BTreeMap::new(),
            repository: updated_contracts::assignment::ManagedRepositoryLimits {
                metadata_limit: 1024 * 1024,
                target_limit: 1024 * 1024,
                transport_timeout_seconds: 5,
            },
            storage: updated_contracts::assignment::ManagedStorage {
                inactive_releases: 2,
                inactive_providers: 2,
                inactive_agents: 2,
                inactive_bytes: 1024 * 1024,
                inactive_repository_caches: 2,
            },
            timeouts: updated_contracts::assignment::ManagedTimeouts {
                check_interval_seconds: 5,
                health_grace_seconds: 5,
                health_successes: 1,
                health_interval_seconds: 1,
                refresh_retry_seconds: 5,
                confirmation_window_seconds: 5,
                agent_check_interval_seconds: 5,
            },
        },
    }
}

/// One agent's genuinely published routing: its assignment document, the agent document that names
/// it, and the bundle the gateway would issue for that agent.
struct Published {
    agent_id: String,
    agent_path: String,
    agent_document: String,
    managed_configuration: String,
}

/// A routing repository under one set of keys — one root of trust, publishing generation after
/// generation, exactly as a fleet's control plane does.
struct Routing {
    dir: PathBuf,
    keys: repo::Keys,
    scratch: PathBuf,
}

impl Routing {
    async fn author(tmp: &Path) -> Routing {
        let dir = tmp.join("repo");
        let keys = repo::generate_keys(&tmp.join("keys")).await.unwrap();
        repo::init(&dir, &keys, 365).await.unwrap();
        Routing {
            dir,
            keys,
            scratch: tmp.join("sources"),
        }
    }

    /// Publish one generation carrying an assignment per `(agent_id, install_root)` pair, exactly
    /// as the control plane does: `assignments/agents/<agent>.json` referencing a
    /// content-addressed managed configuration.
    async fn publish(&self, agents: &[(&str, &Path)]) -> Vec<Published> {
        std::fs::create_dir_all(&self.scratch).unwrap();
        let mut targets = Vec::new();
        let mut published = Vec::new();
        for (agent_id, install_root) in agents {
            let config_bytes = serde_json::to_vec(&assignment(install_root)).unwrap();
            let config_sha = updated::hash::sha256_bytes(&config_bytes);
            let config_path = format!("assignments/configs/{config_sha}.json");
            let config_source = self.scratch.join(format!("{config_sha}.json"));
            std::fs::write(&config_source, &config_bytes).unwrap();
            let agent = updated_contracts::artifact::AgentDocument {
                schema: 1,
                config: updated_contracts::artifact::TargetReference {
                    path: config_path.clone(),
                    sha256: config_sha.clone(),
                },
            };
            let agent_bytes = serde_json::to_vec(&agent).unwrap();
            let agent_source = self
                .scratch
                .join(format!("{agent_id}-{config_sha}-agent.json"));
            std::fs::write(&agent_source, &agent_bytes).unwrap();
            let agent_path = format!("assignments/agents/{agent_id}.json");
            targets.push(repo::PublishTarget {
                name: config_path,
                source: config_source,
                custom: Default::default(),
            });
            targets.push(repo::PublishTarget {
                name: agent_path.clone(),
                source: agent_source,
                custom: Default::default(),
            });
            published.push(Published {
                agent_id: (*agent_id).to_string(),
                agent_path,
                agent_document: String::from_utf8(agent_bytes).unwrap(),
                managed_configuration: String::from_utf8(config_bytes).unwrap(),
            });
        }
        repo::add_release(&self.dir, &self.keys, targets, 365)
            .await
            .unwrap();
        published
    }
}

/// The policy as a node holds it. The mTLS identity is presented only when a versioned root is
/// fetched from a network origin; a `file:` routing base is served straight off disk, so a test
/// that exercises the rotation walk needs no PKI and one that does not never touches these paths.
fn policy() -> EmbeddedChainPolicy {
    EmbeddedChainPolicy::new(updated::tls::Identity::new(
        "/nonexistent/agent.crt",
        "/nonexistent/agent.key",
        "/nonexistent/ca.crt",
    ))
}

/// The bundle the gateway issues for `published` — every byte of it genuinely signed.
fn bundle_for(repo_dir: &Path, published: &Published) -> EnrollmentBundle {
    EnrollmentBundle {
        schema: 1,
        agent_id: published.agent_id.clone(),
        routing_base_url: "https://updates.example/".into(),
        assignment: published.agent_path.clone(),
        routing_root: role(repo_dir, "root.json"),
        initial: InitialSignedConfiguration {
            timestamp: role(repo_dir, "timestamp.json"),
            snapshot: role(repo_dir, "snapshot.json"),
            targets: role(repo_dir, "targets.json"),
            agent_document: published.agent_document.clone(),
            managed_configuration: published.managed_configuration.clone(),
        },
    }
}

#[tokio::test]
async fn a_refresh_may_not_move_the_node_onto_another_agents_assignment() {
    let (_tmp, tmp) = scratch("bundle-pin-assignment");
    let install_root = tmp.join("install");
    let routing = Routing::author(&tmp).await;
    let published = routing
        .publish(&[("node-a", &install_root), ("node-b", &install_root)])
        .await;
    let repo_dir = routing.dir.clone();
    let current = bundle_for(&repo_dir, &published[0]);

    // The identical bundle is the ordinary refresh: same chain, same everything.
    policy()
        .accept(&current, &current)
        .await
        .expect("a bundle for this node's own assignment is adoptable");

    // A taken-over gateway keeps `agentId` truthful — so the identity check passes — and swaps in
    // node B's genuinely published, correctly signed routing. Nothing is forged.
    let mut swapped = bundle_for(&repo_dir, &published[1]);
    swapped.agent_id = current.agent_id.clone();
    let refusal = policy()
        .accept(&swapped, &current)
        .await
        .expect_err("another agent's assignment must be refused however well it verifies")
        .to_string();
    assert!(
        refusal.contains("assignments/agents/node-b.json") && refusal.contains("moving this node"),
        "the refusal must name the substituted assignment, got: {refusal}"
    );
    let _ = std::fs::remove_dir_all(tmp);
}

#[tokio::test]
async fn a_refresh_may_not_move_where_routing_is_read_from() {
    let (_tmp, tmp) = scratch("bundle-pin-routing-base");
    let install_root = tmp.join("install");
    let routing = Routing::author(&tmp).await;
    let current = bundle_for(
        &routing.dir,
        &routing.publish(&[("node-a", &install_root)]).await[0],
    );

    // What a refresh is FOR: a later generation of the same repository under the same root, so the
    // chain documents differ but nothing about where the node reads or writes does.
    let rotated = bundle_for(
        &routing.dir,
        &routing.publish(&[("node-a", &install_root)]).await[0],
    );
    assert_ne!(rotated.initial.timestamp, current.initial.timestamp);
    policy()
        .accept(&rotated, &current)
        .await
        .expect("a metadata-only refresh under the pinned root is the point of the refresh path");

    // The move that cannot be undone: the node's own bundle, byte-identical but for a plaintext
    // field no signature covers. Adopted, it would make the node classify itself as a local
    // deployment with no gateway to ask, so no later refresh could ever correct it.
    let mut severed = current.clone();
    severed.routing_base_url = "/var/tmp/attacker-routing/".into();
    let refusal = policy()
        .accept(&severed, &current)
        .await
        .expect_err("a refresh must never move where routing metadata comes from")
        .to_string();
    assert!(
        refusal.contains("/var/tmp/attacker-routing/")
            && refusal.contains("https://updates.example/"),
        "the refusal must name both bases, got: {refusal}"
    );
    let _ = std::fs::remove_dir_all(tmp);
}

/// A refresh may advance the node's pinned root by one version, or by a few walked ones. A candidate
/// beyond the catch-up ceiling cannot be checked against anything this node holds — and adopting one
/// would be terminal: every genuine root the operator ever publishes afterwards is below the
/// fast-forwarded pin and is refused as a rollback, so the node can never be corrected by another
/// refresh.
///
/// It must also be refused *before a single fetch*, since the walk's range comes from the candidate
/// root — a document nothing has authenticated at the point the range is read — and a candidate free
/// to name it could conscript the node's control loop into a long sequence of network round trips.
/// The bundles here name a routing origin that holds no metadata at all, so a decision that needed
/// the network would come back as an unchainable empty walk; naming the ceiling instead is what shows
/// nothing was fetched.
#[tokio::test]
async fn a_refresh_may_not_fast_forward_the_pinned_root_version() {
    let (_tmp, tmp) = scratch("bundle-root-fast-forward");
    let install_root = tmp.join("install");
    let routing = Routing::author(&tmp).await;
    let empty_origin = tmp.join("empty-origin");
    std::fs::create_dir_all(&empty_origin).unwrap();
    let current = served_from(
        bundle_for(
            &routing.dir,
            &routing.publish(&[("node-a", &install_root)]).await[0],
        ),
        &empty_origin,
    );

    // A whole repository minted under THE SAME root keys, but starting at a version far above the
    // node's pin — everything a taken-over gateway holding one key the pinned root vouches for can
    // author. Its chain is entirely self-consistent and the pinned root's own keys signed its root,
    // so only the catch-up ceiling stands between the node and a permanent lockout.
    let ahead = Routing {
        dir: tmp.join("ahead"),
        keys: repo::Keys::in_dir(&tmp.join("keys")),
        scratch: tmp.join("ahead-sources"),
    };
    repo::init_from_version(&ahead.dir, &ahead.keys, 365, 1_000_000)
        .await
        .unwrap();
    let fast_forwarded = served_from(
        bundle_for(
            &ahead.dir,
            &ahead.publish(&[("node-a", &install_root)]).await[0],
        ),
        &empty_origin,
    );
    assert_eq!(fast_forwarded.assignment, current.assignment);
    assert_ne!(fast_forwarded.routing_root, current.routing_root);
    let refusal = policy()
        .accept(&fast_forwarded, &current)
        .await
        .expect_err("a root several versions ahead must be refused however well it verifies")
        .to_string();
    assert!(
        refusal.contains("versions ahead of the pinned root") && refusal.contains("fast-forward"),
        "the refusal must name the catch-up ceiling, decided with nothing fetched, got: {refusal}"
    );
    let _ = std::fs::remove_dir_all(tmp);
}

/// The version of one of a bundle's embedded non-root roles.
fn role_version(document: &str) -> u64 {
    serde_json::from_str::<serde_json::Value>(document).unwrap()["signed"]["version"]
        .as_u64()
        .unwrap()
}

/// The root is held to "never backwards", but a bundle carries a whole generation of the routing
/// repository. A gateway that had been taken over can reply with the node's own root, its own
/// assignment path and its own install root — and an OLDER, genuinely signed, not-yet-expired
/// timestamp/snapshot/targets, carrying the managed configuration an operator has since withdrawn.
/// Every signature and digest verifies, so only a version floor on the other three roles refuses it.
#[tokio::test]
async fn a_refresh_may_not_roll_the_repository_generation_back() {
    let (_tmp, tmp) = scratch("bundle-generation-rollback");
    let install_root = tmp.join("install");
    let routing = Routing::author(&tmp).await;
    let withdrawn = bundle_for(
        &routing.dir,
        &routing.publish(&[("node-a", &install_root)]).await[0],
    );
    let current = bundle_for(
        &routing.dir,
        &routing.publish(&[("node-a", &install_root)]).await[0],
    );

    // Same root, same pins — only the generation differs, which is exactly what makes it verify.
    assert_eq!(withdrawn.routing_root, current.routing_root);
    assert_eq!(withdrawn.assignment, current.assignment);
    assert!(role_version(&withdrawn.initial.targets) < role_version(&current.initial.targets));

    let refusal = policy()
        .accept(&withdrawn, &current)
        .await
        .expect_err("an older repository generation must be refused however well it verifies")
        .to_string();
    assert!(
        refusal.contains("this node already holds") && refusal.contains("rollback"),
        "the refusal must say the candidate generation is behind the held one, got: {refusal}"
    );

    // Idempotence: the ordinary refresh returns the generation the node already has when nothing
    // has been published since, and equal versions with equal bytes is not a rollback.
    policy()
        .accept(&current, &current)
        .await
        .expect("a same-generation re-fetch must still be adoptable");
    policy()
        .accept(&withdrawn, &withdrawn)
        .await
        .expect("the floor is the node's own generation, not the newest one published");
    let _ = std::fs::remove_dir_all(tmp);
}

#[tokio::test]
async fn a_refresh_may_not_move_the_nodes_install_root() {
    let (_tmp, tmp) = scratch("bundle-pin-install-root");
    let pinned = tmp.join("install");
    let routing = Routing::author(&tmp).await;
    let current = bundle_for(
        &routing.dir,
        &routing.publish(&[("node-a", &pinned)]).await[0],
    );

    // The same agent, the same assignment path, the same root and the same signing keys — but the
    // operator edited the group's `installRoot`, so the next generation the gateway serves would
    // repoint `versions/`, the transaction journal and the rejected-hash set at an empty directory
    // on the next boot, and the node's own live assignment would then be rejected for having the
    // OLD root.
    let moved = tmp.join("moved");
    let relocating = bundle_for(
        &routing.dir,
        &routing.publish(&[("node-a", &moved)]).await[0],
    );
    assert_eq!(relocating.assignment, current.assignment);
    assert_eq!(relocating.routing_root, current.routing_root);
    let refusal = policy()
        .accept(&relocating, &current)
        .await
        .expect_err("a refresh must never relocate the node's managed state")
        .to_string();
    assert!(
        refusal.contains("would move install_root")
            && refusal.contains(&pinned.display().to_string()),
        "the refusal must name the pinned install root, got: {refusal}"
    );
    let _ = std::fs::remove_dir_all(tmp);
}

/// The same bundle, but naming the repository directory itself as its routing origin. A `file:`
/// base is a real deployment shape and the one a test can serve, so the versioned roots the
/// rotation walk fetches come from the same place a node's would.
fn served_from(mut bundle: EnrollmentBundle, repo_dir: &Path) -> EnrollmentBundle {
    bundle.routing_base_url =
        url::Url::from_directory_path(std::fs::canonicalize(repo_dir).unwrap())
            .unwrap()
            .to_string();
    bundle
}

fn root_version(bundle: &EnrollmentBundle) -> u64 {
    serde_json::from_str::<serde_json::Value>(&bundle.routing_root).unwrap()["signed"]["version"]
        .as_u64()
        .unwrap()
}

/// A node offline across two root ceremonies comes back pinned two versions behind everything the
/// repository publishes. Its pin advances only by adopting a bundle, and a bundle may advance it
/// only one version, so without a catch-up the node refuses every bundle forever and only
/// re-enrolment recovers it. The catch-up is the TUF rotation walk: fetch the roots in between and
/// verify each against the one before it.
#[tokio::test]
async fn a_refresh_walks_the_published_roots_to_catch_a_lagging_pin_up() {
    let (_tmp, tmp) = scratch("bundle-root-catch-up");
    let install_root = tmp.join("install");
    let routing = Routing::author(&tmp).await;
    let current = served_from(
        bundle_for(
            &routing.dir,
            &routing.publish(&[("node-a", &install_root)]).await[0],
        ),
        &routing.dir,
    );

    // Two ceremonies while the node is away — v1 to v2 to v3, each co-signed by a key the previous
    // root trusts, which is what a renewal and a rotate-root leave behind. v3 is NOT verifiable
    // under v1: the keys that signed it are ones only v2 introduced.
    let successor = tmp.join("successor.pk8");
    repo::generate_root_key(&successor).await.unwrap();
    repo::rotate_root(&routing.dir, &routing.keys.roots[1..], &successor, 365)
        .await
        .unwrap();
    let third = tmp.join("third.pk8");
    repo::generate_root_key(&third).await.unwrap();
    repo::rotate_root(&routing.dir, std::slice::from_ref(&successor), &third, 365)
        .await
        .unwrap();
    let candidate = served_from(
        bundle_for(
            &routing.dir,
            &routing.publish(&[("node-a", &install_root)]).await[0],
        ),
        &routing.dir,
    );
    assert_eq!(root_version(&current), 1);
    assert_eq!(root_version(&candidate), 3);

    policy()
        .accept(&candidate, &current)
        .await
        .expect("a two-version rotation is adoptable once the root in between is walked");

    // The same candidate with the chain broken. Nothing about the bundle changed — only the node's
    // ability to verify how the repository got there — and that alone must refuse it.
    let intermediate = routing.dir.join("metadata/2.root.json");
    let withheld = tmp.join("2.root.json");
    std::fs::rename(&intermediate, &withheld).unwrap();
    let refusal = policy()
        .accept(&candidate, &current)
        .await
        .expect_err("a root two versions ahead is unverifiable with the version between it missing")
        .to_string();
    assert!(
        refusal.contains("the refreshed root is not signed by the pinned root"),
        "the refusal must say the candidate could not be chained to the pin, got: {refusal}"
    );

    // A chain that skips: the candidate itself served in place of the version before it. The walk
    // must not accept a link it cannot verify, or the fast-forward it exists to block would simply
    // be supplied as its own intermediate.
    std::fs::copy(routing.dir.join("metadata/3.root.json"), &intermediate).unwrap();
    let refusal = policy()
        .accept(&candidate, &current)
        .await
        .expect_err("a rotation chain with a hole in it must be refused")
        .to_string();
    assert!(
        refusal.contains("published root version 3")
            && refusal.contains("not signed by the pinned root"),
        "the refusal must name the link that could not be verified, got: {refusal}"
    );
    let _ = std::fs::remove_dir_all(tmp);
}
