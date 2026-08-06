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

fn scratch(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "updated-tuf-{label}-{}-{}",
        std::process::id(),
        updated::rand::token().unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
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
            mode: updated_contracts::assignment::RuntimeMode::Managed,
            product: "app".into(),
            channel: "stable".into(),
            install_root: install_root.to_path_buf(),
            args: vec![],
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
                inactive_supervisors: 2,
                inactive_bytes: 1024 * 1024,
                inactive_repository_caches: 2,
            },
            timeouts: updated_contracts::assignment::ManagedTimeouts {
                check_interval_seconds: 5,
                health_grace_seconds: 5,
                health_successes: 1,
                health_interval_seconds: 1,
                retry_after_seconds: 5,
                refresh_retry_seconds: 5,
                confirmation_window_seconds: 5,
                supervisor_check_interval_seconds: 5,
                drain_hold_seconds: Some(0),
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
    let tmp = scratch("bundle-pin-assignment");
    let install_root = tmp.join("install");
    let routing = Routing::author(&tmp).await;
    let published = routing
        .publish(&[("node-a", &install_root), ("node-b", &install_root)])
        .await;
    let repo_dir = routing.dir.clone();
    let current = bundle_for(&repo_dir, &published[0]);

    // The identical bundle is the ordinary refresh: same chain, same everything.
    EmbeddedChainPolicy
        .accept(&current, &current)
        .expect("a bundle for this node's own assignment is adoptable");

    // A taken-over gateway keeps `agentId` truthful — so the identity check passes — and swaps in
    // node B's genuinely published, correctly signed routing. Nothing is forged.
    let mut swapped = bundle_for(&repo_dir, &published[1]);
    swapped.agent_id = current.agent_id.clone();
    let refusal = EmbeddedChainPolicy
        .accept(&swapped, &current)
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
    let tmp = scratch("bundle-pin-routing-base");
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
    EmbeddedChainPolicy
        .accept(&rotated, &current)
        .expect("a metadata-only refresh under the pinned root is the point of the refresh path");

    // The move that cannot be undone: the node's own bundle, byte-identical but for a plaintext
    // field no signature covers. Adopted, it would make the node classify itself as a local
    // deployment with no gateway to ask, so no later refresh could ever correct it.
    let mut severed = current.clone();
    severed.routing_base_url = "/var/tmp/attacker-routing/".into();
    let refusal = EmbeddedChainPolicy
        .accept(&severed, &current)
        .expect_err("a refresh must never move where routing metadata comes from")
        .to_string();
    assert!(
        refusal.contains("/var/tmp/attacker-routing/")
            && refusal.contains("https://updates.example/"),
        "the refusal must name both bases, got: {refusal}"
    );
    let _ = std::fs::remove_dir_all(tmp);
}

#[tokio::test]
async fn a_refresh_may_not_move_the_nodes_install_root() {
    let tmp = scratch("bundle-pin-install-root");
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
    let refusal = EmbeddedChainPolicy
        .accept(&relocating, &current)
        .expect_err("a refresh must never relocate the node's managed state")
        .to_string();
    assert!(
        refusal.contains("would move install_root")
            && refusal.contains(&pinned.display().to_string()),
        "the refusal must name the pinned install root, got: {refusal}"
    );
    let _ = std::fs::remove_dir_all(tmp);
}

