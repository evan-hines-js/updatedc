//! End-to-end proof: author a TUF repo with the builder, then load it as a client
//! over `file://` URLs and verify + download a target through the full TUF chain.

use updated::config::RepositorySource;
use updated_tuf::policy::DefaultPolicy;
use updated_tuf::{repo, TrustedRepository};

async fn author(tmp: &std::path::Path) -> (std::path::PathBuf, repo::Keys, String) {
    let repo_dir = tmp.join("repo");
    let keys_dir = tmp.join("keys");
    let keys = repo::generate_keys(&keys_dir).await.unwrap();
    repo::init(&repo_dir, &keys, 365).await.unwrap();

    let artifact = tmp.join("app-bin");
    std::fs::write(&artifact, b"hello-app-1.0.0").unwrap();
    let target = repo::PublishTarget::application(
        "app", "stable", "1.0.0", "linux", "x86_64", "app", artifact,
    );
    let path = target.name.clone();
    repo::add_release(&repo_dir, &keys, vec![target], 365)
        .await
        .unwrap();
    (repo_dir, keys, path)
}

fn client_config(repo_dir: &std::path::Path) -> RepositorySource {
    let url = |sub: &str| {
        url::Url::from_directory_path(std::fs::canonicalize(repo_dir.join(sub)).unwrap())
            .unwrap()
            .to_string()
    };
    RepositorySource {
        metadata_url: url("metadata"),
        targets_url: url("targets"),
        root: repo_dir.join("metadata/root.json"),
        metadata_limit: 1024 * 1024,
        target_limit: 100 * 1024 * 1024,
        transport_timeout: std::time::Duration::from_secs(5),
        mtls: updated::tls::Identity::new(
            repo_dir.join("client.crt"),
            repo_dir.join("client.key"),
            repo_dir.join("ca.crt"),
        ),
    }
}

fn policy() -> DefaultPolicy {
    DefaultPolicy {
        product: "app".into(),
        channel: "stable".into(),
        os: "linux".into(),
        arch: "x86_64".into(),
    }
}

#[tokio::test]
async fn preplaced_enrollment_resolves_offline_and_rejects_tampering() {
    let tmp = std::env::temp_dir().join(format!(
        "updated-tuf-offline-{}-{}",
        std::process::id(),
        updated::rand::token().unwrap()
    ));
    std::fs::create_dir_all(&tmp).unwrap();
    let repo_dir = tmp.join("routing");
    let keys = repo::generate_keys(&tmp.join("routing-keys"))
        .await
        .unwrap();
    repo::init(&repo_dir, &keys, 365).await.unwrap();

    let root_text = std::fs::read_to_string(repo_dir.join("metadata/root.json")).unwrap();
    let root: serde_json::Value = serde_json::from_str(&root_text).unwrap();
    let runtime = updated_contracts::assignment::ManagedRuntime {
        mode: updated_contracts::assignment::RuntimeMode::Managed,
        product: "offline-app".into(),
        channel: "stable".into(),
        install_root: tmp.join("install"),
        args: vec!["serve".into()],
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
    };
    let assignment = updated_contracts::assignment::RepositoryAssignment {
        schema: updated_contracts::assignment::RepositoryAssignment::SCHEMA,
        deployment: "offline".into(),
        metadata_url: "http://127.0.0.1:9/release/metadata/".into(),
        targets_url: "http://127.0.0.1:9/release/targets/".into(),
        report_url: None,
        application: updated_contracts::artifact::TargetReference {
            path: "products/offline-app/stable/1/linux-x86_64/app".into(),
            sha256: "a".repeat(64),
        },
        ordered_install_fallback: false,
        provider_set: updated_contracts::artifact::TargetReference {
            path: "provider-sets/default.json".into(),
            sha256: "b".repeat(64),
        },
        release_root: root.clone(),
        runtime,
    };
    let config_bytes = serde_json::to_vec(&assignment).unwrap();
    let config_sha = updated::hash::sha256_bytes(&config_bytes);
    let config_path = format!("assignments/configs/{config_sha}.json");
    let agent = updated_contracts::artifact::AgentDocument {
        schema: 1,
        config: updated_contracts::artifact::TargetReference {
            path: config_path.clone(),
            sha256: config_sha,
        },
    };
    let agent_bytes = serde_json::to_vec(&agent).unwrap();
    let config_source = tmp.join("managed.json");
    let agent_source = tmp.join("agent.json");
    std::fs::write(&config_source, &config_bytes).unwrap();
    std::fs::write(&agent_source, &agent_bytes).unwrap();
    let agent_path = "assignments/agents/offline.json";
    repo::add_release(
        &repo_dir,
        &keys,
        vec![
            repo::PublishTarget {
                name: config_path,
                source: config_source,
                custom: Default::default(),
            },
            repo::PublishTarget {
                name: agent_path.into(),
                source: agent_source,
                custom: Default::default(),
            },
        ],
        365,
    )
    .await
    .unwrap();
    let timestamp = std::fs::read_to_string(repo_dir.join("metadata/timestamp.json")).unwrap();
    let timestamp_value: serde_json::Value = serde_json::from_str(&timestamp).unwrap();
    let snapshot_version = timestamp_value["signed"]["meta"]["snapshot.json"]["version"]
        .as_u64()
        .unwrap();
    let snapshot = std::fs::read_to_string(
        repo_dir.join(format!("metadata/{snapshot_version}.snapshot.json")),
    )
    .unwrap();
    let snapshot_value: serde_json::Value = serde_json::from_str(&snapshot).unwrap();
    let targets_version = snapshot_value["signed"]["meta"]["targets.json"]["version"]
        .as_u64()
        .unwrap();
    let targets =
        std::fs::read_to_string(repo_dir.join(format!("metadata/{targets_version}.targets.json")))
            .unwrap();
    let bundle = updated_contracts::enrollment::EnrollmentBundle {
        schema: 1,
        agent_id: "offline".into(),
        routing_base_url: "http://127.0.0.1:9/routing/".into(),
        assignment: agent_path.into(),
        routing_root: root_text,
        initial: updated_contracts::enrollment::InitialSignedConfiguration {
            timestamp,
            snapshot,
            targets,
            agent_document: String::from_utf8(agent_bytes).unwrap(),
            managed_configuration: String::from_utf8(config_bytes).unwrap(),
        },
    };
    let bootstrap = tmp.join("bootstrap.toml");
    std::fs::write(
        &bootstrap,
        "[enrollment]\nurl='https://127.0.0.1:9'\nname='offline'\nclient_cert='unused-offline.crt'\nclient_key='unused-offline.key'\nca='unused-offline-ca.crt'\n",
    )
    .unwrap();
    let enrollment_state = tmp.join("enrollment-state");
    std::fs::create_dir_all(&enrollment_state).unwrap();
    // A network-free first boot against a remote gateway must preplace both halves of
    // steady state: the signed enrollment bundle and the node's already-minted identity.
    // The transport does not parse these fixtures until a request is made.
    std::fs::write(enrollment_state.join("agent.crt"), "preplaced leaf").unwrap();
    std::fs::write(enrollment_state.join("agent.key"), "preplaced key").unwrap();
    std::fs::write(
        enrollment_state.join("enrollment.json"),
        serde_json::to_vec(&bundle).unwrap(),
    )
    .unwrap();
    let config = updated_tuf::resolve_managed_config(&bootstrap, &enrollment_state)
        .await
        .unwrap();
    assert_eq!(config.application.product, "offline-app");
    assert_eq!(config.application.args, vec!["serve".to_string()]);

    // Boot configuration — the managed process's arguments, and which secret populates which
    // environment variable — is read before any network fetch and cannot be verified at that
    // moment, so it comes only from the enrollment directory. A document planted under
    // `install_root` (recoverable state the guardian and supervisor churn through) must have no
    // say in how the application is launched.
    let planted = config.application.install_root.join("state");
    std::fs::create_dir_all(&planted).unwrap();
    let mut hostile: serde_json::Value =
        serde_json::from_str(&bundle.initial.managed_configuration).unwrap();
    hostile["runtime"]["args"] = serde_json::json!(["--exfiltrate"]);
    std::fs::write(
        planted.join("repository-assignment.json"),
        serde_json::to_vec(&hostile).unwrap(),
    )
    .unwrap();
    let config = updated_tuf::resolve_managed_config(&bootstrap, &enrollment_state)
        .await
        .unwrap();
    assert_eq!(
        config.application.args,
        vec!["serve".to_string()],
        "install_root state must not choose the managed process's arguments"
    );

    // The same document in the enrollment directory — where the update loop persists it, beside
    // the bundle and the node's key — is the node's live configuration and is honoured.
    std::fs::write(
        updated::config::persisted_assignment_path(&enrollment_state),
        serde_json::to_vec(&hostile).unwrap(),
    )
    .unwrap();
    let config = updated_tuf::resolve_managed_config(&bootstrap, &enrollment_state)
        .await
        .unwrap();
    assert_eq!(config.application.args, vec!["--exfiltrate".to_string()]);
    std::fs::remove_file(updated::config::persisted_assignment_path(
        &enrollment_state,
    ))
    .unwrap();

    let mut tampered = bundle;
    let mut tampered_config: serde_json::Value =
        serde_json::from_str(&tampered.initial.managed_configuration).unwrap();
    tampered_config["deployment"] = serde_json::json!("attacker");
    tampered.initial.managed_configuration = serde_json::to_string(&tampered_config).unwrap();
    let tampered_state = tmp.join("tampered-state");
    std::fs::create_dir_all(&tampered_state).unwrap();
    std::fs::write(tampered_state.join("agent.crt"), "preplaced leaf").unwrap();
    std::fs::write(tampered_state.join("agent.key"), "preplaced key").unwrap();
    std::fs::write(
        tampered_state.join("enrollment.json"),
        serde_json::to_vec(&tampered).unwrap(),
    )
    .unwrap();
    let error = updated_tuf::resolve_managed_config(&bootstrap, &tampered_state)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("digest mismatch"), "{error}");
    let _ = std::fs::remove_dir_all(tmp);
}

#[tokio::test]
async fn publish_then_verify_and_download() {
    let tmp = std::env::temp_dir().join(format!("updated-tuf-rt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();

    let (repo_dir, keys, target_path) = author(&tmp).await;

    // The generated signing keys are owner-only on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(tmp.join("keys/root.pk8"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "signing key is owner-only: {mode:o}");
    }

    let repo = TrustedRepository::load(&client_config(&repo_dir), &tmp.join("ds"))
        .await
        .unwrap();

    // A manually placed repository uses the identical TUF path. Absolute directories
    // are merely shorthand for file: base URLs; there is no separate offline verifier.
    let mut local = client_config(&repo_dir);
    local.metadata_url = std::fs::canonicalize(repo_dir.join("metadata"))
        .unwrap()
        .display()
        .to_string();
    local.targets_url = std::fs::canonicalize(repo_dir.join("targets"))
        .unwrap()
        .display()
        .to_string();
    let local_repo = TrustedRepository::load(&local, &tmp.join("ds-local-paths"))
        .await
        .unwrap();
    assert!(local_repo
        .all_targets()
        .iter()
        .any(|target| target.path == target_path));

    let found = repo
        .all_targets()
        .into_iter()
        .find(|t| t.path == target_path)
        .expect("target is present in verified metadata");
    assert_eq!(found.length, 15);
    assert_eq!(
        found.custom.get("version").and_then(|v| v.as_str()),
        Some("1.0.0")
    );

    // Policy: the right platform is authorized, an equal version is *not* a downgrade,
    // and an older installed version is refused with a descriptive message.
    let policy = policy();
    policy.authorize(None, &found).unwrap();
    policy
        .authorize(Some("1.0.0"), &found)
        .expect("same version is not a downgrade");
    let downgrade = policy.authorize(Some("2.0.0"), &found).unwrap_err();
    assert!(
        downgrade.to_string().contains("policy rejected candidate"),
        "{downgrade}"
    );
    assert!(
        downgrade.to_string().contains("refusing downgrade"),
        "{downgrade}"
    );

    // Selection picks the sole eligible release, and staging downloads exactly its
    // verified bytes to the destination.
    let selected = repo
        .select_release(&policy, None, |_| {}, |_, _| false)
        .expect("selects the sole release");
    assert_eq!(selected.version, "1.0.0");

    let staged_path = tmp.join("staged");
    repo.stage_release(&selected, &staged_path).await.unwrap();
    assert_eq!(std::fs::read(&staged_path).unwrap(), b"hello-app-1.0.0");

    let out = tmp.join("downloaded");
    repo.download_target(&found, &out).await.unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), b"hello-app-1.0.0");

    // A pre-planted destination symlink is replaced as a directory entry; its target is
    // never opened or truncated by the privileged download path.
    #[cfg(unix)]
    {
        let victim = tmp.join("victim");
        let redirected = tmp.join("redirected-download");
        std::fs::write(&victim, b"do-not-touch").unwrap();
        std::os::unix::fs::symlink(&victim, &redirected).unwrap();
        repo.download_target(&found, &redirected).await.unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"do-not-touch");
        assert_eq!(std::fs::read(&redirected).unwrap(), b"hello-app-1.0.0");
        assert!(!std::fs::symlink_metadata(&redirected)
            .unwrap()
            .file_type()
            .is_symlink());
    }

    // The target byte cap fails closed when exceeded, and is inclusive at exactly the
    // target size (the boundary the streaming check enforces).
    let mut tight = client_config(&repo_dir);
    tight.target_limit = 5; // the target is 15 bytes
    let repo_tight = TrustedRepository::load(&tight, &tmp.join("ds-tight"))
        .await
        .unwrap();
    let found_t = repo_tight
        .all_targets()
        .into_iter()
        .find(|t| t.path == target_path)
        .unwrap();
    let cap_err = repo_tight
        .download_target(&found_t, &tmp.join("too-big"))
        .await
        .unwrap_err();
    assert!(cap_err.to_string().contains("exceeded"), "{cap_err}");

    let mut exact = client_config(&repo_dir);
    exact.target_limit = 15; // exactly the target size is allowed
    let repo_exact = TrustedRepository::load(&exact, &tmp.join("ds-exact"))
        .await
        .unwrap();
    let found_e = repo_exact
        .all_targets()
        .into_iter()
        .find(|t| t.path == target_path)
        .unwrap();
    repo_exact
        .download_target(&found_e, &tmp.join("exact"))
        .await
        .unwrap();

    // A second signed release must bump the metadata versions so a refresh picks it up.
    let artifact2 = tmp.join("app-bin-2");
    std::fs::write(&artifact2, b"hello-app-2.0.0!").unwrap();
    let target2 = repo::PublishTarget::application(
        "app", "stable", "2.0.0", "linux", "x86_64", "app", artifact2,
    );
    let path2 = target2.name.clone();
    repo::add_release(&repo_dir, &keys, vec![target2], 365)
        .await
        .unwrap();

    // Re-acquiring the repository against the same datastore — exactly what the
    // supervisor and one-shot updater do each cycle — refreshes the metadata chain and
    // surfaces the newly published release. There is one path to fresh metadata.
    let repo = TrustedRepository::load(&client_config(&repo_dir), &tmp.join("ds"))
        .await
        .unwrap();
    let found2 = repo
        .all_targets()
        .into_iter()
        .find(|t| t.path == path2)
        .expect("re-acquisition surfaces the newly published 2.0.0 release");
    assert_eq!(
        found2.custom.get("version").and_then(|v| v.as_str()),
        Some("2.0.0")
    );

    // Republishing one logical name must not invalidate a reader that already trusted
    // the previous metadata generation. Each generation resolves to its own immutable,
    // digest-prefixed target object.
    let assignment_name = "assignments/agents/agent.json";
    let assignment_v1 = tmp.join("assignment-v1");
    std::fs::write(&assignment_v1, b"assignment generation one").unwrap();
    repo::add_release(
        &repo_dir,
        &keys,
        vec![repo::PublishTarget {
            name: assignment_name.into(),
            source: assignment_v1,
            custom: Default::default(),
        }],
        365,
    )
    .await
    .unwrap();
    let old = TrustedRepository::load(&client_config(&repo_dir), &tmp.join("ds-old-assignment"))
        .await
        .unwrap();
    let old_target = old
        .all_targets()
        .into_iter()
        .find(|target| target.path == assignment_name)
        .unwrap();

    let assignment_v2 = tmp.join("assignment-v2");
    std::fs::write(&assignment_v2, b"assignment generation two").unwrap();
    repo::add_release(
        &repo_dir,
        &keys,
        vec![repo::PublishTarget {
            name: assignment_name.into(),
            source: assignment_v2,
            custom: Default::default(),
        }],
        365,
    )
    .await
    .unwrap();

    let old_out = tmp.join("old-assignment");
    old.download_target(&old_target, &old_out).await.unwrap();
    assert_eq!(
        std::fs::read(old_out).unwrap(),
        b"assignment generation one"
    );
    let new = TrustedRepository::load(&client_config(&repo_dir), &tmp.join("ds-new-assignment"))
        .await
        .unwrap();
    let new_target = new
        .all_targets()
        .into_iter()
        .find(|target| target.path == assignment_name)
        .unwrap();
    let new_out = tmp.join("new-assignment");
    new.download_target(&new_target, &new_out).await.unwrap();
    assert_eq!(
        std::fs::read(new_out).unwrap(),
        b"assignment generation two"
    );
    assert!(!repo_dir.join("targets").join(assignment_name).exists());

    // Exact-set publication removes obsolete logical routes from the new metadata while
    // retaining immutable objects needed by readers of older metadata generations.
    let exact = tmp.join("exact-assignment");
    std::fs::write(&exact, b"only current route").unwrap();
    repo::replace_release(
        &repo_dir,
        &keys,
        vec![repo::PublishTarget {
            name: "assignments/agents/current.json".into(),
            source: exact,
            custom: Default::default(),
        }],
        365,
    )
    .await
    .unwrap();
    let replaced = TrustedRepository::load(&client_config(&repo_dir), &tmp.join("ds-replaced"))
        .await
        .unwrap();
    let current = replaced.all_targets();
    assert_eq!(current.len(), 1);
    assert_eq!(current[0].path, "assignments/agents/current.json");

    let _ = std::fs::remove_dir_all(&tmp);
}
