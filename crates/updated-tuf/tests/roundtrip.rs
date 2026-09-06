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

/// The small-limits runtime both fixtures in this file use: a 1 MiB target ceiling and five-second
/// cadences, so an offline repository exercises the bounds without waiting out production defaults.
/// Written once — the two copies agreed on all fourteen values and differed only in these two.
fn small_runtime(
    product: &str,
    install_root: std::path::PathBuf,
) -> updated_contracts::assignment::ManagedRuntime {
    let nominal = updated_contracts::assignment::testing::runtime();
    updated_contracts::assignment::ManagedRuntime {
        product: product.into(),
        install_root,
        repository: updated_contracts::assignment::ManagedRepositoryLimits {
            metadata_limit: 1024 * 1024,
            target_limit: 1024 * 1024,
            transport_timeout_seconds: 5,
        },
        storage: updated_contracts::assignment::ManagedStorage {
            inactive_bytes: 1024 * 1024,
            ..nominal.storage
        },
        timeouts: updated_contracts::assignment::ManagedTimeouts {
            check_interval_seconds: 5,
            health_grace_seconds: 5,
            health_successes: 1,
            health_interval_seconds: 1,
            refresh_retry_seconds: 5,
            confirmation_window_seconds: 5,
        },
        ..nominal
    }
}

fn client_config(repo_dir: &std::path::Path) -> RepositorySource {
    updated_tuf::testing::offline_source(repo_dir)
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
async fn preplaced_enrollment_resolves_offline_through_the_live_repository() {
    let scratch = tempfile::tempdir().unwrap();
    let tmp = scratch.path().to_path_buf();
    let repo_dir = tmp.join("routing");
    let keys = repo::generate_keys(&tmp.join("routing-keys"))
        .await
        .unwrap();
    repo::init(&repo_dir, &keys, 365).await.unwrap();

    let root_text = std::fs::read_to_string(repo_dir.join("metadata/root.json")).unwrap();
    let root: serde_json::Value = serde_json::from_str(&root_text).unwrap();
    let runtime = small_runtime("offline-app", tmp.join("install"));
    let assignment = updated_contracts::assignment::RepositoryAssignment {
        schema: updated_contracts::assignment::RepositoryAssignment::SCHEMA,
        deployment: "offline".into(),
        metadata_url: "https://127.0.0.1:9/release/metadata/".into(),
        targets_url: "https://127.0.0.1:9/release/targets/".into(),
        application: updated_contracts::releases::testing::install(
            "1.0.0",
            updated_contracts::artifact::TargetReference {
                path: "products/offline-app/stable/1/linux-x86_64/app".into(),
                sha256: "a".repeat(64),
            },
        ),

        release_root: root.clone(),
        runtime,
    };
    let config_bytes = serde_json::to_vec(&assignment).unwrap();
    let config_sha = updated_contracts::digest::sha256_bytes(&config_bytes);
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
    let routing_base_url = url::Url::from_directory_path(std::fs::canonicalize(&repo_dir).unwrap())
        .unwrap()
        .to_string();
    let bundle = updated_contracts::enrollment::EnrollmentBundle {
        schema: 1,
        agent_id: updated_contracts::identity::ResourceName::new("offline").unwrap(),
        routing_base_url,
        assignment: agent_path.into(),
        install_root: assignment.runtime.install_root.clone(),
        routing_root: root_text,
    };
    let config_path = tmp.join("config.toml");
    std::fs::write(
        &config_path,
        "[enrollment]\nurl='https://127.0.0.1:9'\nname='offline'\nca='unused-offline-ca.crt'\n",
    )
    .unwrap();
    let enrollment_state = tmp.join("enrollment-state");
    std::fs::create_dir_all(&enrollment_state).unwrap();
    // A local routing repository is the offline path: the small preplaced object pins its root and
    // the first boot resolves the live assignment through the same TUF path every later poll uses.
    std::fs::write(
        enrollment_state.join("enrollment.json"),
        serde_json::to_vec(&bundle).unwrap(),
    )
    .unwrap();
    let config = updated_tuf::resolve_managed_config(&config_path, &enrollment_state)
        .await
        .unwrap();
    assert_eq!(config.application.product, "offline-app");
}

/// The file `resolve_assignment` writes IS this node's live boot config: the next boot launches the
/// managed application from it before any network, and the write destroys the previous one. So a
/// published document this build could never fetch from — or one that would move the node out of
/// the install root the enrollment bundle put it in — must be refused BEFORE the write. Refusing it
/// afterwards (in the caller, or in the reader a boot later) leaves the node with no good
/// assignment and a failure that is never retryable.
#[tokio::test]
async fn a_resolved_assignment_is_validated_before_it_becomes_the_live_boot_config() {
    let scratch = tempfile::tempdir().unwrap();
    let tmp = scratch.path().to_path_buf();
    let repo_dir = tmp.join("routing");
    let keys = repo::generate_keys(&tmp.join("routing-keys"))
        .await
        .unwrap();
    repo::init(&repo_dir, &keys, 365).await.unwrap();
    let root: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(repo_dir.join("metadata/root.json")).unwrap(),
    )
    .unwrap();

    let install_root = tmp.join("install");
    let enrollment_state = tmp.join("enrollment-state");
    std::fs::create_dir_all(&enrollment_state).unwrap();

    let assignment = |metadata_url: &str, install: &std::path::Path| {
        updated_contracts::assignment::RepositoryAssignment {
            schema: updated_contracts::assignment::RepositoryAssignment::SCHEMA,
            deployment: "commit".into(),
            metadata_url: metadata_url.into(),
            targets_url: "https://127.0.0.1:9/release/targets/".into(),
            application: updated_contracts::releases::testing::install(
                "1.0.0",
                updated_contracts::artifact::TargetReference {
                    path: "products/app/stable/1/linux-x86_64/app".into(),
                    sha256: "a".repeat(64),
                },
            ),

            release_root: root.clone(),
            runtime: small_runtime("app", install.to_path_buf()),
        }
    };

    let mut targets = Vec::new();
    let mut publish =
        |name: &str, assignment: &updated_contracts::assignment::RepositoryAssignment| -> String {
            let config_bytes = serde_json::to_vec(assignment).unwrap();
            let config_sha = updated_contracts::digest::sha256_bytes(&config_bytes);
            let config_path = format!("assignments/configs/{config_sha}.json");
            let config_source = tmp.join(format!("{name}-config.json"));
            std::fs::write(&config_source, &config_bytes).unwrap();
            let agent = updated_contracts::artifact::AgentDocument {
                schema: 1,
                config: updated_contracts::artifact::TargetReference {
                    path: config_path.clone(),
                    sha256: config_sha,
                },
            };
            let agent_source = tmp.join(format!("{name}-agent.json"));
            std::fs::write(&agent_source, serde_json::to_vec(&agent).unwrap()).unwrap();
            let agent_path = format!("assignments/agents/{name}.json");
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
            agent_path
        };
    let good = publish(
        "good",
        &assignment("https://127.0.0.1:9/release/metadata/", &install_root),
    );
    // A metadata_url without its trailing slash is not a base directory this build can fetch from.
    let unfetchable = publish(
        "unfetchable",
        &assignment("https://127.0.0.1:9/release/metadata", &install_root),
    );
    let relocating = publish(
        "relocating",
        &assignment("https://127.0.0.1:9/release/metadata/", &tmp.join("moved")),
    );
    repo::add_release(&repo_dir, &keys, targets, 365)
        .await
        .unwrap();

    let routing = |agent_path: &str| updated::config::Routing {
        root: repo_dir.join("metadata/root.json"),
        base_url: url::Url::from_directory_path(std::fs::canonicalize(&repo_dir).unwrap())
            .unwrap()
            .to_string(),
        assignment: agent_path.to_string(),
        transport_timeout: std::time::Duration::from_secs(5),
        mtls: updated::tls::Identity::new(
            repo_dir.join("client.crt"),
            repo_dir.join("client.key"),
            repo_dir.join("ca.crt"),
        ),
    };
    let paths = updated::config::Paths::resolve(&install_root, &enrollment_state);

    TrustedRepository::resolve_assignment(&routing(&good), &paths)
        .await
        .expect("a usable document is committed as the live boot config");
    let committed = std::fs::read(&paths.assignment).unwrap();

    for (agent_path, expected) in [(&unfetchable, "metadataUrl"), (&relocating, "installRoot")] {
        let Err(error) = TrustedRepository::resolve_assignment(&routing(agent_path), &paths).await
        else {
            panic!("an unusable document must never be committed");
        };
        assert!(!error.is_retryable(), "{error}");
        assert!(error.to_string().contains(expected), "{error}");
        assert_eq!(
            std::fs::read(&paths.assignment).unwrap(),
            committed,
            "the live boot config must survive a rejected {expected}"
        );
        // The download scratch is scratch on the rejection path too. A node re-resolves every
        // check interval, so a copy left behind here is a copy of an unusable document sitting
        // beside the live one for as long as the control plane keeps publishing it.
        assert!(
            !updated::config::with_suffix(&paths.assignment, ".resolving").exists(),
            "a rejected {expected} left its staging file behind"
        );
    }
}

#[tokio::test]
async fn publish_then_verify_and_download() {
    let scratch = tempfile::tempdir().unwrap();
    let tmp = scratch.path().to_path_buf();

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
    local.metadata_url.push(std::path::MAIN_SEPARATOR);
    local.targets_url = std::fs::canonicalize(repo_dir.join("targets"))
        .unwrap()
        .display()
        .to_string();
    local.targets_url.push(std::path::MAIN_SEPARATOR);
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

    // The same pinned-package verifier protects preflight, upgrades, and exact repair.
    let policy = policy();
    let package = updated_contracts::artifact::TargetReference {
        path: found.path.clone(),
        sha256: updated_tuf::select::target_sha(&found),
    };
    repo.verify_release(&policy, "1.0.0", &package).unwrap();
    assert!(repo.verify_release(&policy, "2.0.0", &package).is_err());
    let mut wrong_platform = policy;
    wrong_platform.arch = "wrong-architecture".into();
    assert!(repo
        .verify_release(&wrong_platform, "1.0.0", &package)
        .is_err());

    let out = tmp.join("downloaded");
    let mut downloaded = repo.download_target(&found, &out).await.unwrap();
    assert_eq!(downloaded.read_bounded(1024).unwrap(), b"hello-app-1.0.0");

    // A pre-planted destination symlink is replaced as a directory entry; its target is
    // never opened or truncated by the privileged download path.
    #[cfg(unix)]
    {
        let victim = tmp.join("victim");
        let redirected = tmp.join("redirected-download");
        std::fs::write(&victim, b"do-not-touch").unwrap();
        std::os::unix::fs::symlink(&victim, &redirected).unwrap();
        let mut downloaded = repo.download_target(&found, &redirected).await.unwrap();
        assert_eq!(std::fs::read(&victim).unwrap(), b"do-not-touch");
        assert_eq!(downloaded.read_bounded(1024).unwrap(), b"hello-app-1.0.0");
        assert!(!std::fs::symlink_metadata(&redirected)
            .unwrap()
            .file_type()
            .is_symlink());

        // Replacing the directory entry after download does not replace the authenticated handle
        // consumers use. This is the verify/use race the handle API exists to close.
        let replacement = tmp.join("replacement");
        std::fs::write(&replacement, b"unsigned replacement").unwrap();
        std::fs::rename(&replacement, &redirected).unwrap();
        assert_eq!(downloaded.read_bounded(1024).unwrap(), b"hello-app-1.0.0");
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
    let _downloaded = repo_exact
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
    // agent and one-shot updater do each cycle — refreshes the metadata chain and
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
    let mut old_download = old.download_target(&old_target, &old_out).await.unwrap();
    assert_eq!(
        old_download.read_bounded(1024).unwrap(),
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
    let mut new_download = new.download_target(&new_target, &new_out).await.unwrap();
    assert_eq!(
        new_download.read_bounded(1024).unwrap(),
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
}

/// A download killed mid-stream — SIGKILL from the service manager, a reboot, power loss — leaves its
/// full-size staging temp behind, and nothing outside this crate reclaims it: the staging roots
/// hold fixed destination files rather than per-attempt directories, so the bundle sweep and the
/// directory pruner never see them. Without the sweep here a crash-looping node accumulates one
/// bundle-sized orphan per attempt until the install root fills and every update fails.
#[tokio::test]
async fn downloading_reclaims_staging_temps_orphaned_by_an_earlier_interrupted_download() {
    let scratch = tempfile::tempdir().unwrap();
    let tmp = scratch.path().to_path_buf();
    let (repo_dir, _keys, target_path) = author(&tmp).await;
    let repo = TrustedRepository::load(&client_config(&repo_dir), &tmp.join("ds"))
        .await
        .unwrap();
    let found = repo
        .all_targets()
        .into_iter()
        .find(|t| t.path == target_path)
        .unwrap();

    let staging = tmp.join("staging");
    std::fs::create_dir_all(&staging).unwrap();
    let orphan = staging.join(".target-1234-5678-9.tmp");
    std::fs::write(&orphan, vec![0u8; 4096]).unwrap();
    // Backdate it past the stale-temp age so it reads as an abandoned leftover rather than a
    // temp some concurrent writer still owns.
    std::fs::File::options()
        .write(true)
        .open(&orphan)
        .unwrap()
        .set_modified(std::time::SystemTime::now() - std::time::Duration::from_secs(3600))
        .unwrap();
    // A temp written just now belongs to a download in flight beside this one and must survive.
    let in_flight = staging.join(".target-1234-5678-10.tmp");
    std::fs::write(&in_flight, b"still being written").unwrap();
    // Nothing else in the staging root is this sweep's business.
    let unrelated = staging.join("stage-abcdef");
    std::fs::create_dir_all(&unrelated).unwrap();

    let mut downloaded = repo
        .download_target(&found, &staging.join("app"))
        .await
        .unwrap();

    assert_eq!(downloaded.read_bounded(1024).unwrap(), b"hello-app-1.0.0");
    assert!(
        !orphan.exists(),
        "the orphaned staging temp must be reclaimed by the next download"
    );
    assert!(
        in_flight.exists(),
        "a temp still being written is not ours to yank"
    );
    assert!(
        unrelated.is_dir(),
        "the sweep touches only its own staging temps"
    );
}
