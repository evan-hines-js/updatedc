//! End-to-end proof: author a TUF repo with the builder, then load it as a client
//! over `file://` URLs and verify + download a target through the full TUF chain.

use updated::config::Repository;
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

fn client_config(repo_dir: &std::path::Path) -> Repository {
    let url = |sub: &str| {
        url::Url::from_directory_path(std::fs::canonicalize(repo_dir.join(sub)).unwrap())
            .unwrap()
            .to_string()
    };
    Repository {
        metadata_url: url("metadata"),
        targets_url: url("targets"),
        root: repo_dir.join("metadata/root.json"),
        datastore: None,
        metadata_limit: 1024 * 1024,
        target_limit: 100 * 1024 * 1024,
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

    let mut repo = TrustedRepository::load(&client_config(&repo_dir), &tmp.join("ds"))
        .await
        .unwrap();

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
    let staged = repo
        .stage_update(&policy, None, &staged_path, |_| {}, |_, _| false)
        .await
        .unwrap()
        .expect("stages the sole release");
    assert_eq!(staged.version, "1.0.0");
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

    repo.refresh().await.unwrap();
    let found2 = repo
        .all_targets()
        .into_iter()
        .find(|t| t.path == path2)
        .expect("refresh surfaces the newly published 2.0.0 release");
    assert_eq!(
        found2.custom.get("version").and_then(|v| v.as_str()),
        Some("2.0.0")
    );

    let _ = std::fs::remove_dir_all(&tmp);
}
