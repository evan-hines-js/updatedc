//! Root rotation, end to end. These tests author real TUF repositories on disk and load
//! them back through the actual `tough` client — the same verification a node performs — so
//! they prove not just the metadata shape but that the co-signed transition, the retirement
//! of the old key, and the survival of signed releases all hold under real verification.

use std::path::{Path, PathBuf};

use tough::{Repository, RepositoryLoader, TargetName};
use updated_tuf::repo::{self, Keys, PublishTarget};

fn scratch(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "updated-tuf-{label}-{}-{}",
        std::process::id(),
        updated::rand::token().unwrap()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A minted repository plus its keys, and the pinned v1 root bytes captured at init.
struct Fixture {
    tmp: PathBuf,
    repo_dir: PathBuf,
    keys: Keys,
    pinned_v1: Vec<u8>,
}

impl Fixture {
    async fn new(label: &str) -> Self {
        let tmp = scratch(label);
        let repo_dir = tmp.join("repo");
        let keys = repo::generate_keys(&tmp.join("keys")).await.unwrap();
        repo::init(&repo_dir, &keys, 365).await.unwrap();
        let pinned_v1 = tokio::fs::read(repo_dir.join("metadata/1.root.json"))
            .await
            .unwrap();
        Fixture {
            tmp,
            repo_dir,
            keys,
            pinned_v1,
        }
    }

    fn metadata(&self) -> PathBuf {
        self.repo_dir.join("metadata")
    }

    /// Mint a fresh successor key file under the fixture's scratch dir.
    async fn mint_key(&self, name: &str) -> PathBuf {
        let path = self.tmp.join(name);
        repo::generate_root_key(&path).await.unwrap();
        path
    }

    /// Publish an application release with the (unchanging) online keys.
    async fn publish_app(&self, version: &str) -> String {
        let source = self.tmp.join(format!("app-{version}.bin"));
        tokio::fs::write(&source, format!("app {version}").as_bytes())
            .await
            .unwrap();
        let target =
            PublishTarget::application("app", "stable", version, "linux", "x86_64", "app", source);
        let name = target.name.clone();
        repo::add_release(&self.repo_dir, &self.keys, vec![target], 365)
            .await
            .unwrap();
        name
    }

    /// Load the repository through `tough`, pinned to the original v1 root — exactly what a
    /// node that only ever trusted the first root does. A broken chain fails closed here.
    async fn load_pinned_to_v1(&self) -> Repository {
        let metadata_url =
            url::Url::from_directory_path(std::fs::canonicalize(self.metadata()).unwrap()).unwrap();
        let targets_url = url::Url::from_directory_path(
            std::fs::canonicalize(self.repo_dir.join("targets")).unwrap(),
        )
        .unwrap();
        RepositoryLoader::new(&self.pinned_v1, metadata_url, targets_url)
            .transport(tough::FilesystemTransport)
            .expiration_enforcement(tough::ExpirationEnforcement::Safe)
            .load()
            .await
            .expect("client pinned to the original root loads the current repository")
    }
}

async fn signed_json(metadata: &Path, file: &str) -> serde_json::Value {
    let bytes = tokio::fs::read(metadata.join(file)).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

async fn root_version(metadata: &Path, file: &str) -> u64 {
    signed_json(metadata, file).await["signed"]["version"]
        .as_u64()
        .unwrap()
}

async fn root_keyids(metadata: &Path, file: &str) -> Vec<String> {
    signed_json(metadata, file).await["signed"]["roles"]["root"]["keyids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|id| id.as_str().unwrap().to_string())
        .collect()
}

fn has_target(repo: &Repository, path: &str) -> bool {
    let name = TargetName::new(path).unwrap();
    repo.targets().signed.targets.contains_key(&name)
}

#[tokio::test]
async fn a_fresh_root_carries_two_side_by_side_keys() {
    let fixture = Fixture::new("mint").await;
    assert_eq!(fixture.keys.roots.len(), 2, "two root key files are minted");
    assert_eq!(root_version(&fixture.metadata(), "root.json").await, 1);
    assert_eq!(
        root_keyids(&fixture.metadata(), "root.json").await.len(),
        2,
        "root role lists both keys"
    );
    // The minted root is itself loadable and internally consistent.
    let repo = fixture.load_pinned_to_v1().await;
    assert_eq!(repo.root().signed.version.get(), 1);
}

#[tokio::test]
async fn rotation_bumps_the_version_and_swaps_exactly_one_key() {
    let fixture = Fixture::new("swap").await;
    let successor = fixture.mint_key("root.new.pk8").await;
    repo::rotate_root(&fixture.repo_dir, &fixture.keys.roots[1..], &successor, 365)
        .await
        .unwrap();

    let metadata = fixture.metadata();
    assert_eq!(root_version(&metadata, "root.json").await, 2);
    assert!(metadata.join("2.root.json").exists());

    let v1 = root_keyids(&metadata, "1.root.json").await;
    let v2 = root_keyids(&metadata, "2.root.json").await;
    assert_eq!(v2.len(), 2, "root still has two keys");
    assert_eq!(
        v2.iter().filter(|id| v1.contains(id)).count(),
        1,
        "exactly one continuity key retained"
    );
    assert!(
        v2.iter().any(|id| !v1.contains(id)),
        "a fresh successor is added"
    );
    assert_eq!(
        v1.iter().filter(|id| !v2.contains(id)).count(),
        1,
        "exactly one key retired"
    );
}

#[tokio::test]
async fn a_client_pinned_to_the_old_root_follows_the_rotation() {
    let fixture = Fixture::new("follow").await;
    let successor = fixture.mint_key("root.new.pk8").await;
    repo::rotate_root(&fixture.repo_dir, &fixture.keys.roots[1..], &successor, 365)
        .await
        .unwrap();

    let repo = fixture.load_pinned_to_v1().await;
    assert_eq!(
        repo.root().signed.version.get(),
        2,
        "client advanced to the rotated root"
    );
}

#[tokio::test]
async fn sequential_rotations_chain_all_the_way_back_to_the_first_root() {
    let fixture = Fixture::new("chain").await;

    // Rotation 1: retain the standby (roots[1]), retire the active (roots[0]), add C.
    let c = fixture.mint_key("c.pk8").await;
    repo::rotate_root(&fixture.repo_dir, &fixture.keys.roots[1..], &c, 365)
        .await
        .unwrap();
    // Rotation 2: retain C (the prior successor), add D. Mirrors "promote standby" in Vault.
    let d = fixture.mint_key("d.pk8").await;
    repo::rotate_root(&fixture.repo_dir, std::slice::from_ref(&c), &d, 365)
        .await
        .unwrap();

    assert_eq!(root_version(&fixture.metadata(), "root.json").await, 3);
    let repo = fixture.load_pinned_to_v1().await;
    assert_eq!(
        repo.root().signed.version.get(),
        3,
        "a client that only trusts the first root follows two rotations"
    );
}

#[tokio::test]
async fn releases_signed_before_a_rotation_still_verify_after_it() {
    let fixture = Fixture::new("survive").await;
    let target = fixture.publish_app("1.0.0").await;

    let successor = fixture.mint_key("root.new.pk8").await;
    repo::rotate_root(&fixture.repo_dir, &fixture.keys.roots[1..], &successor, 365)
        .await
        .unwrap();

    let repo = fixture.load_pinned_to_v1().await;
    assert_eq!(repo.root().signed.version.get(), 2);
    assert!(
        has_target(&repo, &target),
        "the pre-rotation release remains verifiable under the rotated root"
    );
}

#[tokio::test]
async fn releases_signed_after_a_rotation_verify_for_a_client_on_the_old_root() {
    let fixture = Fixture::new("post").await;

    let successor = fixture.mint_key("root.new.pk8").await;
    repo::rotate_root(&fixture.repo_dir, &fixture.keys.roots[1..], &successor, 365)
        .await
        .unwrap();
    // Online keys are unchanged by rotation, so a normal release still publishes.
    let target = fixture.publish_app("2.0.0").await;

    let repo = fixture.load_pinned_to_v1().await;
    assert_eq!(repo.root().signed.version.get(), 2);
    assert!(
        has_target(&repo, &target),
        "a post-rotation release verifies for a client that only trusted the original root"
    );
}

#[tokio::test]
async fn a_retained_key_absent_from_the_current_root_is_rejected() {
    let fixture = Fixture::new("stranger").await;
    let stranger = fixture.mint_key("stranger.pk8").await;
    let successor = fixture.mint_key("successor.pk8").await;

    let error = repo::rotate_root(
        &fixture.repo_dir,
        std::slice::from_ref(&stranger),
        &successor,
        365,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("not in the current root"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn reusing_an_existing_root_key_as_the_successor_is_rejected() {
    let fixture = Fixture::new("reuse").await;
    // The active key (roots[0]) is already in the root; it cannot be the "new" key.
    let error = repo::rotate_root(
        &fixture.repo_dir,
        &fixture.keys.roots[1..],
        &fixture.keys.roots[0],
        365,
    )
    .await
    .unwrap_err()
    .to_string();
    assert!(
        error.contains("already belongs"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn a_retired_key_can_no_longer_authorize_the_next_rotation() {
    let fixture = Fixture::new("retired").await;
    // Rotation retires roots[0].
    let successor = fixture.mint_key("root.new.pk8").await;
    repo::rotate_root(&fixture.repo_dir, &fixture.keys.roots[1..], &successor, 365)
        .await
        .unwrap();

    // Attempting to authorize the next rotation with the retired key must fail closed.
    let next = fixture.mint_key("next.pk8").await;
    let error = repo::rotate_root(&fixture.repo_dir, &fixture.keys.roots[..1], &next, 365)
        .await
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("not in the current root"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn rotation_requires_a_continuity_key() {
    let fixture = Fixture::new("empty").await;
    let successor = fixture.mint_key("root.new.pk8").await;
    let error = repo::rotate_root(&fixture.repo_dir, &[], &successor, 365)
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("continuity"), "unexpected error: {error}");
}
