#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! CI package validation and publication. This binary never reads or patches Kubernetes resources.
//! Operators select the returned immutable package reference through deployment YAML.

use std::path::{Path, PathBuf};
use std::sync::Arc;

mod cli;
mod package;
mod package_check;
mod publish;
mod repository;

use cli::*;
use publish::*;
use repository::*;

use clap::{Args, Parser, Subcommand, ValueEnum};
use object_store::ObjectStore;
use updatec::S3Destination;
use updated_tuf::repo::{self, PublishTarget};

type Error = Box<dyn std::error::Error>;

pub(crate) fn main() -> std::process::ExitCode {
    // Private subprocess entrypoints used by the CI conformance harness.
    if let Some(code) = updated::command_adapter::dispatch() {
        return code;
    }
    if let Some(code) = updated::helper::dispatch() {
        return code;
    }
    run_main()
}

#[tokio::main]
async fn run_main() -> std::process::ExitCode {
    // Publication uses the workspace TLS provider.
    updated::tls::install_crypto_provider();
    let result = match Cli::parse().command {
        Command::Publish(args) => publish(*args).await,
        Command::Check(args) => package::check(*args),
        // Local and synchronous: it drives child processes against a scratch directory and touches
        // no repository at all.
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("updatectl: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use object_store::memory::InMemory;
    use object_store::ObjectStoreExt as _;
    use updated_tuf::repo;

    fn scratch(label: &str) -> (tempfile::TempDir, PathBuf) {
        let guard = tempfile::tempdir().unwrap();
        let dir = guard.path().join(label);
        std::fs::create_dir_all(&dir).unwrap();
        (guard, dir)
    }

    fn destination(prefix: &str) -> S3Destination {
        S3Destination {
            bucket: "releases".into(),
            prefix: prefix.into(),
            region: "us-east-1".into(),
            credentials_secret_ref: None,
            endpoint: None,
            public_endpoint: None,
        }
    }

    #[tokio::test]
    async fn consecutive_metadata_only_publishes_retain_remote_target_bytes() {
        let (_tmp, root) = scratch("metadata-only-publishes");
        let keys = repo::generate_keys(&root.join("keys")).await.unwrap();
        let origin = root.join("origin");
        repo::init(&origin, &keys, 365).await.unwrap();
        let store = InMemory::new();
        let dest = destination("releases/app");
        updatec::runtime::publish_repository(&store, &dest, &origin)
            .await
            .unwrap();

        let first_source = root.join("first.tar.zst");
        tokio::fs::write(&first_source, b"first").await.unwrap();
        let first = PublishTarget::application(
            "app",
            "stable",
            "1.0.0",
            "linux",
            "x86_64",
            "app",
            first_source,
        );
        let first_name = first.name.clone();
        let checkout = checkout_metadata(&store, &dest).await.unwrap();
        repo::add_release(checkout.path(), &keys, vec![first], 365)
            .await
            .unwrap();
        checkout.publish(&store, &dest, &keys, 365).await.unwrap();
        let first_digest = repo::target_sha256(checkout.path(), &first_name)
            .await
            .unwrap();

        let second_source = root.join("second.tar.zst");
        tokio::fs::write(&second_source, b"second").await.unwrap();
        let second = PublishTarget::application(
            "provider",
            "stable",
            "1.0.0",
            "linux",
            "x86_64",
            "provider",
            second_source,
        );
        let second_name = second.name.clone();
        let checkout = checkout_metadata(&store, &dest).await.unwrap();
        assert!(
            std::fs::read_dir(checkout.path().join("targets"))
                .unwrap()
                .next()
                .is_none(),
            "a metadata checkout must not download old target bodies"
        );
        repo::add_release(checkout.path(), &keys, vec![second], 365)
            .await
            .unwrap();
        checkout.publish(&store, &dest, &keys, 365).await.unwrap();
        let second_digest = repo::target_sha256(checkout.path(), &second_name)
            .await
            .unwrap();

        for (name, digest) in [(first_name, first_digest), (second_name, second_digest)] {
            let key = updatec::object_key(&dest.prefix, &format!("targets/{digest}.{name}"));
            store
                .head(&key)
                .await
                .unwrap_or_else(|error| panic!("retained target {key} is absent: {error}"));
        }
    }

    #[tokio::test]
    async fn a_missing_or_wrong_sized_retained_target_aborts_before_any_publication_write() {
        let (_tmp, root) = scratch("missing-retained-target");
        let keys = repo::generate_keys(&root.join("keys")).await.unwrap();
        let origin = root.join("origin");
        repo::init(&origin, &keys, 365).await.unwrap();
        let store = InMemory::new();
        let dest = destination("releases/app");
        updatec::runtime::publish_repository(&store, &dest, &origin)
            .await
            .unwrap();

        let first_source = root.join("first.tar.zst");
        tokio::fs::write(&first_source, b"first").await.unwrap();
        let first = PublishTarget::application(
            "app",
            "stable",
            "1.0.0",
            "linux",
            "x86_64",
            "app",
            first_source,
        );
        let first_name = first.name.clone();
        let checkout = checkout_metadata(&store, &dest).await.unwrap();
        repo::add_release(checkout.path(), &keys, vec![first], 365)
            .await
            .unwrap();
        checkout.publish(&store, &dest, &keys, 365).await.unwrap();
        let first_digest = repo::target_sha256(checkout.path(), &first_name)
            .await
            .unwrap();
        let first_key = updatec::object_key(
            &dest.prefix,
            &format!("targets/{first_digest}.{first_name}"),
        );
        store.delete(&first_key).await.unwrap();
        let generation = MetadataGeneration::live(&store, &dest).await.unwrap();

        let second_source = root.join("second.tar.zst");
        tokio::fs::write(&second_source, b"second").await.unwrap();
        let second = PublishTarget::application(
            "provider",
            "stable",
            "1.0.0",
            "linux",
            "x86_64",
            "provider",
            second_source,
        );
        let second_name = second.name.clone();
        let checkout = checkout_metadata(&store, &dest).await.unwrap();
        repo::add_release(checkout.path(), &keys, vec![second], 365)
            .await
            .unwrap();
        let second_digest = repo::target_sha256(checkout.path(), &second_name)
            .await
            .unwrap();
        let second_key = updatec::object_key(
            &dest.prefix,
            &format!("targets/{second_digest}.{second_name}"),
        );

        let error = checkout
            .publish(&store, &dest, &keys, 365)
            .await
            .expect_err("metadata must never commit over a missing retained target")
            .to_string();
        assert!(error.contains("retained target"), "{error}");
        assert!(
            store.head(&second_key).await.is_err(),
            "new bytes were written"
        );
        assert_eq!(
            MetadataGeneration::live(&store, &dest).await.unwrap(),
            generation,
            "metadata advanced despite the missing retained target"
        );

        store
            .put(
                &first_key,
                object_store::PutPayload::from_bytes(b"wrong-size".to_vec().into()),
            )
            .await
            .unwrap();
        let error = checkout
            .publish(&store, &dest, &keys, 365)
            .await
            .expect_err("metadata must never commit over a wrong-sized retained target")
            .to_string();
        assert!(error.contains("signed length"), "{error}");
        assert!(
            store.head(&second_key).await.is_err(),
            "new bytes were written after the retained-target size check failed"
        );
        assert_eq!(
            MetadataGeneration::live(&store, &dest).await.unwrap(),
            generation,
            "metadata advanced despite the wrong-sized retained target"
        );
    }

    /// A shared bucket is not a trusted local directory. Only the active TUF closure is an input
    /// to a new signature; unrelated objects and nested keys must neither be flattened into the
    /// checkout nor uploaded again by the next publish.
    #[tokio::test]
    async fn metadata_checkout_ignores_objects_outside_the_active_tuf_closure() {
        let (_tmp, root) = scratch("metadata-closure");
        let keys = repo::generate_keys(&root.join("keys")).await.unwrap();
        let origin = root.join("origin");
        repo::init(&origin, &keys, 365).await.unwrap();

        let store = InMemory::new();
        let dest = destination("releases/app");
        updatec::runtime::publish_repository(&store, &dest, &origin)
            .await
            .unwrap();
        let generation = MetadataGeneration::live(&store, &dest).await.unwrap();
        for relative in [
            "metadata/junk.json",
            "metadata/nested/root.json",
            "metadata/999999.root.json",
            "metadata/999999.timestamp.json",
            "metadata/nested/999999.targets.json",
        ] {
            let key = updatec::object_key(&dest.prefix, relative);
            store
                .put(
                    &key,
                    object_store::PutPayload::from_bytes(b"untrusted".to_vec().into()),
                )
                .await
                .unwrap();
        }

        let checkout = checkout_metadata(&store, &dest).await.unwrap();
        assert_eq!(
            checkout.generation, generation,
            "unreferenced objects changed the active generation"
        );
        let mirror = checkout.path().join("metadata");
        let mut names = std::fs::read_dir(&mirror)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        names.sort();
        assert_eq!(
            names,
            [
                "1.root.json",
                "1.snapshot.json",
                "1.targets.json",
                "root.json",
                "timestamp.json",
            ]
        );
    }

    #[tokio::test]
    async fn replacing_pointer_bytes_without_bumping_a_version_invalidates_checkout() {
        let (_tmp, root) = scratch("pointer-replacement");
        let keys = repo::generate_keys(&root.join("keys")).await.unwrap();
        let origin = root.join("origin");
        repo::init(&origin, &keys, 365).await.unwrap();
        let store = InMemory::new();
        let dest = destination("releases/app");
        updatec::runtime::publish_repository(&store, &dest, &origin)
            .await
            .unwrap();
        let checkout = checkout_metadata(&store, &dest).await.unwrap();

        for document in ["root.json", "timestamp.json"] {
            let key = updatec::object_key(&dest.prefix, &format!("metadata/{document}"));
            let original = store.get(&key).await.unwrap().bytes().await.unwrap();
            let mut replaced = original.to_vec();
            replaced.push(b'\n');
            assert_eq!(
                signed_metadata_version(&original, document).unwrap(),
                signed_metadata_version(&replaced, document).unwrap()
            );
            store
                .put(
                    &key,
                    object_store::PutPayload::from_bytes(replaced.clone().into()),
                )
                .await
                .unwrap();

            let error = checkout
                .publish(&store, &dest, &keys, 365)
                .await
                .expect_err("changed pointer bytes must invalidate the checkout")
                .to_string();
            assert!(
                error.contains(document) && error.contains("another publisher"),
                "{error}"
            );
            assert_eq!(
                store
                    .get(&key)
                    .await
                    .unwrap()
                    .bytes()
                    .await
                    .unwrap()
                    .as_ref(),
                replaced
            );
            store
                .put(&key, object_store::PutPayload::from_bytes(original))
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn a_fresh_ci_run_can_publish_after_an_abandoned_metadata_upload() {
        let (_tmp, root) = scratch("interrupted-publication");
        let keys = repo::generate_keys(&root.join("keys")).await.unwrap();
        let origin = root.join("origin");
        repo::init(&origin, &keys, 365).await.unwrap();
        let store = InMemory::new();
        let dest = destination("releases/app");
        updatec::runtime::publish_repository(&store, &dest, &origin)
            .await
            .unwrap();
        let abandoned = checkout_metadata(&store, &dest).await.unwrap();
        let artifact = root.join("app");
        std::fs::write(&artifact, b"abandoned build").unwrap();
        let target = |source| {
            PublishTarget::application("app", "stable", "1.0.0", "linux", "x86_64", "app", source)
        };
        repo::add_release(abandoned.path(), &keys, vec![target(artifact.clone())], 365)
            .await
            .unwrap();
        // The old CI process uploaded an immutable role and died before committing timestamp.
        let occupied_key = updatec::object_key(&dest.prefix, "metadata/2.targets.json");
        let occupied = std::fs::read(abandoned.path().join("metadata/2.targets.json")).unwrap();
        store
            .put(
                &occupied_key,
                object_store::PutPayload::from_bytes(occupied.clone().into()),
            )
            .await
            .unwrap();
        drop(abandoned);

        let fresh = checkout_metadata(&store, &dest).await.unwrap();
        std::fs::write(&artifact, b"successful build").unwrap();
        let release = target(artifact);
        let target_name = release.name.clone();
        repo::add_release(fresh.path(), &keys, vec![release], 365)
            .await
            .unwrap();
        let expected_sha = repo::target_sha256(fresh.path(), &target_name)
            .await
            .unwrap();
        fresh
            .publish(&store, &dest, &keys, 365)
            .await
            .expect("an abandoned immutable version must not wedge future CI runs");

        let verified = checkout_metadata(&store, &dest).await.unwrap();
        assert_eq!(
            repo::target_sha256(verified.path(), &target_name)
                .await
                .unwrap(),
            expected_sha
        );
        assert_eq!(
            store
                .get(&occupied_key)
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap()
                .as_ref(),
            occupied
        );
    }

    #[tokio::test]
    async fn occupied_metadata_cannot_cause_unbounded_signing_or_advance_the_commit() {
        let (_tmp, root) = scratch("occupied-generations");
        let keys = repo::generate_keys(&root.join("keys")).await.unwrap();
        let origin = root.join("origin");
        repo::init(&origin, &keys, 365).await.unwrap();
        let store = InMemory::new();
        let dest = destination("releases/app");
        updatec::runtime::publish_repository(&store, &dest, &origin)
            .await
            .unwrap();
        for version in 2..=100 {
            let key =
                updatec::object_key(&dest.prefix, &format!("metadata/{version}.targets.json"));
            store
                .put(
                    &key,
                    object_store::PutPayload::from_bytes(b"occupied".to_vec().into()),
                )
                .await
                .unwrap();
        }
        let checkout = checkout_metadata(&store, &dest).await.unwrap();
        repo::add_release(checkout.path(), &keys, vec![], 365)
            .await
            .unwrap();
        let error = checkout
            .publish(&store, &dest, &keys, 365)
            .await
            .expect_err("persistent collisions must stop");
        assert!(
            matches!(
                error.downcast_ref::<updatec::runtime::StorageError>(),
                Some(updatec::runtime::StorageError::OnlineMetadataConflict(_))
            ),
            "{error}"
        );
        assert_eq!(
            MetadataGeneration::live(&store, &dest).await.unwrap(),
            checkout.generation
        );
    }

    #[tokio::test]
    async fn metadata_checkout_uses_the_shared_object_size_bound() {
        let store = InMemory::new();
        let dest = destination("releases/app");
        let root = updatec::object_key(&dest.prefix, "metadata/root.json");
        store
            .put(
                &root,
                object_store::PutPayload::from_bytes(
                    vec![0; updatec::OBJECT_BYTES_LIMIT as usize + 1].into(),
                ),
            )
            .await
            .unwrap();
        let mirror = tempfile::tempdir().unwrap();

        let error = download_metadata(&store, &dest, mirror.path())
            .await
            .expect_err("oversized metadata must be refused before collection")
            .to_string();
        assert!(error.contains("over the 8388608-byte limit"), "{error}");
    }

    /// Publishing is read-modify-write over shared signed metadata: two publishers against one
    /// prefix each sign a generation N+1 that omits the other's targets, and the last upload wins
    /// — silently erasing a target that a freshly patched UpdateGroup already points at. A
    /// checkout must refuse to publish over a generation it never saw, uploading nothing.
    #[tokio::test]
    async fn a_republish_refuses_a_generation_it_did_not_check_out() {
        let (_tmp, root) = scratch("concurrent");
        let keys = repo::generate_keys(&root.join("keys")).await.unwrap();
        let origin = root.join("origin");
        repo::init(&origin, &keys, 365).await.unwrap();

        let store = InMemory::new();
        let dest = destination("releases/app");
        updatec::runtime::publish_repository(&store, &dest, &origin)
            .await
            .unwrap();

        // Both publishers check out the same generation, as two CI jobs would.
        let ours = checkout_metadata(&store, &dest).await.unwrap();
        let theirs = checkout_metadata(&store, &dest).await.unwrap();
        assert_eq!(
            ours.generation,
            MetadataGeneration::live(&store, &dest).await.unwrap()
        );

        // The other publisher commits while we are still building and signing.
        let file = root.join("theirs.json");
        tokio::fs::write(&file, b"{}").await.unwrap();
        repo::add_release(
            theirs.path(),
            &keys,
            vec![PublishTarget {
                name: "products/theirs/stable/1.0.0/linux-x86_64/theirs".into(),
                source: file,
                custom: Default::default(),
            }],
            365,
        )
        .await
        .unwrap();
        theirs.publish(&store, &dest, &keys, 365).await.unwrap();
        let published = MetadataGeneration::live(&store, &dest).await.unwrap();
        assert_ne!(published, ours.generation);

        let error = ours
            .publish(&store, &dest, &keys, 365)
            .await
            .expect_err("a stale checkout must not overwrite the live generation")
            .to_string();
        assert!(error.contains("another publisher"), "{error}");

        // The other publisher's generation is intact: nothing was uploaded over it.
        assert_eq!(
            MetadataGeneration::live(&store, &dest).await.unwrap(),
            published
        );
        let mirror = root.join("mirror");
        tokio::fs::create_dir_all(&mirror).await.unwrap();
        download_metadata(&store, &dest, &mirror).await.unwrap();
        let timestamp = tokio::fs::read(mirror.join("timestamp.json"))
            .await
            .unwrap();
        let snapshot_version =
            referenced_metadata_version(&timestamp, "timestamp.json", "snapshot.json").unwrap();
        let snapshot = tokio::fs::read(mirror.join(format!("{snapshot_version}.snapshot.json")))
            .await
            .unwrap();
        let targets_version =
            referenced_metadata_version(&snapshot, "snapshot.json", "targets.json").unwrap();
        let targets =
            tokio::fs::read_to_string(mirror.join(format!("{targets_version}.targets.json")))
                .await
                .unwrap();
        assert!(
            targets.contains("products/theirs/stable/1.0.0/linux-x86_64/theirs"),
            "the concurrent publisher's signed target survived"
        );
    }

    /// The concurrent-publish guard must survive a root rotation. A rotation bumps root and
    /// nothing else, so any measure that collapses the roles into one maximum is parked above the
    /// timestamp — and every publish after it looks unchanged, letting a stale checkout overwrite
    /// a concurrent publisher's signed targets exactly as if there were no guard at all.
    #[tokio::test]
    async fn a_root_rotation_does_not_blind_the_concurrent_publish_guard() {
        let (_tmp, root) = scratch("rotated-generation");
        let keys = repo::generate_keys(&root.join("keys")).await.unwrap();
        let origin = root.join("origin");
        repo::init(&origin, &keys, 365).await.unwrap();

        // Rotate the root once: root reaches version 2 while timestamp stays at 1.
        let successor = root.join("successor.pk8");
        repo::generate_root_key(&successor).await.unwrap();
        repo::rotate_root(&origin, &keys.roots[1..], &successor, 365)
            .await
            .unwrap();

        let store = InMemory::new();
        let dest = destination("releases/app");
        updatec::runtime::publish_repository(&store, &dest, &origin)
            .await
            .unwrap();

        let ours = checkout_metadata(&store, &dest).await.unwrap();
        let theirs = checkout_metadata(&store, &dest).await.unwrap();
        let file = root.join("theirs.json");
        tokio::fs::write(&file, b"{}").await.unwrap();
        repo::add_release(
            theirs.path(),
            &keys,
            vec![PublishTarget {
                name: "products/theirs/stable/1.0.0/linux-x86_64/theirs".into(),
                source: file,
                custom: Default::default(),
            }],
            365,
        )
        .await
        .unwrap();
        theirs.publish(&store, &dest, &keys, 365).await.unwrap();

        let error = ours
            .publish(&store, &dest, &keys, 365)
            .await
            .expect_err("a stale checkout must abort even when root outranks timestamp")
            .to_string();
        assert!(error.contains("timestamp.json"), "{error}");
        assert!(error.contains("another publisher"), "{error}");

        // The concurrent publisher's target is still the one in verified metadata.
        let mirror = root.join("mirror");
        tokio::fs::create_dir_all(&mirror).await.unwrap();
        download_metadata(&store, &dest, &mirror).await.unwrap();
        // Under consistent_snapshot the targets role lives only at its versioned name.
        let mut survived = false;
        for entry in std::fs::read_dir(&mirror).unwrap() {
            let path = entry.unwrap().path();
            if path.to_string_lossy().ends_with(".targets.json") {
                survived |= std::fs::read_to_string(&path)
                    .unwrap()
                    .contains("products/theirs/stable/1.0.0/linux-x86_64/theirs");
            }
        }
        assert!(
            survived,
            "the concurrent publisher's signed target survived"
        );
    }

    #[tokio::test]
    async fn publication_requires_the_online_keys_but_not_the_root_keys() {
        let (_tmp, dir) = scratch("keys");
        for key in ["targets.pk8", "snapshot.pk8", "timestamp.pk8"] {
            std::fs::write(dir.join(key), b"x").unwrap();
        }
        // No root.pk8 present: publication's key resolution must still succeed.
        assert!(open_keys(&dir).is_ok());
        std::fs::remove_file(dir.join("targets.pk8")).unwrap();
        assert!(open_keys(&dir).is_err(), "a missing online key is rejected");
    }

    /// Author a repo, publish it to an in-memory store, then exercise publication
    /// across a root rotation and prove a client pinned to the original root
    /// follows the rotation — exercising `MetadataGeneration::live`, `download_metadata`, prefix
    /// handling, and `publish_repository` exactly as the binary uses them.
    #[tokio::test]
    async fn s3_round_trip_publishes_downloads_and_rotates() {
        let (_tmp, root) = scratch("s3");
        let keys = repo::generate_keys(&root.join("keys")).await.unwrap();
        let origin = root.join("origin");
        repo::init(&origin, &keys, 365).await.unwrap();

        let store = InMemory::new();
        let dest = destination("releases/app");

        updatec::runtime::publish_repository(&store, &dest, &origin)
            .await
            .unwrap();
        // Pull the metadata back down through the one production checkout path.
        let checkout = checkout_metadata(&store, &dest).await.unwrap();
        let pinned = tokio::fs::read(checkout.path().join("metadata/1.root.json"))
            .await
            .unwrap();

        // Rotate against the downloaded copy, then re-publish it.
        let successor = root.join("successor.pk8");
        repo::generate_root_key(&successor).await.unwrap();
        repo::rotate_root(checkout.path(), &keys.roots[1..], &successor, 365)
            .await
            .unwrap();
        checkout.publish(&store, &dest, &keys, 365).await.unwrap();

        // Download once more into a clean checkout and verify through the real client.
        let mirror = checkout_metadata(&store, &dest).await.unwrap();
        let mirror_metadata = mirror.path().join("metadata");

        let metadata_url =
            url::Url::from_directory_path(std::fs::canonicalize(&mirror_metadata).unwrap())
                .unwrap();
        let targets_url = url::Url::from_directory_path(
            std::fs::canonicalize(mirror.path().join("targets")).unwrap(),
        )
        .unwrap();
        let repo = tough::RepositoryLoader::new(&pinned, metadata_url, targets_url)
            .transport(tough::FilesystemTransport)
            .expiration_enforcement(tough::ExpirationEnforcement::Safe)
            .load()
            .await
            .expect("client pinned to the original root loads the round-tripped repository");
        assert_eq!(
            repo.root().signed.version.get(),
            2,
            "the rotation survived the S3 publish/download round-trip"
        );
    }
}
