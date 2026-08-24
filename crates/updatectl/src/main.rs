//! `updatectl` — the CI-facing publisher for `updated`.
//!
//! No `kubectl` and no secret-management code of its own:
//!
//! * `trust-root` mints a fresh TUF trust root — a one-time bootstrap, and the *only* command
//!   that mints a role key set. It generates the ed25519 role keys into an empty directory
//!   (which the operator then loads into Vault) and refuses one that already holds a role key,
//!   so a new root never inherits an old key; it initializes the empty release repository in
//!   S3, and prints the `root.json` that every group pins in its
//!   `release_repository.root_json`. Keys are staged and only land in `--keys-dir` once the
//!   repository is published, so an attempt that fails partway is retried by the identical
//!   re-run — which also sweeps the staging directory a killed run left behind. It needs no
//!   Kubernetes access at all.
//!
//! * `deploy` is the per-release command. It reads the role keys from a directory — in
//!   production a Vault-backed Secret projected into the pod as a read-only file mount —
//!   builds the canonical deterministic `tar.zst` bundle, signs and publishes it as a TUF
//!   target into the S3 repository, then patches the named `UpdateGroup` to reference the
//!   new target. It touches Kubernetes only to patch that one resource.
//!
//! * `reconciler-check` is the pre-publication conformance harness for the one cross-organization
//!   surface in the system: it runs a release's own node reconciler against a scratch install root
//!   through the published argv grammar and checks the properties the agent cannot enforce —
//!   replay tolerance, observation purity, fingerprint stability, and the two refusals. It touches
//!   no repository, no keys, and no Kubernetes.
//!
//! * `node-public-key` derives the canonical inventory pin from a manually provisioned P-256 key.
//!   It reuses the online enrollment parser, so offline and online identity have one encoding.
//!
//! Keys are always just a directory of `root.pk8`, `targets.pk8`, `snapshot.pk8`, and
//! `timestamp.pk8`. Delivery (Vault → Secret → mount) is the platform's job; `updatectl`
//! stays out of the secret business. It only ever *mints and signs* — it never verifies;
//! signature verification is entirely the node's job, gated by the group's configuration.
//!
//! Everything reuses the operator's own libraries (`updated::bundle`, `updated_tuf::repo`,
//! `updatec`), so a CI publish and an operator republish agree on one bundle format, one
//! TUF layout, and one S3 object layout — there is no second code path to drift.
//!
//! Linux only: bundles carry Unix executable bits and the default platform is the host's
//! `linux-<arch>`. Every flag also reads a `UPDATECTL_*` environment variable, and AWS
//! credentials come from the standard environment, so a pipeline can inject everything
//! without assembling a command line.

use std::path::{Path, PathBuf};
use std::sync::Arc;

mod cli;
mod deploy;
mod keys;
mod publish;
mod reconciler_check;
mod repository;
mod root;

use cli::*;
use deploy::*;
use keys::*;
use publish::*;
use repository::*;
use root::*;

use clap::{Args, Parser, Subcommand, ValueEnum};
use futures::StreamExt;
use kube::api::{Api, Patch, PatchParams};
use kube::Client;
use object_store::ObjectStore;
use updatec::{S3Destination, UpdateGroup};
use updated_tuf::repo::{self, PublishTarget};

type Error = Box<dyn std::error::Error>;

/// Every role-key file a trust root is built from, standing in `dir`: the active root, its standby
/// successor, and the three online roles.
///
/// The names come from [`repo::Keys`] rather than a list of this tool's own. `repo::generate_keys`
/// mints exactly the key set `Keys::in_dir` reads, and this tool renames that set out of its
/// staging directory — a second copy of the list here would silently strand a key the library
/// started minting, in the one place that reports the bootstrap as having succeeded. `Keys::in_dir`
/// names the standby successor only where one is present, so over a freshly minted staging
/// directory this is the full set, and over `--keys-dir` it is exactly the role keys standing there.
fn role_key_names(dir: &Path) -> Result<Vec<String>, Error> {
    let keys = repo::Keys::in_dir(dir)?;
    Ok(keys
        .roots
        .iter()
        .chain([&keys.targets, &keys.snapshot, &keys.timestamp])
        .filter_map(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .collect())
}

#[tokio::main]
pub(crate) async fn main() -> std::process::ExitCode {
    // The kube client and S3 store both drive rustls; install the workspace's one provider.
    updated::tls::install_crypto_provider();
    let result = match Cli::parse().command {
        Command::TrustRoot(args) => trust_root(args).await,
        Command::RotateRoot(args) => rotate_root(args).await,
        Command::Deploy(args) => deploy(args).await,
        Command::PublishProviderArtifact(args) => publish_provider_artifact(args).await,
        Command::PublishProviderSet(args) => publish_provider_set(args).await,
        Command::NodePublicKey(args) => print_node_public_key(args),
        // Local and synchronous: it drives child processes against a scratch directory and touches
        // no repository at all.
        Command::ReconcilerCheck(args) => reconciler_check::reconciler_check(args),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("updatectl: {error}");
            std::process::ExitCode::FAILURE
        }
    }
}

pub(crate) fn print_node_public_key(args: NodePublicKeyArgs) -> Result<(), Error> {
    println!("{}", node_public_key(&args.key)?);
    Ok(())
}

/// Derive the exact public-key encoding online enrollment extracts from a CSR. Reusing that parser
/// keeps manual inventory on the same canonical P-256 path rather than introducing another key
/// parser or encoding convention.
pub(crate) fn node_public_key(path: &Path) -> Result<String, Error> {
    let key = updated::tls::read_private_key_pem(path, foundation::file::FinalSymlink::Follow)?;
    let csr = updated::csr::csr_for(&key, "manual identity")?;
    Ok(updatec::join::csr_public_key(&csr)?.to_hex())
}

#[cfg(test)]
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

    /// The same backend the CLI flags produce. `checkout_metadata` reads it only to name the
    /// repository in its diagnostics.
    fn backend(prefix: &str) -> Backend {
        Backend {
            keys_dir: PathBuf::new(),
            bucket: "releases".into(),
            region: "us-east-1".into(),
            prefix: prefix.into(),
            endpoint: None,
        }
    }

    fn provider_set_args() -> ProviderSetArgs {
        ProviderSetArgs {
            backend: backend("releases/app"),
            id: "web-linux-v4".into(),
            provider_path: "providers/lifecycle/1.0.0/linux-x86_64/lifecycle".into(),
            provider_sha256: "a".repeat(64),
            provider_arg: Vec::new(),
            provider_timeout_ms: 300_000,
            expiry_days: 365,
        }
    }

    #[test]
    fn manual_node_pin_uses_the_online_enrollment_encoding() {
        let (guard, dir) = scratch("node-key");
        let path = dir.join("agent.key");
        let key = updated::csr::generate_key().unwrap();
        std::fs::write(&path, &key).unwrap();

        let csr = updated::csr::csr_for(&key, "online enrollment").unwrap();
        let expected = updatec::join::csr_public_key(&csr).unwrap().to_hex();
        assert_eq!(node_public_key(&path).unwrap(), expected);
        drop(guard);
    }

    /// A published provider set is an immutable signed target. Every flag combination the agent's
    /// own `validate` rejects must be refused here, before signing — a set that no node can accept
    /// cannot be repaired, only superseded under a new id.
    #[test]
    fn a_provider_set_is_held_to_the_agents_validation_before_it_is_signed() {
        let set = provider_set(&provider_set_args()).unwrap();
        assert_eq!(
            set.reconciler.artifact.sha256,
            "a".repeat(64),
            "the canonical digest is preserved exactly"
        );

        let cases = [
            ("timeout", {
                let mut args = provider_set_args();
                args.provider_timeout_ms = 0;
                args
            }),
            ("id", {
                let mut args = provider_set_args();
                args.id = "web linux".into();
                args
            }),
            ("artifact reference", {
                let mut args = provider_set_args();
                args.provider_path = "../escape".into();
                args
            }),
            ("artifact reference", {
                let mut args = provider_set_args();
                args.provider_sha256 = "not-a-digest".into();
                args
            }),
            ("artifact reference", {
                let mut args = provider_set_args();
                args.provider_sha256 = "A".repeat(64);
                args
            }),
            ("arguments", {
                let mut args = provider_set_args();
                args.provider_arg = vec!["--flag".into(); 257];
                args
            }),
        ];
        for (expected, args) in cases {
            let error = provider_set(&args)
                .err()
                .unwrap_or_else(|| panic!("{expected}: expected a rejection"))
                .to_string();
            assert!(error.contains(expected), "{error}");
            assert!(
                error.contains("nothing was signed"),
                "the operator is told the repository is untouched: {error}"
            );
        }
    }

    /// A published provider set is immutable, and its reconciler reference is only ever resolved
    /// much later, on a node, by `stage_providers` — where a well-formed but unresolvable reference
    /// (a stale digest paired with a fresh path) stalls the whole group with nothing to correct in
    /// place. It must be resolved against the signed metadata in hand, before anything is signed.
    #[tokio::test]
    async fn a_provider_set_resolves_its_reconciler_against_the_signed_metadata_before_signing() {
        let (_tmp, root) = scratch("provider-set-resolve");
        let keys = repo::generate_keys(&root.join("keys")).await.unwrap();
        let origin = root.join("origin");
        repo::init(&origin, &keys, 365).await.unwrap();
        let store = InMemory::new();
        let dest = destination("releases/app");
        let backend = backend("releases/app");
        updatec::runtime::publish_repository(&store, &dest, &origin)
            .await
            .unwrap();

        // The reconciler artifact the operator published first.
        let artifact = root.join("lifecycle.tar.zst");
        tokio::fs::write(&artifact, b"reconciler").await.unwrap();
        let target = PublishTarget::application(
            "lifecycle",
            "stable",
            "1.0.0",
            "linux",
            "x86_64",
            "lifecycle",
            artifact,
        );
        let path = target.name.clone();
        let checkout = checkout_metadata(&store, &dest, &backend).await.unwrap();
        repo::add_release(checkout.path(), &keys, vec![target], 365)
            .await
            .unwrap();
        checkout.publish(&store, &dest).await.unwrap();
        let sha256 = repo::target_sha256(checkout.path(), &path).await.unwrap();

        let checkout = checkout_metadata(&store, &dest, &backend).await.unwrap();
        let mut args = provider_set_args();
        args.provider_path = path.clone();

        // The stale copy-paste: the right path, a previous build's digest.
        let error =
            repo::verify_provider_set_reconciler(checkout.path(), &provider_set(&args).unwrap())
                .await
                .expect_err("a digest that names a different build is refused at publish time")
                .to_string();
        assert!(error.contains(&sha256), "{error}");
        assert!(error.contains("Nothing was signed"), "{error}");

        // A path no signed target carries at all.
        args.provider_sha256 = sha256.clone();
        args.provider_path = path.replace("1.0.0", "9.9.9");
        let error =
            repo::verify_provider_set_reconciler(checkout.path(), &provider_set(&args).unwrap())
                .await
                .expect_err("an unresolvable path is refused at publish time")
                .to_string();
        assert!(error.contains("does not resolve"), "{error}");

        // The reference the artifact publish actually printed.
        args.provider_path = path.clone();
        repo::verify_provider_set_reconciler(checkout.path(), &provider_set(&args).unwrap())
            .await
            .expect("the published reconciler resolves");
    }

    #[tokio::test]
    async fn consecutive_metadata_only_publishes_retain_remote_target_bytes() {
        let (_tmp, root) = scratch("metadata-only-publishes");
        let keys = repo::generate_keys(&root.join("keys")).await.unwrap();
        let origin = root.join("origin");
        repo::init(&origin, &keys, 365).await.unwrap();
        let store = InMemory::new();
        let dest = destination("releases/app");
        let backend = backend("releases/app");
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
        let checkout = checkout_metadata(&store, &dest, &backend).await.unwrap();
        repo::add_release(checkout.path(), &keys, vec![first], 365)
            .await
            .unwrap();
        checkout.publish(&store, &dest).await.unwrap();
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
        let checkout = checkout_metadata(&store, &dest, &backend).await.unwrap();
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
        checkout.publish(&store, &dest).await.unwrap();
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
        let backend = backend("releases/app");
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
        let checkout = checkout_metadata(&store, &dest, &backend).await.unwrap();
        repo::add_release(checkout.path(), &keys, vec![first], 365)
            .await
            .unwrap();
        checkout.publish(&store, &dest).await.unwrap();
        let first_digest = repo::target_sha256(checkout.path(), &first_name)
            .await
            .unwrap();
        let first_key = updatec::object_key(
            &dest.prefix,
            &format!("targets/{first_digest}.{first_name}"),
        );
        store.delete(&first_key).await.unwrap();
        let generation = RoleVersions::live(&store, &dest).await.unwrap();

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
        let checkout = checkout_metadata(&store, &dest, &backend).await.unwrap();
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
            .publish(&store, &dest)
            .await
            .expect_err("metadata must never commit over a missing retained target")
            .to_string();
        assert!(error.contains("retained target"), "{error}");
        assert!(
            store.head(&second_key).await.is_err(),
            "new bytes were written"
        );
        assert_eq!(
            RoleVersions::live(&store, &dest).await.unwrap(),
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
            .publish(&store, &dest)
            .await
            .expect_err("metadata must never commit over a wrong-sized retained target")
            .to_string();
        assert!(error.contains("signed length"), "{error}");
        assert!(
            store.head(&second_key).await.is_err(),
            "new bytes were written after the retained-target size check failed"
        );
        assert_eq!(
            RoleVersions::live(&store, &dest).await.unwrap(),
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
        for relative in ["metadata/junk.json", "metadata/nested/root.json"] {
            let key = updatec::object_key(&dest.prefix, relative);
            store
                .put(
                    &key,
                    object_store::PutPayload::from_bytes(b"untrusted".to_vec().into()),
                )
                .await
                .unwrap();
        }

        let mirror = root.join("mirror");
        tokio::fs::create_dir_all(&mirror).await.unwrap();
        download_metadata(&store, &dest, &mirror).await.unwrap();
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
        let backend = backend("releases/app");
        updatec::runtime::publish_repository(&store, &dest, &origin)
            .await
            .unwrap();

        // Both publishers check out the same generation, as two CI jobs would.
        let ours = checkout_metadata(&store, &dest, &backend).await.unwrap();
        let theirs = checkout_metadata(&store, &dest, &backend).await.unwrap();
        assert_eq!(
            ours.generation,
            RoleVersions::live(&store, &dest).await.unwrap()
        );

        // The other publisher commits while we are still building and signing.
        let file = root.join("theirs.json");
        tokio::fs::write(&file, b"{}").await.unwrap();
        repo::add_release(
            theirs.path(),
            &keys,
            vec![PublishTarget {
                name: "provider-sets/theirs.json".into(),
                source: file,
                custom: Default::default(),
            }],
            365,
        )
        .await
        .unwrap();
        theirs.publish(&store, &dest).await.unwrap();
        let published = RoleVersions::live(&store, &dest).await.unwrap();
        assert_ne!(published, ours.generation);
        let published = published.highest();

        let error = ours
            .publish(&store, &dest)
            .await
            .expect_err("a stale checkout must not overwrite the live generation")
            .to_string();
        assert!(error.contains("another publisher"), "{error}");

        // The other publisher's generation is intact: nothing was uploaded over it.
        assert_eq!(
            RoleVersions::live(&store, &dest).await.unwrap().highest(),
            published
        );
        let mirror = root.join("mirror");
        tokio::fs::create_dir_all(&mirror).await.unwrap();
        download_metadata(&store, &dest, &mirror).await.unwrap();
        let targets = tokio::fs::read_to_string(mirror.join(format!("{published}.targets.json")))
            .await
            .unwrap();
        assert!(
            targets.contains("provider-sets/theirs.json"),
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
        let backend = backend("releases/app");
        updatec::runtime::publish_repository(&store, &dest, &origin)
            .await
            .unwrap();

        let ours = checkout_metadata(&store, &dest, &backend).await.unwrap();
        let theirs = checkout_metadata(&store, &dest, &backend).await.unwrap();
        // The state the guard used to be blind to: root is ahead of every other role.
        assert!(
            ours.generation.0[0] > ours.generation.0[1],
            "root outranks timestamp after a rotation: {:?}",
            ours.generation
        );

        let file = root.join("theirs.json");
        tokio::fs::write(&file, b"{}").await.unwrap();
        repo::add_release(
            theirs.path(),
            &keys,
            vec![PublishTarget {
                name: "provider-sets/theirs.json".into(),
                source: file,
                custom: Default::default(),
            }],
            365,
        )
        .await
        .unwrap();
        theirs.publish(&store, &dest).await.unwrap();

        let error = ours
            .publish(&store, &dest)
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
                    .contains("provider-sets/theirs.json");
            }
        }
        assert!(
            survived,
            "the concurrent publisher's signed target survived"
        );
    }

    /// `trust-root` promises a *fresh* trust root, and an operator reaches for it after a key
    /// disclosure. A directory still holding the exposed key must never be reused and the new root
    /// signed by it — the command refuses instead, before anything is minted, signed, or uploaded.
    #[test]
    fn trust_root_refuses_a_keys_dir_that_already_holds_a_role_key() {
        let (_tmp, dir) = scratch("trust-root-keys");
        assert!(ensure_keys_dir_is_empty(&dir).is_ok(), "an empty dir mints");

        std::fs::write(dir.join("targets.pk8"), b"leaked").unwrap();
        let error = ensure_keys_dir_is_empty(&dir)
            .expect_err("a leftover role key must be refused, never silently reused")
            .to_string();
        assert!(error.contains("targets.pk8"), "{error}");
        assert!(error.contains("will not reuse"), "{error}");
        assert!(
            error.contains("not the remains of an interrupted run"),
            "{error}"
        );

        // Every role key counts, including the standby root.
        std::fs::remove_file(dir.join("targets.pk8")).unwrap();
        std::fs::write(dir.join("root.next.pk8"), b"standby").unwrap();
        assert!(ensure_keys_dir_is_empty(&dir).is_err());
    }

    /// The bootstrap is mint-then-publish and the publish is allowed to fail (S3 transient,
    /// truncated upload), which leaves the repository uninitialized. The identical re-run must
    /// complete the bootstrap, and the failed attempt must leave no private key material in
    /// `--keys-dir` for the operator to hand-delete.
    #[tokio::test]
    async fn an_interrupted_trust_root_leaves_no_key_and_is_completed_by_an_identical_re_run() {
        let (_tmp, scratch_dir) = scratch("trust-root-retry");
        let keys_dir = scratch_dir.join("keys");

        // Attempt one: the keys are staged, then the publish fails and uploads nothing. Dropping
        // the guard — what the process exit does — removes the whole staging directory.
        let staged = {
            let pending = PendingRoleKeys::mint(&keys_dir).await.unwrap();
            assert!(
                pending.keys().roots.len() == 2 && pending.keys().targets.exists(),
                "the full role set is minted into the staging directory"
            );
            pending.material.path().to_path_buf()
        };
        assert!(!staged.exists(), "the failed attempt removed its staging");
        assert_eq!(
            std::fs::read_dir(&keys_dir).unwrap().count(),
            0,
            "a bootstrap that did not publish writes no key material to --keys-dir"
        );

        // Attempt two: the same command, from the state attempt one left behind.
        let pending = PendingRoleKeys::mint(&keys_dir)
            .await
            .expect("the re-run is not blocked by the interrupted attempt");
        let staged = pending.material.path().to_path_buf();
        pending.commit().unwrap();
        assert!(!staged.exists(), "the staging directory is cleaned up");
        let delivered = role_key_names(&keys_dir).unwrap();
        assert_eq!(delivered.len(), 5, "the full role set is delivered");
        for name in delivered {
            let path = keys_dir.join(&name);
            assert!(
                path.exists(),
                "{name} is delivered once the bootstrap lands"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "the delivered key stays private");
            }
        }
    }

    /// The delivery moves exactly the key set the mint produced, and leaves nothing behind.
    ///
    /// The names come from `repo::Keys`, not from a list this tool keeps of its own, precisely so
    /// this holds: a key `repo::generate_keys` began minting that `commit` did not know to move
    /// would sit in the staging directory of a LIVE trust root — the only copy of a published
    /// root's key — while the operator was told the bootstrap had succeeded.
    #[tokio::test]
    async fn the_delivery_moves_every_key_the_mint_produced() {
        let (_tmp, scratch_dir) = scratch("trust-root-delivers-all");
        let keys_dir = scratch_dir.join("keys");
        let pending = PendingRoleKeys::mint(&keys_dir).await.unwrap();
        let staged = pending.material.path().to_path_buf();
        let mut minted = entry_names(&staged);
        minted.sort();
        assert!(!minted.is_empty(), "the mint produced a role key set");

        pending.commit().unwrap();
        assert!(
            !staged.exists(),
            "no minted key is stranded in the staging directory"
        );
        let mut delivered = entry_names(&keys_dir);
        delivered.sort();
        assert_eq!(
            delivered, minted,
            "--keys-dir holds exactly what was minted for it"
        );
    }

    fn entry_names(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect()
    }

    /// `Drop` covers every failure the process survives, but a signal does not go through it: a
    /// Ctrl-C or a runner timeout during the S3 publish leaves a staging directory of five private
    /// keys behind. It is invisible to the role-key emptiness check, so it used to accumulate
    /// one per interrupted run against a documented promise of nothing to hand-delete. The next
    /// `trust-root` sweeps it: the bootstrap is not blocked and nothing is left over.
    #[tokio::test]
    async fn a_staging_directory_left_by_a_killed_run_is_swept_by_the_next() {
        let (_tmp, scratch_dir) = scratch("trust-root-stale-staging");
        let keys_dir = scratch_dir.join("keys");
        std::fs::create_dir_all(&keys_dir).unwrap();
        let stale = keys_dir.join(format!(
            "{}4242.1700000000000000000",
            pending_prefix(ROLE_KEYS_STEM)
        ));
        std::fs::create_dir(&stale).unwrap();
        std::fs::write(stale.join("root.pk8"), b"orphaned").unwrap();

        let pending = PendingRoleKeys::mint(&keys_dir)
            .await
            .expect("a killed run's staging directory does not block the next bootstrap");
        assert!(
            !stale.exists(),
            "the abandoned key material is removed, not accumulated"
        );
        assert_ne!(
            pending.material.path(),
            stale,
            "this run staged somewhere of its own"
        );
        pending.commit().unwrap();

        let mut left: Vec<String> = std::fs::read_dir(&keys_dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        let mut expected = role_key_names(&keys_dir).unwrap();
        expected.sort();
        assert_eq!(expected.len(), 5, "the full role set is delivered");
        assert_eq!(
            left, expected,
            "--keys-dir holds the five delivered keys and no staging directory of any vintage"
        );
    }

    /// The one directory a `commit` leaves behind when it fails part way: the keys of a repository
    /// that IS published.
    fn preserved_key_dir(keys_dir: &Path) -> PathBuf {
        let mut found: Vec<PathBuf> = std::fs::read_dir(keys_dir)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with(&published_prefix(ROLE_KEYS_STEM))
            })
            .collect();
        assert_eq!(found.len(), 1, "exactly one preserved directory: {found:?}");
        found.pop().unwrap()
    }

    /// A `commit` that fails part way deliberately keeps the staged keys — by then the repository
    /// is published and they are its only copy. Under the staging name the next `trust-root` in the
    /// same `--keys-dir` swept them as abandoned pre-publish material (and only afterwards failed
    /// its own emptiness check), so an automated retry destroyed the live root's online role keys.
    #[tokio::test]
    async fn keys_a_failed_commit_preserved_survive_the_next_runs_sweep() {
        let (_tmp, scratch_dir) = scratch("trust-root-preserved");
        let keys_dir = scratch_dir.join("keys");
        std::fs::create_dir_all(&keys_dir).unwrap();

        // The publish landed; delivery then trips over a role key that appeared under it.
        let pending = PendingRoleKeys::mint(&keys_dir).await.unwrap();
        std::fs::write(keys_dir.join("targets.pk8"), b"planted").unwrap();
        pending.commit().expect_err("delivery is refused");
        let preserved = preserved_key_dir(&keys_dir);
        let published_root = role_key_names(&preserved).unwrap();
        assert_eq!(published_root.len(), 5, "the whole role set is preserved");
        for name in &published_root {
            assert!(
                preserved.join(name).exists(),
                "{name} of the published root is kept"
            );
        }

        // The identical automated re-run. It aborts on the planted key, and must not have taken
        // the published root's keys with it on the way there.
        std::fs::create_dir(keys_dir.join(format!(
            "{}4242.1700000000000000000",
            pending_prefix(ROLE_KEYS_STEM)
        )))
        .unwrap();
        assert!(
            PendingRoleKeys::mint(&keys_dir).await.is_err(),
            "a role key in --keys-dir still blocks a fresh bootstrap"
        );
        assert!(
            !keys_dir
                .join(format!(
                    "{}4242.1700000000000000000",
                    pending_prefix(ROLE_KEYS_STEM)
                ))
                .exists(),
            "abandoned pre-publish staging is still swept"
        );
        for name in &published_root {
            assert!(
                preserved.join(name).exists(),
                "{name} of the published root survives the re-run's sweep"
            );
        }
    }

    /// The emptiness check and the mint used to be separated by seconds of S3 round trips, and the
    /// mint adopted whatever key file had appeared in the window — pinning it into the fleet's new
    /// root. Nothing minted here comes from `--keys-dir`, so a key planted at any point is never
    /// adopted: before the mint it is refused, and after it the delivery refuses to clobber it.
    #[tokio::test]
    async fn a_key_planted_in_the_mint_window_is_never_adopted_into_the_fresh_root() {
        let (_tmp, scratch_dir) = scratch("trust-root-planted");
        let keys_dir = scratch_dir.join("keys");
        std::fs::create_dir_all(&keys_dir).unwrap();

        let pending = PendingRoleKeys::mint(&keys_dir).await.unwrap();
        let minted = std::fs::read(pending.keys().targets.clone()).unwrap();

        // The window: another local principal plants a well-formed key while the publish is in
        // flight. It is signed into nothing — the root was built from the staged keys alone.
        std::fs::write(keys_dir.join("targets.pk8"), b"planted").unwrap();
        let error = pending
            .commit()
            .expect_err("delivery must not clobber a file it did not mint")
            .to_string();
        assert!(error.contains("targets.pk8"), "{error}");
        let staged = preserved_key_dir(&keys_dir);
        assert!(
            error.contains(&staged.display().to_string()),
            "the operator is told where the published root's keys actually are: {error}"
        );
        assert_eq!(
            std::fs::read(keys_dir.join("targets.pk8")).unwrap(),
            b"planted".to_vec(),
            "the planted file is left untouched rather than clobbered"
        );
        assert_ne!(
            minted,
            b"planted".to_vec(),
            "…and it is not the key the root was signed with"
        );
        assert!(
            staged.join("root.pk8").exists() && staged.join("root.next.pk8").exists(),
            "the staged set is intact for the operator to collect"
        );

        // A key standing there before the mint is refused outright, nothing is staged.
        assert!(
            PendingRoleKeys::mint(&keys_dir).await.is_err(),
            "a pre-existing role key is refused before anything is minted"
        );
    }

    /// A repository whose `root.json` was removed out of band — a lifecycle rule, a partial
    /// restore, an operator tidying what looks like a duplicate of the versioned copies — is still
    /// serving a fleet that has accepted timestamp N. Probing only `root.json` declared it
    /// uninitialized, so `trust-root` re-initialized it at version 1 with no flag and no warning,
    /// and every node silently refused the older metadata forever.
    #[tokio::test]
    async fn a_half_deleted_repository_is_still_live_and_still_sets_the_version_floor() {
        let (_tmp, root) = scratch("half-deleted");
        let keys = repo::generate_keys(&root.join("keys")).await.unwrap();
        let origin = root.join("origin");
        repo::init(&origin, &keys, 365).await.unwrap();
        let store = InMemory::new();
        let dest = destination("releases/app");
        let backend = backend("releases/app");
        updatec::runtime::publish_repository(&store, &dest, &origin)
            .await
            .unwrap();

        // Publish a release so the online roles stand above the root's version.
        let file = root.join("app.bin");
        tokio::fs::write(&file, b"payload").await.unwrap();
        let checkout = checkout_metadata(&store, &dest, &backend).await.unwrap();
        repo::add_release(
            checkout.path(),
            &keys,
            vec![PublishTarget {
                name: "products/app/stable/1.0.0/linux-x86_64/app".into(),
                source: file,
                custom: Default::default(),
            }],
            365,
        )
        .await
        .unwrap();
        checkout.publish(&store, &dest).await.unwrap();
        let live = RoleVersions::live(&store, &dest).await.unwrap();
        let floor = live.highest();
        assert!(
            floor > 1,
            "the live repository has published past version 1"
        );

        // The unversioned root.json disappears; timestamp.json keeps serving the fleet.
        store
            .delete(&updatec::object_key(&dest.prefix, "metadata/root.json"))
            .await
            .unwrap();

        let live = RoleVersions::live(&store, &dest).await.unwrap();
        assert!(
            live.is_initialized(),
            "a live timestamp means a live repository, whatever became of root.json"
        );
        assert_eq!(
            live.highest(),
            floor,
            "the version floor survives the missing root: a replacement starts above it"
        );
        let described = live.describe_present();
        assert!(
            described.contains("timestamp.json"),
            "the operator is told exactly what is standing: {described}"
        );

        // Now the timestamp goes too, leaving only the versioned snapshot and targets — the copies
        // that carry the versions the fleet has actually accepted. Reading unversioned names alone
        // collapsed the floor to the root's version here and re-signed the replacement below them.
        store
            .delete(&updatec::object_key(
                &dest.prefix,
                "metadata/timestamp.json",
            ))
            .await
            .unwrap();

        let live = RoleVersions::live(&store, &dest).await.unwrap();
        assert!(
            live.is_initialized(),
            "versioned metadata standing at the prefix is a live repository"
        );
        assert_eq!(
            live.highest(),
            floor,
            "the floor comes from the versioned copies once the unversioned documents are gone"
        );
    }

    /// The provider set a release pins is signed into the app target and read exactly once —
    /// during an ordered-fallback descent on a node, mid-rollback. A well-formed but mismatched
    /// path/digest pair is therefore resolved against the checked-out signed metadata here, where
    /// the answer is already in hand, instead of stalling a node at recovery time.
    #[tokio::test]
    async fn deploy_resolves_the_pinned_provider_set_against_the_checked_out_metadata() {
        let (_tmp, root) = scratch("provider-set-ref");
        let keys = repo::generate_keys(&root.join("keys")).await.unwrap();
        let origin = root.join("origin");
        repo::init(&origin, &keys, 365).await.unwrap();

        let store = InMemory::new();
        let dest = destination("releases/app");
        let backend = backend("releases/app");
        updatec::runtime::publish_repository(&store, &dest, &origin)
            .await
            .unwrap();

        // Publish one provider set, as `publish-provider-set` does.
        let published = checkout_metadata(&store, &dest, &backend).await.unwrap();
        let file = root.join("set.json");
        tokio::fs::write(&file, b"{}").await.unwrap();
        repo::add_release(
            published.path(),
            &keys,
            vec![PublishTarget {
                name: "provider-sets/web-v4.json".into(),
                source: file,
                custom: Default::default(),
            }],
            365,
        )
        .await
        .unwrap();
        let sha = repo::target_sha256(published.path(), "provider-sets/web-v4.json")
            .await
            .unwrap();
        published.publish(&store, &dest).await.unwrap();

        let checkout = checkout_metadata(&store, &dest, &backend).await.unwrap();
        assert_eq!(
            resolve_provider_set(&checkout, Some("provider-sets/web-v4.json"), Some(&sha))
                .await
                .unwrap(),
            Some(("provider-sets/web-v4.json".to_string(), sha.clone())),
            "the published set resolves and is signed in its lowercase form"
        );
        assert_eq!(
            resolve_provider_set(&checkout, None, None).await.unwrap(),
            None,
            "omitting the flags leaves provider selection to the assignment head"
        );
        let error = resolve_provider_set(
            &checkout,
            Some("provider-sets/web-v4.json"),
            Some(&sha.to_ascii_uppercase()),
        )
        .await
        .expect_err("noncanonical digest aliases must be refused before signing")
        .to_string();
        assert!(error.contains("canonical lowercase"), "{error}");

        // The stale copy-paste: a path that was never published, paired with a valid digest.
        let error = resolve_provider_set(&checkout, Some("provider-sets/web-v3.json"), Some(&sha))
            .await
            .expect_err("an unresolvable provider set path must not be signed")
            .to_string();
        assert!(error.contains("does not resolve"), "{error}");
        assert!(error.contains("Nothing was signed"), "{error}");

        // A real path against the wrong release's digest.
        let error = resolve_provider_set(
            &checkout,
            Some("provider-sets/web-v4.json"),
            Some(&"b".repeat(64)),
        )
        .await
        .expect_err("a digest that is not this target's must not be signed")
        .to_string();
        assert!(
            error.contains("does not match the signed digest"),
            "{error}"
        );

        let error =
            resolve_provider_set(&checkout, Some("provider-sets/web-v4.json"), Some("nope"))
                .await
                .expect_err("a malformed digest is still rejected")
                .to_string();
        assert!(error.contains("canonical lowercase SHA-256"), "{error}");
    }

    /// An emergency override must be self-clearing. The deploy patch therefore states
    /// `emergencyCorrection` on every publish rather than only when it is set — a merge patch that
    /// omitted the field would leave a previous `true` in place, exempting every later release of
    /// the group from its set's rollout schedule forever.
    #[test]
    fn the_deploy_patch_always_states_whether_this_is_an_emergency_correction() {
        let ordinary = group_patch("products/app/stable/1.0.0/linux-x86_64/app", "ab", false);
        assert_eq!(
            ordinary["spec"]["emergencyCorrection"],
            serde_json::json!(false)
        );
        assert_eq!(
            ordinary["spec"]["deployment"]["application"]["path"],
            "products/app/stable/1.0.0/linux-x86_64/app"
        );
        let emergency = group_patch("products/app/stable/0.9.0/linux-x86_64/app", "cd", true);
        assert_eq!(
            emergency["spec"]["emergencyCorrection"],
            serde_json::json!(true)
        );
        // Nothing else in the deployment spec is touched by either patch.
        assert_eq!(
            ordinary["spec"]["deployment"].as_object().unwrap().len(),
            1,
            "the patch names only the application reference"
        );
    }

    #[tokio::test]
    async fn deploy_requires_the_online_keys_but_not_the_root_keys() {
        let (_tmp, dir) = scratch("keys");
        for key in ["targets.pk8", "snapshot.pk8", "timestamp.pk8"] {
            std::fs::write(dir.join(key), b"x").unwrap();
        }
        // No root.pk8 present: deploy's key resolution must still succeed.
        assert!(open_keys(&dir).is_ok());
        std::fs::remove_file(dir.join("targets.pk8")).unwrap();
        assert!(open_keys(&dir).is_err(), "a missing online key is rejected");
    }

    /// The root rotation is mint-then-publish and the publish is allowed to fail (generation
    /// guard, S3 transient), which uploads nothing and leaves the root unrotated. The identical
    /// re-run — the only thing an operator answering a key disclosure should have to do — must
    /// complete the ceremony, and the failed attempt must leave no key material behind for it to
    /// stumble over.
    #[tokio::test]
    async fn an_interrupted_root_rotation_leaves_no_key_and_is_completed_by_an_identical_re_run() {
        let (_tmp, root) = scratch("rotate-retry");
        let keys = repo::generate_keys(&root.join("keys")).await.unwrap();
        let origin = root.join("origin");
        repo::init(&origin, &keys, 365).await.unwrap();
        let store = InMemory::new();
        let dest = destination("releases/app");
        updatec::runtime::publish_repository(&store, &dest, &origin)
            .await
            .unwrap();

        // Attempt one: the key is staged, then the publish fails and uploads nothing. Dropping
        // the guard — what the process exit does — removes the staged key.
        let successor = root.join("successor.pk8");
        ensure_new_key_out_is_free(&successor).unwrap();
        let staged = {
            let pending = PendingRootKey::mint(&successor).await.unwrap();
            pending.path().to_path_buf()
        };
        assert!(
            !staged.exists(),
            "the failed attempt removed its staged key"
        );
        assert!(
            !successor.exists(),
            "a rotation that did not publish writes nothing to --new-key-out"
        );

        // Attempt two: the same command, from the state attempt one left behind.
        ensure_new_key_out_is_free(&successor)
            .expect("the re-run is not blocked by the interrupted attempt");
        let checkout = checkout_metadata(&store, &dest, &backend("releases/app"))
            .await
            .unwrap();
        let pending = PendingRootKey::mint(&successor).await.unwrap();
        repo::rotate_root(checkout.path(), &keys.roots[1..], pending.path(), 365)
            .await
            .unwrap();
        checkout.publish(&store, &dest).await.unwrap();
        pending.commit().unwrap();
        let published = store
            .get(&updatec::object_key(&dest.prefix, "metadata/root.json"))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(
            updatec::runtime::signed_version(&published).unwrap_or(0),
            2,
            "the retry published the rotated root"
        );
        assert!(
            successor.exists(),
            "the successor key is delivered once the rotation published"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&successor).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the delivered key stays private");
        }
    }

    /// Whatever sits at `--new-key-out` would be signed into the new root at threshold 1, so a
    /// file the ceremony did not mint is refused — a private-looking mode is not provenance, and
    /// nothing is signed or uploaded.
    #[tokio::test]
    async fn a_pre_existing_file_at_new_key_out_is_never_adopted_as_root_key_material() {
        let (_tmp, root) = scratch("rotate-planted");

        // A key of the attacker's own making, at exactly the mode a minted key carries.
        let planted = root.join("planted.pk8");
        repo::generate_root_key(&planted).await.unwrap();
        let bytes = std::fs::read(&planted).unwrap();
        let error = ensure_new_key_out_is_free(&planted)
            .unwrap_err()
            .to_string();
        assert!(error.contains("already exists"), "{error}");
        assert_eq!(
            std::fs::read(&planted).unwrap(),
            bytes,
            "the refusal leaves the operator's path untouched"
        );

        // Nor a directory, nor a symlink pointing at key material elsewhere.
        let dir = root.join("dir.pk8");
        std::fs::create_dir(&dir).unwrap();
        assert!(ensure_new_key_out_is_free(&dir).is_err());
        #[cfg(unix)]
        {
            let link = root.join("link.pk8");
            std::os::unix::fs::symlink(&planted, &link).unwrap();
            assert!(
                ensure_new_key_out_is_free(&link).is_err(),
                "a symlink is refused without following it"
            );
        }
    }

    /// Author a repo, publish it to an in-memory store, then run the CLI's own
    /// download → rotate → re-publish cycle and prove a client pinned to the original root
    /// follows the rotation — exercising `RoleVersions::live`, `download_metadata`, prefix
    /// handling, and `publish_repository` exactly as the binary uses them.
    #[tokio::test]
    async fn s3_round_trip_publishes_downloads_and_rotates() {
        let (_tmp, root) = scratch("s3");
        let keys = repo::generate_keys(&root.join("keys")).await.unwrap();
        let origin = root.join("origin");
        repo::init(&origin, &keys, 365).await.unwrap();

        let store = InMemory::new();
        let dest = destination("releases/app");

        assert!(
            !RoleVersions::live(&store, &dest)
                .await
                .unwrap()
                .is_initialized(),
            "an empty store is not initialized"
        );
        updatec::runtime::publish_repository(&store, &dest, &origin)
            .await
            .unwrap();
        assert!(
            RoleVersions::live(&store, &dest)
                .await
                .unwrap()
                .is_initialized(),
            "publishing makes the store report initialized"
        );

        // Pull the metadata back down through the one production checkout path.
        let checkout = checkout_metadata(&store, &dest, &backend("releases/app"))
            .await
            .unwrap();
        let pinned = tokio::fs::read(checkout.path().join("metadata/1.root.json"))
            .await
            .unwrap();

        // Rotate against the downloaded copy, then re-publish it.
        let successor = root.join("successor.pk8");
        repo::generate_root_key(&successor).await.unwrap();
        repo::rotate_root(checkout.path(), &keys.roots[1..], &successor, 365)
            .await
            .unwrap();
        checkout.publish(&store, &dest).await.unwrap();

        // Download once more into a clean checkout and verify through the real client.
        let mirror = checkout_metadata(&store, &dest, &backend("releases/app"))
            .await
            .unwrap();
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
