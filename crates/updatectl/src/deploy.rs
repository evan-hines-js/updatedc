//! `deploy`: build and sign an application bundle, publish it, then roll a named `UpdateGroup`
//! onto the resulting target, and report what was published for the CI step that follows.

use crate::*;

pub(crate) async fn deploy(args: DeployArgs) -> Result<(), Error> {
    let backend = &args.backend;
    updated_contracts::identity::parse_release_version(&args.version).ok_or_else(|| {
        format!(
            "--version {:?} is not a bounded semantic version",
            args.version
        )
    })?;
    let platform = args
        .platform
        .clone()
        .unwrap_or_else(|| format!("linux-{}", std::env::consts::ARCH));
    let (os, arch) = platform
        .split_once('-')
        .ok_or_else(|| format!("--platform must be <os>-<arch>, got {platform:?}"))?;

    // Confirm the group exists before doing any signing work.
    let client = Client::try_default().await?;
    let groups: Api<UpdateGroup> = Api::namespaced(client, &args.namespace);
    groups.get(&args.group).await.map_err(|error| {
        format!(
            "UpdateGroup {} not found in {}: {error}",
            args.group, args.namespace
        )
    })?;

    let (destination, store, keys, checkout) = checkout_repository(backend).await?;

    // Resolve the provider set against the metadata in hand, before any bundle is built.
    let provider_set = resolve_provider_set(
        &checkout,
        args.provider_set_path.as_deref(),
        args.provider_set_sha256.as_deref(),
    )
    .await?;

    // Build the bundle into a scratch dir, then register it as a signed target.
    let build_dir = tempfile::tempdir()?;
    let archive = build_dir.path().join("bundle.tar.zst");
    build_bundle(
        &args.source,
        &archive,
        build_dir.path(),
        &args.product,
        &args.version,
        &platform,
        &args.entrypoint,
    )?;

    let mut target = PublishTarget::application(
        &args.product,
        &args.channel,
        &args.version,
        os,
        arch,
        &args.product,
        archive,
    );
    // Bind the resolved provider set into this app version's signed metadata, so a later
    // ordered-fallback descent rolls providers back with it.
    if let Some((path, sha256)) = &provider_set {
        target = target.with_provider_set(path, sha256);
    }
    let target_name = target.name.clone();
    repo::add_release(checkout.path(), &keys, vec![target], args.expiry_days).await?;
    let sha256 = repo::target_sha256(checkout.path(), &target_name).await?;

    // Upload immutable target bytes first and re-signed metadata last (timestamp is the
    // commit point) — the operator's exact publication order. The group patch below references
    // this generation, so a concurrent publisher must abort the upload rather than drop it.
    checkout.publish(store.as_ref(), &destination).await?;
    eprintln!("published signed target {target_name} (sha256 {sha256})");

    // Roll the group. A JSON merge patch touches only the application reference, leaving
    // the rest of the deployment spec intact; the operator republishes assignments.
    //
    // `emergencyCorrection` is written on EVERY deploy, true or false. A merge patch that omitted
    // it would leave a previous `true` in place, so a one-off emergency would silently keep every
    // later release of this group exempt from its set's rollout schedule.
    let patch = group_patch(&target_name, &sha256, args.emergency);
    groups
        .patch(&args.group, &PatchParams::default(), &Patch::Merge(&patch))
        .await?;
    eprintln!(
        "rolled UpdateGroup {} in {} to {} {}",
        args.group, args.namespace, args.product, args.version
    );
    if args.emergency {
        eprintln!(
            "declared an emergency correction: this deployment is admitted without waiting for \
             the governing UpdateGroupSet's rollout schedule"
        );
    }

    report_deploy(&args, &platform, &target_name, &sha256)
}

/// Resolve `--provider-set-path`/`--provider-set-sha256` against the signed metadata this publish
/// already holds, returning the normalized reference to sign into the app target.
///
/// The reference is signed into the app version's custom metadata and then read exactly once,
/// much later: when an ordered-fallback descent picks this version on a node, `stage_providers`
/// calls `exact_target` on it. A well-formed but unresolvable reference — a stale copy-paste of a
/// previous set's path against the new set's digest, or a set published under a different prefix —
/// is accepted by every syntactic check and only fails there, leaving the node unable to complete
/// the rollback it is in the middle of. The checkout in hand is the same signed targets metadata
/// the node will verify against, so resolving it here turns that into a publish-time refusal with
/// nothing signed or uploaded. The shared digest grammar admits only canonical lowercase hex, so
/// the reference verified here is exactly the spelling later signed and compared by every agent.
pub(crate) async fn resolve_provider_set(
    checkout: &Checkout,
    path: Option<&str>,
    sha256: Option<&str>,
) -> Result<Option<(String, String)>, Error> {
    // clap's `requires` makes the flags all-or-nothing.
    let (Some(path), Some(sha256)) = (path, sha256) else {
        return Ok(None);
    };
    if !updated_contracts::is_canonical_sha256(sha256) {
        return Err(format!(
            "--provider-set-sha256 {sha256:?} is not a canonical lowercase SHA-256"
        )
        .into());
    }
    repo::verify_target_reference(
        checkout.path(),
        path,
        sha256,
        "--provider-set-path",
        "--provider-set-sha256",
        "provider sets",
        "Publish the provider set with `publish-provider-set` against this same bucket and \
         prefix first, and pass the path it prints. Nothing was signed or uploaded.",
    )
    .await?;
    Ok(Some((path.to_string(), sha256.to_string())))
}

/// The merge patch that rolls an `UpdateGroup` onto a freshly published target.
///
/// `emergencyCorrection` is always written, true or false. A merge patch that omitted it would
/// leave a previous `true` in place, so a one-off emergency would silently keep every later release
/// of this group exempt from its `UpdateGroupSet`'s rollout schedule.
pub(crate) fn group_patch(target: &str, sha256: &str, emergency: bool) -> serde_json::Value {
    serde_json::json!({
        "spec": {
            "deployment": { "application": { "path": target, "sha256": sha256 } },
            "emergencyCorrection": emergency,
        }
    })
}

/// Check out the release repository's current signed metadata into a throwaway temp dir, ready
/// for a new target to be added and republished. The one preamble every publishing command
/// shares — `deploy` and both provider publishes — so a rule added to it (a liveness assertion, a
/// keys-mode check) cannot end up applying to some of them.
pub(crate) async fn checkout_repository(
    backend: &Backend,
) -> Result<(S3Destination, Arc<dyn ObjectStore>, repo::Keys, Checkout), Error> {
    let (destination, store) = build_store(backend)?;
    let keys = open_keys(&backend.keys_dir)?;
    let checkout = checkout_metadata(store.as_ref(), &destination, backend).await?;
    Ok((destination, store, keys, checkout))
}

/// One checked-out generation of a release repository's signed metadata, plus the per-role
/// versions it was taken at.
///
/// Publishing is read-modify-write over shared S3 metadata: the checkout carries generation N,
/// `repo::add_release` signs N+1 locally, and the upload overwrites `N+1.targets.json`,
/// `N+1.snapshot.json`, and `timestamp.json` unconditionally. Two publishers against one prefix
/// therefore each sign an N+1 that omits the other's targets, and the loser's freshly patched
/// UpdateGroup points at a target that is no longer in verified metadata — every node in that
/// group stalls on "desired target absent from verified metadata" until someone republishes.
/// A single publisher per lineage is the documented model, so the recorded generation is not a
/// lock; it is the check that makes the unsupported case abort loudly with nothing uploaded
/// instead of silently dropping another publisher's signed targets.
pub(crate) struct Checkout {
    pub(crate) dir: tempfile::TempDir,
    pub(crate) generation: RoleVersions,
}

impl Checkout {
    pub(crate) fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Publish the edited checkout, refusing to overwrite a generation this process never saw.
    pub(crate) async fn publish(
        &self,
        store: &dyn ObjectStore,
        destination: &S3Destination,
    ) -> Result<(), Error> {
        let live = RoleVersions::live(store, destination).await?;
        if let Some(moved) = live.moved_since(&self.generation) {
            return Err(format!(
                "release repository at s3://{}/{} moved {moved} while this publish was building \
                 and signing: another publisher is writing the same prefix. Nothing was uploaded \
                 — re-run this command once that publish has settled, and publish one release \
                 lineage from one place.",
                destination.bucket, destination.prefix
            )
            .into());
        }
        updatec::runtime::publish_repository(store, destination, self.path()).await?;
        Ok(())
    }
}

/// Check out a repository's current TUF metadata into a throwaway temp dir: create `metadata/` and
/// `targets/`, download the metadata, and confirm the repository is initialized (has
/// `metadata/root.json`). The single definition of that checkout preamble — deploy, root rotation,
/// and the provider-publish path all go through it, so they cannot drift on the directory layout or
/// the uninitialized-repository guard.
pub(crate) async fn checkout_metadata(
    store: &dyn ObjectStore,
    destination: &S3Destination,
    backend: &Backend,
) -> Result<Checkout, Error> {
    let repo_dir = tempfile::tempdir()?;
    let metadata_dir = repo_dir.path().join("metadata");
    tokio::fs::create_dir_all(&metadata_dir).await?;
    tokio::fs::create_dir_all(repo_dir.path().join("targets")).await?;
    let generation = RoleVersions::live(store, destination).await?;
    download_metadata(store, destination, &metadata_dir).await?;
    if !foundation::file::path_entry_exists(&metadata_dir.join("root.json"))? {
        return Err(format!(
            "release repository at s3://{}/{} is not initialized (no metadata/root.json); run \
             `updatectl trust-root` first",
            backend.bucket, backend.prefix
        )
        .into());
    }
    // A TUF generation is several objects. Refuse a checkout assembled while another publisher
    // was moving them rather than blessing a mixed local view as the generation we observed.
    let after = RoleVersions::live(store, destination).await?;
    if after != generation {
        return Err(format!(
            "release repository at s3://{}/{} changed while its metadata was being checked out; \
             retry after the other publisher has settled",
            destination.bucket, destination.prefix
        )
        .into());
    }
    Ok(Checkout {
        dir: repo_dir,
        generation,
    })
}

/// Emit the machine-readable deploy result: a clean stdout payload (text or JSON) plus,
/// under GitHub Actions, `target`/`sha256`/`version` step outputs for later steps.
pub(crate) fn report_deploy(
    args: &DeployArgs,
    platform: &str,
    target: &str,
    sha256: &str,
) -> Result<(), Error> {
    match args.output {
        OutputFormat::Text => {
            println!("target={target}");
            println!("sha256={sha256}");
        }
        OutputFormat::Json => {
            let document = serde_json::json!({
                "namespace": args.namespace,
                "group": args.group,
                "product": args.product,
                "channel": args.channel,
                "version": args.version,
                "platform": platform,
                "target": target,
                "sha256": sha256,
                "emergency": args.emergency,
            });
            println!("{}", serde_json::to_string(&document)?);
        }
    }
    emit_github_outputs(&[
        ("target", target),
        ("sha256", sha256),
        ("version", &args.version),
    ])
}

/// Append `key=value` lines to the file named by `$GITHUB_OUTPUT`, the idiomatic way a
/// GitHub Actions step exposes outputs. A no-op elsewhere.
///
/// The whole document is validated before the file is opened, so a value cannot inject a second
/// output through a newline and a bad later pair cannot leave a convincing partial result.
pub(crate) fn emit_github_outputs(pairs: &[(&str, &str)]) -> Result<(), Error> {
    let Some(path) = std::env::var_os("GITHUB_OUTPUT") else {
        return Ok(());
    };
    use std::io::Write;
    let mut document = String::new();
    for (key, value) in pairs {
        document.push_str(&github_output_line(key, value)?);
    }
    let mut file = foundation::file::open_append_file(std::path::Path::new(&path))?;
    file.write_all(document.as_bytes())?;
    Ok(())
}

/// Serialize the deliberately single-line subset of GitHub's environment-file protocol.
fn github_output_line(key: &str, value: &str) -> std::io::Result<String> {
    if key.is_empty()
        || key
            .as_bytes()
            .iter()
            .any(|byte| matches!(byte, b'=' | b'\r' | b'\n'))
        || value
            .as_bytes()
            .iter()
            .any(|byte| matches!(byte, b'\r' | b'\n'))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "GitHub output keys must be non-empty and key/value pairs must be single-line",
        ));
    }
    Ok(format!("{key}={value}\n"))
}

#[cfg(test)]
mod github_output_tests {
    use super::github_output_line;

    #[test]
    fn github_outputs_accept_only_the_single_line_protocol() {
        assert_eq!(
            github_output_line("sha256", "abc123").unwrap(),
            "sha256=abc123\n"
        );
        for (key, value) in [
            ("", "value"),
            ("bad=name", "value"),
            ("bad\nname", "value"),
            ("name", "first\nsecond=forged"),
            ("name", "first\rsecond"),
        ] {
            assert!(github_output_line(key, value).is_err());
        }
    }
}
