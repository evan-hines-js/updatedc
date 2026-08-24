//! Publishing the two immutable signed targets that a deployment references: the lifecycle
//! provider artifact, and the provider set that binds it by path and digest.

use crate::*;

/// Publish a provider artifact bundle as a signed target, without rolling any group.
pub(crate) async fn publish_provider_artifact(args: ProviderArtifactArgs) -> Result<(), Error> {
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

    let (destination, store, keys, checkout) = checkout_repository(backend).await?;

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

    let target = PublishTarget::application(
        &args.product,
        &args.channel,
        &args.version,
        os,
        arch,
        &args.product,
        archive,
    );
    let target_name = target.name.clone();
    repo::add_release(checkout.path(), &keys, vec![target], args.expiry_days).await?;
    let sha256 = repo::target_sha256(checkout.path(), &target_name).await?;
    checkout.publish(store.as_ref(), &destination).await?;
    // stdout carries the machine-readable `path sha256` for the caller to reference; diagnostics
    // go to stderr.
    println!("{target_name} {sha256}");
    eprintln!("published provider artifact {target_name} (sha256 {sha256})");
    Ok(())
}

/// Publish an immutable provider set (`provider-sets/<id>.json`) as a signed target.
pub(crate) async fn publish_provider_set(args: ProviderSetArgs) -> Result<(), Error> {
    let backend = &args.backend;
    let set = provider_set(&args)?;

    let (destination, store, keys, checkout) = checkout_repository(backend).await?;
    repo::verify_provider_set_reconciler(checkout.path(), &set).await?;

    let build_dir = tempfile::tempdir()?;
    let source = build_dir.path().join("provider-set.json");
    tokio::fs::write(&source, set.to_bounded_json().map_err(Error::from)?).await?;
    let target_name = format!("provider-sets/{}.json", set.id);
    let target = PublishTarget {
        name: target_name.clone(),
        source,
        custom: Default::default(),
    };
    repo::add_release(checkout.path(), &keys, vec![target], args.expiry_days).await?;
    let sha256 = repo::target_sha256(checkout.path(), &target_name).await?;
    checkout.publish(store.as_ref(), &destination).await?;
    println!("{target_name} {sha256}");
    eprintln!("published provider set {target_name} (sha256 {sha256})");
    Ok(())
}

/// Bind this command's arguments to the provider-set document it will sign. The publish-time
/// refusal itself lives with the contract, in `ProviderSet::for_publication`, so both publishers
/// hold a set to the same rule and tell an operator about it in the same words.
pub(crate) fn provider_set(
    args: &ProviderSetArgs,
) -> Result<updated_contracts::artifact::ProviderSet, Error> {
    updated_contracts::artifact::ProviderSet::for_publication(
        args.id.clone(),
        updated_contracts::artifact::Reconciler {
            artifact: updated_contracts::artifact::TargetReference {
                path: args.provider_path.clone(),
                sha256: args.provider_sha256.clone(),
            },
            args: args.provider_arg.clone(),
            timeout_millis: args.provider_timeout_ms,
        },
    )
    .map_err(Error::from)
}
