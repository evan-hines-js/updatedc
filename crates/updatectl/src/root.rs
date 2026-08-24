//! Minting and rotating the TUF trust root. Both commands stage key material before anything is
//! signed, so a publish that does not land leaves the keys directory exactly as it found it.

use crate::*;

pub(crate) async fn trust_root(args: TrustRootArgs) -> Result<(), Error> {
    let backend = &args.backend;
    let (destination, store) = build_store(backend)?;

    // ONE probe of the live repository answers both questions this ceremony asks of it: is
    // anything published here, and how high have its roles gone. Reading them from different
    // objects is how a half-deleted repository (say root.json expired out from under a live
    // timestamp) gets re-initialized at version 1 with no flag and no warning.
    let live = RoleVersions::live(store.as_ref(), &destination).await?;

    // Refuse to silently invalidate an already-published repository.
    if !args.force && live.is_initialized() {
        return Err(format!(
            "release repository at s3://{}/{} is already initialized ({}); pass --force to \
             replace it (this invalidates everything signed under the old root)",
            backend.bucket,
            backend.prefix,
            live.describe_present()
        )
        .into());
    }
    // A replacement must start ABOVE the versions the live repository has already published.
    // TUF clients remember the highest version they accepted and refuse anything lower, so a
    // replacement republished at version 1 is silently rejected by every node that ever saw the
    // old repository — no error at the publisher, and every agent stalled indefinitely. The floor
    // comes from the same reading that decided the repository is live, so no partial deletion can
    // put the two answers out of step; on an empty prefix it is 0 and the fresh root starts at 1.
    let start_version = live.highest() + 1;
    if live.is_initialized() {
        eprintln!(
            "replacing a live repository ({}): starting its metadata at version {start_version} \
             so clients past the old versions still accept it (nodes must still be re-pinned to \
             the new root)",
            live.describe_present()
        );
    }

    // Mint the role keys into a private staging directory inside --keys-dir, then build an empty
    // signed repository in a throwaway temp dir. Nothing lands in --keys-dir until the repository
    // is published, so an attempt whose publish fails leaves the directory exactly as it found it
    // and the identical re-run completes the bootstrap.
    let pending = PendingRoleKeys::mint(&backend.keys_dir).await?;
    let repo_dir = tempfile::tempdir()?;
    repo::init_from_version(
        repo_dir.path(),
        pending.keys(),
        args.expiry_days,
        start_version,
    )
    .await?;
    let root_json = repo::root_bytes(repo_dir.path()).await?;

    updatec::runtime::publish_repository(store.as_ref(), &destination, repo_dir.path()).await?;
    eprintln!(
        "initialized release repository at s3://{}/{}",
        backend.bucket, backend.prefix
    );

    // The repository is published, so the staged keys are now the only copy of a live trust root's
    // role keys — they are delivered BEFORE anything else this command does. Emitting root.json can
    // fail for its own routine reasons (a missing `--root-out` parent, EPIPE on a piped stdout), and
    // every one of those failures returns before `commit`, which is where the keys are placed:
    // losing them strands a published repository that can never be signed into or rotated again.
    // The root document itself is recoverable — it is served at metadata/root.json under the very
    // prefix that was just published — so it is the emission, not the delivery, that goes second.
    pending.commit().map_err(|error| {
        format!(
            "{error}\nThe root document was not emitted; it can be fetched from \
             metadata/root.json under s3://{}/{}, so the groups can still be pinned — only the \
             keys are unplaced.",
            backend.bucket, backend.prefix
        )
    })?;
    eprintln!("minted fresh role keys in {}", backend.keys_dir.display());

    emit_root(
        &root_json,
        args.root_out.as_deref(),
        args.output,
        serde_json::json!({
            "bucket": backend.bucket,
            "prefix": backend.prefix,
            "keysDir": backend.keys_dir,
        }),
    )
    .await
}

pub(crate) async fn rotate_root(args: RotateRootArgs) -> Result<(), Error> {
    let backend = &args.backend;

    // Nothing is minted, signed or uploaded until the destination for the successor key is known
    // to be free: the key that ends up at --new-key-out must be one this ceremony minted.
    ensure_new_key_out_is_free(&args.new_key_out)?;
    let (destination, store) = build_store(backend)?;

    // The current root must carry two keys (active + standby) so one can sign the transition.
    let keys = repo::Keys::in_dir(&backend.keys_dir)?;
    if keys.roots.len() < 2 {
        return Err(format!(
            "--keys-dir {} does not hold a standby root key (root.next.pk8); the root was \
             minted single-key and cannot be rotated in place — re-mint with `trust-root`",
            backend.keys_dir.display()
        )
        .into());
    }

    // Pull the current metadata so the new root version bumps from it.
    let checkout = checkout_metadata(store.as_ref(), &destination, backend).await?;

    // Mint the successor into a private staging file, then publish a new root version co-signed by
    // the retained standby (which retires the old active key) and the successor. The staged key
    // only moves to --new-key-out after the publish lands; an attempt that fails removes it, so
    // the retry is a plain re-run that mints again.
    let pending = PendingRootKey::mint(&args.new_key_out).await?;
    let retained = &keys.roots[1..];
    repo::rotate_root(checkout.path(), retained, pending.path(), args.expiry_days).await?;
    let root_json = repo::root_bytes(checkout.path()).await?;
    checkout.publish(store.as_ref(), &destination).await?;
    pending.commit()?;

    eprintln!(
        "rotated root at s3://{}/{}; minted successor key at {}",
        backend.bucket,
        backend.prefix,
        args.new_key_out.display()
    );
    eprintln!(
        "in Vault: promote the standby (root.next.pk8) to active (root.pk8), then install {} \
         as the new root.next.pk8",
        args.new_key_out.display()
    );
    eprintln!("existing devices follow the new root automatically; no group changes needed");

    emit_root(
        &root_json,
        args.root_out.as_deref(),
        args.output,
        serde_json::json!({
            "bucket": backend.bucket,
            "prefix": backend.prefix,
            "newKeyOut": args.new_key_out,
        }),
    )
    .await
}

/// Deliver the root document a ceremony just signed: to `--root-out` when the operator named a
/// file, to stdout when the run is human-readable and named none, and inside the JSON summary when
/// the run is machine-readable. `context` carries the keys that differ per ceremony.
pub(crate) async fn emit_root(
    root_json: &[u8],
    root_out: Option<&Path>,
    output: OutputFormat,
    context: serde_json::Value,
) -> Result<(), Error> {
    match root_out {
        Some(path) => {
            tokio::fs::write(path, root_json).await?;
            eprintln!("wrote root.json to {}", path.display());
        }
        None if output == OutputFormat::Text => {
            use std::io::Write;
            std::io::stdout().write_all(root_json)?;
        }
        None => {}
    }
    if output == OutputFormat::Json {
        let mut document = context;
        document["root"] = String::from_utf8_lossy(root_json).into_owned().into();
        println!("{}", serde_json::to_string(&document)?);
    }
    Ok(())
}
