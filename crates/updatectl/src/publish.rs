//! Build, sign, and publish a package. Return its immutable reference for deployment YAML.

use crate::*;

pub(crate) async fn publish(args: PublishArgs) -> Result<(), Error> {
    let backend = &args.backend;
    // Validate and snapshot generated execution metadata before network access or signing.
    let package = package::prepare(&args.source, &args.procedure)?;
    updated_contracts::identity::parse_release_version(&args.version).ok_or_else(|| {
        format!(
            "--version {:?} is not a bounded semantic version",
            args.version
        )
    })?;
    for (name, value) in [("product", &args.product), ("channel", &args.channel)] {
        if !updated_contracts::identity::is_segment(value) {
            return Err(format!("invalid --{name}: expected a portable identity").into());
        }
    }
    let platform = args
        .platform
        .clone()
        .unwrap_or_else(foundation::platform::platform_key);
    let (os, arch) = platform
        .split_once('-')
        .ok_or_else(|| format!("--platform must be <os>-<arch>, got {platform:?}"))?;

    // Build the bundle into a scratch dir, then register it as a signed target.
    let build_dir = tempfile::tempdir()?;
    let archive = build_dir.path().join("bundle.tar.zst");
    build_payload_bundle(
        &package.source,
        &archive,
        &args.product,
        &args.version,
        &platform,
    )?;

    let (destination, store, keys, checkout) = checkout_repository(backend).await?;

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

    // Upload immutable target bytes first and re-signed metadata last (timestamp is the
    // commit point). A concurrent publisher must abort rather than drop another release.
    checkout
        .publish(store.as_ref(), &destination, &keys, args.expiry_days)
        .await?;
    eprintln!("published signed target {target_name} (sha256 {sha256})");

    report_publish(&args, &platform, &target_name, &sha256)
}

/// Check out signed metadata and online signing keys for a CI publication.
pub(crate) async fn checkout_repository(
    backend: &Backend,
) -> Result<(S3Destination, Arc<dyn ObjectStore>, repo::Keys, Checkout), Error> {
    let (destination, store) = build_store(backend)?;
    let keys = open_keys(&backend.keys_dir)?;
    let checkout = checkout_metadata(store.as_ref(), &destination).await?;
    Ok((destination, store, keys, checkout))
}

/// One checked-out generation of a release repository's signed metadata.
///
/// Reject a stale checkout before uploading. The shared repository publisher owns the atomic
/// publication boundary: create-only versioned metadata and conditional root/timestamp writes
/// also reject a competing writer that races this preflight check.
pub(crate) struct Checkout {
    pub(crate) dir: tempfile::TempDir,
    pub(crate) generation: MetadataGeneration,
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
        keys: &repo::Keys,
        expiry_days: i64,
    ) -> Result<(), Error> {
        // Bounded recovery from interrupted uploads. Every retry uses the same shared signer
        // and publisher; only a typed online-metadata collision permits advancing the version.
        let mut retries = 0;
        loop {
            let live = MetadataGeneration::live(store, destination).await?;
            if let Some(document) = live.changed_document(&self.generation) {
                return Err(format!(
                "release repository at s3://{}/{} changed {document} while this publish was building \
                 and signing: another publisher is writing the same prefix. Refusing to commit this checkout \
                 — re-run this command once that publish has settled, and publish one release \
                 lineage from one place.",
                destination.bucket, destination.prefix
            )
            .into());
            }
            match updatec::runtime::publish_repository(store, destination, self.path()).await {
                Ok(()) => return Ok(()),
                Err(updatec::runtime::StorageError::OnlineMetadataConflict(_)) if retries < 8 => {
                    retries += 1;
                    repo::add_release(self.path(), keys, vec![], expiry_days).await?;
                }
                Err(error) => return Err(error.into()),
            }
        }
    }
}

/// Read one coherent repository generation before publishing a new package.
pub(crate) async fn checkout_metadata(
    store: &dyn ObjectStore,
    destination: &S3Destination,
) -> Result<Checkout, Error> {
    let repo_dir = tempfile::tempdir()?;
    let metadata_dir = repo_dir.path().join("metadata");
    tokio::fs::create_dir_all(&metadata_dir).await?;
    tokio::fs::create_dir_all(repo_dir.path().join("targets")).await?;
    let generation = MetadataGeneration::live(store, destination).await?;
    download_metadata(store, destination, &metadata_dir).await?;
    // A TUF generation is several objects. Refuse a checkout assembled while another publisher
    // was moving them rather than blessing a mixed local view as the generation we observed.
    let after = MetadataGeneration::live(store, destination).await?;
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

/// Emit the machine-readable publication result: a clean stdout payload (text or JSON) plus,
/// under GitHub Actions, `target`/`sha256`/`version` step outputs for later steps.
pub(crate) fn report_publish(
    args: &PublishArgs,
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
                "product": args.product,
                "channel": args.channel,
                "version": args.version,
                "platform": platform,
                "target": target,
                "sha256": sha256,
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
#[cfg_attr(coverage_nightly, coverage(off))]
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
