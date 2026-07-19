//! Offline key generation — the standalone "mint the signing keys" step, independent of S3
//! or Kubernetes. This is the same key material the dev/mock `server` mints, made a
//! first-class part of the production CLI so keys can be generated on a trusted machine and
//! loaded into Vault without going near the demo server.
//!
//! `trust-root` still mints inline for a one-shot bootstrap; `keygen` is the seam for the
//! Vault-first flow: generate here, load into Vault, then `trust-root`/`deploy` read the
//! keys back from a mount.

use std::path::{Path, PathBuf};

use clap::Args;
use updated_tuf::repo;

use crate::{Error, OutputFormat};

#[derive(Args, Debug)]
pub(crate) struct KeygenArgs {
    /// Directory to mint the ed25519 role keys into: `root.pk8` (active) and `root.next.pk8`
    /// (side-by-side rotation standby), plus `targets.pk8`, `snapshot.pk8`, `timestamp.pk8`.
    /// Existing key files are validated and kept, so the command is idempotent.
    #[arg(long, env = "UPDATECTL_KEYS_DIR")]
    keys_dir: PathBuf,

    /// Result format written to stdout. Diagnostics always go to stderr.
    #[arg(long, value_enum, env = "UPDATECTL_OUTPUT", default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

pub(crate) async fn run(args: KeygenArgs) -> Result<(), Error> {
    let keys = repo::generate_keys(&args.keys_dir).await?;
    let paths = key_paths(&keys);
    for path in &paths {
        eprintln!("role key: {}", path.display());
    }
    eprintln!(
        "keep these private — load them into Vault (or your secret store); only \
         `targets/snapshot/timestamp` are needed by `deploy`, the root keys only by \
         `trust-root`/`rotate-root`"
    );

    match args.output {
        OutputFormat::Text => println!("keys_dir={}", args.keys_dir.display()),
        OutputFormat::Json => {
            let names: Vec<String> = paths.iter().map(|path| path.display().to_string()).collect();
            let document = serde_json::json!({
                "keysDir": args.keys_dir,
                "keys": names,
            });
            println!("{}", serde_json::to_string(&document)?);
        }
    }
    Ok(())
}

/// The full role key set in a stable order: root keys first, then the online roles.
fn key_paths(keys: &repo::Keys) -> Vec<&Path> {
    let mut paths: Vec<&Path> = keys.roots.iter().map(PathBuf::as_path).collect();
    paths.push(&keys.targets);
    paths.push(&keys.snapshot);
    paths.push(&keys.timestamp);
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn keygen_mints_the_full_role_set() {
        let dir = std::env::temp_dir().join(format!(
            "updatectl-keygen-{}-{}",
            std::process::id(),
            updated::rand::token().unwrap()
        ));
        run(KeygenArgs {
            keys_dir: dir.clone(),
            output: OutputFormat::Text,
        })
        .await
        .unwrap();

        for name in [
            "root.pk8",
            "root.next.pk8",
            "targets.pk8",
            "snapshot.pk8",
            "timestamp.pk8",
        ] {
            assert!(dir.join(name).exists(), "{name} was minted");
        }
    }

    #[tokio::test]
    async fn keygen_is_idempotent() {
        let dir = std::env::temp_dir().join(format!(
            "updatectl-keygen-idem-{}-{}",
            std::process::id(),
            updated::rand::token().unwrap()
        ));
        let args = || KeygenArgs {
            keys_dir: dir.clone(),
            output: OutputFormat::Text,
        };
        run(args()).await.unwrap();
        let before = std::fs::read(dir.join("root.pk8")).unwrap();
        // A second run keeps the existing keys rather than regenerating them.
        run(args()).await.unwrap();
        assert_eq!(before, std::fs::read(dir.join("root.pk8")).unwrap());
    }
}
