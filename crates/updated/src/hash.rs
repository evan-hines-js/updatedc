//! Content-identity of a file on disk: its streaming SHA-256, plus the single
//! "do these bytes match the digest we trust?" check the whole tower gates on
//! before it executes or commits an application binary — the supervisor and the
//! one-shot updater share one implementation so the trust boundary cannot drift.

use std::io::{self, Read};
use std::path::Path;

use aws_lc_rs::digest::{Context, SHA256};

/// Streaming SHA-256 of the file at `path`, lowercase hex.
pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut ctx = Context::new(&SHA256);
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    Ok(hex::encode(ctx.finish().as_ref()))
}

/// Whether the file at `path` hashes to `expected` (case-insensitive hex). A
/// missing or unreadable file, or any mismatch, is `false`. Use when a boolean
/// drift decision is all that's needed; use [`verify_file`] when the caller must
/// distinguish "wrong bytes" from "cannot read" or surface the mismatch as an error.
pub fn file_matches(path: &Path, expected: &str) -> bool {
    sha256_file(path).is_ok_and(|got| got.eq_ignore_ascii_case(expected))
}

/// Verify the file at `path` hashes to `expected`: propagate a read error, and
/// report a mismatch as an error naming both digests. Callers use this on the
/// commit/execute path where drifted or tampered bytes must fail closed.
pub fn verify_file(path: &Path, expected: &str) -> io::Result<()> {
    let got = sha256_file(path)?;
    if got.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "binary hash {got} != expected {expected}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("updated-hash-{}-{name}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn matches_and_verify_agree_on_known_bytes() {
        let f = tmp("known");
        std::fs::write(&f, b"the exact bytes").unwrap();
        // Pin the actual digest: a hasher returning a constant, or one that stopped
        // reading the file body, would not produce this exact hex.
        let want = sha256_file(&f).unwrap();
        assert_eq!(
            want,
            "70c940552e567905b6e8321e87284124ba5753614a7c8f16dc56538a00173c36"
        );

        assert!(file_matches(&f, &want));
        assert!(file_matches(&f, &want.to_uppercase())); // case-insensitive
        verify_file(&f, &want).unwrap();

        let wrong = "0".repeat(64);
        assert!(!file_matches(&f, &wrong));
        assert!(verify_file(&f, &wrong).is_err());
        let _ = std::fs::remove_file(&f);
    }

    #[test]
    fn missing_file_is_false_for_matches_and_error_for_verify() {
        let f = tmp("absent");
        assert!(!file_matches(&f, &"0".repeat(64)));
        assert!(verify_file(&f, &"0".repeat(64)).is_err());
    }
}
