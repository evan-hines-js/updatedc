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

/// SHA-256 of in-memory `bytes`, lowercase hex. Bundle manifests and release ids
/// digest small buffers; keeping this beside [`sha256_file`] means every digest the
/// tower trusts is produced in one place, so the trust boundary cannot drift.
pub fn sha256_bytes(bytes: &[u8]) -> String {
    use aws_lc_rs::digest::{digest, SHA256};
    hex::encode(digest(&SHA256, bytes).as_ref())
}

/// Whether `s` is a syntactically valid SHA-256 digest: exactly 64 ASCII hex
/// characters. The one definition of that shape, shared by the bundle manifest and
/// the rejection record.
pub fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
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
    fn file_and_byte_hashing_agree_on_known_bytes() {
        let f = tmp("known");
        std::fs::write(&f, b"the exact bytes").unwrap();
        // Pin the actual digest: a hasher returning a constant, or one that stopped
        // reading the file body, would not produce this exact hex.
        let want = sha256_file(&f).unwrap();
        assert_eq!(
            want,
            "70c940552e567905b6e8321e87284124ba5753614a7c8f16dc56538a00173c36"
        );

        // Streaming-file and in-memory hashing are the same content-identity.
        assert_eq!(sha256_bytes(b"the exact bytes"), want);
        verify_file(&f, &want).unwrap();
        verify_file(&f, &want.to_uppercase()).unwrap(); // case-insensitive

        assert!(verify_file(&f, &"0".repeat(64)).is_err());
        let _ = std::fs::remove_file(&f);
    }

    #[test]
    fn missing_file_is_error_for_verify() {
        let f = tmp("absent");
        assert!(verify_file(&f, &"0".repeat(64)).is_err());
    }

    #[test]
    fn is_sha256_hex_accepts_only_64_hex_chars() {
        assert!(is_sha256_hex(&"a".repeat(64)));
        assert!(is_sha256_hex(&"A".repeat(64))); // any ASCII hex case
        assert!(!is_sha256_hex(&"a".repeat(63)), "too short");
        assert!(!is_sha256_hex(&"a".repeat(65)), "too long");
        assert!(!is_sha256_hex(&format!("{}z", "a".repeat(63))), "non-hex");
    }
}
