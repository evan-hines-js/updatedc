//! Content-identity of *files*: the streaming SHA-256 that hashes bytes off a disk handle.
//!
//! The digest primitive itself is not here. It lives in [`updated_contracts::digest`], at the
//! bottom of the stack where the protocol types that carry digests can reach it, so there is one
//! SHA-256 implementation and one canonical spelling for every consumer. This module adds only
//! what needs a filesystem — which is exactly why it cannot live down there — and it streams
//! through the same hasher, so a file digest and an in-memory digest of the same bytes are the same
//! identity by construction.

use std::io::{self, Read, Seek};
use std::path::Path;

use updated_contracts::digest::Sha256Hasher;

/// Streaming SHA-256 of the file at `path`, canonical lowercase hex.
pub fn sha256_file(path: &Path) -> io::Result<String> {
    let mut file = foundation::file::open_regular(path, foundation::file::FinalSymlink::Refuse)?;
    sha256_file_handle(&mut file).map(|(digest, _)| digest)
}

/// Hash one already-open regular file and leave it rewound for the operation that consumes the
/// authenticated bytes. The returned length and digest are derived from the same handle, closing
/// the verify-then-reopen race at every downloaded-target boundary.
pub fn sha256_file_handle(file: &mut std::fs::File) -> io::Result<(String, u64)> {
    file.rewind()?;
    let mut hasher = Sha256Hasher::new();
    let mut buf = [0u8; 64 * 1024];
    let mut length = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        length = length
            .checked_add(n as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "file length overflow"))?;
    }
    file.rewind()?;
    Ok((hasher.finish_hex(), length))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_and_its_bytes_have_one_content_identity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("known");
        std::fs::write(&path, b"the exact bytes").unwrap();

        // Pin the actual digest: a hasher returning a constant, or one that stopped reading the
        // file body, would not produce this exact hex.
        let digest = sha256_file(&path).unwrap();
        assert_eq!(
            digest,
            "70c940552e567905b6e8321e87284124ba5753614a7c8f16dc56538a00173c36"
        );
        assert_eq!(
            digest,
            updated_contracts::digest::sha256_bytes(b"the exact bytes")
        );
    }

    #[test]
    fn hashing_a_handle_reports_its_length_and_rewinds_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sized");
        std::fs::write(&path, b"the exact bytes").unwrap();

        let mut file = std::fs::File::open(&path).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        // Already at EOF: the digest must still cover the whole file, and the handle must come
        // back positioned for the consumer of the authenticated bytes.
        let (digest, length) = sha256_file_handle(&mut file).unwrap();
        assert_eq!(length, 15);
        assert_eq!(digest, sha256_file(&path).unwrap());
        let mut rest = Vec::new();
        file.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"the exact bytes");
    }
}
