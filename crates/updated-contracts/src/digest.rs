//! Content identity: the one SHA-256 implementation the whole system digests bytes with, and the
//! one grammar it spells the result in.
//!
//! It lives in the contracts crate because a digest is a *protocol* value long before it is a file:
//! an assignment names a release by it, an inventory revision is one, a telemetry report carries
//! three. Anything above this crate that hashed bytes on its own would be a second implementation
//! of the identity the trust boundary is built on, so there is no second implementation to reach
//! for — [`sha256_bytes`] and [`Sha256Hasher`] are the only ways to produce one, and
//! [`digests_match`] is the only way to come to a verdict about two.
//!
//! The purely lexical half of the rule ("what does a digest look like") lives lower still, in
//! `foundation`, because the permanent launcher must apply it without linking a crypto library.
//! [`is_canonical_sha256`] is re-exported here so callers have one name for it.

use aws_lc_rs::digest::{digest, Context, SHA256};

pub use foundation::digest::{is_canonical_sha256, parse_canonical_sha256};

/// SHA-256 of in-memory `bytes`, in the canonical lowercase-hex spelling.
pub fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(digest(&SHA256, bytes).as_ref())
}

/// An incremental SHA-256, for the digests computed over several fields or a stream rather than one
/// buffer. The same backend as [`sha256_bytes`], so a streamed digest and a one-shot digest of the
/// same bytes are the same identity by construction.
pub struct Sha256Hasher(Context);

impl Sha256Hasher {
    pub fn new() -> Self {
        Self(Context::new(&SHA256))
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    /// Consume the hasher and return the canonical lowercase-hex digest.
    pub fn finish_hex(self) -> String {
        hex::encode(self.0.finish().as_ref())
    }
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether two hex digests name the same content.
///
/// Every serialized digest boundary accepts only the canonical lowercase spelling. Rechecking that
/// grammar here means a locally corrupted durable value cannot regain an obsolete alias, while
/// keeping every trust-path comparison on one implementation.
pub fn digests_match(got: &str, expected: &str) -> bool {
    is_canonical_sha256(got) && is_canonical_sha256(expected) && got == expected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_shot_and_incremental_are_the_same_identity() {
        // Pin the actual digest: a hasher returning a constant, or one that dropped a chunk,
        // would not produce this exact hex.
        let want = "70c940552e567905b6e8321e87284124ba5753614a7c8f16dc56538a00173c36";
        assert_eq!(sha256_bytes(b"the exact bytes"), want);

        let mut hasher = Sha256Hasher::new();
        hasher.update(b"the exact ");
        hasher.update(b"bytes");
        assert_eq!(hasher.finish_hex(), want);
    }

    #[test]
    fn a_verdict_requires_two_canonical_spellings_of_the_same_digest() {
        let digest = sha256_bytes(b"the exact bytes");
        assert!(digests_match(&digest, &digest));
        assert!(!digests_match(&digest, &digest.to_uppercase()));
        assert!(!digests_match(&digest, &"0".repeat(64)));
        assert!(!digests_match("", ""));
    }
}
