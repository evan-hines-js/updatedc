//! Cryptographically-random identifiers used across the tower.
//!
//! Unique, unguessable names for ephemeral artifacts — per-attempt lifecycle IDs and scratch
//! paths — so two concurrent operations never collide and a stale one can't be mistaken for a
//! fresh one. They are not a sandbox boundary against code running as the
//! same OS identity. The deliberately dependency-free launcher has its own freshness nonce.

use std::io;

use aws_lc_rs::rand;

/// A fresh 256-bit random token, hex-encoded.
pub fn token() -> io::Result<String> {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes).map_err(|e| io::Error::other(format!("randomness: {e}")))?;
    Ok(hex::encode(bytes))
}

/// Whether a value could have been emitted by [`token`].
///
/// The one reader-side grammar for everything [`token`] produces: durable attempt identities on
/// deserialization (journals, installed rollback intent), and capability tokens on the way back in
/// off the wire. All of them become filenames, map keys, or reconciler idempotency keys, so none of
/// them may be an arbitrary non-empty string.
///
/// Public because the check has to live where the *producer* lives. A consumer that spells the
/// grammar out for itself — "64 characters, hexadecimal" — is a second definition that drifts:
/// `is_ascii_hexdigit` accepts uppercase, [`token`] never emits it, and the two disagree about
/// whether `A9…` is a token this system could have issued.
pub fn is_token(value: &str) -> bool {
    updated_contracts::is_canonical_sha256(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokens_are_fresh_and_full_width() {
        let a = token().unwrap();
        let b = token().unwrap();
        assert_eq!(a.len(), 64, "256 bits as hex");
        assert_ne!(a, b, "two tokens must not collide");
        assert!(is_token(&a));
        assert!(!is_token("attempt"));
    }
}
