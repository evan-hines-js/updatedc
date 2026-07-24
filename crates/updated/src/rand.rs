//! Cryptographically-random identifiers used across the tower.
//!
//! Unique, unguessable names for ephemeral artifacts — content-addressed staging directories
//! and per-attempt lifecycle IDs — so two concurrent operations never collide and a stale one
//! can't be mistaken for a fresh one. They are not a sandbox boundary against code running as the
//! same OS identity. The deliberately dependency-free bootstrap has its own freshness nonce.

use std::io;

use aws_lc_rs::rand;

/// A fresh 256-bit random token, hex-encoded.
pub fn token() -> io::Result<String> {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes).map_err(|e| io::Error::other(format!("randomness: {e}")))?;
    Ok(hex::encode(bytes))
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
    }
}
