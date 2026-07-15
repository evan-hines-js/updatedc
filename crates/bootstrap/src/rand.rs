//! Freshness nonces for the control protocol.
//!
//! A nonce here proves *recency*, not secrecy: it lets the guardian tell this
//! launch's readiness acknowledgement apart from a stale one left by a previous
//! attempt, over a private inherited channel that no attacker can reach. So it needs
//! to be unique across launches and guardian restarts, not cryptographically random —
//! which is why it can be a dependency-free mix of wall-clock nanoseconds, the PID,
//! and a monotonic counter rather than a draw from a crypto library.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use control::Nonce;

/// A fresh 16-byte nonce, unique across launches and restarts.
pub fn nonce() -> Nonce {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let pid = std::process::id() as u64;
    let mut a = splitmix64(nanos ^ (pid.rotate_left(32)));
    let mut b = splitmix64(seq.wrapping_add(nanos).wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let mut out = [0u8; 16];
    // Two independently seeded 64-bit streams fill the 16 bytes.
    a = splitmix64(a);
    b = splitmix64(b);
    out[..8].copy_from_slice(&a.to_le_bytes());
    out[8..].copy_from_slice(&b.to_le_bytes());
    out
}

/// Lowercase hex of a nonce, to pass the readiness nonce to the supervisor by env.
pub fn to_hex(nonce: &Nonce) -> String {
    let mut s = String::with_capacity(32);
    for b in nonce {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonces_are_fresh() {
        let a = nonce();
        let b = nonce();
        assert_ne!(a, b, "two nonces must not collide");
    }

    #[test]
    fn hex_is_full_width() {
        assert_eq!(to_hex(&[0u8; 16]).len(), 32);
        assert_eq!(to_hex(&[0xABu8; 16]), "ab".repeat(16));
    }

    #[test]
    fn splitmix64_matches_its_published_reference_vectors() {
        // Pin the mixer because weakening it can collapse independently seeded nonce
        // streams into correlated values while a two-sample freshness test still passes.
        assert_eq!(splitmix64(0), 0xe220_a839_7b1d_cdaf);
        assert_eq!(splitmix64(1), 0x910a_2dec_8902_5cc1);
        assert_eq!(splitmix64(u64::MAX), 0xe4d9_7177_1b65_2c20);
    }
}
