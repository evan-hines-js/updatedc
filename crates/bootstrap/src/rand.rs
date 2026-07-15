//! Freshness nonces for the private inherited control channel.
//!
//! These prove recency, not secrecy, so wall-clock nanoseconds, PID, and a process
//! sequence are sufficient; cryptographic randomness would add policy and dependencies.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use control::Nonce;

pub fn nonce() -> Nonce {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0);
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let pid = u64::from(std::process::id());
    let a = splitmix64(splitmix64(nanos ^ pid.rotate_left(32)));
    let b = splitmix64(splitmix64(
        sequence
            .wrapping_add(nanos)
            .wrapping_mul(0x9E37_79B9_7F4A_7C15),
    ));
    let mut out = [0; 16];
    out[..8].copy_from_slice(&a.to_le_bytes());
    out[8..].copy_from_slice(&b.to_le_bytes());
    out
}

pub fn to_hex(nonce: &Nonce) -> String {
    let mut out = String::with_capacity(nonce.len() * 2);
    for byte in nonce {
        out.push(char::from_digit((byte >> 4) as u32, 16).unwrap());
        out.push(char::from_digit((byte & 0xf) as u32, 16).unwrap());
    }
    out
}

fn splitmix64(mut value: u64) -> u64 {
    value = value.wrapping_add(0x9E37_79B9_7F4A_7C15);
    value = (value ^ (value >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonces_are_fresh_and_hex_is_full_width() {
        assert_ne!(nonce(), nonce());
        assert_eq!(to_hex(&[0xab; 16]), "ab".repeat(16));
    }

    #[test]
    fn splitmix64_matches_reference_vectors() {
        assert_eq!(splitmix64(0), 0xe220_a839_7b1d_cdaf);
        assert_eq!(splitmix64(1), 0x910a_2dec_8902_5cc1);
        assert_eq!(splitmix64(u64::MAX), 0xe4d9_7177_1b65_2c20);
    }
}
