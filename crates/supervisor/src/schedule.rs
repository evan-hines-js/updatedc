use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub(crate) fn jitter(duration: Duration, percent: u32) -> Duration {
    let tick = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64);
    jitter_with(
        duration,
        percent,
        tick ^ (u64::from(std::process::id()) << 32),
    )
}

/// The pure jitter computation, taking its entropy explicitly so the arithmetic is
/// deterministically testable (`jitter` supplies wall-clock nanoseconds XOR the PID).
fn jitter_with(duration: Duration, percent: u32, entropy: u64) -> Duration {
    if duration.is_zero() || percent == 0 {
        return duration;
    }
    let x = mix(entropy);
    let span = u64::from(percent) * 2 + 1;
    let signed = (x % span) as i64 - i64::from(percent);
    let millis = duration.as_millis().min(u128::from(u64::MAX)) as u64;
    let delta = millis.saturating_mul(signed.unsigned_abs()) / 100;
    Duration::from_millis(if signed < 0 {
        millis.saturating_sub(delta)
    } else {
        millis.saturating_add(delta)
    })
}

fn mix(mut seed: u64) -> u64 {
    seed ^= seed << 13;
    seed ^= seed >> 7;
    seed ^= seed << 17;
    seed
}

pub(crate) fn network_backoff(base: Duration, failures: u32) -> Duration {
    let factor = 1u32.checked_shl(failures.min(6)).unwrap_or(64);
    base.saturating_mul(factor)
        .min(Duration::from_secs(15 * 60))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn now_unix_reads_the_wall_clock() {
        // A real Unix timestamp, not a stubbed constant (lower bound: 2023-11-14).
        assert!(now_unix() >= 1_700_000_000);
    }

    #[test]
    fn mix_matches_pinned_reference_vectors() {
        // Dense inputs so a flipped xor/or/and or a reversed shift changes the output.
        assert_eq!(mix(0x0123_4567_89ab_cdef), 0x3f28_00d6_569e_01b4);
        assert_eq!(mix(0xffff_ffff_ffff_ffff), 0x0000_0000_3f80_1fc0);
        assert_eq!(mix(0xdead_beef_cafe_babe), 0x27dc_5c1b_2d04_284b);
    }

    fn entropy_for_residue(span: u64, residue: u64) -> u64 {
        (0u64..).find(|&e| mix(e) % span == residue).unwrap()
    }

    #[test]
    fn jitter_spans_exactly_plus_or_minus_percent() {
        let base = Duration::from_millis(1000);
        let span = 21; // percent = 10 -> 2*10 + 1
                       // Smallest residue is the full negative swing, largest the full positive, the
                       // midpoint no change — pinning the exact edges of the ±10% window.
        assert_eq!(
            jitter_with(base, 10, entropy_for_residue(span, 0)),
            Duration::from_millis(900)
        );
        assert_eq!(
            jitter_with(base, 10, entropy_for_residue(span, 20)),
            Duration::from_millis(1100)
        );
        assert_eq!(
            jitter_with(base, 10, entropy_for_residue(span, 10)),
            Duration::from_millis(1000)
        );
    }

    #[test]
    fn jitter_is_identity_when_disabled() {
        // Zero duration or zero percent returns the input untouched, for any entropy.
        assert_eq!(jitter_with(Duration::ZERO, 10, 12345), Duration::ZERO);
        assert_eq!(
            jitter_with(Duration::from_millis(500), 0, 12345),
            Duration::from_millis(500)
        );
    }
}
