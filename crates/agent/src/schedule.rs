use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

pub(crate) fn jitter(duration: Duration, percent: u32) -> Duration {
    let entropy = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos() as u64)
        ^ (u64::from(std::process::id()) << 32);
    jitter_with(duration, percent, entropy)
}

/// Stable fleet spreading for work whose cadence should survive process restarts. The node identity
/// chooses one offset inside the jitter window, so peers do not stampede while one node does not
/// randomly move its schedule on every refresh.
pub(crate) fn jitter_for_key(duration: Duration, percent: u32, key: &str) -> Duration {
    let entropy = key.bytes().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0000_0100_0000_01b3)
    });
    jitter_with(duration, percent, entropy)
}

/// The pure jitter computation, taking its entropy explicitly so the arithmetic is
/// deterministically testable (`jitter` supplies wall-clock nanoseconds XOR the PID).
fn jitter_with(duration: Duration, percent: u32, entropy: u64) -> Duration {
    if duration.is_zero() || percent == 0 {
        return duration;
    }
    let span = u64::from(percent) * 2 + 1;
    let signed = (mix(entropy) % span) as i64 - i64::from(percent);
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
    foundation::time::exponential_backoff(base, failures, 6, Duration::from_secs(15 * 60))
}

// ------------------------------- async waits --------------------------------

/// Sleep, returning `true` early if shutdown was requested.
pub(crate) async fn sleep_interruptible(delay: Duration, shutdown: &AtomicBool) -> bool {
    let deadline = Instant::now() + delay;
    while Instant::now() < deadline {
        if shutdown.load(Ordering::SeqCst) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    shutdown.load(Ordering::SeqCst)
}

/// Resolve when the OS asks the agent to stop.
#[cfg(unix)]
pub(crate) async fn wait_for_shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => return,
    };
    let mut int = match signal(SignalKind::interrupt()) {
        Ok(s) => s,
        Err(_) => return,
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}
#[cfg(windows)]
pub(crate) async fn wait_for_shutdown_signal() {
    use tokio::signal::windows::{ctrl_c, ctrl_close, ctrl_shutdown};
    let (mut c, mut close, mut down) = match (ctrl_c(), ctrl_close(), ctrl_shutdown()) {
        (Ok(c), Ok(close), Ok(down)) => (c, close, down),
        _ => return,
    };
    tokio::select! {
        _ = c.recv() => {}
        _ = close.recv() => {}
        _ = down.recv() => {}
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
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
        // Bounded so a residue the mixer never produces fails fast instead of hanging the test.
        // The spans here are tiny (a handful of buckets), so a match appears almost immediately.
        (0u64..1 << 20)
            .find(|&e| mix(e) % span == residue)
            .unwrap_or_else(|| {
                panic!("no entropy in [0, 2^20) maps to residue {residue} mod {span}")
            })
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

    #[test]
    fn keyed_jitter_is_stable_for_a_node() {
        let interval = Duration::from_secs(300);
        assert_eq!(
            jitter_for_key(interval, 10, "node-a"),
            jitter_for_key(interval, 10, "node-a")
        );
        assert_ne!(
            jitter_for_key(interval, 10, "node-a"),
            jitter_for_key(interval, 10, "node-b")
        );
    }
}
