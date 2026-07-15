use std::time::Duration;

pub fn exponential_backoff(
    base: Duration,
    failures: u32,
    max_shift: u32,
    cap: Duration,
) -> Duration {
    let factor = 1u32
        .checked_shl(failures.min(max_shift))
        .unwrap_or(u32::MAX);
    base.saturating_mul(factor).min(cap)
}
