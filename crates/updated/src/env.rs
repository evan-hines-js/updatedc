//! Environment variable names the update tower still uses, in one place.
//!
//! The program that *sets* a variable and the program that *reads* it — the
//! supervisor, the managed application, and the tests — all
//! reference these constants instead of string literals, so a rename can never desync
//! them. All share the `UPDATED_` prefix.
//!
//! The guardian⇄supervisor launch contract (the control-channel endpoint, the
//! readiness nonce, the state directory) lives in the frozen `control` crate, not
//! here — the guardian depends on nothing in this crate.

// ── supervisor → managed application: health proof ─────────────────────────────

/// Per-launch random token the supervisor puts in the application's environment; the
/// app echoes it in its health response ([`crate::health::TOKEN_HEADER`]) so the
/// supervisor knows the answer came from the exact process it launched.
pub const HEALTH_TOKEN: &str = "UPDATED_HEALTH_TOKEN";

// ── supervisor → managed application ───────────────────────────────────────────

/// Root of the managed installation.
pub const INSTALL_ROOT: &str = "UPDATED_INSTALL_ROOT";

// ── test-only fault injection ──────────────────────────────────────────────────

/// Transaction boundary at which the supervisor should crash, for recovery tests.
pub const CHAOS_POINT: &str = "UPDATED_CHAOS_POINT";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_var_is_prefixed() {
        for var in [HEALTH_TOKEN, INSTALL_ROOT, CHAOS_POINT] {
            assert!(
                var.starts_with("UPDATED_"),
                "{var} must use the UPDATED_ prefix"
            );
        }
    }
}
