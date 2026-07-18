//! Environment variable names the update tower still uses, in one place.
//!
//! The program that *sets* a variable and the program that *reads* it — the
//! supervisor, the managed application, the operator transition adapter, the tests — all
//! reference these constants instead of string literals, so a rename can never desync
//! them. All share the `UPDATED_` prefix.
//!
//! The guardian⇄supervisor launch contract (the control-channel endpoint, the
//! readiness nonce, the state directory) lives in the frozen [`control`] crate, not
//! here — the guardian depends on nothing in this crate.

// ── supervisor → managed application: health proof ─────────────────────────────

/// Per-launch random token the supervisor puts in the application's environment; the
/// app echoes it in its health response ([`crate::health::TOKEN_HEADER`]) so the
/// supervisor knows the answer came from the exact process it launched.
pub const HEALTH_TOKEN: &str = "UPDATED_HEALTH_TOKEN";

// ── supervisor → operator transition adapter ──────────────────────────────────

/// PID of the running child, exposed to the operator's transition adapter.
pub const CHILD_PID: &str = "UPDATED_CHILD_PID";
/// Root of the managed installation, exposed to the operator's transition adapter.
pub const INSTALL_ROOT: &str = "UPDATED_INSTALL_ROOT";
/// Immutable directory of the release the command is being asked to activate.
pub const CANDIDATE: &str = "UPDATED_CANDIDATE";
/// Immutable directory of the release currently being replaced.
pub const PREDECESSOR: &str = "UPDATED_PREDECESSOR";
/// Semantic version of [`CANDIDATE`].
pub const CANDIDATE_VERSION: &str = "UPDATED_CANDIDATE_VERSION";
/// Semantic version of [`PREDECESSOR`].
pub const PREDECESSOR_VERSION: &str = "UPDATED_PREDECESSOR_VERSION";
/// Stable content-derived identity for one update attempt and its recovery retries.
pub const TRANSITION_ID: &str = "UPDATED_TRANSITION_ID";
/// Lifecycle phase requested from the operator transition adapter.
pub const TRANSITION_PHASE: &str = "UPDATED_TRANSITION_PHASE";

// ── test-only fault injection ──────────────────────────────────────────────────

/// Transaction boundary at which the supervisor should crash, for recovery tests.
pub const CHAOS_POINT: &str = "UPDATED_CHAOS_POINT";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_var_is_prefixed() {
        for var in [
            HEALTH_TOKEN,
            CHILD_PID,
            INSTALL_ROOT,
            CANDIDATE,
            PREDECESSOR,
            CANDIDATE_VERSION,
            PREDECESSOR_VERSION,
            TRANSITION_ID,
            TRANSITION_PHASE,
            CHAOS_POINT,
        ] {
            assert!(
                var.starts_with("UPDATED_"),
                "{var} must use the UPDATED_ prefix"
            );
        }
    }
}
