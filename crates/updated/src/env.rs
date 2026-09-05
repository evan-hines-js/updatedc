//! Environment variable names the update tower still uses, in one place.
//!
//! The program that *sets* a variable and the program that *reads* it — the agent and its tests —
//! reference these constants instead of string literals, so a rename can never desync them. All
//! share the `UPDATED_` prefix.
//!
//! A reconciler is told everything it needs on argv, under the one
//! invocation environment [`crate::reconciler::configure_environment`] builds — a cleared environment
//! plus a minimal search path and the deployment's secrets — so nothing in this file crosses that
//! boundary either.

/// Persistent agent state supplied by the platform service definition.
pub const STATE_DIR: &str = "UPDATED_STATE_DIR";

// ── test-only fault injection ──────────────────────────────────────────────────

/// Transaction boundary at which the agent should crash, for recovery tests.
pub const CHAOS_POINT: &str = "UPDATED_CHAOS_POINT";

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn every_var_is_prefixed() {
        assert!(
            CHAOS_POINT.starts_with("UPDATED_"),
            "{CHAOS_POINT} must use the UPDATED_ prefix"
        );
        assert!(STATE_DIR.starts_with("UPDATED_"));
    }
}
