//! The one value the lifecycle fixture and the demo that publishes it must agree on.

/// The deployment-command timeout the demo publishes with `updatectl deploy --timeout-seconds`.
/// The native runtime bounds command execution, so one `converge` — fixed steps and both dwells — must finish
/// inside it or a healthy release is killed mid-convergence and the cohort rolls back.
pub const PROVIDER_TIMEOUT_MS: u64 = 25_000;
