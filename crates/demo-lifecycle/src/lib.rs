//! The one value the lifecycle fixture and the demo that publishes it must agree on.

/// The provider execution timeout the demo signs into its provider sets
/// (`updatectl publish-provider-set --provider-timeout-ms`). The agent bounds the *entire*
/// hook invocation by it, so one `apply` — every fixed step plus BOTH dwells — must finish inside
/// it or a healthy release is killed mid-apply and the cohort rolls back.
pub const PROVIDER_TIMEOUT_MS: u64 = 15_000;
