//! The readiness contract between a supervisor and its child.
//!
//! Health is a plain HTTP readiness check: the supervisor GETs the app's configured URL and
//! any 2xx is healthy. An app the supervisor happens to control *may* additionally echo
//! [`crate::env::HEALTH_TOKEN`] in the [`TOKEN_HEADER`] header (and its version in
//! [`VERSION_HEADER`]); when present, the supervisor verifies them, catching a forged or
//! stale process answering on the port. When absent — as with any off-the-shelf app — the
//! supervisor trusts the 2xx alone and never forces the protocol onto the app. The env var
//! name lives in [`crate::env`] with every other tower variable; the header names live here.

/// Optional response header by which an app can echo the health token the supervisor passed
/// in [`crate::env::HEALTH_TOKEN`]. Best-effort: absence is fine, a wrong value fails.
pub const TOKEN_HEADER: &str = "X-Updated-Token";
/// Baked application version returned by reload-capable services. Unlike the
/// launch token, this changes when a same-PID `exec` loads the candidate image.
pub const VERSION_HEADER: &str = "X-Updated-Version";
