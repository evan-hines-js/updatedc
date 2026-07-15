//! The instance-bound readiness contract between a supervisor and its child.
//!
//! The child proves an answer came from the exact process the supervisor launched by
//! echoing [`crate::env::HEALTH_TOKEN`] in the [`TOKEN_HEADER`] response header. The
//! token's env var name lives in [`crate::env`] with every other tower variable; the
//! HTTP header names live here.

/// Response header carrying the health token the supervisor passed in
/// [`crate::env::HEALTH_TOKEN`].
pub const TOKEN_HEADER: &str = "X-Updated-Token";
/// Baked application version returned by reload-capable services. Unlike the
/// launch token, this changes when a same-PID `exec` loads the candidate image.
pub const VERSION_HEADER: &str = "X-Updated-Version";
