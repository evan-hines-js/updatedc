//! Reusable client-side installation primitives shared by the supervisor:
//! crash-safe filesystem replacement, a single-instance lock, the health-proof
//! constants, health-rejection tracking, the committed
//! installed-state record, and the shared operator-config loader (which also resolves
//! the tower's canonical on-disk paths).
//!
//! The trust and download path — authenticating releases and streaming verified
//! target bytes — lives in [`updated-tuf`](../updated_tuf/index.html) on top of
//! TUF. This crate is everything that happens *after* verified bytes are staged
//! on disk, plus the small OS glue the supervisor needs. Application process
//! ownership and boot-safe identity now live in the guardian (`bootstrap`), not here.

pub mod bundle;
pub mod config;
pub mod env;
pub mod gc;
pub mod hash;
pub mod health;
pub mod lock;
pub mod on_launch;
pub mod provider;
pub mod rand;
pub mod reject;
pub mod state;
pub mod transaction;

/// Deserialize an optional value while still requiring the field itself to exist.
/// Serde otherwise treats a missing `Option<T>` as `None`, creating an implicit legacy
/// schema alongside the current durable format.
pub(crate) fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    <Option<T> as serde::Deserialize>::deserialize(deserializer)
}
