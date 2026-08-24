//! Reusable node-side installation primitives shared by the agent:
//! crash-safe filesystem replacement, a single-instance lock,
//! health-rejection tracking, the committed
//! installed-state record, and the operator-config loader (which also resolves
//! the tower's canonical on-disk paths).
//!
//! Cross-process artifact, enrollment, and telemetry contracts live in
//! [`updated-contracts`](../updated_contracts/index.html); this crate is not a compatibility facade
//! for those protocol definitions.
//!
//! The trust and download path — authenticating releases and streaming verified
//! target bytes — lives in [`updated-tuf`](../updated_tuf/index.html) on top of
//! TUF. This crate is everything that happens *after* verified bytes are staged
//! on disk, plus the small OS glue the agent needs. Application process
//! ownership and boot-safe identity now live in the launcher (`launcher`), not here.

pub mod bundle;
pub mod config;
pub mod csr;
pub mod enrollment;
pub mod env;
pub mod gc;
pub mod hash;
pub mod http;
pub mod install;
pub mod journal;
pub mod lock;
pub mod provider;
pub mod rand;
pub mod reconciler;
pub mod reject;
pub mod state;
#[cfg(test)]
mod testing;
pub mod tls;
pub mod transaction;
