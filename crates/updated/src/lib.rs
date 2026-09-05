#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

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
//! ownership lives in release reconciler hooks; persistent node identity lives in agent state.

pub mod bundle;
pub mod bundle_store;
pub mod command_adapter;
pub mod config;
pub mod csr;
pub mod enrollment;
pub mod env;
pub mod gc;
pub mod hash;
pub mod helper;
pub mod http;
pub mod install;
pub mod journal;
pub mod lock;
pub mod native_runtime;
pub mod rand;
pub mod reconciler;
pub mod reject;
pub mod state;
#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod testing;
pub mod tls;
pub mod transaction;
