//! Shared e2e harness library. `harness` holds the low-level process / TUF / HTTP primitives
//! (Ctx, Proc, Service, publish, serve, waits); `fixtures` holds the `Node` launcher+agent config
//! builder and version-path helpers; `fixture` is the signed node reconciler every scenario runs —
//! the hook that owns the workload. Both drivers (the scenario runner in `src/main.rs` and the
//! standalone kill fuzzer in `crates/killfuzz`) depend on this library, so the fragile TUF/launcher
//! setup and the one reconciler implementation live in exactly one place.
pub mod fixture;
pub mod fixtures;
pub mod harness;
