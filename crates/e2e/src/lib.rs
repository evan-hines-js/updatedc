//! Shared e2e harness library. `harness` holds the low-level process / TUF / HTTP primitives
//! (Ctx, Proc, Service, publish, serve, waits); `fixtures` holds the `Sup` supervisor+guardian
//! config builder and version-path helpers. Both the e2e scenario runner (`src/main.rs`) and the
//! standalone kill fuzzer (`crates/killfuzz`) depend on this library so the fragile TUF/guardian
//! setup lives in exactly one place.
pub mod fixtures;
pub mod harness;
