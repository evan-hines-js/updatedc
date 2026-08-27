#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Dependency-isolated mechanisms shared across the permanent-launcher boundary.
//!
//! This crate may use `std` and operating-system bindings only. It contains no
//! application policy, wire protocol, configuration, serialization, or runtime.
//!
//! # Rollout rule
//!
//! Consumers statically link their own copy and commonly run different foundation
//! versions. Compatibility is intentionally asymmetric: a routine tower upgrade must
//! never require redeploying the launcher. A rare launcher/OS upgrade may establish a
//! new baseline and require coordinated tower binaries, because that deployment can
//! carry them together. Shared wire formats and cross-process compatibility contracts
//! still belong in dedicated versioned crates such as `control`, where that transition
//! can be negotiated explicitly.

pub mod digest;
pub mod durable;
pub mod file;
pub mod log;
pub mod manifest;
pub mod platform;
pub mod process;
pub mod time;

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod dependency_isolation {
    const MANIFEST: &str = include_str!("../Cargo.toml");
    const ALLOWED: &[&str] = &["libc", "windows-sys"];

    #[test]
    fn depends_only_on_system_bindings() {
        for name in crate::manifest::shipped_dependency_names(MANIFEST) {
            assert!(
                ALLOWED.contains(&name),
                "foundation must not depend on {name:?}"
            );
        }
    }
}
