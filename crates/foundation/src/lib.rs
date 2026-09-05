#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Dependency-isolated operating-system mechanisms shared by runtime crates.
//!
//! This crate may use `std` and operating-system bindings only. It contains no
//! application policy, wire protocol, configuration, serialization, or runtime.
//!
//! Consumers statically link their own copy. Shared wire formats and cross-process compatibility
//! contracts belong in dedicated versioned crates such as `updated-contracts`.

pub mod boot;
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
