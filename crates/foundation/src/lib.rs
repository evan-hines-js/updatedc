//! Dependency-isolated mechanisms shared across the permanent-guardian boundary.
//!
//! This crate may use `std` and operating-system bindings only. It contains no
//! application policy, wire protocol, configuration, serialization, or runtime.
//!
//! # Rollout rule
//!
//! Consumers statically link their own copy and commonly run different foundation
//! versions. Compatibility is intentionally asymmetric: a routine tower upgrade must
//! never require redeploying the guardian. A rare guardian/OS upgrade may establish a
//! new baseline and require coordinated tower binaries, because that deployment can
//! carry them together. Shared wire formats and cross-process compatibility contracts
//! still belong in dedicated versioned crates such as `control`, where that transition
//! can be negotiated explicitly.

pub mod durable;
pub mod log;
pub mod time;

#[cfg(test)]
mod dependency_isolation {
    const MANIFEST: &str = include_str!("../Cargo.toml");
    const ALLOWED: &[&str] = &["libc", "windows-sys"];

    #[test]
    fn depends_only_on_system_bindings() {
        let mut in_deps = false;
        for line in MANIFEST.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                in_deps = line.contains("dependencies");
                continue;
            }
            if !in_deps || line.is_empty() || line.starts_with('#') {
                continue;
            }
            let name = line.split(['=', '.', ' ']).next().unwrap_or("").trim();
            assert!(
                ALLOWED.contains(&name),
                "foundation must not depend on {name:?}"
            );
        }
    }
}
