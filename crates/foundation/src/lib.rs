//! Dependency-isolated mechanisms shared across the permanent-guardian boundary.
//!
//! This crate may use `std` and operating-system bindings only. It contains no
//! application policy, wire protocol, configuration, serialization, or runtime.

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
