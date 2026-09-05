//! Shared platform naming conventions.
//!
//! These are the small strings that more than one crate must agree on *by construction*,
//! not by two copies of the same `cfg!` happening to match.

/// The `"{os}-{arch}"` key that names a platform's release bundle (e.g. `linux-x86_64`).
/// The agent requests bundles by this key and the control plane selects provider bundles
/// against it, so every side must derive it the same way.
pub fn platform_key() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn platform_key_joins_os_and_arch() {
        let key = platform_key();
        assert!(key.contains('-'));
        assert!(key.starts_with(std::env::consts::OS));
        assert!(key.ends_with(std::env::consts::ARCH));
    }
}
