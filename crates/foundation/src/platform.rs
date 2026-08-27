//! Shared platform naming conventions.
//!
//! These are the small strings that more than one crate must agree on *by construction*,
//! not by two copies of the same `cfg!` happening to match. The agent binary's
//! filename, for instance, is written by the agent's self-update staging and read
//! back by the launcher's validation — a drift between them would strand every update.

/// The `"{os}-{arch}"` key that names a platform's release bundle (e.g. `linux-x86_64`).
/// The agent requests bundles by this key and the control plane selects provider bundles
/// against it, so every side must derive it the same way.
pub fn platform_key() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// The agent executable's on-disk filename for this platform. Staged under a
/// content-addressed directory by self-update and validated by the launcher; both link
/// this crate, so they cannot disagree.
pub fn agent_binary_name() -> &'static str {
    if cfg!(windows) {
        "updated-agent.exe"
    } else {
        "updated-agent"
    }
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

    #[test]
    fn agent_binary_name_matches_the_platform() {
        let name = agent_binary_name();
        if cfg!(windows) {
            assert_eq!(name, "updated-agent.exe");
        } else {
            assert_eq!(name, "updated-agent");
        }
    }
}
