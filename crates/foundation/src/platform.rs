//! Shared platform naming conventions.
//!
//! These are the small strings that more than one crate must agree on *by construction*,
//! not by two copies of the same `cfg!` happening to match. The supervisor binary's
//! filename, for instance, is written by the supervisor's self-update staging and read
//! back by the guardian's validation — a drift between them would strand every update.

/// The `"{os}-{arch}"` key that names a platform's release bundle (e.g. `linux-x86_64`).
/// The agent requests bundles by this key and the control plane selects provider bundles
/// against it, so every side must derive it the same way.
pub fn platform_key() -> String {
    format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH)
}

/// The supervisor executable's on-disk filename for this platform. Staged under a
/// content-addressed directory by self-update and validated by the guardian; both link
/// this crate, so they cannot disagree.
pub fn supervisor_binary_name() -> &'static str {
    if cfg!(windows) {
        "supervisor.exe"
    } else {
        "supervisor"
    }
}

#[cfg(test)]
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
    fn supervisor_binary_name_matches_the_platform() {
        let name = supervisor_binary_name();
        if cfg!(windows) {
            assert_eq!(name, "supervisor.exe");
        } else {
            assert_eq!(name, "supervisor");
        }
    }
}
