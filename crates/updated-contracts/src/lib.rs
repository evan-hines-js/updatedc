//! Strict, versioned contracts shared across the node and control-plane boundary.
//!
//! This crate owns serialized protocol types and the validation/security rules required to
//! interpret them consistently. It deliberately contains no installation, process, filesystem,
//! HTTP-client, or Kubernetes behavior.
//!
//! It is also the single home of the two *grammar* primitives those rules are built from —
//! [`path`] confinement and [`is_sha256_hex`]. They live at the bottom of the dependency stack
//! precisely so a protocol check and the node-side code that later acts on the same value cannot
//! drift apart.

pub mod artifact;
pub mod assignment;
pub mod enrollment;
pub mod path;
pub mod reconciler;
pub mod telemetry;

/// Deserialize a nullable value while still requiring the field to be present. Serialized
/// contracts use this for deliberate nullability without silently accepting an older shape.
pub(crate) fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    <Option<T> as serde::Deserialize<'de>>::deserialize(deserializer)
}

/// Whether `value` is a syntactically valid SHA-256 digest: exactly 64 ASCII hex characters. The
/// one definition of that shape, shared by every signed target reference, the bundle manifest, the
/// repository lineage, and the rejection record.
pub fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_sha256_hex_accepts_only_64_hex_chars() {
        assert!(is_sha256_hex(&"a".repeat(64)));
        assert!(is_sha256_hex(&"A".repeat(64))); // any ASCII hex case
        assert!(!is_sha256_hex(&"a".repeat(63)), "too short");
        assert!(!is_sha256_hex(&"a".repeat(65)), "too long");
        assert!(!is_sha256_hex(&format!("{}z", "a".repeat(63))), "non-hex");
    }
}

#[cfg(test)]
mod dependency_isolation {
    const CONTRACT_MANIFEST: &str = include_str!("../Cargo.toml");
    const UPDATED_CONFIG: &str = include_str!("../../updated/src/config.rs");
    const PRODUCTION_MANIFESTS: &[(&str, &str)] = &[
        ("foundation", include_str!("../../foundation/Cargo.toml")),
        ("control", include_str!("../../control/Cargo.toml")),
        ("bootstrap", include_str!("../../bootstrap/Cargo.toml")),
        ("updated", include_str!("../../updated/Cargo.toml")),
        ("updated-tuf", include_str!("../../updated-tuf/Cargo.toml")),
        (
            "update-client",
            include_str!("../../update-client/Cargo.toml"),
        ),
        ("supervisor", include_str!("../../supervisor/Cargo.toml")),
        ("updatec", include_str!("../../updatec/Cargo.toml")),
        (
            "updated-healthproxy",
            include_str!("../../updated-healthproxy/Cargo.toml"),
        ),
        ("updatectl", include_str!("../../updatectl/Cargo.toml")),
    ];

    #[test]
    fn contracts_never_depend_on_the_node_runtime() {
        assert!(!dependency_names(CONTRACT_MANIFEST).any(|name| name == "updated"));
    }

    #[test]
    fn node_adapter_does_not_redeclare_or_reexport_wire_contracts() {
        assert!(
            !UPDATED_CONFIG.contains("pub use updated_contracts"),
            "updated::config must not be a compatibility facade for contract types"
        );
        for name in [
            "RepositoryAssignment",
            "ManagedRuntime",
            "SecretReference",
            "ManagedRepositoryLimits",
            "ManagedStorage",
            "ManagedTimeouts",
        ] {
            assert!(
                !UPDATED_CONFIG.contains(&format!("pub struct {name}"))
                    && !UPDATED_CONFIG.contains(&format!("pub enum {name}")),
                "updated::config must adapt, never own {name}"
            );
        }
    }

    #[test]
    fn production_crates_never_depend_on_demo_or_test_packages() {
        const FORBIDDEN: &[&str] = &[
            "demo-lifecycle",
            "e2e",
            "killfuzz",
            "sampleapp",
            "server",
            "updatec-demo",
        ];
        for (package, manifest) in PRODUCTION_MANIFESTS {
            for dependency in dependency_names(manifest) {
                assert!(
                    !FORBIDDEN.contains(&dependency),
                    "production package {package} must not depend on {dependency}"
                );
            }
        }
    }

    fn dependency_names(manifest: &str) -> impl Iterator<Item = &str> {
        let mut in_dependencies = false;
        manifest.lines().filter_map(move |line| {
            let line = line.trim();
            if line.starts_with('[') {
                in_dependencies = line.contains("dependencies");
                return None;
            }
            if !in_dependencies || line.is_empty() || line.starts_with('#') {
                return None;
            }
            let name = line.split(['=', '.', ' ']).next()?.trim();
            (!name.is_empty()).then_some(name)
        })
    }
}
