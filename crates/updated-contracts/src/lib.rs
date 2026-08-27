//! Strict, versioned contracts shared across the node and control-plane boundary.
//!
//! This crate owns serialized protocol types and the validation/security rules required to
//! interpret them consistently. It deliberately contains no installation, process, filesystem,
//! HTTP-client, or Kubernetes behavior.
//!
//! It is also the single home of the *grammar* primitives those rules are built from —
//! [`identity`], [`path`] confinement, [`digest`] content identity, and [`key`] signature
//! verification. They live at the bottom of the dependency stack precisely so a protocol check and
//! the node-side code that later acts on the same value cannot drift apart.

pub mod artifact;
pub mod assignment;
pub mod backend;
pub mod bounded;
pub mod dataflow;
pub mod digest;
pub mod endpoint;
pub mod enrollment;
pub mod identity;
pub mod key;
pub mod path;
pub mod reconciler;
pub mod telemetry;

/// Deserialize a nullable value while still requiring the field to be present. Serialized
/// contracts and durable records use this for deliberate nullability without silently accepting
/// an older shape — serde otherwise treats a missing `Option<T>` as `None`.
pub fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    <Option<T> as serde::Deserialize<'de>>::deserialize(deserializer)
}

/// The digest grammar every wire value, durable identity, and object key is spelled in, hoisted to
/// the crate root because nearly every contract in this crate is validated against it.
pub use digest::is_canonical_sha256;

/// The one conformance harness for `schemas/`.
///
/// The `schemas/*.schema.json` files are the normative wire contract: integrators write producers
/// against those files rather than against this crate, and nothing else in the workspace reads
/// them. Without a check tying each schema to the type that serializes it, the two drift into
/// mutually unparseable shapes — a document the published schema blesses that every agent rejects
/// at `serde_json::from_slice`, discovered only when a rollout stalls.
///
/// It lives at the crate root because every contract module needs exactly the same three
/// operations, and a rule about the normative contract that is written twice is a rule one half of
/// the schemas silently stops getting.
#[cfg(test)]
pub(crate) mod published_schema {
    use serde::Serialize;
    use serde_json::Value;

    /// Read one file from the published `schemas/` directory, panicking with its path.
    pub(crate) fn read(relative: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../schemas")
            .join(relative);
        let bytes = std::fs::read(&path)
            .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
        serde_json::from_slice(&bytes)
            .unwrap_or_else(|error| panic!("parsing {}: {error}", path.display()))
    }

    /// The field names the Rust type actually serializes. Callers pass a value with every
    /// serde-optional field populated, so the comparison is against the widest document the type
    /// can emit.
    pub(crate) fn serialized(value: &impl Serialize) -> Vec<String> {
        let mut keys: Vec<String> = serde_json::to_value(value)
            .expect("serialize")
            .as_object()
            .expect("object")
            .keys()
            .cloned()
            .collect();
        keys.sort();
        keys
    }

    /// A strict object schema must be closed, declare exactly the fields the type serializes, and
    /// require all of them except the ones serde may omit — otherwise a schema-valid document loses
    /// a mandatory field or a type-valid document trips `additionalProperties`. A type with no
    /// optional fields passes an empty `optional`.
    pub(crate) fn assert_object(
        object: &Value,
        value: &impl Serialize,
        optional: &[&str],
        what: &str,
    ) {
        assert_eq!(
            object["additionalProperties"],
            Value::Bool(false),
            "{what} is deny_unknown_fields"
        );
        let mut properties: Vec<String> = object["properties"]
            .as_object()
            .unwrap_or_else(|| panic!("{what} properties"))
            .keys()
            .cloned()
            .collect();
        properties.sort();
        assert_eq!(properties, serialized(value), "{what} properties");

        let mut required: Vec<String> = object["required"]
            .as_array()
            .unwrap_or_else(|| panic!("{what} required"))
            .iter()
            .map(|name| name.as_str().expect("required name").to_owned())
            .collect();
        required.sort();
        let mut expected: Vec<String> = properties
            .into_iter()
            .filter(|name| !optional.contains(&name.as_str()))
            .collect();
        expected.sort();
        assert_eq!(required, expected, "{what} required");
    }
}

#[cfg(test)]
mod dependency_isolation {
    const CONTRACT_MANIFEST: &str = include_str!("../Cargo.toml");
    const UPDATED_CONFIG: &str = include_str!("../../updated/src/config.rs");
    const UPDATEC_LIB: &str = include_str!("../../updatec/src/lib.rs");
    const PRODUCTION_MANIFESTS: &[(&str, &str)] = &[
        ("foundation", include_str!("../../foundation/Cargo.toml")),
        ("control", include_str!("../../control/Cargo.toml")),
        ("launcher", include_str!("../../launcher/Cargo.toml")),
        ("updated", include_str!("../../updated/Cargo.toml")),
        ("updated-tuf", include_str!("../../updated-tuf/Cargo.toml")),
        ("agent", include_str!("../../agent/Cargo.toml")),
        ("updatec", include_str!("../../updatec/Cargo.toml")),
        (
            "updated-healthproxy",
            include_str!("../../updated-healthproxy/Cargo.toml"),
        ),
        ("updatectl", include_str!("../../updatectl/Cargo.toml")),
    ];

    #[test]
    fn contracts_never_depend_on_the_node_runtime() {
        assert!(
            !foundation::manifest::shipped_dependency_names(CONTRACT_MANIFEST).contains(&"updated")
        );
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
        // A twin escapes the name check simply by being renamed — `Storage` was `ManagedStorage`
        // with the same five fields and a field-by-field identity copy, and the guard stayed green.
        // The retention bounds are pure data with no node-local unit to convert to (unlike
        // `Timeouts`, which turns second counts into `Duration`s), so the adapter holds the
        // contract type itself and has no reason to spell any of these names.
        for field in [
            "inactive_releases",
            "inactive_providers",
            "inactive_agents",
            "inactive_bytes",
            "inactive_repository_caches",
        ] {
            assert!(
                !UPDATED_CONFIG.contains(field),
                "updated::config names {field}, so it is re-declaring ManagedStorage under \
                 another name instead of holding it"
            );
        }
    }

    /// The control plane's CRD must EMBED the managed-runtime policy structs, never mirror them.
    ///
    /// It used to mirror them: `RepositoryLimitsSpec`, `StorageSpec` and `TimeoutsSpec` were
    /// field-for-field copies of the three contract types. Adding a field to the contract failed to
    /// compile, but adding one to the *spec* did not — an operator could set it in YAML and it would
    /// silently never reach a node — and nothing caught a mis-wired mapping between two `u64`s.
    ///
    /// The exhaustive destructuring in `TryFrom<DeploymentSpec> for DesiredDeployment` is what makes
    /// the two sides impossible to drift *today*; this is what stops the mirror being reintroduced
    /// tomorrow. Field names rather than type names, because a twin escapes a name check simply by
    /// being renamed — which is exactly how the `updated::config` twin above survived its own guard.
    #[test]
    fn the_control_plane_crd_embeds_the_managed_policy_rather_than_mirroring_it() {
        for field in [
            // ManagedRepositoryLimits
            "metadata_limit",
            "target_limit",
            "transport_timeout_seconds",
            // ManagedStorage
            "inactive_releases",
            "inactive_providers",
            "inactive_agents",
            "inactive_bytes",
            "inactive_repository_caches",
            // ManagedTimeouts
            "check_interval_seconds",
            "health_grace_seconds",
            "health_successes",
            "health_interval_seconds",
            "refresh_retry_seconds",
            "confirmation_window_seconds",
            "agent_check_interval_seconds",
        ] {
            assert!(
                !UPDATEC_LIB.contains(field),
                "updatec names {field}, so it is declaring a twin of a managed policy struct \
                 instead of embedding the contract's own type"
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
            "updatec-e2e",
        ];
        for (package, manifest) in PRODUCTION_MANIFESTS {
            for dependency in foundation::manifest::shipped_dependency_names(manifest) {
                assert!(
                    !FORBIDDEN.contains(&dependency),
                    "production package {package} must not depend on {dependency}"
                );
            }
        }
    }
}

/// Closedness is a property of EVERY document this crate deserializes, so it is checked as one.
///
/// `serde(deny_unknown_fields)` is what makes an unrecognized field a refusal rather than a silent
/// no-op. Without it a node accepts a document carrying a directive this build does not implement
/// and proceeds as though it had — the failure mode a strict, versioned contract exists to prevent.
///
/// It held on every type when this was written. That is exactly when to nail it down: the invariant
/// was one forgotten attribute away from lapsing on the next type anyone adds, with nothing failing.
#[cfg(test)]
mod closed_documents {
    const MODULES: &[(&str, &str)] = &[
        ("artifact", include_str!("artifact.rs")),
        ("assignment", include_str!("assignment.rs")),
        ("backend", include_str!("backend.rs")),
        ("bounded", include_str!("bounded.rs")),
        ("dataflow", include_str!("dataflow.rs")),
        ("digest", include_str!("digest.rs")),
        ("enrollment", include_str!("enrollment.rs")),
        ("identity", include_str!("identity.rs")),
        ("key", include_str!("key.rs")),
        ("path", include_str!("path.rs")),
        ("reconciler", include_str!("reconciler.rs")),
        ("telemetry", include_str!("telemetry.rs")),
    ];

    /// The attribute block immediately above each `pub struct`/`pub enum`, paired with its name.
    ///
    /// "Immediately above" means the unbroken run of `#[...]` and `///` lines preceding it, which is
    /// where a derive and its `serde` attribute always sit.
    fn declarations(source: &str) -> Vec<(String, String)> {
        let lines: Vec<&str> = source.lines().collect();
        let mut found = Vec::new();
        for (index, line) in lines.iter().enumerate() {
            let Some(rest) = line
                .strip_prefix("pub struct ")
                .or_else(|| line.strip_prefix("pub enum "))
            else {
                continue;
            };
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            let mut attributes = String::new();
            for above in lines[..index].iter().rev() {
                let trimmed = above.trim_start();
                if !(trimmed.starts_with("#[")
                    || trimmed.starts_with("///")
                    || trimmed.starts_with(')'))
                {
                    break;
                }
                attributes.insert_str(0, above);
            }
            found.push((name, attributes));
        }
        found
    }

    #[test]
    fn every_deserializable_contract_type_refuses_unknown_fields() {
        let mut checked = 0;
        for (module, source) in MODULES {
            for (name, attributes) in declarations(source) {
                if !attributes.contains("Deserialize") {
                    continue;
                }
                checked += 1;
                assert!(
                    attributes.contains("deny_unknown_fields"),
                    "{module}::{name} derives Deserialize without serde(deny_unknown_fields), so a \
                     document carrying a field this build does not understand is accepted in silence"
                );
            }
        }
        // A scanner that matched nothing would pass this test forever while enforcing nothing.
        assert!(
            checked >= 20,
            "the declaration scan found only {checked} deserializable types, so it has stopped \
             matching this crate's source and is no longer enforcing anything"
        );
    }
}
