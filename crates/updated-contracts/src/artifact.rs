//! Signed target references and lifecycle-provider manifests.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDocument {
    pub schema: u32,
    pub config: TargetReference,
}

impl AgentDocument {
    /// Read by nodes, like [`crate::assignment::RepositoryAssignment`]: the writer-restraint rule
    /// in `docs/wire-compatibility-design.md` applies — the control plane must never emit a new
    /// schema ahead of the fleet floor, because the node that cannot read this document cannot
    /// receive the upgrade that would teach it to.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != 1 {
            return Err(format!("unsupported agent document schema {}", self.schema));
        }
        if !self.config.is_valid() {
            return Err("agent document config reference is invalid".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetReference {
    pub path: String,
    pub sha256: String,
}

impl TargetReference {
    pub fn is_valid(&self) -> bool {
        crate::path::is_confined_relative(&self.path) && crate::is_sha256_hex(&self.sha256)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderSet {
    pub schema: u32,
    pub id: String,
    pub reconciler: Reconciler,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reconciler {
    pub artifact: TargetReference,
    pub args: Vec<String>,
    pub timeout_millis: u64,
}

impl ProviderSet {
    /// The only provider-set document schema this build accepts. Every bound below is mirrored
    /// by `schemas/provider-set.schema.json`, and this module's tests check that file against
    /// these constants so the published contract and the deployed type cannot drift.
    pub const SCHEMA: u32 = 1;
    pub const MAX_ID_BYTES: usize = 128;
    pub const MAX_ARGS: usize = 256;
    pub const MAX_ARG_BYTES: usize = 16_384;
    pub const MIN_TIMEOUT_MILLIS: u64 = 1;
    pub const MAX_TIMEOUT_MILLIS: u64 = 86_400_000;

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != Self::SCHEMA {
            return Err(format!("unsupported provider-set schema {}", self.schema));
        }
        let valid_id = !self.id.is_empty()
            && self.id.len() <= Self::MAX_ID_BYTES
            && self.id.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
            });
        if !valid_id {
            return Err("provider-set id is invalid".into());
        }
        if !(Self::MIN_TIMEOUT_MILLIS..=Self::MAX_TIMEOUT_MILLIS)
            .contains(&self.reconciler.timeout_millis)
        {
            return Err("node reconciler has an invalid timeout".into());
        }
        if self.reconciler.args.len() > Self::MAX_ARGS
            || self
                .reconciler
                .args
                .iter()
                .any(|arg| arg.len() > Self::MAX_ARG_BYTES)
        {
            return Err("node reconciler has invalid arguments".into());
        }
        if !self.reconciler.artifact.is_valid() {
            return Err("node reconciler artifact reference is invalid".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reconciler() -> Reconciler {
        Reconciler {
            artifact: TargetReference {
                path: "providers/lifecycle.bundle".into(),
                sha256: "a".repeat(64),
            },
            args: Vec::new(),
            timeout_millis: 30_000,
        }
    }

    #[test]
    fn references_reject_traversal_and_malformed_digests() {
        let digest = "a".repeat(64);
        assert!(TargetReference {
            path: "providers/app.json".into(),
            sha256: digest.clone(),
        }
        .is_valid());
        assert!(!TargetReference {
            path: "../app.json".into(),
            sha256: digest,
        }
        .is_valid());
    }

    #[test]
    fn agent_documents_round_trip_and_validate_the_reference() {
        let valid = AgentDocument {
            schema: 1,
            config: TargetReference {
                path: "assignments/configs/abc.json".into(),
                sha256: "a".repeat(64),
            },
        };
        valid.validate().unwrap();
        assert_eq!(
            serde_json::from_str::<AgentDocument>(&serde_json::to_string(&valid).unwrap()).unwrap(),
            valid
        );
        let mut invalid = valid;
        invalid.config.sha256 = "not-a-sha".into();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn provider_sets_are_strict_and_bounded() {
        ProviderSet {
            schema: 1,
            id: "application-policy".into(),
            reconciler: reconciler(),
        }
        .validate()
        .unwrap();

        let unknown = r#"{"schema":1,"id":"future","reconciler":{"artifact":{"path":"provider","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"args":[],"timeout_millis":1,"future":true}}"#;
        assert!(serde_json::from_str::<ProviderSet>(unknown).is_err());

        let invalid = ProviderSet {
            schema: 1,
            id: "unsafe".into(),
            reconciler: Reconciler {
                artifact: TargetReference {
                    path: "../escape".into(),
                    sha256: "a".repeat(64),
                },
                ..reconciler()
            },
        };
        assert!(invalid
            .validate()
            .unwrap_err()
            .contains("artifact reference"));
    }

    /// The `schemas/*.schema.json` files are the normative wire
    /// contract, and integrators write producers against those files rather than against this
    /// crate. Nothing else in the workspace reads `schemas/`, so without these checks the two can
    /// drift into mutually unparseable shapes — a published document every agent rejects at
    /// `serde_json::from_slice`, discovered only when a rollout stalls.
    mod published_schemas {
        use super::*;
        use serde_json::Value;

        fn read(relative: &str) -> Value {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../schemas")
                .join(relative);
            let bytes = std::fs::read(&path)
                .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|error| panic!("parsing {}: {error}", path.display()))
        }

        /// The field names a strict object schema declares. Every contract document is
        /// `deny_unknown_fields` with no serde defaults, so the schema must be closed and its
        /// required set must be exactly its property set.
        fn fields(object: &Value) -> Vec<String> {
            assert_eq!(
                object["additionalProperties"],
                Value::Bool(false),
                "the type is deny_unknown_fields"
            );
            let mut properties: Vec<String> = object["properties"]
                .as_object()
                .expect("properties")
                .keys()
                .cloned()
                .collect();
            let mut required: Vec<String> = object["required"]
                .as_array()
                .expect("required")
                .iter()
                .map(|name| name.as_str().expect("required name").to_owned())
                .collect();
            properties.sort();
            required.sort();
            assert_eq!(
                properties, required,
                "the type has no optional fields and no serde defaults"
            );
            properties
        }

        /// The field names the Rust type actually serializes.
        fn serialized(value: &impl Serialize) -> Vec<String> {
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

        const TARGET_REFERENCE_ID: &str =
            "https://updated.dev/schemas/target-reference.schema.json";

        #[test]
        fn target_reference_schema_matches_the_type() {
            let schema = read("target-reference.schema.json");
            assert_eq!(schema["$id"], Value::from(TARGET_REFERENCE_ID));
            let reference = TargetReference {
                path: "providers/lifecycle.bundle".into(),
                sha256: "a".repeat(64),
            };
            assert!(reference.is_valid());
            assert_eq!(fields(&schema), serialized(&reference));
        }

        #[test]
        fn agent_document_schema_matches_the_type() {
            let schema = read("agent-document.schema.json");
            let document = AgentDocument {
                schema: 1,
                config: TargetReference {
                    path: "assignments/configs/production-web.json".into(),
                    sha256: "4".repeat(64),
                },
            };
            document.validate().unwrap();
            assert_eq!(fields(&schema), serialized(&document));
            assert_eq!(schema["properties"]["schema"]["const"], Value::from(1));
            assert_eq!(
                schema["properties"]["config"]["$ref"],
                Value::from(TARGET_REFERENCE_ID)
            );

            let example: AgentDocument =
                serde_json::from_value(read("examples/agent-document.json")).unwrap();
            example.validate().unwrap();
        }

        #[test]
        fn provider_set_schema_matches_the_type() {
            let schema = read("provider-set.schema.json");
            let set = ProviderSet {
                schema: ProviderSet::SCHEMA,
                id: "web-linux-v4".into(),
                reconciler: reconciler(),
            };
            set.validate().unwrap();

            assert_eq!(fields(&schema), serialized(&set));
            assert_eq!(
                schema["properties"]["schema"]["const"],
                Value::from(ProviderSet::SCHEMA)
            );
            assert_eq!(
                schema["properties"]["id"]["maxLength"],
                Value::from(ProviderSet::MAX_ID_BYTES)
            );
            assert_eq!(
                schema["properties"]["reconciler"]["$ref"],
                Value::from("#/$defs/reconciler")
            );

            let nested = &schema["$defs"]["reconciler"];
            assert_eq!(fields(nested), serialized(&set.reconciler));
            assert_eq!(
                nested["properties"]["artifact"]["$ref"],
                Value::from(TARGET_REFERENCE_ID)
            );
            assert_eq!(
                nested["properties"]["args"]["maxItems"],
                Value::from(ProviderSet::MAX_ARGS)
            );
            assert_eq!(
                nested["properties"]["args"]["items"]["maxLength"],
                Value::from(ProviderSet::MAX_ARG_BYTES)
            );
            assert_eq!(
                nested["properties"]["timeout_millis"]["minimum"],
                Value::from(ProviderSet::MIN_TIMEOUT_MILLIS)
            );
            assert_eq!(
                nested["properties"]["timeout_millis"]["maximum"],
                Value::from(ProviderSet::MAX_TIMEOUT_MILLIS)
            );

            // The published example is the first thing an integrator copies: it must be a
            // document this build parses and accepts.
            let example: ProviderSet =
                serde_json::from_value(read("examples/provider-set.json")).unwrap();
            example.validate().unwrap();
        }
    }
}
