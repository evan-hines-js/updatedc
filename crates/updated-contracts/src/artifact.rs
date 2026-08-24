//! Signed target references and lifecycle-provider manifests.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDocument {
    pub schema: u32,
    pub config: TargetReference,
}

impl AgentDocument {
    pub const MAX_DOCUMENT_BYTES: usize = 4 * 1024;

    /// Exact current schema only. Unknown fields and alternate shapes are refused by serde before
    /// validation.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != 1 {
            return Err(format!("unsupported agent document schema {}", self.schema));
        }
        if !self.config.is_valid() {
            return Err("agent document config reference is invalid".into());
        }
        Ok(())
    }

    pub fn to_bounded_json(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        crate::bounded::encode(self, "agent document", Self::MAX_DOCUMENT_BYTES)
    }

    pub fn from_bounded_json(bytes: &[u8]) -> Result<Self, String> {
        let document: Self =
            crate::bounded::decode(bytes, "agent document", Self::MAX_DOCUMENT_BYTES)?;
        document.validate()?;
        Ok(document)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetReference {
    pub path: String,
    pub sha256: String,
}

impl TargetReference {
    pub const MAX_PATH_BYTES: usize = 1024;

    pub fn is_valid(&self) -> bool {
        self.path.len() <= Self::MAX_PATH_BYTES
            && crate::path::is_confined_relative(&self.path)
            && crate::is_canonical_sha256(&self.sha256)
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
    ///
    /// Exact current schema only, with no compatibility aliases or reader window.
    pub const SCHEMA: u32 = 1;
    pub const MAX_ID_BYTES: usize = crate::identity::MAX_SEGMENT_BYTES;
    pub const MAX_ARGS: usize = 256;
    pub const MAX_ARG_BYTES: usize = 16_384;
    pub const MIN_TIMEOUT_MILLIS: u64 = 1;
    pub const MAX_TIMEOUT_MILLIS: u64 = 86_400_000;
    /// Whole-document ceiling used by both publishers and nodes. The argument payload can expand
    /// by up to six bytes per input byte under JSON escaping; 32 MiB covers that worst case plus
    /// the bounded id/reference fields and structural overhead.
    pub const MAX_DOCUMENT_BYTES: usize = 32 * 1024 * 1024;

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != Self::SCHEMA {
            return Err(format!("unsupported provider-set schema {}", self.schema));
        }
        if !crate::identity::is_segment(&self.id) {
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

    /// Build the document a publisher is about to sign, held to exactly the rule every agent
    /// applies, and refuse before anything is signed or uploaded.
    ///
    /// A published set is an immutable signed target keyed by id: a document that fails
    /// [`ProviderSet::validate`] is accepted by no node in the fleet, and the only remedy is
    /// republishing under a *new* id. Every publisher therefore runs the agent's own `validate`
    /// here rather than a weaker digest-only approximation of it.
    ///
    /// It lives beside the type because the refusal is a property of the contract, not of any one
    /// front end. `updatectl publish-provider-set` and `server publish-provider-set` each used to
    /// carry their own copy of the construction and the operator-facing wording, so a change to
    /// either was a change one publisher silently kept telling operators the old way.
    pub fn for_publication(id: String, reconciler: Reconciler) -> Result<Self, String> {
        let set = Self {
            schema: Self::SCHEMA,
            id,
            reconciler,
        };
        set.validate().map_err(|error| {
            format!(
                "refusing to publish provider set {:?}: {error} (nothing was signed or uploaded)",
                set.id
            )
        })?;
        Ok(set)
    }

    /// Canonical publisher representation under the same whole-document ceiling nodes enforce.
    pub fn to_bounded_json(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        crate::bounded::encode(self, "provider-set document", Self::MAX_DOCUMENT_BYTES)
    }

    /// Read a published provider set: the producer's ceiling and the agent's own `validate` in one
    /// step, like every other document in this crate.
    ///
    /// This type had only the producing half. Its one reader assembled the other from three pieces
    /// — bound the read, `serde_json::from_slice`, then remember to `validate` — and got it right;
    /// a second reader would have had to remember all three, with nothing but this comment to say
    /// so. The ceiling belongs to the document, not to whoever happens to parse it.
    pub fn from_bounded_json(bytes: &[u8]) -> Result<Self, String> {
        let set: Self =
            crate::bounded::decode(bytes, "provider-set document", Self::MAX_DOCUMENT_BYTES)?;
        set.validate()?;
        Ok(set)
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

    /// Reading a published set applies the producer's ceiling and the agent's validation together.
    #[test]
    fn a_provider_set_is_read_back_under_the_ceiling_it_was_written_with() {
        let set = ProviderSet::for_publication("web-linux".into(), reconciler()).unwrap();
        let bytes = set.to_bounded_json().unwrap();
        assert_eq!(ProviderSet::from_bounded_json(&bytes).unwrap(), set);

        // Past the ceiling: refused by size, before anything is trusted.
        let oversized = vec![b' '; ProviderSet::MAX_DOCUMENT_BYTES + 1];
        let error = ProviderSet::from_bounded_json(&oversized).expect_err("over the ceiling");
        assert!(error.contains("provider-set document"), "{error}");

        // Within the ceiling but not a set this build would ever publish.
        let invalid = serde_json::to_vec(&serde_json::json!({
            "schema": ProviderSet::SCHEMA,
            "id": "web linux",
            "reconciler": {
                "artifact": {"path": "providers/lifecycle.bundle", "sha256": "a".repeat(64)},
                "args": [],
                "timeout_millis": 30_000,
            }
        }))
        .unwrap();
        assert!(
            ProviderSet::from_bounded_json(&invalid).is_err(),
            "reading must apply the same validate the agent does"
        );
    }

    #[test]
    fn a_set_for_publication_stamps_the_current_schema_and_refuses_before_signing() {
        let set = ProviderSet::for_publication("web-linux".into(), reconciler())
            .expect("a well-formed set publishes");
        assert_eq!(
            set.schema,
            ProviderSet::SCHEMA,
            "the publisher never picks the schema"
        );
        assert_eq!(set.id, "web-linux");

        let cases = [
            (
                "timeout",
                "web-linux".to_string(),
                Reconciler {
                    timeout_millis: 0,
                    ..reconciler()
                },
            ),
            ("id", "web linux".to_string(), reconciler()),
            (
                "artifact reference",
                "web-linux".to_string(),
                Reconciler {
                    artifact: TargetReference {
                        path: "../escape".into(),
                        sha256: "a".repeat(64),
                    },
                    ..reconciler()
                },
            ),
            (
                "arguments",
                "web-linux".to_string(),
                Reconciler {
                    args: vec!["--flag".into(); ProviderSet::MAX_ARGS + 1],
                    ..reconciler()
                },
            ),
        ];
        for (expected, id, reconciler) in cases {
            let error = ProviderSet::for_publication(id, reconciler)
                .expect_err(&format!("{expected}: expected a rejection"));
            assert!(error.contains(expected), "{error}");
            assert!(
                error.contains("nothing was signed or uploaded"),
                "every publisher tells the operator the repository is untouched: {error}"
            );
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
        assert!(!TargetReference {
            path: "x".repeat(TargetReference::MAX_PATH_BYTES + 1),
            sha256: "a".repeat(64),
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
        assert!(AgentDocument::from_bounded_json(&vec![
            b' ';
            AgentDocument::MAX_DOCUMENT_BYTES + 1
        ])
        .unwrap_err()
        .contains("byte limit"));
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

        assert!(crate::identity::is_segment("app.lifecycle_v2"));
        assert!(!crate::identity::is_segment("-application-policy"));
        assert!(!crate::identity::is_segment(
            &"a".repeat(crate::identity::MAX_SEGMENT_BYTES + 1)
        ));

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

    /// The artifact contracts' half of the published-schema conformance check. The harness itself
    /// — and the rule it enforces — is [`crate::published_schema`]; every type here is closed with
    /// no serde defaults, so each one passes an empty `optional` set.
    mod published_schemas {
        use super::*;
        use crate::published_schema::{assert_object, read};
        use serde_json::Value;

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
            assert_object(&schema, &reference, &[], "target reference");
            assert_eq!(
                schema["properties"]["sha256"]["pattern"],
                Value::from(foundation::digest::CANONICAL_SHA256_PATTERN)
            );
            assert_eq!(
                schema["properties"]["path"]["pattern"],
                Value::from(crate::path::CONFINED_RELATIVE_PATTERN)
            );
            assert_eq!(
                schema["properties"]["path"]["maxLength"],
                Value::from(TargetReference::MAX_PATH_BYTES)
            );
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
            assert_object(&schema, &document, &[], "agent document");
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

            assert_object(&schema, &set, &[], "provider set");
            assert_eq!(
                schema["properties"]["schema"]["const"],
                Value::from(ProviderSet::SCHEMA)
            );
            assert_eq!(
                schema["properties"]["id"]["pattern"],
                Value::from(crate::identity::SEGMENT_PATTERN)
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
            assert_object(nested, &set.reconciler, &[], "reconciler");
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
