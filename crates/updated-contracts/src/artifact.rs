//! Signed target references and lifecycle-provider manifests.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentDocument {
    pub schema: u32,
    pub config: TargetReference,
}

impl AgentDocument {
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
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != 1 {
            return Err(format!("unsupported provider-set schema {}", self.schema));
        }
        let valid_id = !self.id.is_empty()
            && self.id.len() <= 128
            && self.id.bytes().enumerate().all(|(index, byte)| {
                byte.is_ascii_alphanumeric() || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
            });
        if !valid_id {
            return Err("provider-set id is invalid".into());
        }
        if !(1..=86_400_000).contains(&self.reconciler.timeout_millis) {
            return Err("node reconciler has an invalid timeout".into());
        }
        if self.reconciler.args.len() > 256
            || self.reconciler.args.iter().any(|arg| arg.len() > 16_384)
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
}
