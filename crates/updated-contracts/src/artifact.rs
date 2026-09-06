//! Signed routing documents and immutable package references.

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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, schemars::JsonSchema)]
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
