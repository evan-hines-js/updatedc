//! Enrollment and certificate-renewal wire contracts.

use std::io;

use serde::{Deserialize, Serialize};

/// The one enrollment endpoint.
pub const ENROLL_PATH: &str = "/enroll";
/// The per-node certificate-renewal endpoint.
pub const RENEW_PATH: &str = "/renew";
/// Where an already-enrolled node re-fetches its enrollment bundle, authenticated by the per-node
/// certificate it minted at [`ENROLL_PATH`].
///
/// The bundle carries signed TUF metadata, and signed metadata expires. Written once at enrollment
/// and never replaced, it eventually holds nothing a node can take for the repository's current
/// state — so this endpoint exists to replace it, and only that: it mints nothing, registers
/// nothing, and returns the same bundle `/enroll` would issue for a node that enrolled today. The
/// node keeps its enrollment-time root of trust across the swap by requiring the returned
/// `routingRoot` to be the pinned root or a rotation signed by it.
pub const BUNDLE_PATH: &str = "/bundle";

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollmentRequest {
    pub name: String,
    pub csr: String,
}

impl EnrollmentRequest {
    pub fn name_is_wellformed(&self) -> bool {
        !self.name.is_empty()
            && self.name.len() <= 253
            && self
                .name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !self.name.starts_with('-')
            && !self.name.ends_with('-')
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollResponse {
    pub leaf: String,
    #[serde(default)]
    pub chain: String,
    pub bundle: EnrollmentBundle,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenewalRequest {
    pub csr: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RenewalResponse {
    pub leaf: String,
    #[serde(default)]
    pub chain: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollmentBundle {
    pub schema: u32,
    pub agent_id: String,
    pub routing_base_url: String,
    pub assignment: String,
    /// Exact UTF-8 bytes of signed metadata; TUF authenticates the serialized bytes.
    pub routing_root: String,
    pub initial: InitialSignedConfiguration,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InitialSignedConfiguration {
    pub timestamp: String,
    pub snapshot: String,
    pub targets: String,
    pub agent_document: String,
    pub managed_configuration: String,
}

impl EnrollmentBundle {
    pub fn validate_shape(&self) -> io::Result<()> {
        if self.schema != 1 || self.agent_id.is_empty() {
            return Err(invalid(
                "unsupported enrollment bundle or empty agent identity",
            ));
        }
        if !self.routing_base_url.ends_with('/') || self.assignment.starts_with('/') {
            return Err(invalid("invalid enrollment routing location"));
        }
        if !crate::path::is_confined_relative(&self.assignment) {
            return Err(invalid("invalid enrollment assignment path"));
        }
        for (name, value) in [
            ("routingRoot", &self.routing_root),
            ("timestamp", &self.initial.timestamp),
            ("snapshot", &self.initial.snapshot),
            ("targets", &self.initial.targets),
            ("agentDocument", &self.initial.agent_document),
            ("managedConfiguration", &self.initial.managed_configuration),
        ] {
            let value: serde_json::Value = serde_json::from_str(value)
                .map_err(|error| invalid(&format!("enrollment {name} is invalid JSON: {error}")))?;
            if !value.is_object() {
                return Err(invalid(&format!(
                    "enrollment {name} must encode a JSON object"
                )));
            }
        }
        Ok(())
    }
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
