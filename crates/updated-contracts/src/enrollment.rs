//! Enrollment and certificate-renewal wire contracts.

use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::dataflow::DownloadCapability;
use crate::identity::ResourceName;

/// The one enrollment endpoint.
pub const ENROLL_PATH: &str = "/enroll";
/// The per-node certificate-renewal endpoint.
pub const RENEW_PATH: &str = "/renew";
/// Whole-document ceiling shared by persisted bundles and their content-addressed S3 objects. A
/// producer that cannot fit this contract must fail before publishing bytes every node will refuse.
pub const MAX_DOCUMENT_BYTES: usize = 8 * 1024 * 1024;
/// Control responses carry only a certificate or an exact-object capability, never bundle bytes.
pub const MAX_CONTROL_DOCUMENT_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollmentRequest {
    pub name: ResourceName,
    pub csr: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollResponse {
    pub leaf: String,
    pub bundle_download: DownloadCapability,
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
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollmentBundle {
    pub schema: u32,
    pub agent_id: ResourceName,
    pub routing_base_url: String,
    pub assignment: String,
    /// Immutable node-local boundary authenticated at enrollment. Live signed assignments may
    /// change every other runtime field but may never relocate durable install state.
    pub install_root: PathBuf,
    /// Exact UTF-8 bytes of signed metadata; TUF authenticates the serialized bytes.
    pub routing_root: String,
}

impl EnrollmentBundle {
    pub fn validate_shape(&self) -> io::Result<()> {
        if self.schema != 1 {
            return Err(invalid("unsupported enrollment bundle"));
        }
        if crate::assignment::canonical_repository_base(&self.routing_base_url).is_err()
            || self.assignment.starts_with('/')
            || !self.install_root.is_absolute()
        {
            return Err(invalid("invalid enrollment routing location"));
        }
        if !crate::path::is_confined_relative(&self.assignment) {
            return Err(invalid("invalid enrollment assignment path"));
        }
        if crate::telemetry::split_assignment_path(&self.assignment)
            .is_none_or(|(_, agent)| agent != self.agent_id.as_str())
        {
            return Err(invalid(
                "enrollment assignment does not name the bundle's agent identity",
            ));
        }
        let root: serde_json::Value =
            serde_json::from_str(&self.routing_root).map_err(|error| {
                invalid(&format!("enrollment routingRoot is invalid JSON: {error}"))
            })?;
        if !root.is_object() {
            return Err(invalid("enrollment routingRoot must encode a JSON object"));
        }
        Ok(())
    }

    pub fn to_bounded_json(&self) -> io::Result<Vec<u8>> {
        self.validate_shape()?;
        encode_bounded(self, MAX_DOCUMENT_BYTES)
    }

    pub fn from_bounded_json(bytes: &[u8]) -> io::Result<Self> {
        let bundle: Self = decode_bounded(bytes, MAX_DOCUMENT_BYTES)?;
        bundle.validate_shape()?;
        Ok(bundle)
    }
}

impl EnrollResponse {
    pub fn to_bounded_json(&self) -> io::Result<Vec<u8>> {
        self.bundle_download
            .validate()
            .map_err(|error| invalid(&error))?;
        encode_bounded(self, MAX_CONTROL_DOCUMENT_BYTES)
    }

    pub fn from_bounded_json(bytes: &[u8]) -> io::Result<Self> {
        let response: Self = decode_bounded(bytes, MAX_CONTROL_DOCUMENT_BYTES)?;
        response
            .bundle_download
            .validate()
            .map_err(|error| invalid(&error))?;
        Ok(response)
    }
}

impl RenewalResponse {
    pub fn to_bounded_json(&self) -> io::Result<Vec<u8>> {
        encode_bounded(self, MAX_CONTROL_DOCUMENT_BYTES)
    }

    pub fn from_bounded_json(bytes: &[u8]) -> io::Result<Self> {
        decode_bounded(bytes, MAX_CONTROL_DOCUMENT_BYTES)
    }
}

/// This module's `io::Result` spelling of the one bounded codec.
///
/// The bound itself is not restated here — [`crate::bounded`] owns it, as it does for every other
/// contract document. These two only carry the result into the `io::Error` shape the enrollment
/// boot path is written in.
fn encode_bounded<T: Serialize>(value: &T, limit: usize) -> io::Result<Vec<u8>> {
    crate::bounded::encode(value, "enrollment document", limit).map_err(|error| invalid(&error))
}

fn decode_bounded<T: serde::de::DeserializeOwned>(bytes: &[u8], limit: usize) -> io::Result<T> {
    crate::bounded::decode(bytes, "enrollment document", limit).map_err(|error| invalid(&error))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn bundle(base: &str) -> EnrollmentBundle {
        EnrollmentBundle {
            schema: 1,
            agent_id: ResourceName::new("agent-7").unwrap(),
            routing_base_url: base.into(),
            assignment: "assignments/agents/agent-7.json".into(),
            install_root: crate::assignment::testing::runtime().install_root,
            routing_root: "{}".into(),
        }
    }

    fn download() -> DownloadCapability {
        DownloadCapability {
            schema: DownloadCapability::SCHEMA,
            url: "https://objects.example/enrollments/bundle.json?X-Amz-Signature=secret".into(),
            sha256: "a".repeat(64),
        }
    }

    #[test]
    fn enrollment_routing_uses_the_shared_repository_base_grammar() {
        assert!(bundle("https://updates.example/routing/")
            .validate_shape()
            .is_ok());
        let offline = if cfg!(windows) {
            "file:///C:/ProgramData/updated/routing/"
        } else {
            "file:///var/lib/updated/routing/"
        };
        assert!(bundle(offline).validate_shape().is_ok());
        for invalid in [
            "http://updates.example/routing/",
            "https://user:secret@updates.example/routing/",
            "https://updates.example/routing/?token=bearer",
            "https://updates.example/routing/#fragment",
            "https://updates.example/routing",
            "relative/routing/",
        ] {
            assert!(
                bundle(invalid).validate_shape().is_err(),
                "{invalid:?} must be refused"
            );
        }
    }

    #[test]
    fn enrollment_documents_have_one_producer_and_consumer_ceiling() {
        let valid = bundle("https://updates.example/routing/");
        let bytes = valid.to_bounded_json().unwrap();
        assert_eq!(
            EnrollmentBundle::from_bounded_json(&bytes)
                .unwrap()
                .agent_id,
            "agent-7"
        );

        let mut oversized = valid;
        oversized.routing_root = format!("{{\"padding\":\"{}\"}}", "x".repeat(MAX_DOCUMENT_BYTES));
        assert_eq!(
            oversized.to_bounded_json().unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(
            EnrollmentBundle::from_bounded_json(&vec![b' '; MAX_DOCUMENT_BYTES + 1])
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn enrollment_identity_and_assignment_have_one_shared_binding_gate() {
        let mut mismatched = bundle("https://updates.example/routing/");
        mismatched.assignment = "assignments/agents/another-agent.json".into();
        assert!(mismatched.validate_shape().is_err());
        assert!(mismatched.to_bounded_json().is_err());

        let encoded = serde_json::to_string(&bundle("https://updates.example/routing/"))
            .unwrap()
            .replace("agent-7", "Agent-7");
        assert!(serde_json::from_str::<EnrollmentBundle>(&encoded).is_err());
    }

    #[test]
    fn control_responses_carry_only_a_strict_bounded_download_capability() {
        let response = EnrollResponse {
            leaf: "certificate".into(),
            bundle_download: download(),
        };
        let bytes = response.to_bounded_json().unwrap();
        assert_eq!(
            EnrollResponse::from_bounded_json(&bytes)
                .unwrap()
                .bundle_download,
            download()
        );

        let mut invalid = download();
        invalid.url = "http://objects.example/bundle?X-Amz-Signature=secret".into();
        assert!(invalid.to_bounded_json().is_err());
        let mut invalid = download();
        invalid.sha256 = "A".repeat(64);
        assert!(invalid.to_bounded_json().is_err());
        assert!(
            DownloadCapability::from_bounded_json(&vec![b' '; MAX_CONTROL_DOCUMENT_BYTES + 1])
                .is_err()
        );
    }

    /// Enrollment is the gate that decides which names ever exist, so it must not admit one the
    /// storage and inventory readers refuse: such a node runs, heartbeats, and is invisible to
    /// every consumer forever. Anything the shared grammar rejects — the reserved fleet-index
    /// basename above all — must be rejected here too, without enrollment restating the rule.
    #[test]
    fn an_enrollment_name_is_refused_wherever_the_shared_identity_grammar_refuses_it() {
        assert!(ResourceName::new("agent-7").is_ok());
        assert!(ResourceName::new("jenkins-author-0").is_ok());
        // Raw report keys are hashed, so ordinary DNS names no longer collide with controller
        // projection objects or need a second, storage-specific reserved-word grammar.
        assert!(ResourceName::new("fleet").is_ok());
        assert!(ResourceName::new("rack-1.agent-7").is_ok());
        assert!(
            ResourceName::new("a".repeat(crate::identity::MAX_DNS_SUBDOMAIN_BYTES + 1)).is_err()
        );
        for bad in [
            "", "-agent", "agent-", "Agent", "a_b", "a/b", ".agent", "agent.", "a..b",
        ] {
            assert!(ResourceName::new(bad).is_err(), "{bad:?} must be refused");
        }
    }
}
