//! Authenticated, file-native configuration dataflow contracts.
//!
//! Application-facing configuration has exactly one representation: a bounded snapshot of named
//! opaque files. Base64 exists only at the JSON boundary. Health telemetry never carries these
//! bytes, and signed assignments carry only an opaque snapshot generation plus the names a node
//! is authorized to fetch.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Maximum serialized object accepted anywhere in the dataflow path.
///
/// The node, controller, and object-store readers enforce the same ceiling. The value is unrelated
/// to Kubernetes: application payloads never enter Kubernetes objects.
pub const MAX_DATAFLOW_BODY_BYTES: usize = 512 * 1024;
pub const MAX_CAPABILITY_BODY_BYTES: usize = 16 * 1024;
/// Maximum age of a successful live-identity decision reused by the gateway.
///
/// A repository deletion rejects every fresh decision. This bounded reuse window is therefore one
/// component of [`OBJECT_CAPABILITY_DRAIN`], not merely a performance setting hidden in the HTTP
/// implementation.
pub const GATEWAY_AUTHORIZATION_MEMO_TTL: std::time::Duration = std::time::Duration::from_secs(30);
/// Whole-request deadline around authorization and capability signing.
pub const GATEWAY_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Lifetime of every exact-object bearer capability minted by the mTLS gateway.
///
/// The issuer and private-object retirement both consume this value: cleanup must not delete an
/// object while a capability the system minted for it can still be spent.
pub const OBJECT_CAPABILITY_TTL: std::time::Duration = std::time::Duration::from_secs(60);
/// Time from a repository's deletion timestamp after which no capability minted for that
/// incarnation can still create or read an object.
///
/// A cached authorization may begin a request at the end of its memo window; that whole request
/// may then spend its deadline minting a capability, which lives for one final TTL. Keep this sum
/// shared by the gateway and finalizer so changing any side cannot silently reopen the race.
pub const OBJECT_CAPABILITY_DRAIN: std::time::Duration = std::time::Duration::from_secs(
    GATEWAY_AUTHORIZATION_MEMO_TTL.as_secs()
        + GATEWAY_REQUEST_TIMEOUT.as_secs()
        + OBJECT_CAPABILITY_TTL.as_secs(),
);

pub const INPUTS_PATH: &str = "/v1/node/inputs";
pub const INPUTS_ROUTE: &str = "/v1/node/inputs/{assignment_sha256}";
pub const OUTPUTS_PATH: &str = "/v1/node/outputs";
pub const REPORT_PATH: &str = "/v1/node/report";

pub fn inputs_url(base: &str, assignment_sha256: &str) -> Result<String, String> {
    if !crate::is_canonical_sha256(assignment_sha256) {
        return Err("assigned-input URL requires a canonical assignment SHA-256".into());
    }
    Ok(format!(
        "{}{INPUTS_PATH}/{assignment_sha256}",
        base.trim_end_matches('/')
    ))
}

pub fn outputs_url(base: &str) -> String {
    format!("{}{OUTPUTS_PATH}", base.trim_end_matches('/'))
}

pub fn report_url(base: &str) -> String {
    format!("{}{REPORT_PATH}", base.trim_end_matches('/'))
}

/// A short-lived bearer capability for one exact object-store GET.
///
/// It contains no reusable object-store credentials. The mTLS control plane authenticates the
/// expected SHA-256, while the anonymous bearer URL grants only the minimum object-store read.
/// Every consumer validates the document, fetches without client identity, authenticates the
/// exact bytes before parsing them, and never logs the URL.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DownloadCapability {
    pub schema: u32,
    pub url: String,
    pub sha256: String,
}

impl DownloadCapability {
    pub const SCHEMA: u32 = 1;

    pub fn validate(&self) -> Result<(), String> {
        self.bounded_json().map(drop)
    }

    pub fn to_bounded_json(&self) -> Result<Vec<u8>, String> {
        self.bounded_json()
    }

    fn bounded_json(&self) -> Result<Vec<u8>, String> {
        if self.schema != Self::SCHEMA {
            return Err("object download capability schema is unsupported".into());
        }
        capability_url(&self.url)?;
        if !crate::is_canonical_sha256(&self.sha256) {
            return Err(
                "object download capability sha256 must be 64 lowercase hexadecimal characters"
                    .into(),
            );
        }
        crate::bounded::encode(
            self,
            "object download capability",
            MAX_CAPABILITY_BODY_BYTES,
        )
    }

    pub fn from_bounded_json(bytes: &[u8]) -> Result<Self, String> {
        let capability: Self = crate::bounded::decode(
            bytes,
            "object download capability",
            MAX_CAPABILITY_BODY_BYTES,
        )?;
        capability.validate()?;
        Ok(capability)
    }
}

/// One bounded opaque file at the JSON boundary.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileValue {
    pub base64: String,
}

impl FileValue {
    pub const MAX_BYTES: usize = 64 * 1024;

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > Self::MAX_BYTES {
            return Err(format!(
                "dataflow file is {} bytes, past the {}-byte limit",
                bytes.len(),
                Self::MAX_BYTES
            ));
        }
        use base64::Engine as _;
        Ok(Self {
            base64: base64::engine::general_purpose::STANDARD.encode(bytes),
        })
    }

    pub fn bytes(&self) -> Result<Vec<u8>, String> {
        use base64::Engine as _;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.base64)
            .map_err(|_| "dataflow file is not canonical base64".to_string())?;
        if bytes.len() > Self::MAX_BYTES
            || base64::engine::general_purpose::STANDARD.encode(&bytes) != self.base64
        {
            return Err("dataflow file is oversized or not canonical base64".into());
        }
        Ok(bytes)
    }
}

/// The complete atomic named-file snapshot materialized for one reconciler invocation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FileSnapshot {
    pub files: BTreeMap<String, FileValue>,
}

impl FileSnapshot {
    pub const MAX_FILES: usize = 64;

    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    pub fn valid_name(name: &str) -> bool {
        // These names are materialized as real files by every agent. The portable identity grammar
        // prevents case-folding aliases and Windows device names in addition to traversal.
        crate::identity::is_segment(name)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.files.len() > Self::MAX_FILES {
            return Err(format!(
                "dataflow snapshot has {} files, past the {}-file limit",
                self.files.len(),
                Self::MAX_FILES
            ));
        }
        for (name, value) in &self.files {
            if !Self::valid_name(name) {
                return Err(format!("dataflow file name {name:?} is invalid"));
            }
            value.bytes()?;
        }
        bounded_json(self, "dataflow snapshot").map(|_| ())
    }

    /// Validate both the snapshot itself and the exact file authority a signed assignment grants.
    /// Extra files are refused just like missing ones: callers cannot silently acquire data the
    /// assignment did not name, or run half-configured after an incomplete object write.
    pub fn validate_selection(&self, selection: &InputSelection) -> Result<(), String> {
        selection.validate()?;
        self.validate()?;
        let actual: BTreeSet<&str> = self.files.keys().map(String::as_str).collect();
        let expected: BTreeSet<&str> = selection.files.iter().map(String::as_str).collect();
        if actual != expected {
            return Err("dataflow snapshot does not match the signed input selection".into());
        }
        Ok(())
    }

    /// Stable public generation under a controller-private key. A raw digest is deliberately not
    /// exposed: for a low-entropy secret it would be an offline guessing oracle. Repositories use
    /// different keys, so equal snapshots are unlinkable across fleets.
    pub fn opaque_generation(&self, key: &[u8]) -> Result<String, String> {
        if key.len() < 32 {
            return Err("dataflow generation key must be at least 32 bytes".into());
        }
        self.validate()?;
        let encoded = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, key);
        Ok(hex::encode(aws_lc_rs::hmac::sign(&key, &encoded).as_ref()))
    }
}

/// The non-secret dataflow descriptor carried in a signed assignment.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InputSelection {
    /// Opaque controller-generated identifier. Empty only when `files` is empty.
    pub generation: String,
    /// SHA-256 of the exact private [`InputPublication`] object. Its keyed blinding makes this
    /// public commitment safe for low-entropy values while still letting the node authenticate S3
    /// bytes directly from its signed assignment.
    pub object_sha256: String,
    pub files: BTreeSet<String>,
}

impl InputSelection {
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    pub fn validate(&self) -> Result<(), String> {
        let generation_is_canonical = crate::is_canonical_sha256(&self.generation);
        let object_sha256_is_canonical = crate::is_canonical_sha256(&self.object_sha256);
        let empty = self.files.is_empty();
        if self.files.len() > FileSnapshot::MAX_FILES
            || self
                .files
                .iter()
                .any(|name| !FileSnapshot::valid_name(name))
            || (empty != self.generation.is_empty())
            || (empty != self.object_sha256.is_empty())
            || (!empty && (!generation_is_canonical || !object_sha256_is_canonical))
        {
            return Err("dataflow input selection is invalid".into());
        }
        Ok(())
    }
}

/// The private object an assigned node downloads from S3.
///
/// `blinding` is a deterministic HMAC under the repository-private dataflow key. It is carried
/// inside the private object, not the signed assignment. Consequently the assignment can commit to
/// these exact bytes without publishing a raw digest oracle for a low-entropy password, while the
/// same snapshot still has a stable identity across controller restarts.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InputPublication {
    pub schema: u32,
    pub generation: String,
    pub blinding: String,
    pub snapshot: FileSnapshot,
}

impl InputPublication {
    pub const SCHEMA: u32 = 1;
    const BLINDING_DOMAIN: &'static [u8] = b"updated-input-publication-v1\0";

    pub fn from_snapshot(snapshot: FileSnapshot, key: &[u8]) -> Result<Self, String> {
        if snapshot.is_empty() {
            return Err("an empty input snapshot has no private publication".into());
        }
        if key.len() < 32 {
            return Err("dataflow generation key must be at least 32 bytes".into());
        }
        snapshot.validate()?;
        let encoded = serde_json::to_vec(&snapshot).map_err(|error| error.to_string())?;
        let generation = snapshot.opaque_generation(key)?;
        let key = aws_lc_rs::hmac::Key::new(aws_lc_rs::hmac::HMAC_SHA256, key);
        let mut message = Vec::with_capacity(Self::BLINDING_DOMAIN.len() + encoded.len());
        message.extend_from_slice(Self::BLINDING_DOMAIN);
        message.extend_from_slice(&encoded);
        let blinding = hex::encode(aws_lc_rs::hmac::sign(&key, &message).as_ref());
        let publication = Self {
            schema: Self::SCHEMA,
            generation,
            blinding,
            snapshot,
        };
        publication.validate()?;
        Ok(publication)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != Self::SCHEMA
            || !crate::is_canonical_sha256(&self.generation)
            || !crate::is_canonical_sha256(&self.blinding)
            || self.snapshot.is_empty()
        {
            return Err("dataflow input publication identity is invalid".into());
        }
        self.snapshot.validate()?;
        bounded_json(self, "dataflow input publication").map(|_| ())
    }

    pub fn to_bounded_body(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        bounded_json(self, "dataflow input publication")
    }

    pub fn selection(&self) -> Result<InputSelection, String> {
        let body = self.to_bounded_body()?;
        Ok(InputSelection {
            generation: self.generation.clone(),
            object_sha256: crate::digest::sha256_bytes(&body),
            files: self.snapshot.files.keys().cloned().collect(),
        })
    }

    /// Parse only when `bytes` are the exact object committed to by the signed selection.
    pub fn from_bounded_body(bytes: &[u8], selection: &InputSelection) -> Result<Self, String> {
        selection.validate()?;
        if selection.is_empty()
            || bytes.len() > MAX_DATAFLOW_BODY_BYTES
            || crate::digest::sha256_bytes(bytes) != selection.object_sha256
        {
            return Err("dataflow input publication does not match the signed selection".into());
        }
        let publication: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("decoding dataflow input publication: {error}"))?;
        publication.validate()?;
        if publication.generation != selection.generation {
            return Err(
                "dataflow input publication generation does not match the signed selection".into(),
            );
        }
        publication.snapshot.validate_selection(selection)?;
        Ok(publication)
    }
}

/// A healthy node's current output publication. Written to one node-owned private S3 object and
/// consumed only after the SHA-256 of its exact stored bytes is joined to the node's end-to-end
/// signed health report.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutputPublication {
    pub schema: u32,
    pub node: String,
    pub deployment: String,
    pub assignment_sha256: String,
    pub archive_sha256: String,
    pub snapshot: FileSnapshot,
}

impl OutputPublication {
    pub const SCHEMA: u32 = 2;

    pub fn validate(&self, node: &str) -> Result<(), String> {
        if self.schema != Self::SCHEMA
            || self.node != node
            || !crate::identity::is_dns_subdomain(node)
            || !crate::identity::is_segment(&self.deployment)
            || !crate::is_canonical_sha256(&self.assignment_sha256)
            || !crate::is_canonical_sha256(&self.archive_sha256)
        {
            return Err("dataflow output publication identity is invalid".into());
        }
        self.snapshot.validate()?;
        bounded_json(self, "dataflow output publication").map(|_| ())
    }

    pub fn to_bounded_body(&self) -> Result<Vec<u8>, String> {
        self.validate(&self.node)?;
        bounded_json(self, "dataflow output publication")
    }
}

/// A short-lived exact-object S3 POST capability minted after mTLS authorization.
///
/// The form fields are bearer secrets. They are deliberately opaque: consumers submit them once,
/// never log them, and never derive another object or method from them. The signed policy also
/// carries a storage-enforced content-length ceiling, which a presigned PUT cannot express.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UploadCapability {
    pub schema: u32,
    pub url: String,
    pub fields: BTreeMap<String, String>,
}

impl UploadCapability {
    pub const SCHEMA: u32 = 1;

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != Self::SCHEMA {
            return Err("object-store capability schema is unsupported".into());
        }
        upload_action_url(&self.url)?;
        const REQUIRED: [&str; 6] = [
            "key",
            "policy",
            "x-amz-algorithm",
            "x-amz-credential",
            "x-amz-date",
            "x-amz-signature",
        ];
        if self.fields.len() < REQUIRED.len() || self.fields.len() > REQUIRED.len() + 1 {
            return Err("object-store upload capability has an invalid field set".into());
        }
        if self
            .fields
            .keys()
            .any(|field| !REQUIRED.contains(&field.as_str()) && field != "x-amz-security-token")
            || REQUIRED
                .iter()
                .any(|field| self.fields.get(*field).is_none_or(String::is_empty))
        {
            return Err("object-store upload capability has an invalid field set".into());
        }
        if self.fields["x-amz-algorithm"] != "AWS4-HMAC-SHA256"
            || !crate::path::is_confined_relative(&self.fields["key"])
            || self.fields["key"].len() > 1024
            || self.fields["policy"].len() > 8 * 1024
            || self.fields["x-amz-credential"].len() > 1024
            || self.fields["x-amz-date"].len() != 16
            || !crate::is_canonical_sha256(&self.fields["x-amz-signature"])
            || self
                .fields
                .get("x-amz-security-token")
                .is_some_and(|token| token.is_empty() || token.len() > 8 * 1024)
        {
            return Err("object-store upload capability fields are malformed".into());
        }
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(&self.fields["policy"])
            .map_err(|_| "object-store upload capability policy is invalid base64".to_string())?;
        crate::bounded::encode(
            self,
            "object-store upload capability",
            MAX_CAPABILITY_BODY_BYTES,
        )
        .map(drop)
    }
}

/// Parse the only direct-upload action shape an agent may use. Authorization belongs exclusively
/// in the signed form fields: accepting query material here would create a second bearer mechanism
/// and make the exact authority harder to audit.
pub fn upload_action_url(value: &str) -> Result<url::Url, String> {
    crate::endpoint::https_url(value, crate::endpoint::QueryPolicy::Forbidden).map_err(|_| {
        String::from(
            "object-store upload action must be an absolute HTTPS URL without credentials, query material, or a fragment"
        )
    })
}

/// Parse the only bearer-URL shape an agent may spend. Userinfo would put another credential in
/// authority syntax, and fragments are client-local ambiguity; neither belongs in an exact S3
/// capability.
pub fn capability_url(value: &str) -> Result<url::Url, String> {
    crate::endpoint::https_url(value, crate::endpoint::QueryPolicy::Required).map_err(|_| {
        String::from(
            "object-store capability must be an absolute HTTPS URL with bearer query material",
        )
    })
}

fn bounded_json(value: &impl Serialize, what: &str) -> Result<Vec<u8>, String> {
    crate::bounded::encode(value, what, MAX_DATAFLOW_BODY_BYTES)
}

/// Capability fixtures, for this crate's tests and every downstream crate's.
///
/// A presigned POST form is six fields whose exact names and shapes the contract validates, and
/// three crates each wrote out their own copy to stand a capability up in a test. Not `#[cfg(test)]`
/// for the same reason as [`crate::key::testing`]: a `test`-gated item is invisible to other
/// crates, which is what produced the copies.
pub mod testing {
    use std::collections::BTreeMap;

    /// The presigned-POST fields a nominal upload capability carries, for the object at `key`.
    pub fn presigned_post_fields(key: &str) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("key".into(), key.to_string()),
            ("policy".into(), "e30=".into()),
            ("x-amz-algorithm".into(), "AWS4-HMAC-SHA256".into()),
            (
                "x-amz-credential".into(),
                "access/20260820/us-east-1/s3/aws4_request".into(),
            ),
            ("x-amz-date".into(), "20260820T120000Z".into()),
            ("x-amz-signature".into(), "a".repeat(64)),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshots_are_binary_safe_canonical_and_bounded() {
        let snapshot = FileSnapshot {
            files: BTreeMap::from([
                (
                    "host".into(),
                    FileValue::from_bytes(b"db.internal").unwrap(),
                ),
                (
                    "password".into(),
                    FileValue::from_bytes(&[0, 1, 255]).unwrap(),
                ),
            ]),
        };
        snapshot.validate().unwrap();
        assert_eq!(snapshot.files["password"].bytes().unwrap(), [0, 1, 255]);
        for invalid in ["Password", "password.", "con", "nul.txt", "../password"] {
            assert!(
                !FileSnapshot::valid_name(invalid),
                "{invalid:?} would not name one portable materialized file"
            );
        }

        let noncanonical = FileValue {
            base64: "YQ==\n".into(),
        };
        assert!(noncanonical.bytes().is_err());
        assert!(FileValue::from_bytes(&vec![0; FileValue::MAX_BYTES + 1]).is_err());
    }

    #[test]
    fn input_data_must_exactly_match_the_signed_selection() {
        let snapshot = FileSnapshot {
            files: BTreeMap::from([("password".into(), FileValue::from_bytes(b"s3cret").unwrap())]),
        };
        let selection = InputSelection {
            generation: "a".repeat(64),
            object_sha256: "b".repeat(64),
            files: BTreeSet::from(["password".into()]),
        };
        snapshot.validate_selection(&selection).unwrap();
        let another = InputSelection {
            generation: selection.generation,
            object_sha256: selection.object_sha256,
            files: BTreeSet::from(["another".into()]),
        };
        assert!(snapshot.validate_selection(&another).is_err());
    }

    #[test]
    fn public_generations_are_fixed_width_canonical_hmacs() {
        let mut selection = InputSelection {
            generation: "a".repeat(64),
            object_sha256: "b".repeat(64),
            files: BTreeSet::from(["host".into()]),
        };
        selection.validate().unwrap();

        for invalid in ["a".repeat(63), "A".repeat(64), "g".repeat(64)] {
            selection.generation = invalid;
            assert!(selection.validate().is_err());
        }
    }

    #[test]
    fn input_publications_are_stable_blinded_exact_byte_commitments() {
        let snapshot = FileSnapshot {
            files: BTreeMap::from([(
                "password".into(),
                FileValue::from_bytes(b"low-entropy-secret").unwrap(),
            )]),
        };
        let publication = InputPublication::from_snapshot(snapshot.clone(), &[7u8; 32]).unwrap();
        let same = InputPublication::from_snapshot(snapshot, &[7u8; 32]).unwrap();
        let body = publication.to_bounded_body().unwrap();
        let selection = publication.selection().unwrap();

        assert_eq!(
            publication, same,
            "one snapshot has one stable private body"
        );
        assert_ne!(
            selection.object_sha256,
            crate::digest::sha256_bytes(&serde_json::to_vec(&publication.snapshot).unwrap()),
            "the signed assignment must not publish the raw snapshot digest"
        );
        assert_eq!(
            InputPublication::from_bounded_body(&body, &selection).unwrap(),
            publication
        );

        let substituted = InputPublication::from_snapshot(
            FileSnapshot {
                files: BTreeMap::from([(
                    "password".into(),
                    FileValue::from_bytes(b"attacker").unwrap(),
                )]),
            },
            &[7u8; 32],
        )
        .unwrap()
        .to_bounded_body()
        .unwrap();
        assert!(InputPublication::from_bounded_body(&substituted, &selection).is_err());
    }

    #[test]
    fn capabilities_are_absolute_https_urls_without_ambiguous_authority() {
        capability_url("https://objects.example/internal/node?X-Amz-Signature=secret").unwrap();

        for invalid in [
            "http://objects.example/internal/node?signature=secret",
            "https://objects.example/internal/node",
            "https://objects.example/internal/node?",
            "https://user@objects.example/internal/node?signature=secret",
            "https://user:password@objects.example/internal/node?signature=secret",
            "https://objects.example/internal/node?signature=secret#fragment",
            "/internal/node?signature=secret",
        ] {
            assert!(capability_url(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn repository_deletion_outlives_every_capability_minting_phase() {
        assert_eq!(
            OBJECT_CAPABILITY_DRAIN,
            GATEWAY_AUTHORIZATION_MEMO_TTL + GATEWAY_REQUEST_TIMEOUT + OBJECT_CAPABILITY_TTL
        );
    }

    #[test]
    fn input_capability_path_names_the_exact_verified_assignment() {
        let digest = "a".repeat(64);
        assert_eq!(
            inputs_url("https://gateway.example/", &digest).unwrap(),
            format!("https://gateway.example/v1/node/inputs/{digest}")
        );
        assert!(inputs_url("https://gateway.example/", &"A".repeat(64)).is_err());
    }

    #[test]
    fn download_capabilities_bind_one_bounded_exact_object() {
        let capability = DownloadCapability {
            schema: DownloadCapability::SCHEMA,
            url: "https://objects.example/internal/node?X-Amz-Signature=secret".into(),
            sha256: "a".repeat(64),
        };
        let body = capability.to_bounded_json().unwrap();
        assert_eq!(
            DownloadCapability::from_bounded_json(&body).unwrap(),
            capability
        );

        let mut wrong_digest = capability.clone();
        wrong_digest.sha256 = "A".repeat(64);
        assert!(wrong_digest.validate().is_err());
        let mut oversized = capability.clone();
        oversized.url = format!(
            "https://objects.example/input?token={}",
            "x".repeat(MAX_CAPABILITY_BODY_BYTES)
        );
        assert!(oversized.validate().is_err());
        assert!(
            DownloadCapability::from_bounded_json(&vec![b' '; MAX_CAPABILITY_BODY_BYTES + 1])
                .is_err()
        );
    }

    #[test]
    fn upload_capabilities_have_one_strict_bounded_form() {
        let fields = testing::presigned_post_fields("routing/private/outputs/node.json");
        UploadCapability {
            schema: UploadCapability::SCHEMA,
            url: "https://objects.example/fleet/".into(),
            fields: fields.clone(),
        }
        .validate()
        .unwrap();

        for invalid in [
            "http://objects.example/fleet/",
            "https://objects.example/fleet/?signature=another-secret",
            "https://user@objects.example/fleet/",
            "https://objects.example/fleet/#fragment",
            "/fleet/",
        ] {
            assert!(upload_action_url(invalid).is_err(), "accepted {invalid}");
        }
        let mut unexpected = fields.clone();
        unexpected.insert("acl".into(), "public-read".into());
        assert!(UploadCapability {
            schema: UploadCapability::SCHEMA,
            url: "https://objects.example/fleet/".into(),
            fields: unexpected,
        }
        .validate()
        .is_err());
        let mut traversal = fields;
        traversal.insert("key".into(), "../another-object".into());
        assert!(UploadCapability {
            schema: UploadCapability::SCHEMA,
            url: "https://objects.example/fleet/".into(),
            fields: traversal,
        }
        .validate()
        .is_err());
    }
}
