//! Canonical human-readable identities carried across signed and durable boundaries.

use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

use schemars::schema::{InstanceType, Schema, SchemaObject, StringValidation};
use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize};

/// The largest product, channel, platform, provider-set, or deployment identity.
///
/// These values become path segments, status fields, log attributes, and telemetry fields in
/// different parts of the system. Giving all of them one ASCII grammar prevents a value accepted
/// by a publisher from being reinterpreted by a filesystem or making a bounded report impossible
/// to publish.
pub const MAX_SEGMENT_BYTES: usize = 128;

/// [`is_segment`] written as a regular expression, for enforcers that cannot call Rust.
///
/// `schemas/*.schema.json` is the NORMATIVE wire contract — integrators write producers against
/// those files, not against this crate — so each one carries its own copy of this grammar. A second
/// copy is a copy that drifts, and this one had: the schemas blessed
/// `^[A-Za-z0-9][A-Za-z0-9._-]*$`, which admits `Production` (two signed identities for one
/// case-folded directory), `production-` (a trailing dot Windows strips), and `con` (a reserved
/// device name). Every one of those is schema-valid and rejected by every agent that parses it —
/// the exact "published schema blesses a document the fleet refuses" failure the conformance
/// harness exists to prevent, in the one dimension it never checked, because it pinned the pattern
/// to a hand-typed copy of itself rather than to the predicate.
///
/// Exported from beside the predicate so the schemas can be asserted against it instead. ECMA-262
/// lookahead carries the reserved-stem exclusion, which the sibling `path` pattern already relies
/// on. The length bound is not encoded here: schemas carry it as `maxLength`, pinned separately to
/// [`MAX_SEGMENT_BYTES`] (the grammar is ASCII, so bytes and characters agree).
pub const SEGMENT_PATTERN: &str =
    "^(?!(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:$|\\.))[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$";

/// Whether `value` is the one grammar for an opaque identity segment.
///
/// Lowercase and an alphanumeric final byte are portability invariants, not style: Windows folds
/// case and strips trailing dots when resolving names, so accepting `app` beside `APP` or `app.`
/// would give two signed identities one directory. Device stems are reserved even with an
/// extension (`con.txt`), so those are excluded too.
pub fn is_segment(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SEGMENT_BYTES
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || (index > 0 && matches!(byte, b'.' | b'_' | b'-'))
        })
        && value
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && !is_windows_device_stem(value.split('.').next().unwrap_or_default())
}

/// The largest Kubernetes DNS-subdomain identity.
///
/// Nodes, update groups, and repository resources all cross Kubernetes object metadata and wire
/// contracts. They therefore share this one ceiling and grammar instead of maintaining a
/// telemetry-specific approximation of the API server's name rules.
pub const MAX_DNS_SUBDOMAIN_BYTES: usize = 253;

/// [`ResourceName`]'s grammar for generated JSON schemas.
///
/// The runtime predicate remains the admission authority. This adjacent expression makes generated
/// schemas reject the same invalid shapes before they reach Rust; the unit test below pins every
/// clause to representative runtime decisions. The overall byte ceiling is expressed separately as
/// `maxLength` because the grammar is ASCII, so bytes and JSON-schema characters are identical.
pub const DNS_SUBDOMAIN_PATTERN: &str =
    "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$";

/// Whether `value` is the one Kubernetes DNS-subdomain identity grammar.
///
/// This is deliberately separate from [`is_segment`]: opaque portable path segments may contain
/// `_`, while Kubernetes resource identities may contain dots only as separators between DNS
/// labels. Certificate issuance, enrollment, reports, backend inventory, assignments, and durable
/// rollout state all call this predicate, so none can mint or persist an identity another refuses.
fn is_dns_subdomain(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_DNS_SUBDOMAIN_BYTES
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

/// A Kubernetes resource identity that has passed the fleet's one canonical name grammar.
///
/// Nodes, repositories, and rollout groups are the same kind of identity: each is serialized as a
/// Kubernetes DNS subdomain and crosses certificate, object-key, report, and durable-state
/// boundaries. A field-specific wrapper for every use would only move drift into conversion code,
/// so the system has exactly this one type. Its inner string is private, construction is fallible,
/// and deserialization calls the same constructor. Once a value is a `ResourceName`, consumers do
/// not revalidate it.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ResourceName(String);

/// A value is not a canonical [`ResourceName`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourceNameError;

impl ResourceName {
    /// Admit one owned string through the canonical identity grammar.
    pub fn new(value: impl Into<String>) -> Result<Self, ResourceNameError> {
        let value = value.into();
        if is_dns_subdomain(&value) {
            Ok(Self(value))
        } else {
            Err(ResourceNameError)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for ResourceName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl fmt::Display for ResourceNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid Kubernetes resource identity")
    }
}

impl std::error::Error for ResourceNameError {}

impl JsonSchema for ResourceName {
    fn schema_name() -> String {
        "ResourceName".to_owned()
    }

    fn json_schema(_: &mut schemars::gen::SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(InstanceType::String.into()),
            string: Some(Box::new(StringValidation {
                max_length: Some(MAX_DNS_SUBDOMAIN_BYTES as u32),
                min_length: Some(1),
                pattern: Some(DNS_SUBDOMAIN_PATTERN.to_owned()),
            })),
            ..Default::default()
        }
        .into()
    }
}

impl AsRef<str> for ResourceName {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Borrow<str> for ResourceName {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl PartialEq<str> for ResourceName {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<&str> for ResourceName {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl FromStr for ResourceName {
    type Err = ResourceNameError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::new(value)
    }
}

impl TryFrom<String> for ResourceName {
    type Error = ResourceNameError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for ResourceName {
    type Error = ResourceNameError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<'de> Deserialize<'de> for ResourceName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

fn is_windows_device_stem(stem: &str) -> bool {
    matches!(stem, "con" | "prn" | "aux" | "nul")
        || stem
            .strip_prefix("com")
            .or_else(|| stem.strip_prefix("lpt"))
            .is_some_and(|suffix| {
                matches!(suffix, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9")
            })
}

/// Release versions are copied from signed TUF metadata into directory names, durable state, and
/// node reports. Keep the bound and semantic-version grammar at the contract layer so every one of
/// those consumers accepts exactly the same strings.
pub const MAX_RELEASE_VERSION_BYTES: usize = 128;

pub fn parse_release_version(value: &str) -> Option<semver::Version> {
    if value.len() > MAX_RELEASE_VERSION_BYTES
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return None;
    }
    semver::Version::parse(value).ok()
}

pub fn is_release_version(value: &str) -> bool {
    parse_release_version(value).is_some()
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn identity_segments_have_one_bounded_ascii_grammar() {
        assert!(is_segment("production-web_2.1"));
        assert!(!is_segment("-production"));
        assert!(!is_segment("production-"));
        assert!(!is_segment("Production"));
        assert!(!is_segment("con"));
        assert!(!is_segment("nul.log"));
        assert!(!is_segment("com1"));
        assert!(is_segment("com10"));
        assert!(!is_segment("prod/web"));
        assert!(!is_segment("prod\nweb"));
        assert!(!is_segment(&"a".repeat(MAX_SEGMENT_BYTES + 1)));
    }

    #[test]
    fn kubernetes_resource_identities_have_one_dns_subdomain_grammar() {
        assert!(ResourceName::new("agent-7").is_ok());
        assert!(ResourceName::new("rack-1.agent-7").is_ok());
        assert!(ResourceName::new(format!("{}.{}", "a".repeat(63), "b".repeat(63))).is_ok());
        for invalid in [
            "", ".", "..", "a/b", "a\\b", "a:b", "a%b", "a?b", "a#b", "A", "a_b", "-a", "a-",
            "a..b", "a\nb",
        ] {
            assert!(
                ResourceName::new(invalid).is_err(),
                "{invalid:?} must be refused"
            );
        }
        assert!(ResourceName::new("a".repeat(MAX_DNS_SUBDOMAIN_BYTES + 1)).is_err());
    }

    #[test]
    fn resource_names_cannot_bypass_validation_during_deserialization() {
        let name = ResourceName::new("rack-1.agent-7").unwrap();
        assert_eq!(serde_json::to_string(&name).unwrap(), "\"rack-1.agent-7\"");
        assert_eq!(
            serde_json::from_str::<ResourceName>("\"rack-1.agent-7\"").unwrap(),
            name
        );
        assert!(serde_json::from_str::<ResourceName>("\"Agent-7\"").is_err());
    }

    #[test]
    fn resource_name_schema_carries_the_runtime_grammar_and_bound() {
        let schema = schemars::schema_for!(ResourceName);
        let validation = schema.schema.string.expect("ResourceName must be a string");
        assert_eq!(validation.min_length, Some(1));
        assert_eq!(validation.max_length, Some(MAX_DNS_SUBDOMAIN_BYTES as u32));
        assert_eq!(validation.pattern.as_deref(), Some(DNS_SUBDOMAIN_PATTERN));

        assert_eq!(
            DNS_SUBDOMAIN_PATTERN,
            "^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
        );
        for valid in ["a", "agent-7", "rack-1.agent-7"] {
            assert!(ResourceName::new(valid).is_ok());
        }
        for invalid in ["", "-agent", "agent-", "Agent", "agent_7", "rack..agent"] {
            assert!(ResourceName::new(invalid).is_err());
        }
    }

    /// The exported pattern and the predicate accept exactly the same strings.
    ///
    /// Checked clause by clause rather than with a regex engine, which this workspace deliberately
    /// does not depend on (same approach as `foundation::digest`). The literal is asserted first so
    /// that editing the grammar is a deliberate act, and then every clause it encodes is exercised
    /// against the predicate: change `is_segment` and this fails, which is the prompt to change the
    /// pattern the published schemas carry — and the schema tests then demand the schemas follow.
    #[test]
    fn the_exported_pattern_describes_exactly_what_the_predicate_accepts() {
        assert_eq!(
            SEGMENT_PATTERN,
            "^(?!(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:$|\\.))[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$"
        );

        // The leading character class `[a-z0-9]`: exactly which single bytes may open a segment.
        // A single character is also a whole segment, so this sweeps the one-character case too.
        for byte in 0u8..=127 {
            let ch = byte as char;
            let opens = ch.is_ascii_lowercase() || ch.is_ascii_digit();
            assert_eq!(
                is_segment(&ch.to_string()),
                opens,
                "the pattern's leading class and the predicate disagree about {ch:?}"
            );
            // ...and the same class closes a segment, per the trailing `[a-z0-9]`.
            assert_eq!(
                is_segment(&format!("a{ch}")),
                opens,
                "the pattern's trailing class and the predicate disagree about {ch:?}"
            );
        }

        // The interior class `[a-z0-9._-]`, which admits the three punctuation bytes the leading
        // and trailing classes do not.
        for byte in 0u8..=127 {
            let ch = byte as char;
            let interior =
                ch.is_ascii_lowercase() || ch.is_ascii_digit() || matches!(ch, '.' | '_' | '-');
            assert_eq!(
                is_segment(&format!("a{ch}b")),
                interior,
                "the pattern's interior class and the predicate disagree about {ch:?}"
            );
        }

        // The reserved-stem lookahead: a device name alone or followed by an extension, and
        // nothing else that merely starts with those letters.
        for reserved in ["con", "prn", "aux", "nul", "com1", "com9", "lpt1", "lpt9"] {
            assert!(!is_segment(reserved), "{reserved} is a reserved stem");
            assert!(
                !is_segment(&format!("{reserved}.log")),
                "{reserved}.log is a reserved stem with an extension"
            );
            assert!(
                is_segment(&format!("{reserved}x")),
                "{reserved}x merely begins with a reserved stem"
            );
        }
        // The lookahead is anchored to the stem, so a reserved name later in the value is fine.
        assert!(is_segment("app.con"));
        assert!(is_segment("com0"));
        assert!(is_segment("com10"));
    }

    #[test]
    fn release_versions_are_semver_and_bounded() {
        assert!(is_release_version("1.2.3-rc.1+build.7"));
        assert!(!is_release_version("1.2.3-RC.1"));
        assert!(!is_release_version("latest"));
        assert!(!is_release_version(&format!(
            "1.0.0+{}",
            "a".repeat(MAX_RELEASE_VERSION_BYTES)
        )));
    }
}
