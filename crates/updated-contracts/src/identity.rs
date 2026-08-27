//! Canonical human-readable identities carried across signed and durable boundaries.

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

/// Whether `value` is the one Kubernetes DNS-subdomain identity grammar.
///
/// This is deliberately separate from [`is_segment`]: opaque portable path segments may contain
/// `_`, while Kubernetes resource identities may contain dots only as separators between DNS
/// labels. Certificate issuance, enrollment, reports, backend inventory, assignments, and durable
/// rollout state all call this predicate, so none can mint or persist an identity another refuses.
pub fn is_dns_subdomain(value: &str) -> bool {
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
        assert!(is_dns_subdomain("agent-7"));
        assert!(is_dns_subdomain("rack-1.agent-7"));
        assert!(is_dns_subdomain(&format!(
            "{}.{}",
            "a".repeat(63),
            "b".repeat(63)
        )));
        for invalid in [
            "", ".", "..", "a/b", "a\\b", "a:b", "a%b", "a?b", "a#b", "A", "a_b", "-a", "a-",
            "a..b", "a\nb",
        ] {
            assert!(!is_dns_subdomain(invalid), "{invalid:?} must be refused");
        }
        assert!(!is_dns_subdomain(&"a".repeat(MAX_DNS_SUBDOMAIN_BYTES + 1)));
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
