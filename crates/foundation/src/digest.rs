//! Lexical digest invariants shared across the permanent-launcher boundary.
//!
//! This module does not hash bytes or choose cryptographic policy. It only prevents one digest
//! from acquiring multiple filesystem or wire identities through hexadecimal case aliases.

/// [`is_canonical_sha256`] written as a regular expression, for enforcers that cannot call Rust.
///
/// The cluster's `ValidatingAdmissionPolicy` is the last boundary on what the gateway may write
/// into a node's identity, and it is CEL: it has to carry its own copy of this grammar. Exporting
/// the copy from beside the predicate is what lets the rendered chart be asserted against it —
/// `updatec`'s `gateway_write_boundary` test does exactly that, so the in-process check and the
/// admission boundary cannot come to disagree about which digests exist. Such a disagreement shows
/// up as enrolment failing at the API server for values the gateway believes are perfectly valid,
/// or, in the loosening direction, as one digest quietly acquiring a second spelling at the only
/// boundary left if the gateway itself is compromised.
pub const CANONICAL_SHA256_PATTERN: &str = "^[0-9a-f]{64}$";

/// Whether `value` is the canonical SHA-256 spelling: exactly 64 lowercase ASCII hexadecimal
/// characters.
pub fn is_canonical_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Parse an operator-supplied digest, accepting only the canonical spelling.
///
/// Every front end that takes a digest from a human uses this, so `updatectl` and `server` refuse
/// the same inputs for the same stated reason. They did not: `server` checked and explained, while
/// `updatectl` took the string unchecked and let it fail much later against signed metadata, where
/// the complaint was that two flags "name different reconciler builds" — which is not what went
/// wrong when the operator pasted an uppercase digest.
///
/// Uppercase is refused rather than folded. A digest has exactly one spelling in this system: it is
/// a filename, an object key, and a wire value, and accepting a second spelling at the edge is how
/// one piece of content acquires two identities.
pub fn parse_canonical_sha256(value: &str) -> Result<String, String> {
    if is_canonical_sha256(value) {
        return Ok(value.to_owned());
    }
    Err(format!(
        "expected a canonical SHA-256 digest: 64 lowercase hexadecimal characters, got {value:?}"
    ))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// The exported pattern and the predicate accept exactly the same strings.
    ///
    /// Checked class-by-class rather than with a regex engine, which this workspace deliberately
    /// does not depend on: change the predicate and this fails, which is the prompt to change the
    /// pattern the admission policy carries.
    #[test]
    fn the_exported_pattern_describes_exactly_what_the_predicate_accepts() {
        assert_eq!(CANONICAL_SHA256_PATTERN, "^[0-9a-f]{64}$");
        for byte in 0u8..=127 {
            let ch = byte as char;
            let in_class = ch.is_ascii_digit() || ('a'..='f').contains(&ch);
            let candidate: String = std::iter::repeat_n(ch, 64).collect();
            assert_eq!(
                is_canonical_sha256(&candidate),
                in_class,
                "the pattern's character class and the predicate disagree about {ch:?}"
            );
        }
        for length in [0usize, 63, 65, 128] {
            assert!(
                !is_canonical_sha256(&"a".repeat(length)),
                "the pattern fixes the length at 64, so {length} must be refused"
            );
        }
    }

    #[test]
    fn an_operator_digest_is_parsed_only_in_its_canonical_spelling() {
        let digest = "a".repeat(64);
        assert_eq!(parse_canonical_sha256(&digest), Ok(digest.clone()));
        for rejected in [
            digest.to_uppercase(),
            "a".repeat(63),
            "g".repeat(64),
            String::new(),
        ] {
            let error =
                parse_canonical_sha256(&rejected).expect_err("only the canonical spelling parses");
            assert!(error.contains("64 lowercase hexadecimal"), "{error}");
        }
    }

    #[test]
    fn sha256_has_one_lexical_identity() {
        assert!(is_canonical_sha256(&"a".repeat(64)));
        assert!(!is_canonical_sha256(&"A".repeat(64)));
        assert!(!is_canonical_sha256(&"a".repeat(63)));
        assert!(!is_canonical_sha256(&"a".repeat(65)));
        assert!(!is_canonical_sha256(&format!("{}z", "a".repeat(63))));
    }
}
