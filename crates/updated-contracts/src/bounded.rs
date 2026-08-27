//! The one place a serialized contract document meets its byte bound.
//!
//! Every document in this crate is bounded, and the bound is load-bearing in one direction in
//! particular: [`decode`] refuses oversized bytes BEFORE handing them to serde, so a peer cannot
//! make this process allocate and parse an arbitrarily large document by claiming it is one of ours.
//! That rule was written out at each document type — ten times, in three different error styles —
//! and a rule copied ten times is a rule the eleventh document forgets. Here it is the only way to
//! cross the boundary, so forgetting it means not encoding or decoding at all.
//!
//! `what` names the document in the diagnostic. Every message has the same shape, because an
//! operator reading "is 9000 bytes, past the 4096-byte limit" should not have to learn a different
//! phrasing per document.

use serde::{de::DeserializeOwned, Serialize};

/// Serialize `value`, refusing a document past `limit`.
///
/// Bounding the write side too means this process cannot emit a document its own reader would
/// refuse — the failure surfaces where the oversized value was built, not as an unexplained
/// rejection at the far end.
pub fn encode<T: Serialize>(value: &T, what: &str, limit: usize) -> Result<Vec<u8>, String> {
    let bytes = serde_json::to_vec(value).map_err(|error| format!("encoding {what}: {error}"))?;
    check(bytes.len(), what, limit)?;
    Ok(bytes)
}

/// Refuse `bytes` past `limit`, then deserialize.
///
/// The order is the point: the bound is checked against the raw length before serde sees the input.
pub fn decode<T: DeserializeOwned>(bytes: &[u8], what: &str, limit: usize) -> Result<T, String> {
    check(bytes.len(), what, limit)?;
    serde_json::from_slice(bytes).map_err(|error| format!("decoding {what}: {error}"))
}

fn check(length: usize, what: &str, limit: usize) -> Result<(), String> {
    if length > limit {
        return Err(format!(
            "{what} is {length} bytes, past the {limit}-byte limit"
        ));
    }
    Ok(())
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn a_document_within_its_bound_round_trips() {
        let bytes = encode(&"hello", "test document", 64).unwrap();
        assert_eq!(
            decode::<String>(&bytes, "test document", 64).unwrap(),
            "hello"
        );
    }

    #[test]
    fn both_directions_refuse_a_document_past_its_bound() {
        let oversized = "x".repeat(64);
        let encoded = serde_json::to_vec(&oversized).unwrap();

        let error = encode(&oversized, "test document", 8).expect_err("the write side is bounded");
        assert!(error.contains("past the 8-byte limit"), "{error}");
        let error =
            decode::<String>(&encoded, "test document", 8).expect_err("the read side is bounded");
        assert!(error.contains("past the 8-byte limit"), "{error}");
    }

    /// The bound is checked against the raw length, so oversized input never reaches serde. Bytes
    /// that are both too long AND unparseable must fail on the length: a decoder that parsed first
    /// would already have done the work the bound exists to prevent.
    #[test]
    fn the_bound_is_enforced_before_parsing() {
        let error = decode::<String>(&vec![b'{'; 4096], "test document", 8)
            .expect_err("oversized input is refused");
        assert!(
            error.contains("past the 8-byte limit"),
            "the length must be refused before serde is asked to parse: {error}"
        );
    }
}
