//! The one public key this system verifies signatures with, and the one gate that admits one.
//!
//! Four things in this tower pin an ECDSA P-256 key: a node's enrollment key (telemetry reports),
//! the load balancer's inventory (the same key, read from a different object), the agent identity
//! the control plane keeps, and the admission authority's decision key. Each of them used to
//! hex-decode and shape-check on its own, and they had already drifted — one demanded the canonical
//! lowercase spelling, one accepted any hex case, one proved the point was actually on the curve
//! and three did not. A pin that passes at the boundary and fails at the verifier is the worst
//! failure this system has: every signature from that identity is refused, and the logs cannot tell
//! it apart from forgery.
//!
//! So a pinned key has one type. [`P256PublicKey`] is the only way to hold one, the constructors
//! are the only way to make one, and they apply the strictest rule any call site had. A verifier
//! takes this type rather than bytes, which is why "did anyone check this key?" is no longer a
//! question a call site can get wrong.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Why a pinned key was refused. Callers add their own subject ("inventory member `x`", "the
/// decision key") and print this for the reason, so operators get the same diagnosis wherever the
/// mistake was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum P256KeyError {
    /// Not canonical lowercase hexadecimal.
    NotCanonicalHex,
    /// Not the SEC1 uncompressed encoding: 65 bytes, `0x04`, then two non-zero coordinates.
    NotUncompressedPoint { len: usize },
    /// Correctly shaped, but not a point on the P-256 curve.
    NotOnCurve,
}

impl fmt::Display for P256KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotCanonicalHex => f.write_str("is not canonical lowercase hex"),
            Self::NotUncompressedPoint { len } => write!(
                f,
                "is not an uncompressed P-256 point (65 bytes starting 0x04), got {len} byte(s)"
            ),
            Self::NotOnCurve => f.write_str("is not a point on the P-256 curve"),
        }
    }
}

impl std::error::Error for P256KeyError {}

/// A pinned ECDSA P-256 public key, proven well-formed and on-curve at construction.
///
/// Held as its SEC1 uncompressed encoding, which is both the wire spelling (hex) and what the
/// verifier consumes, so there is no second representation to convert between.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct P256PublicKey(Vec<u8>);

/// A serialized pin is its canonical hex spelling, and deserializing one runs the same gate a
/// configured pin goes through. That is what lets a wire type hold a `P256PublicKey` directly
/// instead of a `String` some later reader is trusted to remember to parse.
impl Serialize for P256PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for P256PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        Self::parse_hex(&encoded)
            .map_err(|error| serde::de::Error::custom(format!("public key {error}")))
    }
}

/// The LEXICAL shape of a serialized pin, for enforcers that cannot call Rust.
///
/// Deliberately weaker than [`P256PublicKey::parse_hex`], and that is the whole design: the
/// cluster's `ValidatingAdmissionPolicy` is CEL and cannot do curve arithmetic, so it can check the
/// spelling — canonical lowercase hex, a SEC1 uncompressed point's 65 bytes, the `04` prefix — but
/// never that the point is on the curve or non-zero. It is a boundary behind the real check, not a
/// substitute for it: the gateway has already run the full gate before it writes.
///
/// Exported from beside the parser so the chart cannot spell it differently: the rendered policy is
/// asserted against this constant by `updatec`'s `gateway_write_boundary` test, so editing either
/// side alone fails the build. A pin shape Rust accepts and the policy refuses is enrolment failing
/// at the API server for a key the gateway believes is valid; the reverse quietly widens the last
/// boundary on node identity.
pub const P256_POINT_HEX_PATTERN: &str = "^04[0-9a-f]{128}$";

impl P256PublicKey {
    /// Admit a key from its raw SEC1 uncompressed point — the shape a parsed CSR hands over.
    pub fn from_point(point: &[u8]) -> Result<Self, P256KeyError> {
        if point.len() != 65 || point[0] != 4 || point[1..].iter().all(|byte| *byte == 0) {
            return Err(P256KeyError::NotUncompressedPoint { len: point.len() });
        }
        // Shape is not a curve check: a 65-byte `04`-prefixed string can still be off-curve, and an
        // off-curve pin fails every signature exactly like a forged report. AWS-LC's approved P-256
        // agreement primitive is the point parser; it validates the point and retains nothing, so
        // the boundary and the ECDSA verifier below stay on one crypto provider without minting an
        // unnecessary private key.
        use aws_lc_rs::agreement::{ParsedPublicKey, UnparsedPublicKey, ECDH_P256};
        let peer = UnparsedPublicKey::new(&ECDH_P256, point);
        let _: ParsedPublicKey = (&peer).try_into().map_err(|_| P256KeyError::NotOnCurve)?;
        Ok(Self(point.to_vec()))
    }

    /// Admit a key from the canonical lowercase-hex spelling every serialized pin uses.
    ///
    /// Uppercase hex is refused rather than normalized: the same key must have one name, or an
    /// object keyed by it, a log line about it, and an equality check on it stop agreeing.
    pub fn parse_hex(encoded: &str) -> Result<Self, P256KeyError> {
        let point = hex::decode(encoded).map_err(|_| P256KeyError::NotCanonicalHex)?;
        if hex::encode(&point) != encoded {
            return Err(P256KeyError::NotCanonicalHex);
        }
        Self::from_point(&point)
    }

    /// The SEC1 uncompressed point.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// The canonical spelling [`P256PublicKey::parse_hex`] round-trips.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Whether `signature` — ASN.1 DER, over SHA-256 — is this key's signature on `message`.
    ///
    /// The single ECDSA verification in the system. Callers differ only in what they choose to
    /// treat as the signed message (a DSSE pre-authentication encoding, an exact response body);
    /// the algorithm, the digest, and the key handling are not theirs to pick.
    pub fn verify_asn1(&self, message: &[u8], signature: &[u8]) -> bool {
        use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &self.0)
            .verify(message, signature)
            .is_ok()
    }
}

/// Key fixtures, for this crate's tests and every downstream crate's.
///
/// Not cfg-gated behind `test`, because a `#[cfg(test)]` item is invisible to other crates and
/// Cargo's feature unification would put a `testing` feature into the shipped build anyway. The
/// cost is a few lines of generator in the binary; the benefit is that no test anywhere needs to
/// hand-roll a key — and hand-rolled keys are exactly what this module exists to stop. Every pin in
/// a fixture is now a real on-curve point, so a test cannot pass against a key production would
/// refuse.
pub mod testing {
    use super::P256PublicKey;
    use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    /// A real P-256 keypair, so tests sign and verify against the same primitives production does.
    pub fn keypair() -> (EcdsaKeyPair, P256PublicKey) {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
        let public = P256PublicKey::from_point(key.public_key().as_ref()).unwrap();
        (key, public)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn a_real_key_round_trips_through_its_canonical_spelling() {
        let (_, public) = testing::keypair();
        assert_eq!(P256PublicKey::parse_hex(&public.to_hex()).unwrap(), public);
    }

    /// The exported lexical pattern agrees with the parser on spelling, and is honestly weaker on
    /// everything else.
    ///
    /// Checked class-by-class rather than with a regex engine, which this workspace deliberately
    /// does not depend on. What this pins is that a key the parser accepts always matches the
    /// pattern the admission policy enforces — the direction that breaks enrolment.
    #[test]
    fn the_exported_pattern_matches_every_pin_the_parser_admits() {
        assert_eq!(P256_POINT_HEX_PATTERN, "^04[0-9a-f]{128}$");
        let (_, key) = testing::keypair();
        let hex = key.to_hex();
        assert_eq!(
            hex.len(),
            130,
            "the pattern fixes 04 plus 128 hex characters"
        );
        assert!(hex.starts_with("04"), "a SEC1 uncompressed point");
        assert!(
            hex.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
            "canonical lowercase hex only: {hex}"
        );

        // The pattern is a shape gate, not the parser. It cannot see the curve, which is why the
        // real check runs before anything is written and this only guards the boundary behind it.
        let off_curve = format!("04{}", "0".repeat(128));
        assert!(off_curve.len() == 130 && off_curve.starts_with("04"));
        assert!(
            P256PublicKey::parse_hex(&off_curve).is_err(),
            "the parser refuses what the pattern alone would let through"
        );
    }

    #[test]
    fn one_spelling_only() {
        let (_, public) = testing::keypair();
        let upper = public.to_hex().to_uppercase();
        assert_eq!(
            P256PublicKey::parse_hex(&upper),
            Err(P256KeyError::NotCanonicalHex),
            "uppercase hex would give one key two names"
        );
        assert_eq!(
            P256PublicKey::parse_hex("nothex"),
            Err(P256KeyError::NotCanonicalHex)
        );
    }

    #[test]
    fn shape_is_checked_before_the_curve() {
        for (bytes, len) in [
            (vec![], 0usize),
            (vec![4u8; 64], 64),
            (vec![4u8; 66], 66),
            ([vec![2u8], vec![7u8; 64]].concat(), 65),
        ] {
            assert_eq!(
                P256PublicKey::from_point(&bytes),
                Err(P256KeyError::NotUncompressedPoint { len }),
                "{bytes:?} is not an uncompressed point"
            );
        }
        // The all-zero point is correctly shaped and must still be refused.
        let zeros = [vec![4u8], vec![0u8; 64]].concat();
        assert_eq!(
            P256PublicKey::from_point(&zeros),
            Err(P256KeyError::NotUncompressedPoint { len: 65 })
        );
    }

    #[test]
    fn a_well_shaped_point_that_is_not_on_the_curve_is_refused() {
        // Correct length and prefix, coordinates that satisfy no curve equation. Shape-only
        // validation admitted this, and every signature against it then failed at the verifier.
        let off_curve = [vec![4u8], vec![1u8; 64]].concat();
        assert_eq!(
            P256PublicKey::from_point(&off_curve),
            Err(P256KeyError::NotOnCurve)
        );
    }

    #[test]
    fn a_serialized_pin_is_admitted_by_the_same_gate_as_a_configured_one() {
        let (_, public) = testing::keypair();
        let json = serde_json::to_string(&public).unwrap();
        assert_eq!(json, format!("\"{}\"", public.to_hex()));
        assert_eq!(
            serde_json::from_str::<P256PublicKey>(&json).unwrap(),
            public
        );

        // Every shape the constructors refuse is refused at the wire boundary too, so no reader
        // downstream can be handed a pin nothing validated.
        for bad in [
            "\"\"".to_string(),
            "\"not-hex\"".to_string(),
            format!("\"04{}\"", "ab".repeat(64)),
            format!("\"{}\"", public.to_hex().to_uppercase()),
            "123".to_string(),
        ] {
            assert!(
                serde_json::from_str::<P256PublicKey>(&bad).is_err(),
                "accepted {bad}"
            );
        }
    }

    #[test]
    fn verification_binds_key_message_and_signature() {
        let (key, public) = testing::keypair();
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let signature = key.sign(&rng, b"the signed bytes").unwrap();

        assert!(public.verify_asn1(b"the signed bytes", signature.as_ref()));
        assert!(!public.verify_asn1(b"other bytes", signature.as_ref()));
        assert!(!public.verify_asn1(b"the signed bytes", b"not a signature"));

        let (_, other) = testing::keypair();
        assert!(!other.verify_asn1(b"the signed bytes", signature.as_ref()));
    }
}
