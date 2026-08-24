//! The API-server write boundary and the in-process predicates must agree.
//!
//! `deploy/charts/updatec/templates/gateway-write-boundary.yaml` is a `ValidatingAdmissionPolicy`:
//! the last boundary on what the internet-facing gateway may write into a node's identity, and the
//! only one that still holds if the gateway process itself is compromised. It is CEL, so it cannot
//! call [`updatec::AgentIdentity::is_well_formed_for`] or `gateway::enroll::adopts_preapproval` —
//! it has to carry its own copy of the grammars and the identity kinds those predicates decide on.
//!
//! A second copy of a rule is a rule that drifts. `foundation::digest::CANONICAL_SHA256_PATTERN`
//! and `updated_contracts::key::P256_POINT_HEX_PATTERN` are exported from beside their predicates
//! for exactly this reason — and until this test existed, nothing read them: they were referenced
//! only by their own self-consistency tests, so the pinning they were written for never happened.
//! Either side could be edited alone. A loosened chart regex would let the gateway write an
//! identity the control plane then refuses to verify against; a tightened one would fail enrollment
//! at the API server for values the gateway believes are perfectly valid, which reads as a node
//! that mysteriously cannot enroll rather than as a mistake.
//!
//! So the chart is asserted against the Rust constants here. Changing either side alone fails this
//! test, which is the prompt to change the other.

use updatec::AgentIdentityKind;

/// The rendered-as-written CEL. The grammars and kind literals this test pins are plain text in the
/// template — no Helm interpolation touches them — so the source is what the API server evaluates.
fn policy_source() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../deploy/charts/updatec/templates/gateway-write-boundary.yaml");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()))
}

/// How a kind appears in CEL: its serde wire form, not a hand-typed lowercase guess. Renaming a
/// variant changes this, and the assertions below then demand the chart be renamed with it.
fn wire_kind(kind: AgentIdentityKind) -> String {
    serde_json::to_value(kind)
        .expect("an identity kind serializes")
        .as_str()
        .expect("an identity kind is a JSON string")
        .to_string()
}

/// The digest and public-key grammars the policy admits are the ones the Rust predicates enforce.
///
/// Asserted as the exact `matches(...)` call, not merely "the pattern appears somewhere": the point
/// is that the field is gated by this grammar, and a pattern sitting in a comment would satisfy a
/// bare substring search.
#[test]
fn the_write_boundary_admits_exactly_the_canonical_encodings() {
    let policy = policy_source();

    for (field, pattern) in [
        (
            "registrationSha256",
            foundation::digest::CANONICAL_SHA256_PATTERN,
        ),
        ("publicKey", updated_contracts::key::P256_POINT_HEX_PATTERN),
    ] {
        let gate = format!("object.spec.identity.{field}.matches('{pattern}')");
        assert!(
            policy.contains(&gate),
            "the admission policy must gate {field} on the exported grammar.\n  expected: \
             {gate}\nChange the chart and this constant together, or the API-server boundary and \
             the in-process predicate stop agreeing about which values exist."
        );
    }
}

/// The identity kinds the policy names are the ones the type actually serializes.
///
/// `enrolled` is the only kind the gateway may WRITE (mirroring `is_well_formed_for`'s enrolled
/// arm) and `reserved` is the only kind it may update in place (mirroring `adopts_preapproval`).
/// A renamed variant would leave both CEL literals matching nothing — and a `matchConditions`
/// expression that matches nothing does not deny, it simply never constrains the write.
#[test]
fn the_write_boundary_names_the_identity_kinds_the_type_serializes() {
    let policy = policy_source();

    let enrolled = wire_kind(AgentIdentityKind::Enrolled);
    assert!(
        policy.contains(&format!("object.spec.identity.kind == '{enrolled}'")),
        "the policy must admit writes only of a {enrolled:?} identity"
    );

    let reserved = wire_kind(AgentIdentityKind::Reserved);
    assert!(
        policy.contains(&format!("oldObject.spec.identity.kind == '{reserved}'")),
        "the policy must allow in-place completion only of a {reserved:?} identity"
    );

    // The offline path is never completed over the fleet bootstrap certificate, so its kind must
    // not appear as something this boundary admits at all.
    let manual = wire_kind(AgentIdentityKind::Manual);
    assert!(
        !policy.contains(&format!("identity.kind == '{manual}'")),
        "the gateway write boundary must never admit the operator-provisioned {manual:?} kind"
    );
}
