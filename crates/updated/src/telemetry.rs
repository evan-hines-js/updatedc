//! Node → control-plane rollout telemetry.
//!
//! The control plane can never reach a node, so completion feedback flows the other
//! way through shared storage: a node writes a small [`NodeReport`] to the report
//! location signed into its assignment ([`crate::config::RepositoryAssignment::report_url`]),
//! and the control plane reads it back out of the same object store it publishes to.
//! Reporting is strictly best-effort — a node that cannot write its report keeps
//! running, and a control plane that finds no report rolls without completion gating.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// How old a healthy report may be before a reader treats it as not-ready / not-settled. Shared by
/// every consumer (the control-plane rollout throttle AND the healthproxy) so they agree on when a
/// node that stopped heart-beating drops out — a node that goes silent must age out of "settled" in
/// the same bounded time it ages out of load-balancer rotation. Generous relative to the node's
/// report cadence (every check interval, tens of seconds) so a merely-slow re-report never flaps.
pub const REPORT_FRESHNESS: Duration = Duration::from_secs(60);

/// Milliseconds since the Unix epoch, the shared clock a node stamps its report with and a
/// reader ages it against. Wall-clock (not `Instant`) because writer and reader are different
/// processes; a clock that cannot be read reads as `0`, which every freshness check treats as
/// stale — the fail-closed direction.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// The relative object key, under a report base, a node writes its report to. Keyed by
/// node identity so the control plane can attribute a report to the agent it selected.
pub fn report_object_key(node: &str) -> String {
    format!("telemetry/{node}.json")
}

/// The absolute URL of a node's report under a base location: `<base>/telemetry/<node>.json`,
/// tolerant of a trailing slash on the base. The single place a report base and a node identity
/// become one fetchable/writable URL — shared by the agent that writes its report and any reader
/// (the health proxy) that fetches it, so the two can never drift.
pub fn report_url(base: &str, node: &str) -> String {
    format!("{}/{}", base.trim_end_matches('/'), report_object_key(node))
}

/// The request path a node `PUT`s its report to, relative to the report base.
pub const REPORT_PATH_PREFIX: &str = "/telemetry/";

/// Recover the node identity from a report request path (`/telemetry/<node>.json`),
/// rejecting traversal or unsafe characters. Shared by every control plane so the write
/// path is validated identically wherever a `report_url` happens to point.
pub fn node_from_path(request_path: &str) -> Option<&str> {
    let node = request_path
        .strip_prefix(REPORT_PATH_PREFIX)?
        .strip_suffix(".json")?;
    // Traversal safety is the shared `crate::path` component check; on top of that a report node is
    // a URL segment and a clean identity, so it additionally forbids `.` (any dot, not just `.`/`..`)
    // and the URL-significant `% ? #`.
    let safe = crate::path::is_safe_component(node) && !node.contains(['.', '%', '?', '#']);
    safe.then_some(node)
}

/// A node's self-reported running state. Authenticity is not load-bearing: the report
/// only ever *releases* a throttle slot, so a missing or stale report fails closed
/// (the member is treated as not-yet-settled and keeps its slot).
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeReport {
    pub schema: u32,
    /// The node identity this report is for (matches the selected `UpdateAgent`).
    pub node: String,
    /// The deployment identity the node currently has assigned
    /// ([`crate::config::RepositoryAssignment::deployment`]).
    pub deployment: String,
    /// The semantic version the node is *actually running* right now, independent of what it
    /// was assigned — after a rollback or ordered-fallback descent this is the version that
    /// really answered, not the desired one. It is the control plane's authoritative source
    /// of a node's running version, so no consumer ever has to probe the managed app (which
    /// may speak any protocol, or none). Empty only before the first install completes.
    pub version: String,
    /// Whether the node has *settled* on that deployment: it has finished acting on the
    /// assignment (installed and confirmed it, or attempted and rolled back from it) and
    /// its running app is healthy. A node that has merely fetched the assignment, or has
    /// an unconfirmed update still in flight, reports `false` — so the control plane never
    /// mistakes "received" for "done".
    pub healthy: bool,
    /// Milliseconds since the Unix epoch when the node wrote this report (see [`now_ms`]). A
    /// reader ages the report against this so a node that dies without writing a not-ready
    /// report cannot stay trusted forever — a stale report fails closed. `#[serde(default)]`
    /// so a record written before the field existed still parses, reading as `0` (ancient,
    /// hence stale — the safe default).
    #[serde(default)]
    pub reported_at_ms: u64,
    /// Hex ECDSA-P256 signature over [`NodeReport::signing_bytes`], produced by the node's per-node
    /// key (the same key certifies its mTLS leaf). The control plane verifies it against the node's
    /// pinned public key before trusting the report, so a report is attributable end-to-end
    /// (node → throttle) rather than merely authenticated on the write hop — a compromised gateway
    /// or a direct bucket write cannot forge a node's health. `#[serde(default)]` (empty) for a
    /// record predating signing, which fails verification and so fails closed.
    #[serde(default)]
    pub signature: String,
}

impl NodeReport {
    pub const SCHEMA: u32 = 1;

    pub fn new(
        node: impl Into<String>,
        deployment: impl Into<String>,
        version: impl Into<String>,
        healthy: bool,
    ) -> Self {
        Self {
            schema: Self::SCHEMA,
            node: node.into(),
            deployment: deployment.into(),
            version: version.into(),
            healthy,
            reported_at_ms: now_ms(),
            signature: String::new(),
        }
    }

    /// The canonical bytes a node signs and the control plane verifies: every field EXCEPT the
    /// signature, length-prefixed in a fixed order, so the signature binds the report's identity and
    /// state to the signing node independent of JSON key ordering, whitespace, or transport.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut push = |bytes: &[u8]| {
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        };
        push(&self.schema.to_be_bytes());
        push(self.node.as_bytes());
        push(self.deployment.as_bytes());
        push(self.version.as_bytes());
        push(&[u8::from(self.healthy)]);
        push(&self.reported_at_ms.to_be_bytes());
        out
    }

    /// Milliseconds elapsed between when this report was stamped and `now_ms`, saturating at
    /// zero for a report whose timestamp is (impossibly) in the future. An unstamped report
    /// (`reported_at_ms == 0`) ages as if written at the epoch, so it is always stale.
    pub fn age_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.reported_at_ms)
    }
}

/// Sign a report with a node's private key (PKCS#8 DER — the aws-lc-rs form of the rcgen-minted
/// ECDSA P-256 key that also certifies the node's mTLS leaf). Returns the hex signature to place in
/// [`NodeReport::signature`].
pub fn sign_report(report: &NodeReport, pkcs8_der: &[u8]) -> Result<String, String> {
    use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_der)
        .map_err(|e| format!("loading telemetry signing key: {e}"))?;
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let signature = key
        .sign(&rng, &report.signing_bytes())
        .map_err(|e| format!("signing telemetry report: {e}"))?;
    Ok(hex::encode(signature.as_ref()))
}

/// Verify a report's signature against the node's pinned public key (the uncompressed EC point from
/// its leaf certificate). Returns false on any missing/decode/verify failure so the caller treats an
/// unverifiable report as absent — a report only ever *releases* a throttle slot, so failing closed
/// keeps the slot held.
pub fn verify_report(report: &NodeReport, public_key_point: &[u8]) -> bool {
    use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
    let Ok(signature) = hex::decode(&report.signature) else {
        return false;
    };
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key_point)
        .verify(&report.signing_bytes(), &signature)
        .is_ok()
}

/// The one trust gate for consuming a node report.
///
/// A report is usable only when it names the expected node, is still inside the shared freshness
/// window, and verifies against that node's pinned enrollment key. Rollout admission and
/// load-balancer membership both call this function so attribution, replay resistance, and
/// signature policy cannot drift between control-plane consumers. Health and deployment matching
/// remain consumer-specific decisions made only after this gate succeeds.
pub fn report_is_authentic_and_fresh(
    report: &NodeReport,
    expected_node: &str,
    public_key_point: &[u8],
    now_ms: u64,
) -> bool {
    report.node == expected_node
        && report.age_ms(now_ms) <= REPORT_FRESHNESS.as_millis() as u64
        && verify_report(report, public_key_point)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_round_trip_and_reject_tampering_and_wrong_key() {
        use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
        let pubkey = key.public_key().as_ref().to_vec();

        let mut report = NodeReport::new("agent-9", "deploy-2", "2.0.0", true);
        report.signature = sign_report(&report, pkcs8.as_ref()).unwrap();
        assert!(
            verify_report(&report, &pubkey),
            "genuine report must verify"
        );
        assert!(report_is_authentic_and_fresh(
            &report,
            "agent-9",
            &pubkey,
            report.reported_at_ms
        ));
        assert!(!report_is_authentic_and_fresh(
            &report,
            "another-agent",
            &pubkey,
            report.reported_at_ms
        ));
        assert!(!report_is_authentic_and_fresh(
            &report,
            "agent-9",
            &pubkey,
            report
                .reported_at_ms
                .saturating_add(REPORT_FRESHNESS.as_millis() as u64 + 1)
        ));

        // Any tamper to a signed field breaks verification.
        let mut flipped = report.clone();
        flipped.healthy = false;
        assert!(
            !verify_report(&flipped, &pubkey),
            "tampered healthy must fail"
        );
        let mut renamed = report.clone();
        renamed.node = "agent-attacker".into();
        assert!(!verify_report(&renamed, &pubkey), "tampered node must fail");

        // A signature from a different key must not verify against this node's pinned key.
        let other = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let other_key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, other.as_ref()).unwrap();
        assert!(
            !verify_report(&report, other_key.public_key().as_ref()),
            "wrong key must fail"
        );

        // An unsigned (legacy) report fails closed.
        let unsigned = NodeReport::new("agent-9", "deploy-2", "2.0.0", true);
        assert!(
            !verify_report(&unsigned, &pubkey),
            "empty signature fails closed"
        );
    }

    #[test]
    fn report_key_is_namespaced_by_node() {
        assert_eq!(report_object_key("agent-7"), "telemetry/agent-7.json");
    }

    #[test]
    fn report_url_joins_base_and_key_without_a_double_slash() {
        // The writer (agent) and every reader (health proxy) resolve a report URL through here, so
        // a trailing slash on the base must not produce `//` either way.
        assert_eq!(
            report_url("https://cdn/", "agent-1"),
            "https://cdn/telemetry/agent-1.json"
        );
        assert_eq!(
            report_url("https://cdn", "agent-1"),
            "https://cdn/telemetry/agent-1.json"
        );
    }

    #[test]
    fn node_recovers_from_its_report_path() {
        assert_eq!(node_from_path("/telemetry/agent-7.json"), Some("agent-7"));
        // The key a node writes and the path it PUTs are the two halves of one contract.
        assert_eq!(
            node_from_path(&format!("/{}", report_object_key("agent-7"))),
            Some("agent-7")
        );
    }

    #[test]
    fn node_path_rejects_traversal_and_unsafe_names() {
        for path in [
            "/telemetry/../secret.json",
            "/telemetry/a/b.json",
            "/telemetry/.json",
            "/telemetry/agent-7.txt",
            "/other/agent-7.json",
        ] {
            assert_eq!(node_from_path(path), None, "{path}");
        }
    }

    #[test]
    fn report_roundtrips_and_rejects_unknown_fields() {
        let report = NodeReport::new("agent-7", "deploy-3", "3.0.0", true);
        let json = serde_json::to_string(&report).unwrap();
        assert_eq!(serde_json::from_str::<NodeReport>(&json).unwrap(), report);
        assert!(serde_json::from_str::<NodeReport>(
            r#"{"schema":1,"node":"a","deployment":"d","healthy":true,"extra":1}"#
        )
        .is_err());
    }
}
