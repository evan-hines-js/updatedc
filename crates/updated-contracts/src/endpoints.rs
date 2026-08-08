//! The control plane's endpoint projection: which nodes the load balancer must treat as drained
//! regardless of their own health reports.
//!
//! This is the one channel a per-node operational control (`UpdateAgent.spec.cordon`) reaches the
//! healthproxy through. The control plane can never reach a node, and the node itself is entirely
//! unaware of a cordon — the application keeps running and keeps reporting — so the only thing a
//! cordon may change is what the control plane *publishes*: this document, written to the same
//! shared store the node reports already travel through, read by `updated-healthproxy` on the same
//! cadence as those reports.
//!
//! The document is deliberately NOT signed. A drained entry can only take a node *out* of
//! rotation, which is the state a deleted or stale report already produces — a writer with access
//! to the store can drain any node today by deleting its report, so signing this adds no
//! protection the report path has. In the other direction a forged *absence* leaves a healthy,
//! serving node in rotation, which is the safe steady state. Readers therefore fail OPEN on this
//! document: unreadable or missing means "no node is cordoned", never "drain everyone".

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

/// The object key of the endpoint projection, relative to the published repository prefix — the
/// same base the report namespace hangs off, so every server that serves `telemetry/` can serve
/// this beside it.
pub const ENDPOINTS_OBJECT_KEY: &str = "endpoints/state.json";

/// Upper bound on a published endpoint projection, shared by the writer's probe and the reader's
/// fetch so the two sides cannot drift into a document one accepts and the other silently
/// refuses (a refused read fails OPEN here — an un-cordoned fleet — which is exactly the failure
/// an asymmetric bound would hide). Generous against the real size: a node name per cordoned
/// machine, bounded by the enrollment ceiling.
pub const MAX_PROJECTION_BYTES: usize = 8 * 1024 * 1024;

/// The URL of the endpoint projection under a serving `base`, joined exactly as
/// [`crate::telemetry::report_url`] joins a report's.
pub fn endpoints_url(base: &str) -> String {
    format!("{}/{ENDPOINTS_OBJECT_KEY}", base.trim_end_matches('/'))
}

/// The published endpoint projection: every node the operator has cordoned
/// (`UpdateAgent.spec.cordon`), to be programmed as drained whatever its report says.
///
/// Deliberately NOT `deny_unknown_fields`: the reader fails OPEN on an unusable document, so a
/// strict parse would make any future additive field silently un-cordon every fleet whose
/// healthproxy is one release older than its control plane — the worst possible failure shape for
/// a versioned wire document whose two ends upgrade independently. Unknown fields are ignored;
/// incompatible CHANGES bump `schema`, which the reader checks.
#[derive(Debug, Deserialize, Serialize)]
pub struct EndpointProjection {
    pub schema: u32,
    /// Node identities the load balancer must hold out of rotation. Each satisfies the same node
    /// grammar as a report path ([`crate::telemetry::is_valid_node`]); a reader skips any entry
    /// that does not, so one malformed entry never poisons the rest of the document.
    #[serde(default)]
    pub drained: BTreeSet<String>,
}

impl EndpointProjection {
    pub const SCHEMA: u32 = 1;

    pub fn new(drained: BTreeSet<String>) -> Self {
        Self {
            schema: Self::SCHEMA,
            drained,
        }
    }

    /// The drained set this document asserts, or an empty set when the document cannot be used —
    /// the fail-open reading described at the module level. Entries that are not valid node
    /// identities are dropped individually.
    pub fn parse(bytes: &[u8]) -> BTreeSet<String> {
        let Ok(projection) = serde_json::from_slice::<Self>(bytes) else {
            return BTreeSet::new();
        };
        if projection.schema != Self::SCHEMA {
            return BTreeSet::new();
        }
        projection
            .drained
            .into_iter()
            .filter(|node| crate::telemetry::is_valid_node(node))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_projection_round_trips_and_names_a_stable_key() {
        let projection = EndpointProjection::new(BTreeSet::from(["agent-0".to_string()]));
        let bytes = serde_json::to_vec(&projection).unwrap();
        assert_eq!(
            EndpointProjection::parse(&bytes),
            BTreeSet::from(["agent-0".to_string()])
        );
        assert_eq!(ENDPOINTS_OBJECT_KEY, "endpoints/state.json");
        assert_eq!(
            endpoints_url("http://cdn/"),
            "http://cdn/endpoints/state.json"
        );
    }

    /// The reader fails OPEN: an unusable document means "nobody is cordoned", because a forged or
    /// corrupt drain-everything document must not be able to evict a healthy fleet, while the
    /// report path already covers genuinely unhealthy nodes.
    #[test]
    fn an_unusable_projection_reads_as_empty() {
        assert!(EndpointProjection::parse(b"not json").is_empty());
        assert!(EndpointProjection::parse(b"{}").is_empty());
        let wrong_schema = serde_json::json!({"schema": 99, "drained": ["agent-0"]});
        assert!(EndpointProjection::parse(&serde_json::to_vec(&wrong_schema).unwrap()).is_empty());
    }

    /// One malformed entry is dropped alone; the rest of the document still applies. A name the
    /// report grammar refuses could never belong to a real node, so keeping it would only let a
    /// hostile document smuggle balancer-syntax into consumers.
    #[test]
    fn malformed_node_entries_are_dropped_individually() {
        let mixed =
            serde_json::json!({"schema": 1, "drained": ["agent-0", "../escape", "web.prod"]});
        assert_eq!(
            EndpointProjection::parse(&serde_json::to_vec(&mixed).unwrap()),
            BTreeSet::from(["agent-0".to_string()])
        );
    }
}
