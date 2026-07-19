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

/// The request path a node `PUT`s its report to, relative to the report base.
pub const REPORT_PATH_PREFIX: &str = "/telemetry/";

/// Recover the node identity from a report request path (`/telemetry/<node>.json`),
/// rejecting traversal or unsafe characters. Shared by every control plane so the write
/// path is validated identically wherever a `report_url` happens to point.
pub fn node_from_path(request_path: &str) -> Option<&str> {
    let node = request_path
        .strip_prefix(REPORT_PATH_PREFIX)?
        .strip_suffix(".json")?;
    let safe = !node.is_empty()
        && !node.contains(['/', '\\', '.', '%', '?', '#', ':'])
        && !node.chars().any(char::is_control);
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
        }
    }

    /// Milliseconds elapsed between when this report was stamped and `now_ms`, saturating at
    /// zero for a report whose timestamp is (impossibly) in the future. An unstamped report
    /// (`reported_at_ms == 0`) ages as if written at the epoch, so it is always stale.
    pub fn age_ms(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.reported_at_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_key_is_namespaced_by_node() {
        assert_eq!(report_object_key("agent-7"), "telemetry/agent-7.json");
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
