//! Best-effort rollout telemetry: the node writes its running state to the report
//! location signed into its current assignment, so the control plane — which can never
//! reach the node — can read rollout progress out of shared storage.
//!
//! This is driven entirely by the *current* assignment each cycle: a new assignment
//! that adds `report_url` starts the heartbeat, one that drops it stops the heartbeat,
//! with no persistent telemetry state to reconcile. Every failure path here is a
//! logged no-op — a node that cannot report keeps updating and serving exactly as if
//! telemetry were never configured.

use std::time::Duration;

use updated::config::Routing;
use updated::telemetry::NodeReport;

/// The node's own identity, derived from the exact routing target it resolves
/// (`.../agents/<node>.json`). Returns `None` if the assignment path has no usable
/// file stem, in which case the node simply never reports.
pub fn node_identity(routing: &Routing) -> Option<String> {
    let name = routing
        .assignment
        .rsplit('/')
        .next()
        .unwrap_or(&routing.assignment)
        .strip_suffix(".json")?;
    (!name.is_empty()).then(|| name.to_string())
}

/// Write the node's running state to its report location. Strictly best-effort: any
/// error (no report URL, no derivable identity, network failure, non-success status)
/// is logged and swallowed so reporting can never disrupt the update loop.
pub async fn report_running_state(
    client: &reqwest::Client,
    report_url: Option<&str>,
    node: Option<&str>,
    deployment: &str,
    version: &str,
    healthy: bool,
    signing_key: Option<&[u8]>,
) {
    let (Some(report_url), Some(node)) = (report_url, node) else {
        return;
    };
    let mut report = NodeReport::new(node, deployment, version, healthy);
    // Sign with the node's per-node key so the throttle can verify authenticity end-to-end. A
    // signing failure leaves the report unsigned — best-effort, but it will fail closed at the
    // throttle (treated as not-yet-settled), never trusted.
    if let Some(key) = signing_key {
        match updated::telemetry::sign_report(&report, key) {
            Ok(signature) => report.signature = signature,
            Err(error) => crate::warn(&format!(
                "signing rollout telemetry failed ({error}); continuing unsigned"
            )),
        }
    }
    let body = match serde_json::to_vec(&report) {
        Ok(body) => body,
        Err(error) => {
            crate::warn(&format!(
                "encoding rollout telemetry failed ({error}); continuing"
            ));
            return;
        }
    };
    let target = updated::telemetry::report_url(report_url, node);
    let result = client
        .put(&target)
        .timeout(Duration::from_secs(5))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await;
    match result {
        Ok(response) if response.status().is_success() => {}
        Ok(response) => crate::warn(&format!(
            "rollout telemetry to {target} returned {}; continuing",
            response.status()
        )),
        Err(error) => crate::warn(&format!(
            "rollout telemetry to {target} failed ({error}); continuing"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn routing(assignment: &str) -> Routing {
        Routing {
            root: std::path::PathBuf::from("/root"),
            base_url: "https://cdn/".into(),
            assignment: assignment.into(),
            datastore: None,
            metadata_limit: 1024,
            transport_timeout: Duration::from_secs(5),
            mtls: updated::tls::Identity::new("tls.crt", "tls.key", "ca.crt"),
        }
    }

    #[test]
    fn node_identity_is_the_assignment_target_stem() {
        assert_eq!(
            node_identity(&routing("assignments/agents/agent-123.json")).as_deref(),
            Some("agent-123")
        );
    }

    #[test]
    fn node_identity_is_none_without_a_usable_stem() {
        assert_eq!(node_identity(&routing("assignments/agents/.json")), None);
        assert_eq!(node_identity(&routing("agents/agent")), None);
    }
}
