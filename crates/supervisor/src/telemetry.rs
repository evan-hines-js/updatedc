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
use updated_contracts::telemetry::{
    report_url as telemetry_report_url, sign_report, NodeReport, OutputManifest,
    MAX_OUTPUT_MANIFEST_BYTES,
};

/// The node's own identity, derived from the exact routing target it resolves
/// (`<prefix>/agents/<node>.json`), read through the one parser of that layout. Returns `None` if
/// the assignment is not a routing target naming a valid node identity, in which case the node
/// simply never reports.
pub fn node_identity(routing: &Routing) -> Option<String> {
    updated_contracts::telemetry::split_assignment_path(&routing.assignment)
        .map(|(_, node)| node.to_string())
}

/// What the node is running right now — the signed payload of one heartbeat, gathered by the
/// caller from the assignment it just acted on and its own committed install record.
pub struct RunningState<'a> {
    /// The deployment identity the control plane currently assigns this node.
    pub deployment: &'a str,
    /// Digest of the exact signed assignment document behind that deployment name. This is what
    /// lets the control plane stage a change that keeps the name — a new archive, argument,
    /// secret, or resolved input — one `maxUnavailable` batch at a time.
    pub assignment_sha256: &'a str,
    /// The version actually answering, empty before the first install completes.
    pub version: &'a str,
    /// The SHA-256 of the archive that version was installed from, empty alongside `version`.
    pub archive_sha256: &'a str,
    /// Settled: acted on the assignment and healthy. Never true mid-rollout.
    pub healthy: bool,
    /// Latest successful opaque node-state fingerprint, when one is currently publishable.
    pub fingerprint: Option<&'a updated_contracts::telemetry::Fingerprint>,
    /// Where installed archives live, and the manifest digest identifying the running one — the
    /// two inputs [`load_outputs`] needs. The outputs themselves are read here, not by the caller,
    /// so the rule that only a settled report carries them is enforced in exactly one place.
    pub install_root: &'a std::path::Path,
    pub manifest_sha256: &'a str,
}

/// Read and validate the running archive's bounded output manifest. A missing file means the
/// reconciler emitted no outputs; malformed or oversized data is omitted rather than weakening
/// the health report itself.
pub fn load_outputs(
    install_root: &std::path::Path,
    archive_sha256: &str,
) -> Option<OutputManifest> {
    if archive_sha256.is_empty() {
        return None;
    }
    let path = crate::update::reconciler_output_path(install_root, archive_sha256);
    let metadata = std::fs::metadata(&path).ok()?;
    // The size bound is the *envelope* bound worked backwards (see
    // `MAX_OUTPUT_MANIFEST_BYTES`): a manifest larger than this signs into a report no hop on the
    // publish path would accept, and since outputs ride only on healthy reports, attaching it
    // would silently drain a healthy node forever. Omitting the outputs keeps the node published.
    if !metadata.is_file() || metadata.len() > MAX_OUTPUT_MANIFEST_BYTES as u64 {
        crate::warn("reconciler output manifest is not a bounded regular file; omitting outputs");
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let manifest: OutputManifest = match serde_json::from_slice(&bytes) {
        Ok(manifest) => manifest,
        Err(error) => {
            crate::warn(&format!(
                "decoding reconciler output manifest failed ({error}); omitting outputs"
            ));
            return None;
        }
    };
    if let Err(error) = manifest.validate() {
        crate::warn(&format!(
            "invalid reconciler output manifest ({error}); omitting outputs"
        ));
        return None;
    }
    Some(manifest)
}

/// Write the node's running state to its report location. Strictly best-effort: any
/// error (no report URL, no derivable identity, network failure, non-success status)
/// is logged and swallowed so reporting can never disrupt the update loop.
pub async fn report_running_state(
    client: &reqwest::Client,
    report_url: Option<&str>,
    node: Option<&str>,
    state: &RunningState<'_>,
    signing_key: Option<&[u8]>,
) {
    let (Some(report_url), Some(node)) = (report_url, node) else {
        return;
    };
    // No key means nothing publishable. A report is a signed DSSE envelope — there is no unsigned
    // form — and writing one no reader could verify would be worse than writing nothing: it would
    // OVERWRITE this node's last good report, so a consumer that had a fresh healthy record would be
    // left with an unverifiable one and drain the node. Staying quiet leaves the previous report to
    // age out honestly on its own freshness bound.
    let Some(key) = signing_key else {
        crate::warn("no telemetry signing key available; skipping the rollout heartbeat");
        return;
    };
    let mut report = NodeReport::new(
        node,
        state.deployment,
        state.assignment_sha256,
        state.version,
        state.archive_sha256,
        state.healthy,
    );
    report.fingerprint = state.fingerprint.cloned();
    // Outputs describe what the running archive settled on, so an unsettled node has none to
    // publish — and no reason to pay the read. One gate, at the one place that attaches them.
    report.outputs = state
        .healthy
        .then(|| load_outputs(state.install_root, state.manifest_sha256))
        .flatten();
    // Signed with the node's per-node key so the throttle and the health proxy can verify authenticity
    // end-to-end, rather than trusting the write hop.
    let body = match sign_report(&report, key).and_then(|envelope| {
        serde_json::to_vec(&envelope).map_err(|e| format!("encoding rollout telemetry: {e}"))
    }) {
        Ok(body) => body,
        Err(error) => {
            crate::warn(&format!(
                "preparing rollout telemetry failed ({error}); continuing"
            ));
            return;
        }
    };
    let target = telemetry_report_url(report_url, node);
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
    use std::collections::BTreeMap;

    fn routing(assignment: &str) -> Routing {
        Routing {
            root: std::path::PathBuf::from("/root"),
            base_url: "https://cdn/".into(),
            assignment: assignment.into(),
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
    fn output_files_are_release_partitioned_bounded_and_validated() {
        let root = tempfile::tempdir().unwrap();
        let identity = "a".repeat(64);
        let path = crate::update::reconciler_output_path(root.path(), &identity);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let manifest = OutputManifest {
            schema: OutputManifest::SCHEMA,
            values: BTreeMap::from([(
                "endpoint".into(),
                updated_contracts::telemetry::OutputValue::String {
                    value: "https://vault-0:8200".into(),
                },
            )]),
        };
        std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert_eq!(load_outputs(root.path(), &identity), Some(manifest));
        assert_eq!(load_outputs(root.path(), &"b".repeat(64)), None);

        std::fs::write(path, vec![b'x'; MAX_OUTPUT_MANIFEST_BYTES + 1]).unwrap();
        assert_eq!(load_outputs(root.path(), &identity), None);
    }

    #[test]
    fn node_identity_is_none_without_a_usable_stem() {
        assert_eq!(node_identity(&routing("assignments/agents/.json")), None);
        assert_eq!(node_identity(&routing("agents/agent")), None);
    }
}
