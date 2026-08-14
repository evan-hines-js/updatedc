use crate::*;
use kube::api::{Patch, PatchParams};
use std::time::Duration;

/// Keep each agent pod's set label current so the per-set load-balancer Services select the
/// right pods. A StatefulSet recreates a chaos-killed pod without the label, so this
/// re-applies it on a slow loop, deriving the set from the pod ordinal. Without it a
/// restarted pod would silently fall out of its set's rotation.
pub(crate) fn spawn_pod_set_labeler(fleet: Fleet) {
    tokio::spawn(async move {
        let pods = fleet.pods();
        loop {
            for ordinal in 0..NODE_COUNT {
                let node = format!("agent-{ordinal}");
                let Some(set) = node_set_index(&node) else {
                    continue;
                };
                let patch = serde_json::json!({
                    "metadata": { "labels": { SET_LABEL: set_name(set) } }
                });
                let _ = pods
                    .patch(&node, &PatchParams::default(), &Patch::Merge(&patch))
                    .await;
            }
            tokio::time::sleep(Duration::from_secs(10)).await;
        }
    });
}
