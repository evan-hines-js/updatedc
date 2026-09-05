use crate::*;
use k8s_openapi::api::core::v1::Pod;
use kube::config::{KubeConfigOptions, Kubeconfig};
use kube::{Api, Client, Config};
use std::time::Duration;
use updatec::{UpdateAgent, UpdateGroup, UpdateGroupSet};

/// One node of the managed fleet as the control plane sees it: what the operator recorded from
/// the node's own signed report.
pub(crate) struct FleetNode {
    /// The node name (`agent-<ordinal>`, `jenkins-<role>-<ordinal>`, `haproxy-<ordinal>`), which
    /// is also its pod name.
    pub(crate) node: String,
    pub(crate) selected_group: Option<String>,
    /// The version the node is actually running, straight from the control plane
    /// (`UpdateAgent.status.reportedVersion`) — never probed off the managed app, so it works
    /// for any app kind, a Rust service or a real Jenkins alike.
    pub(crate) version: Option<String>,
    pub(crate) healthy: bool,
}

/// The cluster handles every phase of the run reads the fleet through.
#[derive(Clone)]
pub(crate) struct Fleet {
    pub(crate) client: Client,
}

impl Fleet {
    /// Connect to the kind cluster this run drives, pinned to its context rather than to
    /// kubectl's process-global current context, and start the pod set labeler that keeps the
    /// per-set Services selecting the right pods.
    pub(crate) async fn connect() -> Result<Self, Box<dyn std::error::Error>> {
        let options = KubeConfigOptions {
            context: Some(kube_context()),
            ..Default::default()
        };
        let config = Config::from_custom_kubeconfig(Kubeconfig::read()?, &options).await?;
        let fleet = Self {
            client: Client::try_from(config)?,
        };
        spawn_pod_set_labeler(fleet.clone());
        Ok(fleet)
    }

    pub(crate) fn pods(&self) -> Api<Pod> {
        Api::namespaced(self.client.clone(), NAMESPACE)
    }

    pub(crate) fn agents(&self) -> Api<UpdateAgent> {
        Api::namespaced(self.client.clone(), NAMESPACE)
    }

    pub(crate) fn groups(&self) -> Api<UpdateGroup> {
        Api::namespaced(self.client.clone(), NAMESPACE)
    }

    pub(crate) fn sets(&self) -> Api<UpdateGroupSet> {
        Api::namespaced(self.client.clone(), NAMESPACE)
    }

    /// Every enrolled node the fleet layout labelled, with the control plane's record of what it
    /// runs.
    pub(crate) async fn nodes(&self) -> Result<Vec<FleetNode>, Box<dyn std::error::Error>> {
        let mut nodes = Vec::new();
        for agent in self.agents().list(&Default::default()).await? {
            let Some(node) = agent.spec.labels.get(NODE_LABEL).cloned() else {
                continue;
            };
            // Running version and health come straight from the control plane — the operator
            // publishes each node's last rollout report onto its UpdateAgent status. Nothing here
            // probes the managed app for a version, so a Jenkins node (which speaks no /version
            // endpoint) is read exactly like a sample-app node.
            let (selected_group, version, healthy) = agent
                .status
                .map(|status| {
                    (
                        status.selected_group,
                        status.reported_version,
                        status.reported_ready.unwrap_or(false),
                    )
                })
                .unwrap_or((None, None, false));
            nodes.push(FleetNode {
                node,
                selected_group,
                version,
                healthy,
            });
        }
        nodes.sort_by(|left, right| left.node.cmp(&right.node));
        Ok(nodes)
    }

    /// Wait until every cohort member is healthy on `version`.
    ///
    /// This is the first fleet wait after cluster bring-up, when the apiserver is still settling,
    /// so an unreadable list is retried like an unconverged pass and reported only if the wait as
    /// a whole runs out — the same rule [`await_for`] and the status readers below keep.
    pub(crate) async fn wait_for_convergence(
        &self,
        version: &str,
        timeout_seconds: usize,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut last = Vec::new();
        let mut last_error = String::new();
        for second in 0..timeout_seconds {
            match self.nodes().await {
                Ok(nodes) => {
                    last = nodes;
                    last_error.clear();
                }
                Err(error) => {
                    last_error = error.to_string();
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            }
            let cohort: Vec<&FleetNode> =
                last.iter().filter(|node| is_cohort_member(node)).collect();
            if cohort.len() == NODE_COUNT && cohort.iter().all(|node| node_converged(node, version))
            {
                println!("[e2e] all {NODE_COUNT} cohort members are healthy at {version}");
                return Ok(());
            }
            if second % 15 == 0 {
                println!(
                    "[e2e] waiting for fleet convergence ({}/{NODE_COUNT} exact)",
                    cohort
                        .iter()
                        .filter(|node| node_converged(node, version))
                        .count()
                );
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let lagging = last
            .iter()
            .filter(|node| is_cohort_member(node) && !node_converged(node, version))
            .map(|node| {
                format!(
                    "{}={{healthy:{},version:{},group:{}}}",
                    node.node,
                    node.healthy,
                    node.version.as_deref().unwrap_or("unreachable"),
                    node.selected_group.as_deref().unwrap_or("unassigned")
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        Err(format!(
            "fleet did not converge at {version}: observed {} nodes; lagging [{lagging}]{}{last_error}",
            last.len(),
            if last_error.is_empty() {
                ""
            } else {
                "; last error: "
            }
        )
        .into())
    }
}

/// Whether the node durably rejected the release carrying this artifact digest — the agent's
/// rejection-by-content-hash record, written when a candidate fails its activation and kept for
/// good, so it proves the node *attempted* that exact release and refused it. This is what makes
/// a rollback assertion evidence rather than a guess: a cohort that merely never received the
/// broken release carries no such record.
pub(crate) fn rejected_release(node: &str, artifact_sha256: &str) -> bool {
    let Some(rejection) = updated_contracts::digest::deployment_rejection_sha256(artifact_sha256)
    else {
        return false;
    };
    output(agent_exec(node).args(["cat", "/var/lib/updated/state/rejected"])).is_ok_and(|record| {
        // Runtime rejection is domain-separated from rejection of a malformed archive.
        // Read the identity through the same contract as the agent's journal writer.
        record
            .lines()
            .any(|line| line.trim().split(':').nth(1) == Some(rejection.as_str()))
    })
}

/// A node that belongs to a cohort group, as opposed to the external slice, the Jenkins or
/// HAProxy tiers, or a node still enrolling.
pub(crate) fn is_cohort_member(node: &FleetNode) -> bool {
    node.selected_group
        .as_deref()
        .is_some_and(|group| group.starts_with("fleet-cohort-"))
}

pub(crate) fn node_converged(node: &FleetNode, version: &str) -> bool {
    node.healthy && node.version.as_deref() == Some(version)
}

/// Label carrying a node's name on its `UpdateAgent`, the key every view joins the control
/// plane's record to the cluster's pods by.
pub(crate) const NODE_LABEL: &str = "e2e.updated.dev/node";
/// Label carrying a node's cohort, which each `UpdateGroup` selects on.
pub(crate) const COHORT_LABEL: &str = "e2e.updated.dev/cohort";
/// Label marking a node that runs something other than the sample application (`jenkins`,
/// `haproxy`), so the tiers outside the cohort machinery can be selected as their own workloads.
pub(crate) const KIND_LABEL: &str = "e2e.updated.dev/kind";
/// Label carrying a Jenkins node's instance role (`ci`, `release`).
pub(crate) const ROLE_LABEL: &str = "e2e.updated.dev/role";

/// One in-cluster HTTP read: curl from the release-server pod — the same trust boundary
/// production clients sit in — so no host↔cluster hop can flake an assertion. The single way any
/// scenario asks an in-cluster HTTP endpoint a question.
pub(crate) fn cluster_curl(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    output(
        kubectl()
            .args(RELEASE_SERVER_EXEC)
            .args(["--", "curl", "-sf", "--max-time", "3", url]),
    )
}

/// The pod IP behind `app=<label>` — how a scenario reaches a cluster-internal listener (a
/// metrics exposition) that deliberately has no Service.
pub(crate) fn pod_ip_by_app(label: &str) -> Result<String, Box<dyn std::error::Error>> {
    let ip = output(kubectl().args([
        "-n",
        NAMESPACE,
        "get",
        "pod",
        "-l",
        &format!("app={label}"),
        "-o",
        "jsonpath={.items[0].status.podIP}",
    ]))?
    .trim()
    .to_string();
    if ip.is_empty() {
        return Err(format!("no running pod carries app={label}").into());
    }
    Ok(ip)
}

/// One field of one condition on an `UpdateGroup` (`status`, `reason`), or `None` while the
/// condition has not been published. The single condition reader: every scenario projects the
/// field it needs out of it rather than spelling the jsonpath again.
pub(crate) fn condition_field(group: &str, condition: &str, field: &str) -> Option<String> {
    kubectl_value(
        "updategroup",
        group,
        &format!("{{.status.conditions[?(@.type==\"{condition}\")].{field}}}"),
    )
    .ok()
    .map(|value| value.trim().to_string())
    .filter(|value| !value.is_empty())
}

/// The deployments an `UpdateGroupSet` currently reports HALTED by the regression verdict, by name.
/// An unreadable status is an empty list, never an error: every caller polls, and a transient API
/// failure must not be mistaken for a verdict.
pub(crate) fn halted_deployments(set: &str) -> Vec<String> {
    kubectl_value("updategroupset", set, "{.status.halted[*].deployment}")
        .map(|names| {
            names
                .split_whitespace()
                .map(|name| name.to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// Whether the set's halt record for `deployment` says an `onRegression: rollback` response
/// consumed it — the `rolledBack` flag on the same `status.halted` entry [`halted_deployments`]
/// reads. Unreadable is `false`, never an error, for the same polling reason.
pub(crate) fn halt_rolled_back(set: &str, deployment: &str) -> bool {
    kubectl_value(
        "updategroupset",
        set,
        &format!("{{.status.halted[?(@.deployment==\"{deployment}\")].rolledBack}}"),
    )
    .is_ok_and(|value| value.trim() == "true")
}
