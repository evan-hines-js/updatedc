//! Rollout throttling across an [`UpdateGroupSet`](crate::UpdateGroupSet).
//!
//! A set caps how many of its member groups roll at once. The control plane can never
//! reach a node, so "rolling" and "settled" are decided entirely from node telemetry the
//! agents write to shared storage: a member group is *settled* once every agent it
//! selects reports the deployment identity the operator most recently published for that
//! group, healthy. Held-back members keep their last-admitted deployment — the admitted
//! set is persisted durably in-cluster by the operator (see `runtime`), not on node-local
//! disk — so the signed generation pins them until a slot frees, and a leader change or a
//! cold PVC can never re-seed a fresh baseline and mass-admit an entire set at once.
//!
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::{DesiredDeployment, ResolvedGroup, UpdateGroupSet};
use serde::{Deserialize, Serialize};
use updated_contracts::telemetry::{Envelope, NodeReport};

/// Durable group rollout state. `previous` remains present until every selected node has settled
/// on `current`; this also prevents a second retarget from discarding the deployment held by nodes
/// that have not advanced yet.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct AdmittedDeployment {
    pub current: DesiredDeployment,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous: Option<DesiredDeployment>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RolloutPlan {
    pub sets: Vec<SetStatus>,
    pub node_deployments: BTreeMap<String, DesiredDeployment>,
}

/// Per-set observation the operator publishes as `UpdateGroupSet` status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SetStatus {
    pub name: String,
    pub member_count: usize,
    pub max_concurrent: usize,
    pub rolling: Vec<String>,
    pub settled: Vec<String>,
    /// Members also claimed by another set — rolled up safely (admitted only when every
    /// governing set has a slot). The UI shows these as spanning sets, not plain members.
    pub shared: Vec<String>,
    /// True when the set is outside all its rollout windows: no new rollout is admitted this
    /// pass (members already rolling keep settling). Always false for a window-less set.
    pub frozen: bool,
    /// True when the set's dated calendar has run out — every approved window is in the past, so the
    /// calendar has stopped gating and the set is now ungated at any hour (`window::calendar_open`
    /// fails open). Surfaced so an operator can distinguish "actively inside an approved window"
    /// from "silently expired, now rolling at any time." False for a set with no calendar or one
    /// still active/pending.
    pub calendar_exhausted: bool,
}

/// Everything `plan_rollouts` needs about the current generation, kept separate from
/// Kubernetes types so the core admission logic is pure and unit-testable.
pub struct RolloutInputs<'a> {
    /// Desired member groups by name. Admission never rewrites desired state; its exact result is
    /// returned through `RolloutPlan::node_deployments`.
    pub groups: &'a BTreeMap<String, ResolvedGroup>,
    /// Each group's Kubernetes metadata labels — what a set's selector matches on.
    pub group_labels: &'a BTreeMap<String, BTreeMap<String, String>>,
    /// Node → selected group name, from the publication plan's routing.
    pub node_groups: &'a BTreeMap<String, String>,
    /// Node → its latest self-reported running state.
    pub reports: &'a HashMap<String, Envelope>,
    /// Node → its pinned public key (raw EC point), set at enrollment from the node's CSR. A report
    /// is trusted only if its signature verifies against this key, so rollout decisions act on
    /// end-to-end evidence (node → planner), not gateway write-hop authentication. A node with no
    /// pinned key is unverifiable and can never be seen as settled — it
    /// fails closed.
    pub public_keys: &'a HashMap<String, Vec<u8>>,
}

struct Observations<'a> {
    node_groups: &'a BTreeMap<String, String>,
    reports: &'a HashMap<String, Envelope>,
    public_keys: &'a HashMap<String, Vec<u8>>,
    now_ms: u64,
    /// One verification per node per planning pass. `settled` walks every node of a group and is
    /// itself called from admission, set planning, and status building, so an uncached gate costs a
    /// full ECDSA verify per node per call — work an untrusted writer chooses the size of.
    verified: RefCell<HashMap<String, Option<NodeReport>>>,
}

impl<'a> Observations<'a> {
    fn new(
        node_groups: &'a BTreeMap<String, String>,
        reports: &'a HashMap<String, Envelope>,
        public_keys: &'a HashMap<String, Vec<u8>>,
        now_ms: u64,
    ) -> Self {
        Self {
            node_groups,
            reports,
            public_keys,
            now_ms,
            verified: RefCell::new(HashMap::new()),
        }
    }

    /// This node's report, or `None` when there is nothing trustworthy to read. The gate returns the
    /// report itself, so an unverified envelope yields no value to inspect rather than a value a caller
    /// might use before checking it. The verdict is memoized for the pass; the inputs cannot change
    /// mid-pass, so a repeat lookup is the same answer at no cryptographic cost.
    fn report(&self, node: &str) -> Option<NodeReport> {
        if let Some(cached) = self.verified.borrow().get(node) {
            return cached.clone();
        }
        let verdict = self.verify(node);
        self.verified
            .borrow_mut()
            .insert(node.to_string(), verdict.clone());
        verdict
    }

    fn verify(&self, node: &str) -> Option<NodeReport> {
        let envelope = self.reports.get(node)?;
        let public_key = self.public_keys.get(node)?;
        updated_contracts::telemetry::report_is_authentic_and_fresh(
            envelope,
            node,
            public_key,
            self.now_ms,
        )
    }

    /// Whether this node is acting on the exact assignment `identity` names — the digest of the
    /// published configuration document, not the deployment's name. A name says nothing about
    /// which revision of that deployment the node actually has.
    fn on(&self, node: &str, identity: &str) -> bool {
        self.report(node)
            .is_some_and(|report| report.assignment_sha256 == identity)
    }

    fn healthy(&self, node: &str, identity: &str) -> bool {
        self.report(node)
            .is_some_and(|report| report.assignment_sha256 == identity && report.healthy)
    }

    /// Whether every node this group selects reports `deployment` healthy — and that there IS at
    /// least one such node. Settlement is evidence, and a group nobody runs produces none: an empty
    /// `all()` is vacuously true, which would let a group with no agents satisfy a dependency gate,
    /// clear a rollout predecessor, and free a concurrency slot without a single report behind it.
    ///
    /// A deployment that cannot be encoded has no identity and can never be settled on.
    fn settled(&self, group: &str, deployment: &DesiredDeployment) -> bool {
        let Some(identity) = crate::deployment_identity(deployment) else {
            return false;
        };
        let mut nodes = self
            .node_groups
            .iter()
            .filter(|(_, selected)| selected.as_str() == group)
            .peekable();
        nodes.peek().is_some() && nodes.all(|(node, _)| self.healthy(node, &identity))
    }
}

struct SetPlan {
    members: Vec<String>,
    max_concurrent: usize,
    slots: usize,
    frozen: bool,
}

/// Plan group-set admission and exact node assignments. Desired inventory remains immutable;
/// admission changes are written only to `admitted` and the returned node map.
///
/// `admitted` is the durable admitted-set map: group name → the deployment that group is
/// currently pinned to. It is loaded from the in-cluster store before this call and written
/// back after (see `runtime::{load,store}_admitted_state`). Passing state in and out rather
/// than reading node-local disk is the fix for HA leader failover: the admitted baseline is
/// seeded exactly once in a group's lifetime and then survives every leader change and PVC
/// loss, so a fresh leader can never re-baseline every member to the current desired and
/// admit them all at once — the breach of `max_concurrent` that node-local state allowed.
///
/// A group's FIRST admission runs through the same gates as every later one (`admit_pending`):
/// resolved inputs and settled prerequisites. It is exempt only from a set's concurrency slots and
/// schedule, because there is no predecessor to stage away from and nothing yet published to
/// protect. A group that has not been admitted at all publishes nothing for its nodes, and
/// `domain::plan_reconcile` leaves them out of the generation entirely.
pub(crate) fn plan_rollouts(
    sets: &[UpdateGroupSet],
    inputs: RolloutInputs<'_>,
    admitted: &mut BTreeMap<String, AdmittedDeployment>,
    now: chrono::DateTime<chrono::Utc>,
) -> RolloutPlan {
    let RolloutInputs {
        groups,
        group_labels,
        node_groups,
        reports,
        public_keys,
    } = inputs;

    let desired: BTreeMap<String, DesiredDeployment> = groups
        .iter()
        .map(|(name, group)| (name.clone(), group.deployment.clone()))
        .collect();
    // Only pruning happens outside admission. A group is never *seeded* here: first admission runs
    // through `admit_pending` like every later one, so a group's very first published deployment is
    // gated on the same things a retarget is — resolved inputs and settled prerequisites. Seeding
    // here instead would publish a cold cluster's consumer group with empty `runtime.inputs`.
    admitted.retain(|name, _| desired.contains_key(name));
    let observations = Observations::new(
        node_groups,
        reports,
        public_keys,
        now.timestamp_millis().max(0) as u64,
    );
    finish_settled_rollouts(admitted, &observations);
    let (mut plans, group_plans) =
        build_set_plans(sets, &desired, group_labels, admitted, &observations, now);
    admit_pending(
        groups,
        &desired,
        &group_plans,
        &mut plans,
        admitted,
        &observations,
    );
    let statuses = build_statuses(
        sets,
        &plans,
        &group_plans,
        &desired,
        admitted,
        &observations,
        now,
    );
    let node_deployments = assign_nodes(groups, admitted, &observations);
    RolloutPlan {
        sets: statuses,
        node_deployments,
    }
}

fn finish_settled_rollouts(
    admitted: &mut BTreeMap<String, AdmittedDeployment>,
    observations: &Observations<'_>,
) {
    for (name, state) in admitted.iter_mut() {
        if state.previous.is_some()
            && (state.current.report_url.is_none() || observations.settled(name, &state.current))
        {
            state.previous = None;
        }
    }
}

fn build_set_plans(
    sets: &[UpdateGroupSet],
    desired: &BTreeMap<String, DesiredDeployment>,
    group_labels: &BTreeMap<String, BTreeMap<String, String>>,
    admitted: &BTreeMap<String, AdmittedDeployment>,
    observations: &Observations<'_>,
    now: chrono::DateTime<chrono::Utc>,
) -> (Vec<SetPlan>, BTreeMap<String, Vec<usize>>) {
    let mut plans: Vec<SetPlan> = Vec::with_capacity(sets.len());
    let mut group_plans: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for set in sets {
        let mut members: Vec<String> = desired
            .keys()
            .filter(|name| {
                group_labels.get(*name).is_some_and(|labels| {
                    crate::selector_matches(&set.spec.selector.match_labels, labels)
                })
            })
            .cloned()
            .collect();
        members.sort();
        let max_concurrent = if members.is_empty() {
            0
        } else {
            set.spec.effective_max_concurrent(members.len())
        };
        // A member with no admitted entry has never been published, so it is not occupying a slot.
        let rolling_now = members
            .iter()
            .filter(|name| {
                admitted.get(*name).is_some_and(|state| {
                    state.previous.is_some() || !observations.settled(name, &state.current)
                })
            })
            .count();
        // A set is open only inside its schedule: both its recurring rollout windows and its
        // one-off dated calendar must admit `now` (each is "always open" when unset, so a set
        // using only one mechanism is gated by only that one). Outside the schedule it is
        // frozen — zero free slots — while in-flight members keep settling. An exhausted
        // calendar stops gating (see `window::calendar_open`), so a stale one never wedges it.
        let open = crate::window::is_open(&set.spec.rollout_windows, now)
            && crate::window::calendar_open(&set.spec.calendar, now);
        if !open {
            tracing::info!(
                set = set.metadata.name.as_deref().unwrap_or("<unnamed>"),
                "UpdateGroupSet is outside its rollout schedule (windows/calendar); freezing new rollouts"
            );
        }
        let plan_idx = plans.len();
        for name in &members {
            group_plans.entry(name.clone()).or_default().push(plan_idx);
        }
        plans.push(SetPlan {
            members,
            max_concurrent,
            slots: if !open {
                0
            } else {
                max_concurrent.saturating_sub(rolling_now)
            },
            frozen: !open,
        });
    }
    (plans, group_plans)
}

fn admit_pending(
    groups: &BTreeMap<String, ResolvedGroup>,
    desired: &BTreeMap<String, DesiredDeployment>,
    group_plans: &BTreeMap<String, Vec<usize>>,
    plans: &mut [SetPlan],
    admitted: &mut BTreeMap<String, AdmittedDeployment>,
    observations: &Observations<'_>,
) {
    // Pending is decided on the whole desired deployment, not its identity string. `assign_nodes`
    // publishes the stored `current`, so a body change that keeps the same `deployment` name —
    // a corrected digest, changed args, or dependency inputs that only resolved once the producer
    // came up — is a real change nodes must receive. Comparing names alone dropped those silently
    // and forever, and no operator can name-bump a change the control plane itself resolved.
    let mut pending: Vec<String> = desired
        .keys()
        .filter(|name| {
            admitted
                .get(*name)
                .is_none_or(|state| state.current != desired[*name])
        })
        .cloned()
        .collect();
    pending.sort_by(|a, b| {
        let count = |n: &String| group_plans.get(n).map_or(0, Vec::len);
        count(b).cmp(&count(a)).then_with(|| a.cmp(b))
    });
    for name in pending {
        if !groups[&name].inputs_ready {
            continue;
        }
        // A prerequisite opens only once its desired deployment is admitted and every selected
        // node reports that exact deployment healthy. The graph itself is validated by the domain
        // planner before reaching this function. A dependency with no admitted entry at all has
        // not been published even once, so it cannot have settled.
        if !groups[&name].depends_on.iter().all(|dependency| {
            admitted.get(dependency).is_some_and(|state| {
                state.current == desired[dependency] && state.previous.is_none()
            }) && observations.settled(dependency, &desired[dependency])
        }) {
            continue;
        }
        let telemetry_gated = desired[&name].report_url.is_some();
        // First admission. There is no predecessor to stage away from and nothing for a
        // `maxUnavailable` or a concurrency slot to protect — the group has never been published —
        // so a baseline is admitted outside the set's slots and schedule, but only after the
        // ordering gates above.
        let Some(state) = admitted.get(&name) else {
            admitted.insert(
                name.clone(),
                AdmittedDeployment {
                    current: desired[&name].clone(),
                    previous: None,
                },
            );
            continue;
        };
        // Never overwrite the predecessor of an unfinished rollout, even when this group belongs
        // to no set. The latest desired value remains pending and will be admitted after settling.
        if telemetry_gated
            && (state.previous.is_some() || !observations.settled(&name, &state.current))
        {
            continue;
        }
        // Every telemetry-gated change is staged, including one that keeps the deployment's name:
        // "who has advanced" is decided on the published configuration's digest, so a changed
        // archive, argument, secret, or resolved input is as stageable as a rename. Recording no
        // predecessor for those would hand the new configuration to every node in the group at
        // once — `maxUnavailable` bypassed by an edit that happens not to rename anything.
        let previous = telemetry_gated.then(|| state.current.clone());
        let admit = |admitted: &mut BTreeMap<String, AdmittedDeployment>| {
            admitted.insert(
                name.clone(),
                AdmittedDeployment {
                    current: desired[&name].clone(),
                    previous: previous.clone(),
                },
            );
        };
        match group_plans.get(&name) {
            None => {
                admit(admitted);
            }
            Some(indices) => {
                if indices.iter().all(|&i| plans[i].slots > 0) {
                    admit(admitted);
                    for &i in indices {
                        plans[i].slots -= 1;
                    }
                }
            }
        }
    }
}

fn build_statuses(
    sets: &[UpdateGroupSet],
    plans: &[SetPlan],
    group_plans: &BTreeMap<String, Vec<usize>>,
    desired: &BTreeMap<String, DesiredDeployment>,
    admitted: &BTreeMap<String, AdmittedDeployment>,
    observations: &Observations<'_>,
    now: chrono::DateTime<chrono::Utc>,
) -> Vec<SetStatus> {
    let shared: BTreeSet<String> = group_plans
        .iter()
        .filter(|(_, plans)| plans.len() > 1)
        .map(|(name, _)| name.clone())
        .collect();
    sets
        .iter()
        .zip(plans)
        .map(|(set, plan)| {
            let mut rolling = Vec::new();
            let mut settled_members = Vec::new();
            let mut shared_members = Vec::new();
            for name in &plan.members {
                if shared.contains(name) {
                    shared_members.push(name.clone());
                }
                // Held back — neither rolling nor settled on its desire. A member with no admitted
                // entry has not been published at all, which is the same story for a reader.
                let Some(state) = admitted.get(name).filter(|s| s.current == desired[name]) else {
                    continue;
                };
                if observations.settled(name, &state.current) {
                    settled_members.push(name.clone());
                } else {
                    rolling.push(name.clone());
                }
            }
            let calendar_exhausted = crate::window::calendar_exhausted(&set.spec.calendar, now);
            if calendar_exhausted {
                tracing::warn!(
                    set = set.metadata.name.as_deref().unwrap_or("<unnamed>"),
                    "UpdateGroupSet calendar has run out; it is now UNGATED and will roll at any hour \
                     — add a future approved window (or a rollout window) to re-gate it"
                );
            }
            SetStatus {
                name: set.metadata.name.clone().unwrap_or_default(),
                member_count: plan.members.len(),
                max_concurrent: plan.max_concurrent,
                rolling,
                settled: settled_members,
                shared: shared_members,
                frozen: plan.frozen,
                calendar_exhausted,
            }
        })
        .collect()
}

fn assign_nodes(
    groups: &BTreeMap<String, ResolvedGroup>,
    admitted: &BTreeMap<String, AdmittedDeployment>,
    observations: &Observations<'_>,
) -> BTreeMap<String, DesiredDeployment> {
    let mut node_deployments = BTreeMap::new();
    for (name, group) in groups.iter() {
        // A group awaiting its first admission publishes nothing. Its nodes are left out of the
        // generation entirely (see `domain::plan_reconcile`) so they hold their last known
        // assignment rather than being handed something ungated.
        let Some(state) = admitted.get(name) else {
            continue;
        };
        let mut nodes: Vec<&String> = observations
            .node_groups
            .iter()
            .filter_map(|(node, selected)| (selected == name).then_some(node))
            .collect();
        nodes.sort();
        let Some(previous) = state.previous.as_ref() else {
            for node in nodes {
                node_deployments.insert(node.clone(), state.current.clone());
            }
            continue;
        };
        // Advancement is judged on the exact configuration each node reports acting on, so a
        // change that keeps the deployment's name still stages one batch at a time.
        let (Some(current_id), Some(previous_id)) = (
            crate::deployment_identity(&state.current),
            crate::deployment_identity(previous),
        ) else {
            // Nothing can be shown to have advanced, so hold every node on the predecessor rather
            // than guess.
            for node in nodes {
                node_deployments.insert(node.clone(), previous.clone());
            }
            continue;
        };
        let mut unavailable = 0usize;
        let mut held = Vec::new();
        for node in nodes {
            if observations.on(node, &current_id) {
                if !observations.healthy(node, &current_id) {
                    unavailable += 1;
                }
                node_deployments.insert(node.clone(), state.current.clone());
            } else {
                if !observations.healthy(node, &previous_id) {
                    unavailable += 1;
                }
                held.push(node);
            }
        }
        let capacity = group.max_unavailable.saturating_sub(unavailable);
        for (index, node) in held.into_iter().enumerate() {
            node_deployments.insert(
                node.clone(),
                if index < capacity {
                    state.current.clone()
                } else {
                    previous.clone()
                },
            );
        }
    }
    node_deployments
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A well-formed running digest for report fixtures. Nothing in this module reads it; a report
    /// simply needs one to be well formed.
    const DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    // A fixed instant for tests whose sets carry no rollout windows (always open, so the
    // exact value is irrelevant). Window behaviour is unit-tested in `crate::window`.
    fn test_now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-07-20T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    /// Every fixture group uses a telemetry-gated deployment, so the identity a report carries is
    /// derived from the same shape the planner holds.
    fn deployment_named(id: &str) -> DesiredDeployment {
        deployment(id, true)
    }

    fn deployment(id: &str, with_report: bool) -> DesiredDeployment {
        DesiredDeployment {
            schema: updated_contracts::assignment::RepositoryAssignment::SCHEMA,
            deployment: id.into(),
            metadata_url: "https://cdn/m/".into(),
            targets_url: "https://cdn/t/".into(),
            report_url: with_report.then(|| "https://cdn".into()),
            application: crate::ExactTarget {
                path: "app".into(),
                sha256: "a".repeat(64),
            },
            ordered_install_fallback: false,
            provider_set: crate::ExactTarget {
                path: "prov".into(),
                sha256: "b".repeat(64),
            },
            release_root: serde_json::json!({"signed": {}, "signatures": []}),
            runtime: runtime(),
        }
    }

    fn runtime() -> updated_contracts::assignment::ManagedRuntime {
        updated_contracts::assignment::ManagedRuntime {
            mode: updated_contracts::assignment::RuntimeMode::Managed,
            product: "app".into(),
            channel: "stable".into(),
            install_root: "/opt/app".into(),
            args: vec![],
            secrets: vec![],
            inputs: BTreeMap::new(),
            repository: updated_contracts::assignment::ManagedRepositoryLimits {
                metadata_limit: 1,
                target_limit: 1,
                transport_timeout_seconds: 1,
            },
            storage: updated_contracts::assignment::ManagedStorage {
                inactive_releases: 1,
                inactive_providers: 1,
                inactive_supervisors: 1,
                inactive_bytes: 1,
                inactive_repository_caches: 1,
            },
            timeouts: updated_contracts::assignment::ManagedTimeouts {
                check_interval_seconds: 1,
                health_grace_seconds: 1,
                health_successes: 1,
                health_interval_seconds: 1,
                retry_after_seconds: 1,
                refresh_retry_seconds: 1,
                confirmation_window_seconds: 1,
                supervisor_check_interval_seconds: 1,
                drain_hold_seconds: Some(0),
            },
        }
    }

    fn group(name: &str, deployment: DesiredDeployment) -> ResolvedGroup {
        ResolvedGroup {
            name: name.into(),
            match_labels: BTreeMap::from([("group".into(), name.into())]),
            depends_on: vec![],
            inputs: BTreeMap::new(),
            inputs_ready: true,
            deployment,
            max_unavailable: 1,
        }
    }

    fn admitted(deployment: DesiredDeployment) -> AdmittedDeployment {
        AdmittedDeployment {
            current: deployment,
            previous: None,
        }
    }

    fn pair_set() -> UpdateGroupSet {
        UpdateGroupSet::new(
            "pair-00",
            crate::UpdateGroupSetSpec {
                selector: crate::LabelSelector {
                    match_labels: BTreeMap::from([("set".into(), "pair-00".into())]),
                },
                max_concurrent: None,
                rollout_windows: vec![],
                calendar: vec![],
            },
        )
    }

    /// One shared signing key for the throttle tests (identity binding is proven in `join`/
    /// `telemetry`; here we only need every report to carry a signature that verifies against the
    /// pinned key). `.0` is the PKCS#8 signing key, `.1` the pinned public point.
    static TEST_KEY: std::sync::LazyLock<(Vec<u8>, Vec<u8>)> = std::sync::LazyLock::new(|| {
        let key_pem = updated::csr::generate_key().unwrap();
        let pkcs8 = updated::csr::key_pem_to_pkcs8_der(&key_pem).unwrap();
        let csr = updated::csr::csr_for(&key_pem, "throttle-test").unwrap();
        let public = crate::join::csr_public_key(&csr).unwrap();
        (pkcs8, public)
    });

    /// The pinned-key map the throttle needs: every node routed by `node_groups`, mapped to the
    /// shared test public key (so signed reports verify).
    fn pubkeys(node_groups: &BTreeMap<String, String>) -> HashMap<String, Vec<u8>> {
        node_groups
            .keys()
            .map(|node| (node.clone(), TEST_KEY.1.clone()))
            .collect()
    }

    /// A freshly-stamped report as of `now`. Throttling keys off (deployment, healthy); the running
    /// version is irrelevant here. Stamping against the same instant the pass is planned at is what
    /// a node reporting on every tick looks like — the freshness bound is exercised by its own
    /// tests (`a_stale_report_is_treated_as_not_settled` and the contract's gate tests) rather than
    /// by perturbing these.
    fn report_at(
        now: chrono::DateTime<chrono::Utc>,
        node: &str,
        deployment: &str,
        healthy: bool,
    ) -> (String, Envelope) {
        // A node reports the digest of the configuration it is acting on, so fixtures name the
        // deployment and derive the identity the planner will compare against.
        let identity = crate::deployment_identity(&deployment_named(deployment)).unwrap();
        let mut report = NodeReport::new(node, deployment, identity, deployment, DIGEST, healthy);
        report.reported_at_ms = now.timestamp_millis() as u64;
        let envelope = updated_contracts::telemetry::sign_report(&report, &TEST_KEY.0).unwrap();
        (node.into(), envelope)
    }

    fn report(node: &str, deployment: &str, healthy: bool) -> (String, Envelope) {
        report_at(test_now(), node, deployment, healthy)
    }

    /// A healthy report older than [`updated_contracts::telemetry::REPORT_FRESHNESS`], stamped relative to
    /// `test_now`.
    fn stale_report(node: &str, deployment: &str) -> (String, Envelope) {
        let identity = crate::deployment_identity(&deployment_named(deployment)).unwrap();
        let mut report = NodeReport::new(node, deployment, identity, deployment, DIGEST, true);
        let stale_ms = updated_contracts::telemetry::REPORT_FRESHNESS.as_millis() as u64 + 60_000;
        report.reported_at_ms = (test_now().timestamp_millis() as u64).saturating_sub(stale_ms);
        let envelope = updated_contracts::telemetry::sign_report(&report, &TEST_KEY.0).unwrap();
        (node.into(), envelope)
    }

    /// Group labels for a plain two-member `pair-00` set.
    fn pair_labels() -> BTreeMap<String, BTreeMap<String, String>> {
        BTreeMap::from([
            (
                "a".to_string(),
                BTreeMap::from([("set".to_string(), "pair-00".to_string())]),
            ),
            (
                "b".to_string(),
                BTreeMap::from([("set".to_string(), "pair-00".to_string())]),
            ),
        ])
    }

    /// Node → group routing for a two-member pair, one agent each.
    fn pair_node_groups() -> BTreeMap<String, String> {
        BTreeMap::from([
            ("n-a".to_string(), "a".to_string()),
            ("n-b".to_string(), "b".to_string()),
        ])
    }

    type GroupFixture = (
        BTreeMap<String, ResolvedGroup>,
        BTreeMap<String, String>,
        BTreeMap<String, BTreeMap<String, String>>,
    );

    fn three_node_group() -> GroupFixture {
        let groups = BTreeMap::from([("g".into(), group("g", deployment("v0", true)))]);
        let node_groups = ["n0", "n1", "n2"]
            .into_iter()
            .map(|node| (node.into(), "g".into()))
            .collect();
        (groups, node_groups, BTreeMap::new())
    }

    #[test]
    fn stages_one_node_at_a_time_within_a_group() {
        let (mut groups, node_groups, labels) = three_node_group();
        let mut admitted = BTreeMap::new();
        let baseline = HashMap::from([
            report("n0", "v0", true),
            report("n1", "v0", true),
            report("n2", "v0", true),
        ]);
        plan_rollouts(
            &[],
            RolloutInputs {
                groups: &mut groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &baseline,
                public_keys: &pubkeys(&node_groups),
            },
            &mut admitted,
            test_now(),
        );
        groups.get_mut("g").unwrap().deployment = deployment("v1", true);
        let first = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &mut groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &baseline,
                public_keys: &pubkeys(&node_groups),
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(first.node_deployments["n0"].deployment, "v1");
        assert_eq!(first.node_deployments["n1"].deployment, "v0");
        assert_eq!(first.node_deployments["n2"].deployment, "v0");

        let one_settled = HashMap::from([
            report("n0", "v1", true),
            report("n1", "v0", true),
            report("n2", "v0", true),
        ]);
        let second = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &mut groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &one_settled,
                public_keys: &pubkeys(&node_groups),
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(second.node_deployments["n0"].deployment, "v1");
        assert_eq!(second.node_deployments["n1"].deployment, "v1");
        assert_eq!(second.node_deployments["n2"].deployment, "v0");
    }

    #[test]
    fn thousand_node_rollout_never_exceeds_the_group_budget_and_converges() {
        let mut groups = BTreeMap::from([("g".into(), group("g", deployment("v0", true)))]);
        groups.get_mut("g").unwrap().max_unavailable = 100;
        let node_groups: BTreeMap<String, String> = (0..1_000)
            .map(|index| (format!("node-{index:04}"), "g".into()))
            .collect();
        let keys = pubkeys(&node_groups);
        let mut reports: HashMap<String, Envelope> = node_groups
            .keys()
            .map(|node| report(node, "v0", true))
            .collect();
        let mut admitted = BTreeMap::new();
        let labels = BTreeMap::new();

        plan_rollouts(
            &[],
            RolloutInputs {
                groups: &groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &keys,
            },
            &mut admitted,
            test_now(),
        );
        groups.get_mut("g").unwrap().deployment = deployment("v1", true);

        for batch in 0..10 {
            let plan = plan_rollouts(
                &[],
                RolloutInputs {
                    groups: &groups,
                    group_labels: &labels,
                    node_groups: &node_groups,
                    reports: &reports,
                    public_keys: &keys,
                },
                &mut admitted,
                test_now(),
            );
            let selected: Vec<_> = plan
                .node_deployments
                .iter()
                .filter(|(_, deployment)| deployment.deployment == "v1")
                .map(|(node, _)| node.clone())
                .collect();
            assert_eq!(selected.len(), (batch + 1) * 100);
            // Each admitted member now reports itself settled on v1. Re-signing unconditionally is
            // idempotent — the report's contents are what matter, not how many times it was written —
            // and the envelope keeps its payload opaque, so there is no field to peek at first.
            for advancing in selected {
                reports.insert(advancing.clone(), report(&advancing, "v1", true).1);
            }
        }

        let converged = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &keys,
            },
            &mut admitted,
            test_now(),
        );
        assert!(converged
            .node_deployments
            .values()
            .all(|deployment| deployment.deployment == "v1"));
        assert_eq!(admitted["g"].previous, None);
    }

    #[test]
    fn a_degraded_held_node_consumes_the_unavailable_budget() {
        let (mut groups, node_groups, labels) = three_node_group();
        let mut admitted = BTreeMap::from([(
            "g".into(),
            AdmittedDeployment {
                current: deployment("v1", true),
                previous: Some(deployment("v0", true)),
            },
        )]);
        let reports = HashMap::from([
            report("n0", "v0", true),
            report("n1", "v0", true),
            report("n2", "v0", false),
        ]);
        groups.get_mut("g").unwrap().deployment = deployment("v1", true);
        let outcome = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &mut groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &pubkeys(&node_groups),
            },
            &mut admitted,
            test_now(),
        );
        assert!(outcome
            .node_deployments
            .values()
            .all(|deployment| deployment.deployment == "v0"));
    }

    #[test]
    fn a_mid_roll_retarget_waits_without_losing_the_predecessor() {
        let (mut groups, node_groups, labels) = three_node_group();
        groups.get_mut("g").unwrap().deployment = deployment("v2", true);
        let mut admitted = BTreeMap::from([(
            "g".into(),
            AdmittedDeployment {
                current: deployment("v1", true),
                previous: Some(deployment("v0", true)),
            },
        )]);
        let reports = HashMap::from([
            report("n0", "v1", false),
            report("n1", "v0", true),
            report("n2", "v0", true),
        ]);
        let outcome = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &mut groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &pubkeys(&node_groups),
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(admitted["g"].current.deployment, "v1");
        assert_eq!(admitted["g"].previous.as_ref().unwrap().deployment, "v0");
        assert!(outcome
            .node_deployments
            .values()
            .all(|deployment| deployment.deployment != "v2"));
    }

    #[test]
    fn membership_reordering_never_demotes_an_advanced_node() {
        let mut groups = BTreeMap::from([("g".into(), group("g", deployment("v1", true)))]);
        let node_groups = ["a-new", "m-advanced", "z-held"]
            .into_iter()
            .map(|node| (node.into(), "g".into()))
            .collect();
        let labels = BTreeMap::new();
        let reports = HashMap::from([
            report("a-new", "v0", true),
            report("m-advanced", "v1", false),
            report("z-held", "v0", true),
        ]);
        let mut admitted = BTreeMap::from([(
            "g".into(),
            AdmittedDeployment {
                current: deployment("v1", true),
                previous: Some(deployment("v0", true)),
            },
        )]);
        let outcome = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &mut groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &pubkeys(&node_groups),
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(outcome.node_deployments["m-advanced"].deployment, "v1");
        assert_eq!(outcome.node_deployments["a-new"].deployment, "v0");
        assert_eq!(outcome.node_deployments["z-held"].deployment, "v0");
    }

    #[test]
    fn a_stale_report_is_treated_as_not_settled() {
        // A node that reported healthy once and then went silent must NOT keep a group "settled"
        // forever (the fail-open direction). One pair-member with only a stale report never
        // settles, so it stays `rolling` and its sibling is held — same as a missing report.
        let mut groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment("v1", true))),
            ("b".to_string(), group("b", deployment("v1", true))),
        ]);
        let group_labels = pair_labels();
        let node_groups = pair_node_groups();
        // "a" is admitted v1 but its only report is stale; "b" holds a fresh v1.
        let reports = HashMap::from([stale_report("n-a", "v1"), report("n-b", "v1", true)]);
        let mut admitted = BTreeMap::new();
        let statuses = plan_rollouts(
            &[pair_set()],
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                reports: &reports,
            },
            &mut admitted,
            test_now(),
        );
        assert!(
            statuses.sets[0].rolling.contains(&"a".to_string()),
            "stale 'a' must be rolling, not settled"
        );
        assert!(
            statuses.sets[0].settled.contains(&"b".to_string()),
            "fresh 'b' is settled"
        );
    }

    #[test]
    fn holds_the_second_member_until_the_first_settles() {
        // Two members of a pair, both baseline "v0", one agent each.
        let mut groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment("v0", true))),
            ("b".to_string(), group("b", deployment("v0", true))),
        ]);
        let group_labels = pair_labels();
        let node_groups = pair_node_groups();
        // Seed baseline as admitted (first sight), both settled on v0.
        let reports_v0 = HashMap::from([report("n-a", "v0", true), report("n-b", "v0", true)]);
        let sets = [pair_set()];
        // The durable admitted set survives across passes just as the in-cluster ConfigMap does.
        let mut admitted = BTreeMap::new();
        plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                reports: &reports_v0,
            },
            &mut admitted,
            test_now(),
        );

        // Now both want v1. Only one may roll.
        groups.get_mut("a").unwrap().deployment = deployment("v1", true);
        groups.get_mut("b").unwrap().deployment = deployment("v1", true);
        let statuses = plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                reports: &reports_v0, // agents still on v0
            },
            &mut admitted,
            test_now(),
        );
        // Exactly one member (the first by name, "a") is admitted to v1; "b" is held at v0.
        assert_eq!(admitted["a"].current.deployment, "v1");
        assert_eq!(admitted["b"].current.deployment, "v0");
        assert_eq!(statuses.sets[0].rolling, vec!["a".to_string()]);
        assert!(statuses.sets[0].settled.is_empty());
        assert_eq!(statuses.sets[0].max_concurrent, 1);

        // "a" settles on v1; the slot frees and "b" is admitted.
        let reports_a_done = HashMap::from([report("n-a", "v1", true), report("n-b", "v0", true)]);
        let statuses = plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                reports: &reports_a_done,
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(admitted["a"].current.deployment, "v1");
        assert_eq!(admitted["b"].current.deployment, "v1");
        assert_eq!(statuses.sets[0].settled, vec!["a".to_string()]);
        assert_eq!(statuses.sets[0].rolling, vec!["b".to_string()]);
    }

    #[test]
    fn leader_failover_with_fresh_local_state_still_respects_max_concurrent() {
        // Regression for the node-local-admitted-state HA bug: a rescheduled/second leader that
        // lost its PVC must NOT re-baseline every member to the current desired and admit the whole
        // set at once. With the admitted set carried in durable in-cluster storage, the new leader
        // loads the SAME map even though its local disk is empty, so the throttle holds.
        let group_labels = pair_labels();
        let node_groups = pair_node_groups();
        let reports_v0 = HashMap::from([report("n-a", "v0", true), report("n-b", "v0", true)]);
        let sets = [pair_set()];
        let all_v1 = || {
            BTreeMap::from([
                ("a".to_string(), group("a", deployment("v1", true))),
                ("b".to_string(), group("b", deployment("v1", true))),
            ])
        };

        // Leader 1: seed baseline v0, then admit exactly one of the pair toward v1.
        let mut admitted = BTreeMap::new();
        let mut groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment("v0", true))),
            ("b".to_string(), group("b", deployment("v0", true))),
        ]);
        plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                reports: &reports_v0,
            },
            &mut admitted,
            test_now(),
        );
        let mut groups = all_v1();
        let statuses = plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                reports: &reports_v0,
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(statuses.sets[0].rolling, vec!["a".to_string()]);
        assert_eq!(admitted["a"].current.deployment, "v1");
        assert_eq!(admitted["b"].current.deployment, "v0");

        // Failover: the durable admitted set survives in-cluster, so the new leader loads the SAME
        // map. Neither member has settled on v1 yet (agents still report v0).
        let mut failover_admitted = admitted.clone();
        let mut failover_groups = all_v1();
        let failover_statuses = plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut failover_groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                reports: &reports_v0,
            },
            &mut failover_admitted,
            test_now(),
        );
        assert_eq!(
            failover_admitted["a"].current.deployment, "v1",
            "the in-flight member keeps rolling"
        );
        assert_eq!(
            failover_admitted["b"].current.deployment, "v0",
            "the held member is NOT mass-admitted across failover"
        );
        assert_eq!(
            failover_statuses.sets[0].rolling,
            vec!["a".to_string()],
            "max_concurrent held across the leader change"
        );

        // Contrast: a leader that lost the durable state too (empty admitted map — the old cold-PVC
        // bug) would re-seed both baselines to the current desired and admit BOTH at once. This is
        // exactly the breach the durable in-cluster store prevents.
        let mut cold_admitted = BTreeMap::new();
        let mut cold_groups = all_v1();
        plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut cold_groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                reports: &reports_v0,
            },
            &mut cold_admitted,
            test_now(),
        );
        assert_eq!(cold_admitted["a"].current.deployment, "v1");
        assert_eq!(
            cold_admitted["b"].current.deployment, "v1",
            "empty-state reseed mass-admits both members — the very breach durable admitted state prevents"
        );
    }

    fn set_named(name: &str, label_key: &str, label_value: &str) -> UpdateGroupSet {
        UpdateGroupSet::new(
            name,
            crate::UpdateGroupSetSpec {
                selector: crate::LabelSelector {
                    match_labels: BTreeMap::from([(label_key.into(), label_value.into())]),
                },
                max_concurrent: None,
                rollout_windows: vec![],
                calendar: vec![],
            },
        )
    }

    #[test]
    fn a_shared_group_is_held_until_every_governing_set_has_a_slot() {
        // set-X = {a, b}, roll = {b, c}; b is shared by both (N=1 each). Labels:
        //   a: {set: X}          b: {set: X, roll: r}          c: {set: Y, roll: r}
        let mut groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment("v0", true))),
            ("b".to_string(), group("b", deployment("v0", true))),
            ("c".to_string(), group("c", deployment("v0", true))),
        ]);
        let group_labels = BTreeMap::from([
            (
                "a".to_string(),
                BTreeMap::from([("set".to_string(), "X".to_string())]),
            ),
            (
                "b".to_string(),
                BTreeMap::from([
                    ("set".to_string(), "X".to_string()),
                    ("roll".to_string(), "r".to_string()),
                ]),
            ),
            (
                "c".to_string(),
                BTreeMap::from([
                    ("set".to_string(), "Y".to_string()),
                    ("roll".to_string(), "r".to_string()),
                ]),
            ),
        ]);
        let node_groups = BTreeMap::from([
            ("n-a".to_string(), "a".to_string()),
            ("n-b".to_string(), "b".to_string()),
            ("n-c".to_string(), "c".to_string()),
        ]);
        let sets = [set_named("X", "set", "X"), set_named("roll", "roll", "r")];
        let all_v0 = HashMap::from([
            report("n-a", "v0", true),
            report("n-b", "v0", true),
            report("n-c", "v0", true),
        ]);
        // Seed baseline.
        let mut admitted = BTreeMap::new();
        plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                reports: &all_v0,
            },
            &mut admitted,
            test_now(),
        );

        // Everyone wants v1. In set X (N=1): a and b compete. In roll (N=1): b and c compete.
        // Most-constrained first admits the shared b, consuming X's and roll's only slot, so
        // a is held (X full) and c is held (roll full) — b rolls alone.
        for g in ["a", "b", "c"] {
            groups.get_mut(g).unwrap().deployment = deployment("v1", true);
        }
        let statuses = plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                reports: &all_v0,
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(
            admitted["b"].current.deployment, "v1",
            "shared group b rolls first"
        );
        assert_eq!(
            admitted["a"].current.deployment, "v0",
            "a held: set X's slot taken by b"
        );
        assert_eq!(
            admitted["c"].current.deployment, "v0",
            "c held: roll's slot taken by b"
        );
        // b is reported as shared by both sets.
        assert!(statuses
            .sets
            .iter()
            .all(|s| s.shared == vec!["b".to_string()]));
    }

    #[test]
    fn a_forged_report_never_settles_a_member() {
        // Group `a`'s node presents a healthy, fresh report signed by the WRONG key (a forgery);
        // group `b`'s node presents a genuine one. The throttle must verify against each node's
        // pinned key: `a` must NOT settle (so a forged report can never free a concurrency slot and
        // advance the rollout over a node that never actually settled), while `b` does.
        let mut groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment("v1", true))),
            ("b".to_string(), group("b", deployment("v1", true))),
        ]);
        let group_labels = pair_labels();
        let node_groups = BTreeMap::from([
            ("n-a".to_string(), "a".to_string()),
            ("n-b".to_string(), "b".to_string()),
        ]);
        let identity = crate::deployment_identity(&deployment_named("v1")).unwrap();
        let mut report_a = NodeReport::new("n-a", "v1", identity, "v1", DIGEST, true);
        report_a.reported_at_ms = test_now().timestamp_millis() as u64;
        // Genuinely signed, but by a key the control plane never pinned for this node — the forgery a
        // bucket writer could mount without the node's own key.
        let wrong_key =
            updated::csr::key_pem_to_pkcs8_der(&updated::csr::generate_key().unwrap()).unwrap();
        let forged = updated_contracts::telemetry::sign_report(&report_a, &wrong_key).unwrap();
        let reports = HashMap::from([("n-a".to_string(), forged), report("n-b", "v1", true)]);
        let mut admitted = BTreeMap::from([
            ("a".to_string(), admitted(deployment("v1", true))),
            ("b".to_string(), admitted(deployment("v1", true))),
        ]);
        let statuses = plan_rollouts(
            &[pair_set()],
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &pubkeys(&node_groups),
            },
            &mut admitted,
            test_now(),
        );
        assert!(
            !statuses.sets[0].settled.contains(&"a".to_string()),
            "a forged report must not settle its member"
        );
        assert!(
            statuses.sets[0].rolling.contains(&"a".to_string()),
            "the unverified member is still rolling, not settled"
        );
        assert!(
            statuses.sets[0].settled.contains(&"b".to_string()),
            "a genuine report settles its member"
        );
    }

    fn windowed_set(windows: Vec<crate::window::RolloutWindow>) -> UpdateGroupSet {
        UpdateGroupSet::new(
            "pair-00",
            crate::UpdateGroupSetSpec {
                selector: crate::LabelSelector {
                    match_labels: BTreeMap::from([("set".into(), "pair-00".into())]),
                },
                max_concurrent: None,
                rollout_windows: windows,
                calendar: vec![],
            },
        )
    }

    fn at(rfc3339: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(rfc3339)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn a_closed_window_freezes_new_rollouts_then_opens() {
        let mut groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment("v0", true))),
            ("b".to_string(), group("b", deployment("v0", true))),
        ]);
        let group_labels = pair_labels();
        let node_groups = pair_node_groups();
        // Reports are stamped against the instant each pass is planned at, so a member is settled
        // on v0 whichever day the pass runs.
        let reports_v0 = |now| {
            HashMap::from([
                report_at(now, "n-a", "v0", true),
                report_at(now, "n-b", "v0", true),
            ])
        };
        // "Every Sunday" — closed on a Monday, open on the Sunday.
        let sets = [windowed_set(vec![crate::window::RolloutWindow {
            weekdays: vec![crate::window::Weekday::Sunday],
            ..Default::default()
        }])];
        let mut admitted = BTreeMap::new();

        // Seed baseline at v0 while closed (Monday). Baseline is never a throttled rollout,
        // so both seed regardless of the window.
        let monday = at("2026-07-20T12:00:00Z");
        plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                reports: &reports_v0(monday),
            },
            &mut admitted,
            monday, // closed
        );

        // Both want v1 while closed: nothing new is admitted — the set is frozen.
        groups.get_mut("a").unwrap().deployment = deployment("v1", true);
        groups.get_mut("b").unwrap().deployment = deployment("v1", true);
        let statuses = plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                reports: &reports_v0(monday),
            },
            &mut admitted,
            monday, // closed
        );
        assert_eq!(
            admitted["a"].current.deployment, "v0",
            "held: window closed"
        );
        assert_eq!(
            admitted["b"].current.deployment, "v0",
            "held: window closed"
        );
        assert!(statuses.sets[0].frozen);
        assert!(statuses.sets[0].rolling.is_empty());

        // Sunday arrives: the window opens and the set admits up to max_concurrent (1 here).
        groups.get_mut("a").unwrap().deployment = deployment("v1", true);
        groups.get_mut("b").unwrap().deployment = deployment("v1", true);
        let sunday = at("2026-07-26T12:00:00Z");
        let statuses = plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                reports: &reports_v0(sunday),
            },
            &mut admitted,
            sunday, // open
        );
        assert_eq!(
            admitted["a"].current.deployment, "v1",
            "admitted: window open"
        );
        assert_eq!(
            admitted["b"].current.deployment, "v0",
            "held by concurrency, not the window"
        );
        assert!(!statuses.sets[0].frozen);
        assert_eq!(statuses.sets[0].rolling, vec!["a".to_string()]);
    }

    fn calendared_set(calendar: Vec<crate::window::CalendarEntry>) -> UpdateGroupSet {
        UpdateGroupSet::new(
            "pair-00",
            crate::UpdateGroupSetSpec {
                selector: crate::LabelSelector {
                    match_labels: BTreeMap::from([("set".into(), "pair-00".into())]),
                },
                max_concurrent: None,
                rollout_windows: vec![],
                calendar,
            },
        )
    }

    #[test]
    fn a_dated_calendar_gates_then_runs_out_and_falls_back_open() {
        let mut groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment("v0", true))),
            ("b".to_string(), group("b", deployment("v0", true))),
        ]);
        let group_labels = pair_labels();
        let node_groups = pair_node_groups();
        // The only approved window is 2026-08-25 06:00–09:00 UTC.
        let sets = [calendared_set(vec![crate::window::CalendarEntry {
            date: "2026-08-25".into(),
            start: "06:00".into(),
            end: "09:00".into(),
        }])];
        let mut admitted = BTreeMap::new();
        let seed = |groups: &mut BTreeMap<String, ResolvedGroup>,
                    admitted: &mut BTreeMap<String, AdmittedDeployment>,
                    now| {
            // Both members report themselves settled on v0 as of this pass.
            let reports_v0 = HashMap::from([
                report_at(now, "n-a", "v0", true),
                report_at(now, "n-b", "v0", true),
            ]);
            plan_rollouts(
                &sets,
                RolloutInputs {
                    groups,
                    group_labels: &group_labels,
                    node_groups: &node_groups,
                    public_keys: &pubkeys(&node_groups),
                    reports: &reports_v0,
                },
                admitted,
                now,
            )
        };

        // Baseline seeded before the window (baseline is never throttled).
        seed(&mut groups, &mut admitted, at("2026-08-25T05:00:00Z"));

        // Want v1 before the window: frozen (outside the dated window).
        groups.get_mut("a").unwrap().deployment = deployment("v1", true);
        groups.get_mut("b").unwrap().deployment = deployment("v1", true);
        let statuses = seed(&mut groups, &mut admitted, at("2026-08-25T05:30:00Z"));
        assert_eq!(
            admitted["a"].current.deployment, "v0",
            "held: before the window"
        );
        assert!(statuses.sets[0].frozen);

        // Inside the window: admits up to max_concurrent (1).
        groups.get_mut("a").unwrap().deployment = deployment("v1", true);
        groups.get_mut("b").unwrap().deployment = deployment("v1", true);
        let statuses = seed(&mut groups, &mut admitted, at("2026-08-25T07:00:00Z"));
        assert_eq!(
            admitted["a"].current.deployment, "v1",
            "admitted inside the window"
        );
        assert_eq!(
            admitted["b"].current.deployment, "v0",
            "held by concurrency"
        );
        assert!(!statuses.sets[0].frozen);

        // Long after the window: the calendar has run out, so it stops gating and the held
        // member is free to roll (fallback to open).
        groups.get_mut("a").unwrap().deployment = deployment("v1", true);
        groups.get_mut("b").unwrap().deployment = deployment("v1", true);
        // "a" settled on v1 so its slot is free; "b" now rolls because the calendar ran out.
        let later = at("2026-09-15T12:00:00Z");
        let reports_a_done = HashMap::from([
            report_at(later, "n-a", "v1", true),
            report_at(later, "n-b", "v0", true),
        ]);
        let statuses = plan_rollouts(
            &sets,
            RolloutInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                public_keys: &pubkeys(&node_groups),
                reports: &reports_a_done,
            },
            &mut admitted,
            later,
        );
        assert_eq!(
            admitted["b"].current.deployment, "v1",
            "calendar ran out: b rolls"
        );
        assert!(!statuses.sets[0].frozen);
    }

    /// A whole-day calendar entry for `date`, so the exact wall-clock moment a test runs at
    /// never lands on a window boundary.
    fn full_day(date: chrono::NaiveDate) -> crate::window::CalendarEntry {
        crate::window::CalendarEntry {
            date: date.format("%Y-%m-%d").to_string(),
            start: "00:00".into(),
            end: "24:00".into(),
        }
    }

    /// Two members of one set, baseline v0, one agent each. Returns everything an
    /// `plan_rollouts` call needs plus the reports showing both settled on v0.
    #[allow(clippy::type_complexity)]
    fn two_member_pair(
        now: chrono::DateTime<chrono::Utc>,
    ) -> (
        BTreeMap<String, ResolvedGroup>,
        BTreeMap<String, BTreeMap<String, String>>,
        BTreeMap<String, String>,
        HashMap<String, Envelope>,
    ) {
        let groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment("v0", true))),
            ("b".to_string(), group("b", deployment("v0", true))),
        ]);
        let reports = HashMap::from([
            report_at(now, "n-a", "v0", true),
            report_at(now, "n-b", "v0", true),
        ]);
        (groups, pair_labels(), pair_node_groups(), reports)
    }

    // These two exercise the operator's real admission decision (`plan_rollouts`, the same
    // call `reconcile_once` makes) against calendars built from the actual current time —
    // one covering "now", one a year out — so the gating is validated end-to-end against the
    // wall clock rather than a hardcoded date. The whole-day windows keep the outcome
    // independent of the exact instant the test runs.

    #[test]
    fn calendar_window_covering_the_current_time_admits_the_rollout() {
        let now = chrono::Utc::now();
        // The only approved window is the whole of today (UTC), so `now` is inside it.
        let sets = [calendared_set(vec![full_day(now.date_naive())])];
        let (mut groups, group_labels, node_groups, reports) = two_member_pair(now);
        let mut admitted = BTreeMap::new();
        let mut run = |groups: &mut BTreeMap<String, ResolvedGroup>| {
            plan_rollouts(
                &sets,
                RolloutInputs {
                    groups,
                    group_labels: &group_labels,
                    node_groups: &node_groups,
                    public_keys: &pubkeys(&node_groups),
                    reports: &reports,
                },
                &mut admitted,
                now,
            )
        };

        run(&mut groups); // seed baseline v0
        groups.get_mut("a").unwrap().deployment = deployment("v1", true);
        groups.get_mut("b").unwrap().deployment = deployment("v1", true);
        let statuses = run(&mut groups);

        assert!(!statuses.sets[0].frozen, "the current-time window is open");
        assert_eq!(
            admitted["a"].current.deployment, "v1",
            "admitted: inside today's window"
        );
        assert_eq!(
            admitted["b"].current.deployment, "v0",
            "held by concurrency, not the calendar"
        );
        assert_eq!(statuses.sets[0].rolling, vec!["a".to_string()]);
    }

    #[test]
    fn calendar_window_a_year_from_today_freezes_the_rollout() {
        let now = chrono::Utc::now();
        // The only approved window is a year out — a pending future window, so the set is
        // frozen now (it has not run out; it has not yet begun).
        let next_year = now.date_naive() + chrono::Duration::days(365);
        let sets = [calendared_set(vec![full_day(next_year)])];
        let (mut groups, group_labels, node_groups, reports) = two_member_pair(now);
        let mut admitted = BTreeMap::new();
        let mut run = |groups: &mut BTreeMap<String, ResolvedGroup>| {
            plan_rollouts(
                &sets,
                RolloutInputs {
                    groups,
                    group_labels: &group_labels,
                    node_groups: &node_groups,
                    public_keys: &pubkeys(&node_groups),
                    reports: &reports,
                },
                &mut admitted,
                now,
            )
        };

        run(&mut groups); // seed baseline v0
        groups.get_mut("a").unwrap().deployment = deployment("v1", true);
        groups.get_mut("b").unwrap().deployment = deployment("v1", true);
        let statuses = run(&mut groups);

        assert!(
            statuses.sets[0].frozen,
            "a window a year out has not opened yet"
        );
        assert_eq!(
            admitted["a"].current.deployment, "v0",
            "held: outside the calendar"
        );
        assert_eq!(
            admitted["b"].current.deployment, "v0",
            "held: outside the calendar"
        );
        assert!(statuses.sets[0].rolling.is_empty());
    }

    #[test]
    fn dependency_edges_wait_for_authentic_prerequisite_settlement() {
        let mut groups = BTreeMap::from([
            (
                "initialize".into(),
                group("initialize", deployment("v0", true)),
            ),
            ("join".into(), group("join", deployment("v0", true))),
        ]);
        groups.get_mut("join").unwrap().depends_on = vec!["initialize".into()];
        let node_groups = BTreeMap::from([
            ("node-init".into(), "initialize".into()),
            ("node-join".into(), "join".into()),
        ]);
        let keys = pubkeys(&node_groups);
        let labels = BTreeMap::new();
        let mut reports = HashMap::from([
            report("node-init", "v0", true),
            report("node-join", "v0", true),
        ]);
        let mut admitted = BTreeMap::new();
        let run = |groups: &BTreeMap<String, ResolvedGroup>,
                   reports: &HashMap<String, Envelope>,
                   admitted: &mut BTreeMap<String, AdmittedDeployment>| {
            plan_rollouts(
                &[],
                RolloutInputs {
                    groups,
                    group_labels: &labels,
                    node_groups: &node_groups,
                    reports,
                    public_keys: &keys,
                },
                admitted,
                test_now(),
            )
        };

        run(&groups, &reports, &mut admitted);
        groups.get_mut("initialize").unwrap().deployment = deployment("v1", true);
        groups.get_mut("join").unwrap().deployment = deployment("v1", true);
        run(&groups, &reports, &mut admitted);
        assert_eq!(admitted["initialize"].current.deployment, "v1");
        assert_eq!(admitted["join"].current.deployment, "v0");

        reports.insert("node-init".into(), report("node-init", "v1", true).1);
        run(&groups, &reports, &mut admitted);
        assert_eq!(admitted["join"].current.deployment, "v1");
    }

    #[test]
    fn a_first_sighting_is_gated_like_every_later_admission() {
        // Cold cluster: nothing admitted, no telemetry yet. A consumer group must NOT be published
        // on first sight just because it has no admitted entry — its prerequisite has not settled
        // and its inputs are unresolved, so it would ship with an empty `runtime.inputs`. Its nodes
        // get no assignment at all this generation and hold whatever they already have.
        let mut groups = BTreeMap::from([
            (
                "initialize".into(),
                group("initialize", deployment("init-v1", true)),
            ),
            ("join".into(), group("join", deployment("join-v1", true))),
        ]);
        groups.get_mut("join").unwrap().depends_on = vec!["initialize".into()];
        groups.get_mut("join").unwrap().inputs_ready = false;
        let node_groups = BTreeMap::from([
            ("node-init".into(), "initialize".into()),
            ("node-join".into(), "join".into()),
        ]);
        let keys = pubkeys(&node_groups);
        let labels = BTreeMap::new();
        let mut admitted = BTreeMap::new();
        let plan = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &HashMap::new(),
                public_keys: &keys,
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(admitted["initialize"].current.deployment, "init-v1");
        assert!(
            !admitted.contains_key("join"),
            "a consumer whose inputs are unresolved is not admitted on first sight"
        );
        assert!(
            !plan.node_deployments.contains_key("node-join"),
            "an unadmitted group publishes nothing for its nodes"
        );

        // The producer settles and the consumer's inputs resolve: now it is admitted.
        groups.get_mut("join").unwrap().inputs_ready = true;
        let reports = HashMap::from([report("node-init", "init-v1", true)]);
        let plan = plan_rollouts(
            &[],
            RolloutInputs {
                groups: &groups,
                group_labels: &labels,
                node_groups: &node_groups,
                reports: &reports,
                public_keys: &keys,
            },
            &mut admitted,
            test_now(),
        );
        assert_eq!(admitted["join"].current.deployment, "join-v1");
        assert_eq!(plan.node_deployments["node-join"].deployment, "join-v1");
    }

    #[test]
    fn a_same_name_deployment_change_is_still_re_admitted_and_published() {
        // Dependency inputs resolve inside the control plane, so the deployment body changes with
        // no name to bump. Admission that compared only the name dropped this forever while
        // reporting the group Published.
        let (mut groups, node_groups, labels) = three_node_group();
        let keys = pubkeys(&node_groups);
        let reports = HashMap::from([
            report("n0", "v0", true),
            report("n1", "v0", true),
            report("n2", "v0", true),
        ]);
        let mut admitted = BTreeMap::new();
        let run = |groups: &BTreeMap<String, ResolvedGroup>,
                   admitted: &mut BTreeMap<String, AdmittedDeployment>| {
            plan_rollouts(
                &[],
                RolloutInputs {
                    groups,
                    group_labels: &labels,
                    node_groups: &node_groups,
                    reports: &reports,
                    public_keys: &keys,
                },
                admitted,
                test_now(),
            )
        };
        run(&groups, &mut admitted);

        // Same `deployment` identity, different body.
        let resolved = updated_contracts::telemetry::OutputValue::String {
            value: "https://leader-0:8200".into(),
        };
        groups
            .get_mut("g")
            .unwrap()
            .deployment
            .runtime
            .inputs
            .insert("leader".into(), resolved.clone());
        let plan = run(&groups, &mut admitted);

        assert_eq!(
            admitted["g"].current.runtime.inputs["leader"], resolved,
            "a body change under an unchanged name must be re-admitted"
        );
        assert!(
            admitted["g"].previous.is_some(),
            "and it must be STAGED: the predecessor is retained so the group rolls in batches"
        );
        // `max_unavailable` is 1 for this fixture, so exactly one of the three nodes receives the
        // new body this pass and the other two hold the old one.
        let advanced = plan
            .node_deployments
            .values()
            .filter(|deployment| deployment.runtime.inputs.get("leader") == Some(&resolved))
            .count();
        assert_eq!(
            advanced, 1,
            "an edit that renames nothing must still respect maxUnavailable"
        );
    }
}
