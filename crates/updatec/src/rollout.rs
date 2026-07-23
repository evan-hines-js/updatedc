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
use std::collections::{BTreeMap, BTreeSet, HashMap};

use crate::{DesiredDeployment, ResolvedGroup, UpdateGroupSet};
use serde::{Deserialize, Serialize};
use updated::telemetry::NodeReport;

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
    pub reports: &'a HashMap<String, NodeReport>,
    /// Node → its pinned public key (raw EC point), set at enrollment from the node's CSR. A report
    /// is trusted only if its signature verifies against this key, so rollout decisions act on
    /// end-to-end evidence (node → planner), not gateway write-hop authentication. A node with no
    /// pinned key is unverifiable and can never be seen as settled — it
    /// fails closed.
    pub public_keys: &'a HashMap<String, Vec<u8>>,
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

    // The deployment each group desires this generation.
    let desired: BTreeMap<String, DesiredDeployment> = groups
        .iter()
        .map(|(name, group)| (name.clone(), group.deployment.clone()))
        .collect();
    // Seed any group we have never admitted before to its desired deployment — bringing a
    // group to its initial baseline is not a throttled rollout. This runs against the durable
    // admitted set, so "the first time we see it" is genuinely once per group across the whole
    // fleet lifetime, NOT once per leader/PVC. Groups that no longer exist are pruned so the
    // durable state stays bounded.
    for (name, desired_deployment) in &desired {
        admitted
            .entry(name.clone())
            .or_insert_with(|| AdmittedDeployment {
                current: desired_deployment.clone(),
                previous: None,
            });
    }
    admitted.retain(|name, _| desired.contains_key(name));

    // The wall-clock the throttle ages reports against — the same `now` the windows/calendar use,
    // so a stale report and a closed window are judged against one clock.
    let now_ms = now.timestamp_millis().max(0) as u64;
    let fresh_report = |node: &str| -> Option<&NodeReport> {
        let report = reports.get(node)?;
        // No pinned key ⇒ the report is unverifiable ⇒ never settled (fail closed).
        let public_key = public_keys.get(node)?;
        // A report older than the shared freshness bound reads as not-settled. Without this a
        // node that reported healthy once and then went silent (dead hardware, power loss)
        // would count "settled" forever, letting the throttle admit the next group over a node
        // that has since failed — the fail-*open* direction. The healthproxy ages reports this
        // way too; the throttle must agree.
        (report.node == node
            && report.age_ms(now_ms) <= updated::telemetry::REPORT_FRESHNESS.as_millis() as u64
            // Verify the node itself signed this exact report with its pinned per-node key. An
            // unsigned, forged, or tampered report fails here and is treated as absent — so the
            // throttle acts only on health it can cryptographically attribute to the node.
            && updated::telemetry::verify_report(report, public_key))
        .then_some(report)
    };
    let fresh_healthy = |node: &str, published_id: &str| -> bool {
        fresh_report(node).is_some_and(|report| report.deployment == published_id && report.healthy)
    };
    let settled = |group: &str, published_id: &str| -> bool {
        node_groups
            .iter()
            .filter(|(_, selected)| selected.as_str() == group)
            .all(|(node, _)| fresh_healthy(node, published_id))
    };

    // A member is *rolling* — occupying one of its sets' concurrency slots — whenever its published
    // (admitted) deployment has not settled yet, regardless of what its *current* desired deployment
    // is. Keying off "admitted not settled" (rather than the old "admitted == desired && !settled")
    // matters when a group is re-targeted mid-rollout: its admitted deployment is still physically
    // rolling out to nodes, so it must keep holding its slot rather than freeing it (and letting a
    // second group start) the instant desired changes — which would transiently breach max_concurrent.
    // Finish rolls before considering a new desired target. This is load-bearing for groups that
    // are not members of a set: without it a rapid C -> D retarget could replace `previous` while
    // some nodes still physically run P.
    for (name, state) in admitted.iter_mut() {
        if state.previous.is_some()
            && (state.current.report_url.is_none() || settled(name, &state.current.deployment))
        {
            state.previous = None;
        }
    }
    let is_rolling = |name: &str, admitted: &BTreeMap<String, AdmittedDeployment>| {
        admitted[name].previous.is_some() || !settled(name, &admitted[name].current.deployment)
    };

    // Resolve every set to its members and remaining admission slots. One plan per set,
    // in `sets` order, so a plan index is the set index. A group records which set plans
    // govern it, so admission can require *every* one of them to have a slot — that is
    // what preserves the "no more than N rolling" guarantee for groups shared by
    // overlapping sets (the tightest set wins), instead of each set admitting blindly.
    struct SetPlan {
        members: Vec<String>,
        max_concurrent: usize,
        slots: usize,
        frozen: bool,
    }
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
        let rolling_now = members.iter().filter(|n| is_rolling(n, admitted)).count();
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

    // A group in more than one set is "shared": the control plane rolls it up safely,
    // admitting it only when every set it belongs to has a slot — the tightest set governs.
    // Surfaced on status so the UI can show shared members as spanning sets, not as plain
    // members of one.
    let shared: BTreeSet<String> = group_plans
        .iter()
        .filter(|(_, plans)| plans.len() > 1)
        .map(|(name, _)| name.clone())
        .collect();

    // Admit pending groups, most-constrained (in the most sets) first so a shared group is
    // never starved behind single-set members. A group in no set rolls freely; a group in
    // one or more sets is admitted only while every one of them has a slot, consuming one
    // in each.
    let mut pending: Vec<String> = desired
        .keys()
        .filter(|name| admitted[*name].current.deployment != desired[*name].deployment)
        .cloned()
        .collect();
    pending.sort_by(|a, b| {
        let count = |n: &String| group_plans.get(n).map_or(0, Vec::len);
        count(b).cmp(&count(a)).then_with(|| a.cmp(b))
    });
    for name in pending {
        // Never overwrite the predecessor of an unfinished rollout, even when this group belongs
        // to no set. The latest desired value remains pending and will be admitted after settling.
        let telemetry_gated = desired[&name].report_url.is_some();
        if telemetry_gated
            && (admitted[&name].previous.is_some()
                || !settled(&name, &admitted[&name].current.deployment))
        {
            continue;
        }
        let admit = |admitted: &mut BTreeMap<String, AdmittedDeployment>| {
            let previous = admitted[&name].current.clone();
            admitted.insert(
                name.clone(),
                AdmittedDeployment {
                    current: desired[&name].clone(),
                    previous: telemetry_gated.then_some(previous),
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

    let statuses = sets
        .iter()
        .zip(&plans)
        .map(|(set, plan)| {
            let mut rolling = Vec::new();
            let mut settled_members = Vec::new();
            let mut shared_members = Vec::new();
            for name in &plan.members {
                if shared.contains(name) {
                    shared_members.push(name.clone());
                }
                if admitted[name].current.deployment != desired[name].deployment {
                    continue; // held back — neither rolling nor settled on its desire
                }
                if settled(name, &admitted[name].current.deployment) {
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
        .collect();

    // Turn group-level admission into exact per-node assignments. Already-observed current nodes
    // are retained across membership/order changes. Existing unavailable nodes consume the same
    // budget as newly advanced nodes, so this enforces maxUnavailable rather than merely maxInFlight.
    let mut node_deployments = BTreeMap::new();
    for (name, group) in groups.iter() {
        let state = &admitted[name];
        let mut nodes: Vec<&String> = node_groups
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
        let mut unavailable = 0usize;
        let mut held = Vec::new();
        for node in nodes {
            let observed_current = fresh_report(node)
                .is_some_and(|report| report.deployment == state.current.deployment);
            if observed_current {
                if !fresh_healthy(node, &state.current.deployment) {
                    unavailable += 1;
                }
                node_deployments.insert(node.clone(), state.current.clone());
            } else {
                if !fresh_healthy(node, &previous.deployment) {
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
    RolloutPlan {
        sets: statuses,
        node_deployments,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A fixed instant for tests whose sets carry no rollout windows (always open, so the
    // exact value is irrelevant). Window behaviour is unit-tested in `crate::window`.
    fn test_now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-07-20T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    fn deployment(id: &str, with_report: bool) -> DesiredDeployment {
        DesiredDeployment {
            schema: 2,
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

    fn runtime() -> updated::config::ManagedRuntime {
        updated::config::ManagedRuntime {
            product: "app".into(),
            channel: "stable".into(),
            install_root: "/opt/app".into(),
            args: vec![],
            health_checks: vec![],
            repository: updated::config::ManagedRepositoryLimits {
                metadata_limit: 1,
                target_limit: 1,
                transport_timeout_seconds: 1,
            },
            storage: updated::config::ManagedStorage {
                inactive_releases: 1,
                inactive_providers: 1,
                inactive_supervisors: 1,
                inactive_bytes: 1,
                inactive_repository_caches: 1,
            },
            timeouts: updated::config::ManagedTimeouts {
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

    fn report(node: &str, deployment: &str, healthy: bool) -> (String, NodeReport) {
        // Throttling keys off (deployment, healthy); the running version is irrelevant here.
        // Stamp "always fresh" (a future timestamp ages to 0) so the concurrency tests exercise
        // admission logic against a node reporting on every tick — the freshness bound has its own
        // dedicated test (`a_stale_report_is_treated_as_not_settled`) rather than perturbing these.
        let mut report = NodeReport::new(node, deployment, deployment, healthy);
        report.reported_at_ms = u64::MAX;
        report.signature = updated::telemetry::sign_report(&report, &TEST_KEY.0).unwrap();
        (node.into(), report)
    }

    /// A healthy report older than [`updated::telemetry::REPORT_FRESHNESS`], stamped relative to
    /// `test_now`.
    fn stale_report(node: &str, deployment: &str) -> (String, NodeReport) {
        let mut report = NodeReport::new(node, deployment, deployment, true);
        let stale_ms = updated::telemetry::REPORT_FRESHNESS.as_millis() as u64 + 60_000;
        report.reported_at_ms = (test_now().timestamp_millis() as u64).saturating_sub(stale_ms);
        report.signature = updated::telemetry::sign_report(&report, &TEST_KEY.0).unwrap();
        (node.into(), report)
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
        let mut forged = NodeReport::new("n-a", "v1", "v1", true);
        forged.reported_at_ms = u64::MAX;
        let wrong_key =
            updated::csr::key_pem_to_pkcs8_der(&updated::csr::generate_key().unwrap()).unwrap();
        forged.signature = updated::telemetry::sign_report(&forged, &wrong_key).unwrap();
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
        let reports_v0 = HashMap::from([report("n-a", "v0", true), report("n-b", "v0", true)]);
        // "Every Sunday" — closed on a Monday, open on the Sunday.
        let sets = [windowed_set(vec![crate::window::RolloutWindow {
            weekdays: vec![crate::window::Weekday::Sunday],
            ..Default::default()
        }])];
        let mut admitted = BTreeMap::new();

        // Seed baseline at v0 while closed (Monday). Baseline is never a throttled rollout,
        // so both seed regardless of the window.
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
            at("2026-07-20T12:00:00Z"), // Monday: closed
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
                reports: &reports_v0,
            },
            &mut admitted,
            at("2026-07-20T12:00:00Z"), // Monday: closed
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
            at("2026-07-26T12:00:00Z"), // Sunday: open
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
        let reports_v0 = HashMap::from([report("n-a", "v0", true), report("n-b", "v0", true)]);
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
            at("2026-09-15T12:00:00Z"),
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
    fn two_member_pair() -> (
        BTreeMap<String, ResolvedGroup>,
        BTreeMap<String, BTreeMap<String, String>>,
        BTreeMap<String, String>,
        HashMap<String, NodeReport>,
    ) {
        let groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment("v0", true))),
            ("b".to_string(), group("b", deployment("v0", true))),
        ]);
        let reports = HashMap::from([report("n-a", "v0", true), report("n-b", "v0", true)]);
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
        let (mut groups, group_labels, node_groups, reports) = two_member_pair();
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
        let (mut groups, group_labels, node_groups, reports) = two_member_pair();
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
}
