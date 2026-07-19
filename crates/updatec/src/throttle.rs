//! Rollout throttling across an [`UpdateGroupSet`](crate::UpdateGroupSet).
//!
//! A set caps how many of its member groups roll at once. The control plane can never
//! reach a node, so "rolling" and "settled" are decided entirely from node telemetry the
//! agents write to shared storage: a member group is *settled* once every agent it
//! selects reports the deployment identity the operator most recently published for that
//! group, healthy. Held-back members keep their last-admitted deployment — persisted
//! here — so the signed generation pins them until a slot frees.
//!
//! When a member group carries no `report_url` there is no feedback to gate on, so the
//! set is not throttled (logged, admit all) — a clean degradation to the pre-throttle
//! behaviour rather than a stall.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use crate::{DesiredDeployment, ResolvedGroup, UpdateGroupSet};
use updated::telemetry::NodeReport;

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

/// Everything `apply_throttle` needs about the current generation, kept separate from
/// Kubernetes types so the core admission logic is pure and unit-testable.
pub struct ThrottleInputs<'a> {
    /// Member groups by name, mutated in place so each carries the deployment that should
    /// actually be published (its own desired one, or its held last-admitted one).
    pub groups: &'a mut BTreeMap<String, ResolvedGroup>,
    /// Each group's Kubernetes metadata labels — what a set's selector matches on.
    pub group_labels: &'a BTreeMap<String, BTreeMap<String, String>>,
    /// Node → selected group name, from the publication plan's routing.
    pub node_groups: &'a BTreeMap<String, String>,
    /// Node → its latest self-reported running state.
    pub reports: &'a HashMap<String, NodeReport>,
}

/// Apply every set's throttle. Mutates `inputs.groups` so held-back members carry their
/// last-admitted deployment, persists admission decisions under `admitted_dir`, and
/// returns the per-set status to publish. Groups in no set always roll freely.
pub fn apply_throttle(
    sets: &[UpdateGroupSet],
    inputs: ThrottleInputs<'_>,
    admitted_dir: &Path,
    now: chrono::DateTime<chrono::Utc>,
) -> std::io::Result<Vec<SetStatus>> {
    let ThrottleInputs {
        groups,
        group_labels,
        node_groups,
        reports,
    } = inputs;

    // The deployment each group is currently published on (its "admitted" deployment):
    // read from disk, or seeded to the group's desired deployment the first time we see
    // it — bringing a group to its initial baseline is not a throttled rollout.
    let desired: BTreeMap<String, DesiredDeployment> = groups
        .iter()
        .map(|(name, group)| (name.clone(), group.deployment.clone()))
        .collect();
    let mut admitted: BTreeMap<String, DesiredDeployment> = BTreeMap::new();
    for (name, desired_deployment) in &desired {
        let loaded = load_admitted(admitted_dir, name)?;
        admitted.insert(name.clone(), loaded.unwrap_or_else(|| desired_deployment.clone()));
    }

    // The wall-clock the throttle ages reports against — the same `now` the windows/calendar use,
    // so a stale report and a closed window are judged against one clock.
    let now_ms = now.timestamp_millis().max(0) as u64;
    let fresh_healthy = |node: &str, published_id: &str| -> bool {
        reports.get(node).is_some_and(|report| {
            report.deployment == published_id
                && report.healthy
                // A report older than the shared freshness bound reads as not-settled. Without this
                // a node that reported healthy once and then went silent (dead hardware, power
                // loss) would count "settled" forever, letting the throttle admit the next group
                // over a node that has since failed — the fail-*open* direction. The healthproxy
                // already ages reports this way; the throttle must agree.
                && report.age_ms(now_ms) <= updated::telemetry::REPORT_FRESHNESS.as_millis() as u64
        })
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
    let is_rolling = |name: &str, admitted: &BTreeMap<String, DesiredDeployment>| {
        !settled(name, &admitted[name].deployment)
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
        // Gating needs node feedback: without a report location on every member there is
        // nothing to wait on, so the set degrades to ungated (admit all) rather than
        // stalling forever waiting for reports that will never come.
        let gated = !members.is_empty() && members.iter().all(|n| desired[n].report_url.is_some());
        let max_concurrent = if members.is_empty() {
            0
        } else if gated {
            set.spec.effective_max_concurrent(members.len())
        } else {
            tracing::warn!(
                set = set.metadata.name.as_deref().unwrap_or("<unnamed>"),
                "UpdateGroupSet has members without a report_url; rolling without throttle"
            );
            members.len()
        };
        let rolling_now = members.iter().filter(|n| is_rolling(n, &admitted)).count();
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
            slots: if open {
                max_concurrent.saturating_sub(rolling_now)
            } else {
                0
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
        .filter(|name| admitted[*name].deployment != desired[*name].deployment)
        .cloned()
        .collect();
    pending.sort_by(|a, b| {
        let count = |n: &String| group_plans.get(n).map_or(0, Vec::len);
        count(b).cmp(&count(a)).then_with(|| a.cmp(b))
    });
    for name in pending {
        match group_plans.get(&name) {
            None => {
                admitted.insert(name.clone(), desired[&name].clone());
            }
            Some(indices) => {
                if indices.iter().all(|&i| plans[i].slots > 0) {
                    admitted.insert(name.clone(), desired[&name].clone());
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
                if admitted[name].deployment != desired[name].deployment {
                    continue; // held back — neither rolling nor settled on its desire
                }
                if settled(name, &admitted[name].deployment) {
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

    // Persist any admission changes and pin each group's published deployment to its
    // admitted one.
    for (name, group) in groups.iter_mut() {
        let admitted_deployment = admitted
            .get(name)
            .cloned()
            .unwrap_or_else(|| group.deployment.clone());
        persist_admitted(admitted_dir, name, &admitted_deployment)?;
        group.deployment = admitted_deployment;
    }

    Ok(statuses)
}

fn admitted_path(admitted_dir: &Path, group: &str) -> std::path::PathBuf {
    admitted_dir.join(format!("{group}.json"))
}

fn load_admitted(admitted_dir: &Path, group: &str) -> std::io::Result<Option<DesiredDeployment>> {
    match std::fs::read(admitted_path(admitted_dir, group)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Persist a group's admitted deployment only when it changed, so a steady generation
/// does no disk writes.
fn persist_admitted(
    admitted_dir: &Path,
    group: &str,
    deployment: &DesiredDeployment,
) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(deployment)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    if load_admitted(admitted_dir, group)?.as_ref() == Some(deployment) {
        return Ok(());
    }
    std::fs::create_dir_all(admitted_dir)?;
    foundation::durable::atomic_write(&admitted_path(admitted_dir, group), ".admitted-", &bytes)
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

    fn report(node: &str, deployment: &str, healthy: bool) -> (String, NodeReport) {
        // Throttling keys off (deployment, healthy); the running version is irrelevant here.
        // Stamp "always fresh" (a future timestamp ages to 0) so the concurrency tests exercise
        // admission logic against a node reporting on every tick — the freshness bound has its own
        // dedicated test (`a_stale_report_is_treated_as_not_settled`) rather than perturbing these.
        let mut report = NodeReport::new(node, deployment, deployment, healthy);
        report.reported_at_ms = u64::MAX;
        (node.into(), report)
    }

    /// A healthy report older than [`updated::telemetry::REPORT_FRESHNESS`], stamped relative to
    /// `test_now`.
    fn stale_report(node: &str, deployment: &str) -> (String, NodeReport) {
        let mut report = NodeReport::new(node, deployment, deployment, true);
        let stale_ms = updated::telemetry::REPORT_FRESHNESS.as_millis() as u64 + 60_000;
        report.reported_at_ms = (test_now().timestamp_millis() as u64).saturating_sub(stale_ms);
        (node.into(), report)
    }

    #[test]
    fn a_stale_report_is_treated_as_not_settled() {
        // A node that reported healthy once and then went silent must NOT keep a group "settled"
        // forever (the fail-open direction). One pair-member with only a stale report never
        // settles, so it stays `rolling` and its sibling is held — same as a missing report.
        let dir = tempfile::tempdir().unwrap();
        let mut groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment("v1", true))),
            ("b".to_string(), group("b", deployment("v1", true))),
        ]);
        let group_labels = BTreeMap::from([
            ("a".to_string(), BTreeMap::from([("set".to_string(), "pair-00".to_string())])),
            ("b".to_string(), BTreeMap::from([("set".to_string(), "pair-00".to_string())])),
        ]);
        let node_groups =
            BTreeMap::from([("n-a".to_string(), "a".to_string()), ("n-b".to_string(), "b".to_string())]);
        // "a" is admitted v1 but its only report is stale; "b" holds a fresh v1.
        std::fs::create_dir_all(dir.path()).unwrap();
        let reports = HashMap::from([stale_report("n-a", "v1"), report("n-b", "v1", true)]);
        let statuses = apply_throttle(
            &[pair_set()],
            ThrottleInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                reports: &reports,
            },
            dir.path(),
            test_now(),
        )
        .unwrap();
        assert!(statuses[0].rolling.contains(&"a".to_string()), "stale 'a' must be rolling, not settled");
        assert!(statuses[0].settled.contains(&"b".to_string()), "fresh 'b' is settled");
    }

    #[test]
    fn holds_the_second_member_until_the_first_settles() {
        let dir = tempfile::tempdir().unwrap();
        // Two members of a pair, both baseline "v0", one agent each.
        let mut groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment("v0", true))),
            ("b".to_string(), group("b", deployment("v0", true))),
        ]);
        let group_labels = BTreeMap::from([
            ("a".to_string(), BTreeMap::from([("set".to_string(), "pair-00".to_string())])),
            ("b".to_string(), BTreeMap::from([("set".to_string(), "pair-00".to_string())])),
        ]);
        let node_groups =
            BTreeMap::from([("n-a".to_string(), "a".to_string()), ("n-b".to_string(), "b".to_string())]);
        // Seed baseline as admitted (first sight), both settled on v0.
        let reports_v0 = HashMap::from([report("n-a", "v0", true), report("n-b", "v0", true)]);
        let sets = [pair_set()];
        apply_throttle(
            &sets,
            ThrottleInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                reports: &reports_v0,
            },
            dir.path(),
            test_now(),
        )
        .unwrap();

        // Now both want v1. Only one may roll.
        groups.get_mut("a").unwrap().deployment = deployment("v1", true);
        groups.get_mut("b").unwrap().deployment = deployment("v1", true);
        let statuses = apply_throttle(
            &sets,
            ThrottleInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                reports: &reports_v0, // agents still on v0
            },
            dir.path(),
            test_now(),
        )
        .unwrap();
        // Exactly one member (the first by name, "a") is admitted to v1; "b" is held at v0.
        assert_eq!(groups["a"].deployment.deployment, "v1");
        assert_eq!(groups["b"].deployment.deployment, "v0");
        assert_eq!(statuses[0].rolling, vec!["a".to_string()]);
        assert!(statuses[0].settled.is_empty());
        assert_eq!(statuses[0].max_concurrent, 1);

        // Reconcile re-derives desired from the CRD spec every cycle: the spec still
        // wants v1 for both, so re-express that before the next pass (apply_throttle
        // overwrote "b" with its held v0 for the previous publication only).
        groups.get_mut("a").unwrap().deployment = deployment("v1", true);
        groups.get_mut("b").unwrap().deployment = deployment("v1", true);
        // "a" settles on v1; the slot frees and "b" is admitted.
        let reports_a_done = HashMap::from([report("n-a", "v1", true), report("n-b", "v0", true)]);
        let statuses = apply_throttle(
            &sets,
            ThrottleInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                reports: &reports_a_done,
            },
            dir.path(),
            test_now(),
        )
        .unwrap();
        assert_eq!(groups["a"].deployment.deployment, "v1");
        assert_eq!(groups["b"].deployment.deployment, "v1");
        assert_eq!(statuses[0].settled, vec!["a".to_string()]);
        assert_eq!(statuses[0].rolling, vec!["b".to_string()]);
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
        let dir = tempfile::tempdir().unwrap();
        // set-X = {a, b}, roll = {b, c}; b is shared by both (N=1 each). Labels:
        //   a: {set: X}          b: {set: X, roll: r}          c: {set: Y, roll: r}
        let mut groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment("v0", true))),
            ("b".to_string(), group("b", deployment("v0", true))),
            ("c".to_string(), group("c", deployment("v0", true))),
        ]);
        let group_labels = BTreeMap::from([
            ("a".to_string(), BTreeMap::from([("set".to_string(), "X".to_string())])),
            (
                "b".to_string(),
                BTreeMap::from([("set".to_string(), "X".to_string()), ("roll".to_string(), "r".to_string())]),
            ),
            (
                "c".to_string(),
                BTreeMap::from([("set".to_string(), "Y".to_string()), ("roll".to_string(), "r".to_string())]),
            ),
        ]);
        let node_groups = BTreeMap::from([
            ("n-a".to_string(), "a".to_string()),
            ("n-b".to_string(), "b".to_string()),
            ("n-c".to_string(), "c".to_string()),
        ]);
        let sets = [set_named("X", "set", "X"), set_named("roll", "roll", "r")];
        let all_v0 = HashMap::from([report("n-a", "v0", true), report("n-b", "v0", true), report("n-c", "v0", true)]);
        // Seed baseline.
        apply_throttle(
            &sets,
            ThrottleInputs { groups: &mut groups, group_labels: &group_labels, node_groups: &node_groups, reports: &all_v0 },
            dir.path(),
            test_now(),
        )
        .unwrap();

        // Everyone wants v1. In set X (N=1): a and b compete. In roll (N=1): b and c compete.
        // Most-constrained first admits the shared b, consuming X's and roll's only slot, so
        // a is held (X full) and c is held (roll full) — b rolls alone.
        for g in ["a", "b", "c"] {
            groups.get_mut(g).unwrap().deployment = deployment("v1", true);
        }
        let statuses = apply_throttle(
            &sets,
            ThrottleInputs { groups: &mut groups, group_labels: &group_labels, node_groups: &node_groups, reports: &all_v0 },
            dir.path(),
            test_now(),
        )
        .unwrap();
        assert_eq!(groups["b"].deployment.deployment, "v1", "shared group b rolls first");
        assert_eq!(groups["a"].deployment.deployment, "v0", "a held: set X's slot taken by b");
        assert_eq!(groups["c"].deployment.deployment, "v0", "c held: roll's slot taken by b");
        // b is reported as shared by both sets.
        assert!(statuses.iter().all(|s| s.shared == vec!["b".to_string()]));
    }

    #[test]
    fn without_report_urls_the_set_rolls_unthrottled() {
        let dir = tempfile::tempdir().unwrap();
        let mut groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment("v0", false))),
            ("b".to_string(), group("b", deployment("v0", false))),
        ]);
        let group_labels = BTreeMap::from([
            ("a".to_string(), BTreeMap::from([("set".to_string(), "pair-00".to_string())])),
            ("b".to_string(), BTreeMap::from([("set".to_string(), "pair-00".to_string())])),
        ]);
        let node_groups = BTreeMap::new();
        let reports = HashMap::new();
        let sets = [pair_set()];
        apply_throttle(
            &sets,
            ThrottleInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                reports: &reports,
            },
            dir.path(),
            test_now(),
        )
        .unwrap();
        // Both jump to v1 with no telemetry: both admitted (no throttle).
        groups.get_mut("a").unwrap().deployment = deployment("v1", false);
        groups.get_mut("b").unwrap().deployment = deployment("v1", false);
        let statuses = apply_throttle(
            &sets,
            ThrottleInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                reports: &reports,
            },
            dir.path(),
            test_now(),
        )
        .unwrap();
        assert_eq!(groups["a"].deployment.deployment, "v1");
        assert_eq!(groups["b"].deployment.deployment, "v1");
        assert_eq!(statuses[0].max_concurrent, 2);
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
        let dir = tempfile::tempdir().unwrap();
        let mut groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment("v0", true))),
            ("b".to_string(), group("b", deployment("v0", true))),
        ]);
        let group_labels = BTreeMap::from([
            ("a".to_string(), BTreeMap::from([("set".to_string(), "pair-00".to_string())])),
            ("b".to_string(), BTreeMap::from([("set".to_string(), "pair-00".to_string())])),
        ]);
        let node_groups =
            BTreeMap::from([("n-a".to_string(), "a".to_string()), ("n-b".to_string(), "b".to_string())]);
        let reports_v0 = HashMap::from([report("n-a", "v0", true), report("n-b", "v0", true)]);
        // "Every Sunday" — closed on a Monday, open on the Sunday.
        let sets = [windowed_set(vec![crate::window::RolloutWindow {
            weekdays: vec![crate::window::Weekday::Sunday],
            ..Default::default()
        }])];

        // Seed baseline at v0 while closed (Monday). Baseline is never a throttled rollout,
        // so both seed regardless of the window.
        apply_throttle(
            &sets,
            ThrottleInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                reports: &reports_v0,
            },
            dir.path(),
            at("2026-07-20T12:00:00Z"), // Monday: closed
        )
        .unwrap();

        // Both want v1 while closed: nothing new is admitted — the set is frozen.
        groups.get_mut("a").unwrap().deployment = deployment("v1", true);
        groups.get_mut("b").unwrap().deployment = deployment("v1", true);
        let statuses = apply_throttle(
            &sets,
            ThrottleInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                reports: &reports_v0,
            },
            dir.path(),
            at("2026-07-20T12:00:00Z"), // Monday: closed
        )
        .unwrap();
        assert_eq!(groups["a"].deployment.deployment, "v0", "held: window closed");
        assert_eq!(groups["b"].deployment.deployment, "v0", "held: window closed");
        assert!(statuses[0].frozen);
        assert!(statuses[0].rolling.is_empty());

        // Sunday arrives: the window opens and the set admits up to max_concurrent (1 here).
        groups.get_mut("a").unwrap().deployment = deployment("v1", true);
        groups.get_mut("b").unwrap().deployment = deployment("v1", true);
        let statuses = apply_throttle(
            &sets,
            ThrottleInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                reports: &reports_v0,
            },
            dir.path(),
            at("2026-07-26T12:00:00Z"), // Sunday: open
        )
        .unwrap();
        assert_eq!(groups["a"].deployment.deployment, "v1", "admitted: window open");
        assert_eq!(groups["b"].deployment.deployment, "v0", "held by concurrency, not the window");
        assert!(!statuses[0].frozen);
        assert_eq!(statuses[0].rolling, vec!["a".to_string()]);
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
        let dir = tempfile::tempdir().unwrap();
        let mut groups = BTreeMap::from([
            ("a".to_string(), group("a", deployment("v0", true))),
            ("b".to_string(), group("b", deployment("v0", true))),
        ]);
        let group_labels = BTreeMap::from([
            ("a".to_string(), BTreeMap::from([("set".to_string(), "pair-00".to_string())])),
            ("b".to_string(), BTreeMap::from([("set".to_string(), "pair-00".to_string())])),
        ]);
        let node_groups =
            BTreeMap::from([("n-a".to_string(), "a".to_string()), ("n-b".to_string(), "b".to_string())]);
        let reports_v0 = HashMap::from([report("n-a", "v0", true), report("n-b", "v0", true)]);
        // The only approved window is 2026-08-25 06:00–09:00 UTC.
        let sets = [calendared_set(vec![crate::window::CalendarEntry {
            date: "2026-08-25".into(),
            start: "06:00".into(),
            end: "09:00".into(),
        }])];
        let seed = |groups: &mut BTreeMap<String, ResolvedGroup>, now| {
            apply_throttle(
                &sets,
                ThrottleInputs {
                    groups,
                    group_labels: &group_labels,
                    node_groups: &node_groups,
                    reports: &reports_v0,
                },
                dir.path(),
                now,
            )
            .unwrap()
        };

        // Baseline seeded before the window (baseline is never throttled).
        seed(&mut groups, at("2026-08-25T05:00:00Z"));

        // Want v1 before the window: frozen (outside the dated window).
        groups.get_mut("a").unwrap().deployment = deployment("v1", true);
        groups.get_mut("b").unwrap().deployment = deployment("v1", true);
        let statuses = seed(&mut groups, at("2026-08-25T05:30:00Z"));
        assert_eq!(groups["a"].deployment.deployment, "v0", "held: before the window");
        assert!(statuses[0].frozen);

        // Inside the window: admits up to max_concurrent (1).
        groups.get_mut("a").unwrap().deployment = deployment("v1", true);
        groups.get_mut("b").unwrap().deployment = deployment("v1", true);
        let statuses = seed(&mut groups, at("2026-08-25T07:00:00Z"));
        assert_eq!(groups["a"].deployment.deployment, "v1", "admitted inside the window");
        assert_eq!(groups["b"].deployment.deployment, "v0", "held by concurrency");
        assert!(!statuses[0].frozen);

        // Long after the window: the calendar has run out, so it stops gating and the held
        // member is free to roll (fallback to open).
        groups.get_mut("a").unwrap().deployment = deployment("v1", true);
        groups.get_mut("b").unwrap().deployment = deployment("v1", true);
        // "a" settled on v1 so its slot is free; "b" now rolls because the calendar ran out.
        let reports_a_done = HashMap::from([report("n-a", "v1", true), report("n-b", "v0", true)]);
        let statuses = apply_throttle(
            &sets,
            ThrottleInputs {
                groups: &mut groups,
                group_labels: &group_labels,
                node_groups: &node_groups,
                reports: &reports_a_done,
            },
            dir.path(),
            at("2026-09-15T12:00:00Z"),
        )
        .unwrap();
        assert_eq!(groups["b"].deployment.deployment, "v1", "calendar ran out: b rolls");
        assert!(!statuses[0].frozen);
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
    /// `apply_throttle` call needs plus the reports showing both settled on v0.
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
        let group_labels = BTreeMap::from([
            ("a".to_string(), BTreeMap::from([("set".to_string(), "pair-00".to_string())])),
            ("b".to_string(), BTreeMap::from([("set".to_string(), "pair-00".to_string())])),
        ]);
        let node_groups =
            BTreeMap::from([("n-a".to_string(), "a".to_string()), ("n-b".to_string(), "b".to_string())]);
        let reports = HashMap::from([report("n-a", "v0", true), report("n-b", "v0", true)]);
        (groups, group_labels, node_groups, reports)
    }

    // These two exercise the operator's real admission decision (`apply_throttle`, the same
    // call `reconcile_once` makes) against calendars built from the actual current time —
    // one covering "now", one a year out — so the gating is validated end-to-end against the
    // wall clock rather than a hardcoded date. The whole-day windows keep the outcome
    // independent of the exact instant the test runs.

    #[test]
    fn calendar_window_covering_the_current_time_admits_the_rollout() {
        let dir = tempfile::tempdir().unwrap();
        let now = chrono::Utc::now();
        // The only approved window is the whole of today (UTC), so `now` is inside it.
        let sets = [calendared_set(vec![full_day(now.date_naive())])];
        let (mut groups, group_labels, node_groups, reports) = two_member_pair();
        let run = |groups: &mut BTreeMap<String, ResolvedGroup>| {
            apply_throttle(
                &sets,
                ThrottleInputs {
                    groups,
                    group_labels: &group_labels,
                    node_groups: &node_groups,
                    reports: &reports,
                },
                dir.path(),
                now,
            )
            .unwrap()
        };

        run(&mut groups); // seed baseline v0
        groups.get_mut("a").unwrap().deployment = deployment("v1", true);
        groups.get_mut("b").unwrap().deployment = deployment("v1", true);
        let statuses = run(&mut groups);

        assert!(!statuses[0].frozen, "the current-time window is open");
        assert_eq!(groups["a"].deployment.deployment, "v1", "admitted: inside today's window");
        assert_eq!(groups["b"].deployment.deployment, "v0", "held by concurrency, not the calendar");
        assert_eq!(statuses[0].rolling, vec!["a".to_string()]);
    }

    #[test]
    fn calendar_window_a_year_from_today_freezes_the_rollout() {
        let dir = tempfile::tempdir().unwrap();
        let now = chrono::Utc::now();
        // The only approved window is a year out — a pending future window, so the set is
        // frozen now (it has not run out; it has not yet begun).
        let next_year = now.date_naive() + chrono::Duration::days(365);
        let sets = [calendared_set(vec![full_day(next_year)])];
        let (mut groups, group_labels, node_groups, reports) = two_member_pair();
        let run = |groups: &mut BTreeMap<String, ResolvedGroup>| {
            apply_throttle(
                &sets,
                ThrottleInputs {
                    groups,
                    group_labels: &group_labels,
                    node_groups: &node_groups,
                    reports: &reports,
                },
                dir.path(),
                now,
            )
            .unwrap()
        };

        run(&mut groups); // seed baseline v0
        groups.get_mut("a").unwrap().deployment = deployment("v1", true);
        groups.get_mut("b").unwrap().deployment = deployment("v1", true);
        let statuses = run(&mut groups);

        assert!(statuses[0].frozen, "a window a year out has not opened yet");
        assert_eq!(groups["a"].deployment.deployment, "v0", "held: outside the calendar");
        assert_eq!(groups["b"].deployment.deployment, "v0", "held: outside the calendar");
        assert!(statuses[0].rolling.is_empty());
    }
}
