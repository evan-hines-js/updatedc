//! Pure control-plane reconciliation.
//!
//! This is the only path from desired inventory plus observed telemetry to a publication and a
//! new durable admission state. Kubernetes, object storage, signing, and status writes live in
//! adapters; none of them participate in rollout decisions.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use updated_contracts::telemetry::Envelope;

use crate::rollout::{plan_rollouts, AdmittedDeployment, GroupProgress, RolloutInputs, SetStatus};
use crate::{
    build_publication_plan, resolve_node_groups, DesiredDeployment, PlanError, PublicationPlan,
    ResolvedGroup, ResolvedNode, UpdateGroupSet, UpdateRepositorySpec,
};

pub struct DesiredState<'a> {
    pub repository: &'a UpdateRepositorySpec,
    pub groups: &'a BTreeMap<String, ResolvedGroup>,
    pub group_labels: &'a BTreeMap<String, BTreeMap<String, String>>,
    pub sets: &'a [UpdateGroupSet],
    pub nodes: &'a [ResolvedNode],
    /// Every group quarantined by validation this pass, whether or not it has a durable pin, mapped
    /// to the selector that says which agents are its agents.
    ///
    /// A quarantined group is present-but-frozen, not absent: dependents must not read it as a
    /// missing dependency, which would fail the whole generation closed. A group created with a
    /// typo'd digest was never admitted and so appears here but NOT in `held` — so this, not `held`,
    /// is what decides whether an agent belongs to a quarantined group. An unusable selector is
    /// carried as EMPTY, which selects nothing: the group's membership is genuinely unknown, and
    /// reading an empty selector as "every agent" would withhold the whole fleet over one broken
    /// group.
    pub quarantined: &'a BTreeMap<String, BTreeMap<String, String>>,
    /// Nodes the operator froze (`UpdateAgent.spec.hold`): excluded from admission and always
    /// republished on exactly the body their recorded assignment names — the same carry-forward
    /// arm quarantine-withheld nodes use, failing the generation closed when the body cannot be
    /// resolved, so a hold can never silently become a move.
    pub holds: &'a BTreeSet<String>,
    /// Nodes the operator benched from load-balancer rotation (`UpdateAgent.spec.cordon`):
    /// treated as absent by rollout accounting, still updated, and projected as drained to the
    /// healthproxy by the runtime.
    pub cordons: &'a BTreeSet<String>,
    /// The subset of `quarantined` that has a durable pin, with the deployment each is still
    /// pinned to.
    ///
    /// A quarantined group cannot be planned — its deployment does not parse, or its selector or
    /// `maxUnavailable` is unusable — but the nodes it was published for must not be re-routed
    /// because of it. They keep this exact deployment until the group is fixed, so one typo'd
    /// digest in one `UpdateGroup` neither switches its nodes to the ungated default deployment
    /// nor drops their assignments out of the signed generation.
    pub held: &'a BTreeMap<String, AdmittedDeployment>,
}

pub struct ObservedState<'a> {
    pub reports: &'a HashMap<String, Envelope>,
    pub public_keys: &'a HashMap<String, Vec<u8>>,
    pub admitted: &'a BTreeMap<String, AdmittedDeployment>,
    /// Node → group as of the LAST published generation. Publication replaces the entire target
    /// set, so this is what a node's existing assignment is derived from when its own group cannot
    /// be planned this pass.
    pub routing: &'a BTreeMap<String, String>,
    /// Node → the deployment identity the LAST published generation handed it. Lets a staged
    /// rollout tell an already-advanced node from one that has not moved, without depending on
    /// telemetry that ages out while the node reboots into the update.
    pub assignments: &'a BTreeMap<String, String>,
    pub now: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconcilePlan {
    pub publication: PublicationPlan,
    pub admitted: BTreeMap<String, AdmittedDeployment>,
    /// The routing this generation publishes, to be persisted alongside `admitted`.
    pub routing: BTreeMap<String, String>,
    /// The node → deployment identity this generation publishes, persisted alongside `routing`.
    pub assignments: BTreeMap<String, String>,
    pub set_statuses: Vec<SetStatus>,
    /// Each planned group's verdict for this generation, decided once by the rollout planner. The
    /// group's own Kubernetes status is a projection of this and nothing else — a status path that
    /// re-derived "rolling" and "held" from a deployment-NAME comparison reported a group `Ready`
    /// while a body change to it was still unadmitted.
    pub groups: BTreeMap<String, GroupProgress>,
    /// Per-group node accounting from the planner, for the metrics exposition and the alert
    /// conditions ([`crate::rollout::GroupNodes`]).
    pub node_counts: BTreeMap<String, crate::rollout::GroupNodes>,
    /// Groups bound by the regression verdict, with the halted deployment each is bound by, for
    /// the per-group `DeploymentHalted` condition.
    pub halted_groups: BTreeMap<String, crate::HaltedDeployment>,
    /// Nodes reporting under each report schema, for the metrics exposition
    /// ([`crate::rollout::RolloutPlan::report_schemas`]).
    pub report_schemas: BTreeMap<u32, usize>,
}

pub fn plan_reconcile(
    desired: DesiredState<'_>,
    observed: ObservedState<'_>,
    attempts: &mut crate::evidence::ObservationLog,
) -> Result<ReconcilePlan, PlanError> {
    let quarantined_names: BTreeSet<String> = desired.quarantined.keys().cloned().collect();
    crate::validate_dependency_graph(desired.groups, &quarantined_names)?;
    let node_groups = resolve_node_groups(
        desired.groups.values().cloned(),
        desired.nodes.iter().cloned(),
    )?;
    let mut groups = desired.groups.clone();
    resolve_group_inputs(
        &mut groups,
        &node_groups,
        observed.reports,
        observed.public_keys,
        observed.now.timestamp_millis().max(0) as u64,
    );
    let mut admitted = observed.admitted.clone();
    let mut rollout = plan_rollouts(
        desired.sets,
        RolloutInputs {
            groups: &groups,
            group_labels: desired.group_labels,
            node_groups: &node_groups,
            reports: observed.reports,
            public_keys: observed.public_keys,
            published: observed.assignments,
            held: desired.held,
            holds: desired.holds,
            cordons: desired.cordons,
        },
        &mut admitted,
        attempts,
        observed.now,
    );

    // Nodes that match no `UpdateGroup` route to the pseudo-group "default" and receive the
    // repository's `default_deployment` directly. This cohort is DELIBERATELY NOT throttled: it has
    // no `UpdateGroup`/`UpdateGroupSet` to carry a `maxUnavailable` or health gate, so there is no
    // staged rollout to apply — changing `default_deployment` moves every unmatched node at once.
    // The safety guarantees (one-at-a-time staging, health/telemetry gating, concurrency caps) are a
    // property of *grouped* rollouts; a node that needs them must be placed in a group. Treat
    // `default_deployment` as a fleet-wide switch, not a throttled rollout.
    // `DEFAULT_GROUP` is a reserved name (`resolve_node_groups` refuses a real group that claims
    // it), so a node routed to it is unambiguously a node that matched nothing.
    let default = DesiredDeployment::try_from(desired.repository.default_deployment.clone())
        .map_err(PlanError::InvalidDeployment)?;
    // A node whose labels select a QUARANTINED group is not an unmatched node. Its group is merely
    // absent from the plan this pass, so `resolve_node_groups` had nothing to match it against and
    // resolved it to `default`. Handing it `default_deployment` is the fleet-wide, unthrottled,
    // ungated deployment swap quarantine exists to prevent — a different application, install root,
    // and provider set — and the carry-forward below cannot rescue an agent that was enrolled while
    // the group was broken, because it has no previous routing to carry. It is withheld here
    // instead: an agent with routing keeps it, one without is left out of the generation entirely
    // (nothing of it is published, so there is nothing to lose) until the group is fixed.
    //
    // Membership is decided from `quarantined`, the FULL set, not from `held`, the subset with a
    // durable pin. A group quarantined before it was ever admitted — a typo'd digest on a group
    // added or renamed in the same commit, a bad `maxUnavailable`, the reserved name `default` —
    // has no pin, so keying on `held` matched none of its agents and handed the already-published
    // ones the ungated `default_deployment` in a single signed generation.
    let quarantined: BTreeMap<&String, &String> = desired
        .nodes
        .iter()
        .filter(|node| {
            node_groups
                .get(&node.name)
                .is_some_and(|selected| selected == crate::DEFAULT_GROUP)
        })
        .filter_map(|node| {
            desired
                .quarantined
                .iter()
                .find(|(_, selector)| {
                    !selector.is_empty() && crate::selector_matches(selector, &node.labels)
                })
                .map(|(name, _)| (&node.name, name))
        })
        .collect();
    for (node, selected) in &node_groups {
        // A HELD unmatched node is not handed the current default: hold means "exactly the body
        // your recorded assignment names", and the current `default_deployment` may have moved
        // since. It takes the carry-forward below instead, which republishes the recorded body by
        // identity and faults the generation closed if that body is gone.
        if selected == crate::DEFAULT_GROUP
            && !quarantined.contains_key(node)
            && !desired.holds.contains(node)
        {
            rollout
                .node_deployments
                .insert(node.clone(), default.clone());
        }
    }
    for (node, group) in &quarantined {
        tracing::info!(
            node,
            group,
            "agent selects a quarantined group; withholding the repository default deployment so \
             one broken group is never an ungated deployment swap"
        );
    }

    // A quarantined group is absent from the plan, so `plan_rollouts` pruned its admitted entry and
    // its nodes resolved to `default`. Restore both: the pin stays durable, and every node the
    // group was published for is republished under it, unchanged.
    //
    // The reserved key is NOT restorable. An `UpdateGroup` literally named `default` is quarantined
    // on sight and therefore never admitted, so it has no pin of its own — the only thing keyed
    // `default` in the durable map is the lineage recorded below, and restoring that here put the
    // PRE-compaction copy back over the one `retire_deleted_groups` had just compacted, every
    // pass. `previous` then grew one whole deployment body per `default_deployment` edit, with
    // nothing able to prune it, until the admitted-state ConfigMap outgrew the apiserver's object
    // limit and no generation could publish again. This is the guard that makes "no real group may
    // claim it" below true of every path, not just of `resolve_node_groups`.
    for (name, state) in desired.held {
        if name == crate::DEFAULT_GROUP {
            continue;
        }
        admitted.insert(name.clone(), state.clone());
    }

    // The repository default is a deployment nodes RUN, so its bodies are retained exactly like a
    // group's: recorded in the admitted map under the reserved pseudo-group name (no real group
    // may claim it), where the planner's `retire_deleted_groups` already keeps each superseded
    // body for as long as some node is placed on it. Without this, a node frozen on the OLD
    // default — held, or withheld behind a quarantined group — had no recoverable placement the
    // moment the operator edited `default_deployment`, and the generation faulted closed
    // fleet-wide with nothing able to clear it.
    if let Some(identity) = crate::deployment_identity(&default) {
        match admitted.entry(crate::DEFAULT_GROUP.to_string()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(AdmittedDeployment {
                    current: default.clone(),
                    previous: Vec::new(),
                });
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let state = entry.get_mut();
                if crate::deployment_identity(&state.current).as_ref() != Some(&identity) {
                    let superseded = std::mem::replace(&mut state.current, default.clone());
                    if !state.previous.contains(&superseded) {
                        state.previous.insert(0, superseded);
                    }
                }
            }
        }
    }

    // Every deployment body the control plane still has, by identity — quarantined pins, the
    // retained bodies of deleted groups, and the default lineage included, because all were
    // restored or recorded just above. Built by the one function `assign_nodes` builds its index
    // with, so "where is this node?" is answered identically here and there.
    let bodies = crate::rollout::bodies_by_identity(admitted.values());

    // A node whose group has not been admitted even once has no deployment of its own to publish.
    // It must NOT simply be left out: publication replaces the whole target set, so omitting a node
    // deletes its `agents/<node>.json` and strands it with no routing at all. Instead it is
    // republished under the group it was last routed to — for most nodes that is the pseudo-group
    // `default`, which is exactly what they ran before this group existed. Only a node that has
    // never been published anywhere is left out, and there is nothing there to lose.
    let mut published_nodes = BTreeMap::new();
    for (node, group) in &node_groups {
        // Carry the node's last routing forward only when the group it selects NOW cannot be
        // planned: either that group produced no deployment at all this pass (never admitted —
        // waiting on inputs or prerequisites), or the node fell through to `default` because its
        // group is quarantined and absent from the plan.
        //
        // The quarantine arm must key on where the node resolves NOW, not on where it was last
        // published. Keying on the last group pinned a node that had since been RELABELLED into a
        // healthy group back onto the quarantined group's deployment — and republished it under
        // that group, so the durable routing kept saying so and the node could never be moved
        // until the broken group was fixed. Relabelling is the ordinary remediation for a
        // quarantined group; it must work.
        //
        // A node still selected by a quarantined group with a REAL selector is not in
        // `rollout.node_deployments` at all (it was withheld above), so clause 1 already carries
        // it. The second clause exists only for the group quarantined for an EMPTY selector, which
        // no node can be matched against: its nodes fell to `default` and were handed the
        // repository default, so nothing but their last routing says they belong to it. Testing
        // membership by the last routing alone also caught the node whose `role=edge` label was
        // REMOVED — the label-removal form of the same remediation — and pinned it to the broken
        // group forever, since republishing it there kept the durable routing saying so.
        let last = observed.routing.get(node).filter(|last| {
            !rollout.node_deployments.contains_key(node)
                || (group == crate::DEFAULT_GROUP
                    && desired
                        .quarantined
                        .get(*last)
                        .is_some_and(|selector| selector.is_empty()))
        });
        let carried = match last {
            // A WITHHELD node stays withheld, whatever it was last routed to. It is republished
            // with the exact body the last generation recorded for it, looked up by identity —
            // never the current `default_deployment`. Reaching for the current default here undid
            // the withholding above for every node that happened to be on `default`: a group
            // quarantined before it was ever admitted (typo'd digest, bad `maxUnavailable`,
            // reserved name) moved its machines to a different application and install root in one
            // signed, unstaged, ungated generation — precisely because the group was broken. The
            // index carries the repository default, so the ordinary case (a default unchanged
            // since the node was published) carries forward unchanged; a default that HAS changed
            // is not reconstructible from the recorded identity, so the generation faults closed
            // and the last publication stays live rather than the node being swapped or dropped.
            // A HELD node takes this arm whatever group it was last routed to — `default`
            // included: hold freezes the node on the exact recorded body, and the ordinary
            // `default` arm below would hand it the CURRENT default instead. An ordinary node
            // last routed to `default` must NOT take it merely because the default lineage is
            // recorded in `admitted` under the reserved name: unheld and unquarantined, it keeps
            // following the repository default — the fleet-wide switch — via the arm below.
            Some(last)
                if quarantined.contains_key(node)
                    || desired.holds.contains(node)
                    || (last != crate::DEFAULT_GROUP && admitted.contains_key(last)) =>
            {
                let deployment = placed_deployment(observed.assignments.get(node), &bodies)
                    .ok_or_else(|| PlanError::UnknownPlacement {
                        node: node.clone(),
                        group: last.clone(),
                    })?;
                Some((last.clone(), deployment))
            }
            // A node whose group is merely waiting on its first admission, last routed to the
            // pseudo-group `default`, is withheld by nothing: it has no group deployment of its
            // own and no gate to freeze, so it keeps following the repository default — the
            // fleet-wide switch — exactly as it did before its group existed.
            Some(last) if last == crate::DEFAULT_GROUP => Some((last.clone(), default.clone())),
            _ => None,
        };
        match carried {
            Some((last, deployment)) => {
                if &last != group {
                    tracing::info!(
                        node,
                        group,
                        held = last,
                        "group cannot be planned this generation (quarantined, or waiting on \
                         inputs or prerequisites); republishing the node's last routing unchanged"
                    );
                }
                rollout.node_deployments.insert(node.clone(), deployment);
                published_nodes.insert(node.clone(), last);
            }
            None if rollout.node_deployments.contains_key(node) => {
                published_nodes.insert(node.clone(), group.clone());
            }
            None => tracing::info!(
                node,
                group,
                "group has not been admitted yet and the node has never been published; it is \
                 left out of this generation"
            ),
        }
    }

    // Nothing below this line may drop a node that already has published routing. A generation is
    // signed and replaces every target, so a bug that silently shrinks the plan does not degrade
    // one group — it deletes assignments fleet-wide. Fail the whole generation closed instead and
    // leave the last publication live, the same way an ambiguous node does.
    let dropped: Vec<String> = observed
        .routing
        .keys()
        .filter(|node| node_groups.contains_key(*node) && !published_nodes.contains_key(*node))
        .cloned()
        .collect();
    if !dropped.is_empty() {
        return Err(PlanError::RoutingLoss(dropped));
    }

    let publication = build_publication_plan(
        desired.repository,
        published_nodes,
        rollout.node_deployments,
    )?;
    let routing = publication.node_groups.clone();
    let assignments = publication.node_assignments.clone();
    Ok(ReconcilePlan {
        publication,
        admitted,
        routing,
        assignments,
        set_statuses: rollout.sets,
        groups: rollout.groups,
        node_counts: rollout.node_counts,
        halted_groups: rollout.halted_groups,
        report_schemas: rollout.report_schemas,
    })
}

/// The deployment a carried-forward node is ACTUALLY placed on, among the ones its group is still
/// pinned to.
///
/// Carrying a node forward must be a no-op for the machine, so it republishes what the last signed
/// generation handed THAT node — not the group's `current`. Republishing `current` moved every node
/// of a quarantined group that was mid-rollout onto the half-delivered target in a single
/// generation, with no `maxUnavailable` staging and no health gate, because a quarantined group is
/// never planned and so `assign_nodes` never runs for it. Quarantine must freeze a rollout where it
/// stands, not finish it.
///
/// The node's recorded assignment is looked up in the FLEET-WIDE body index, not only among the
/// deployments this group is pinned to. A node relabelled into a group is deliberately held on its
/// old group's deployment while it waits for a `maxUnavailable` slot (that is what `assign_nodes`'
/// `running` map is for), so searching this group alone made the ordinary staged case the
/// unrecognized one: quarantining the group then moved every one of those nodes onto its `current`
/// in a single generation, ungated — precisely what freezing a quarantined rollout prevents.
///
/// `None` when the node has no recorded assignment, or when its recorded identity is nowhere in the
/// index — the caller faults the generation rather than guessing. Guessing meant `current`, which
/// republished every node of a quarantined mid-rollout group onto the in-flight target at once: the
/// unstaged, ungated move this function exists to prevent, taken precisely when the control plane
/// has lost track of where the fleet is.
fn placed_deployment(
    assigned: Option<&String>,
    bodies: &HashMap<String, &DesiredDeployment>,
) -> Option<DesiredDeployment> {
    bodies
        .get(assigned?)
        .map(|deployment| (*deployment).clone())
}

fn resolve_group_inputs(
    groups: &mut BTreeMap<String, ResolvedGroup>,
    node_groups: &BTreeMap<String, String>,
    reports: &HashMap<String, Envelope>,
    public_keys: &HashMap<String, Vec<u8>>,
    now_ms: u64,
) {
    // Resolve in dependency order, and read producers from the map being BUILT rather than from a
    // snapshot taken before any resolution. A producer that consumes inputs of its own has its
    // `runtime.inputs` filled in during this pass, which changes the configuration digest it is
    // published under — so comparing a report against the pre-resolution copy would never match,
    // and any chain longer than two groups (A → B → C) could never satisfy its consumer.
    let mut resolved: BTreeMap<String, ResolvedGroup> = BTreeMap::new();
    for name in dependency_order(groups) {
        let mut group = groups[&name].clone();
        resolve_one(
            &mut group,
            &resolved,
            node_groups,
            reports,
            public_keys,
            now_ms,
        );
        resolved.insert(name, group);
    }
    *groups = resolved;
}

/// Group names ordered so every group follows the ones it depends on. The graph is already
/// validated acyclic by `validate_dependency_graph`; a name whose dependencies are missing simply
/// comes last, and its unresolved inputs keep it un-admitted.
fn dependency_order(groups: &BTreeMap<String, ResolvedGroup>) -> Vec<String> {
    let mut ordered: Vec<String> = Vec::with_capacity(groups.len());
    let mut placed: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    // Bounded by the group count: each pass places at least one group unless none can be placed.
    for _ in 0..groups.len() {
        for (name, group) in groups {
            if placed.contains(name) {
                continue;
            }
            if group
                .depends_on
                .iter()
                .all(|dependency| placed.contains(dependency) || !groups.contains_key(dependency))
            {
                ordered.push(name.clone());
                placed.insert(name.clone());
            }
        }
    }
    for name in groups.keys() {
        if !placed.contains(name) {
            ordered.push(name.clone());
        }
    }
    ordered
}

fn resolve_one(
    group: &mut ResolvedGroup,
    resolved: &BTreeMap<String, ResolvedGroup>,
    node_groups: &BTreeMap<String, String>,
    reports: &HashMap<String, Envelope>,
    public_keys: &HashMap<String, Vec<u8>>,
    now_ms: u64,
) {
    if group.inputs.is_empty() {
        group.inputs_ready = true;
        return;
    }
    let mut values = BTreeMap::new();
    let ready = group.inputs.iter().all(|(input, reference)| {
        let producers: Vec<&String> = node_groups
            .iter()
            .filter_map(|(node, selected)| (selected == &reference.group).then_some(node))
            .collect();
        let [node] = producers.as_slice() else {
            return false;
        };
        let (Some(envelope), Some(key)) = (reports.get(*node), public_keys.get(*node)) else {
            return false;
        };
        let Some(report) = updated_contracts::telemetry::report_is_authentic_and_fresh(
            envelope, node, key, now_ms,
        ) else {
            return false;
        };
        // The producer must be healthy on the EXACT configuration desired for it, not merely
        // on something sharing its deployment name: an output read off an older revision of
        // that deployment would be wired into the consumer as if it were current.
        // The producer as RESOLVED this pass — inputs of its own already filled in.
        let Some(producer) = resolved.get(&reference.group) else {
            return false;
        };
        let identity = crate::deployment_identity(&producer.deployment);
        // And it must be RUNNING what that configuration installs. The supervisor stamps the
        // assignment it RESOLVED, so a producer that fetched the new assignment and installed
        // nothing — or attempted it and rolled itself back — reports healthy on the new identity
        // while executing the predecessor's bytes, and its outputs are read off the predecessor's
        // manifest. Wiring those into the consumer publishes the old release's endpoints under
        // the new deployment, with the control plane believing the producer moved.
        if !report.healthy
            || Some(&report.assignment_sha256) != identity.as_ref()
            || report.archive_sha256 != producer.deployment.application.sha256
        {
            return false;
        }
        let Some(value) = report
            .outputs
            .as_ref()
            .and_then(|outputs| outputs.values.get(&reference.output))
        else {
            return false;
        };
        values.insert(input.clone(), value.clone());
        true
    });
    group.inputs_ready = ready;
    if ready {
        group.deployment.runtime.inputs = values;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use updated_contracts::artifact::TargetReference;
    use updated_contracts::telemetry::{NodeReport, OutputManifest, OutputValue};

    const DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn deployment(name: &str) -> DesiredDeployment {
        DesiredDeployment {
            schema: DesiredDeployment::SCHEMA,
            deployment: name.into(),
            metadata_url: "https://cdn/metadata/".into(),
            targets_url: "https://cdn/targets/".into(),
            report_url: Some("https://control".into()),
            application: TargetReference {
                path: "app".into(),
                sha256: DIGEST.into(),
            },
            ordered_install_fallback: false,
            provider_set: TargetReference {
                path: "providers".into(),
                sha256: DIGEST.into(),
            },
            release_root: serde_json::json!({}),
            runtime: crate::tests::managed_runtime(),
        }
    }

    #[test]
    fn authentic_single_producer_outputs_become_typed_consumer_inputs() {
        let key_pem = updated::csr::generate_key().unwrap();
        let private = updated::csr::key_pem_to_pkcs8_der(&key_pem).unwrap();
        let public =
            crate::join::csr_public_key(&updated::csr::csr_for(&key_pem, "producer").unwrap())
                .unwrap();
        let now_ms = updated_contracts::telemetry::now_ms();
        let identity = crate::deployment_identity(&deployment("init-v1")).unwrap();
        let mut report = NodeReport::new("producer", "init-v1", identity, "1.0.0", DIGEST, true);
        report.reported_at_ms = now_ms;
        report.outputs = Some(OutputManifest {
            schema: OutputManifest::SCHEMA,
            values: BTreeMap::from([(
                "endpoint".into(),
                OutputValue::String {
                    value: "https://vault-0:8200".into(),
                },
            )]),
        });
        let reports = HashMap::from([(
            "producer".into(),
            updated_contracts::telemetry::sign_report(&report, &private).unwrap(),
        )]);
        let keys = HashMap::from([("producer".into(), public)]);
        let nodes = BTreeMap::from([
            ("producer".into(), "initialize".into()),
            ("consumer".into(), "join".into()),
        ]);
        let mut groups = BTreeMap::from([
            (
                "initialize".into(),
                ResolvedGroup {
                    name: "initialize".into(),
                    match_labels: BTreeMap::new(),
                    depends_on: vec![],
                    inputs: BTreeMap::new(),
                    inputs_ready: true,
                    deployment: deployment("init-v1"),
                    max_unavailable: 1,
                    emergency_correction: false,
                },
            ),
            (
                "join".into(),
                ResolvedGroup {
                    name: "join".into(),
                    match_labels: BTreeMap::new(),
                    depends_on: vec!["initialize".into()],
                    inputs: BTreeMap::from([(
                        "leader".into(),
                        crate::GroupOutputReference {
                            group: "initialize".into(),
                            output: "endpoint".into(),
                        },
                    )]),
                    inputs_ready: false,
                    deployment: deployment("join-v1"),
                    max_unavailable: 1,
                    emergency_correction: false,
                },
            ),
        ]);

        resolve_group_inputs(&mut groups, &nodes, &reports, &keys, now_ms);
        assert!(groups["join"].inputs_ready);
        assert_eq!(
            groups["join"].deployment.runtime.inputs["leader"],
            OutputValue::String {
                value: "https://vault-0:8200".into()
            }
        );

        // The same producer, on the same assignment, healthy — but EXECUTING the predecessor's
        // archive: it fetched the assignment and installed nothing, or attempted it and rolled
        // itself back. Its outputs are read off the predecessor's manifest, so wiring them in
        // would publish the old release's values under the new deployment while the control plane
        // believed the producer had moved.
        let predecessor = "b".repeat(64);
        let mut stale = report.clone();
        stale.archive_sha256 = predecessor;
        stale.outputs = report.outputs.clone();
        let stale_reports = HashMap::from([(
            "producer".into(),
            updated_contracts::telemetry::sign_report(&stale, &private).unwrap(),
        )]);
        let mut groups = BTreeMap::from([
            ("initialize".into(), groups["initialize"].clone()),
            (
                "join".into(),
                ResolvedGroup {
                    inputs_ready: false,
                    deployment: deployment("join-v1"),
                    ..groups["join"].clone()
                },
            ),
        ]);
        resolve_group_inputs(&mut groups, &nodes, &stale_reports, &keys, now_ms);
        assert!(
            !groups["join"].inputs_ready,
            "a producer that has not installed what its configuration names resolves nothing"
        );
        assert!(groups["join"].deployment.runtime.inputs.is_empty());
    }

    fn repository() -> UpdateRepositorySpec {
        UpdateRepositorySpec {
            default_deployment: crate::DeploymentSpec {
                name: "default".into(),
                report_url: "https://control".into(),
                release_repository: crate::ReleaseRepositorySpec {
                    metadata_url: "https://cdn/metadata/".into(),
                    targets_url: "https://cdn/targets/".into(),
                    root_json: "{}".into(),
                },
                application: crate::TargetSpec {
                    path: "app".into(),
                    sha256: DIGEST.into(),
                },
                ordered_install_fallback: false,
                provider_set: crate::TargetSpec {
                    path: "providers".into(),
                    sha256: DIGEST.into(),
                },
                runtime: crate::tests::runtime_spec(),
            },
            signing_secret_ref: crate::LocalSecretReference {
                name: "tuf-signing-keys".into(),
            },
            enrollment: crate::EnrollmentSpec {
                labels: BTreeMap::new(),
            },
            s3: crate::S3Destination {
                bucket: "updates".into(),
                prefix: "routing".into(),
                region: "us-east-1".into(),
                credentials_secret_ref: None,
                endpoint: None,
            },
            assignment_prefix: "assignments".into(),
        }
    }

    fn edge_node() -> Vec<ResolvedNode> {
        vec![ResolvedNode {
            name: "n1".into(),
            labels: BTreeMap::from([("role".to_string(), "edge".to_string())]),
        }]
    }

    /// The quarantined-group map the runtime builds: each group's name mapped to the selector that
    /// says which agents are its agents, whether or not it has a durable pin.
    fn quarantined(groups: &[(&str, &str)]) -> BTreeMap<String, BTreeMap<String, String>> {
        groups
            .iter()
            .map(|(name, role)| {
                (
                    (*name).to_string(),
                    BTreeMap::from([("role".to_string(), (*role).to_string())]),
                )
            })
            .collect()
    }

    fn plan(
        groups: &BTreeMap<String, ResolvedGroup>,
        quarantined: &BTreeMap<String, BTreeMap<String, String>>,
        held: &BTreeMap<String, AdmittedDeployment>,
        admitted: &BTreeMap<String, AdmittedDeployment>,
        routing: &BTreeMap<String, String>,
        assignments: &BTreeMap<String, String>,
    ) -> Result<crate::domain::ReconcilePlan, PlanError> {
        let repository = repository();
        let nodes = edge_node();
        plan_reconcile(
            DesiredState {
                repository: &repository,
                groups,
                group_labels: &BTreeMap::new(),
                sets: &[],
                nodes: &nodes,
                quarantined,
                held,
                holds: &BTreeSet::new(),
                cordons: &BTreeSet::new(),
            },
            ObservedState {
                reports: &HashMap::new(),
                public_keys: &HashMap::new(),
                admitted,
                routing,
                assignments,
                now: chrono::Utc::now(),
            },
            &mut crate::evidence::ObservationLog::default(),
        )
    }

    fn resolved(name: &str, role: &str, depends_on: Vec<String>) -> ResolvedGroup {
        ResolvedGroup {
            name: name.into(),
            match_labels: BTreeMap::from([("role".to_string(), role.to_string())]),
            depends_on,
            inputs: BTreeMap::new(),
            inputs_ready: true,
            deployment: deployment(&format!("{name}-v1")),
            max_unavailable: 1,
            emergency_correction: false,
        }
    }

    /// An `edge` group selecting the test node but gated behind a prerequisite that can never
    /// settle (nothing runs it), so `edge` is never admitted and produces no deployment.
    fn unadmitted_edge_group() -> BTreeMap<String, ResolvedGroup> {
        BTreeMap::from([
            (
                "edge".to_string(),
                resolved("edge", "edge", vec!["prerequisite".into()]),
            ),
            (
                "prerequisite".to_string(),
                resolved("prerequisite", "prerequisite", vec![]),
            ),
        ])
    }

    #[test]
    fn a_quarantined_groups_nodes_keep_their_published_deployment() {
        // One typo'd digest quarantines `edge`. Its nodes must neither be switched to the ungated
        // default deployment nor dropped from the generation — publication replaces every target,
        // so dropping them deletes their assignments outright.
        let pinned = AdmittedDeployment {
            current: deployment("edge-v1"),
            previous: Vec::new(),
        };
        let held = BTreeMap::from([("edge".to_string(), pinned.clone())]);
        let admitted = BTreeMap::from([("edge".to_string(), pinned)]);
        let routing = BTreeMap::from([("n1".to_string(), "edge".to_string())]);

        // The quarantined group is absent from the planned groups entirely.
        let assignments = BTreeMap::from([(
            "n1".to_string(),
            crate::deployment_identity(&deployment("edge-v1")).unwrap(),
        )]);
        let planned = plan(
            &BTreeMap::new(),
            &quarantined(&[("edge", "edge")]),
            &held,
            &admitted,
            &routing,
            &assignments,
        )
        .expect("a quarantined group is survivable");
        assert_eq!(planned.publication.node_groups["n1"], "edge");
        assert!(
            planned
                .publication
                .targets
                .iter()
                .any(|target| target.path == "assignments/agents/n1.json"),
            "the node's assignment must still be published"
        );
        assert_eq!(planned.routing["n1"], "edge");
        assert!(
            planned.admitted.contains_key("edge"),
            "the quarantined group stays pinned; its admitted entry is not collected"
        );
    }

    /// Quarantine must FREEZE a half-finished rollout, not complete it. `edge` was mid-rollout from
    /// edge-v1 to edge-v2 with only n1 handed the target when the operator's next edit quarantined
    /// it. Carrying every one of its nodes forward on the group's `current` moved n2 and n3 onto
    /// edge-v2 in a single signed generation — no `maxUnavailable`, no health gate — because a
    /// quarantined group is never planned, so `assign_nodes` never runs for it.
    #[test]
    fn quarantining_a_mid_rollout_group_freezes_each_node_where_it_is() {
        let pinned = AdmittedDeployment {
            current: deployment("edge-v2"),
            previous: vec![deployment("edge-v1")],
        };
        let held = BTreeMap::from([("edge".to_string(), pinned.clone())]);
        let admitted = BTreeMap::from([("edge".to_string(), pinned)]);
        let nodes: Vec<ResolvedNode> = ["n1", "n2", "n3"]
            .iter()
            .map(|name| ResolvedNode {
                name: (*name).into(),
                labels: BTreeMap::from([("role".to_string(), "edge".to_string())]),
            })
            .collect();
        let routing = nodes
            .iter()
            .map(|node| (node.name.clone(), "edge".to_string()))
            .collect();
        let v1 = crate::deployment_identity(&deployment("edge-v1")).unwrap();
        let v2 = crate::deployment_identity(&deployment("edge-v2")).unwrap();
        // Only n1 was handed the target before the group was quarantined.
        let assignments = BTreeMap::from([
            ("n1".to_string(), v2.clone()),
            ("n2".to_string(), v1.clone()),
            ("n3".to_string(), v1.clone()),
        ]);
        let repository = repository();

        let quarantined = quarantined(&[("edge", "edge")]);
        let planned = plan_reconcile(
            DesiredState {
                repository: &repository,
                groups: &BTreeMap::new(),
                group_labels: &BTreeMap::new(),
                sets: &[],
                nodes: &nodes,
                quarantined: &quarantined,
                held: &held,
                holds: &BTreeSet::new(),
                cordons: &BTreeSet::new(),
            },
            ObservedState {
                reports: &HashMap::new(),
                public_keys: &HashMap::new(),
                admitted: &admitted,
                routing: &routing,
                assignments: &assignments,
                now: chrono::Utc::now(),
            },
            &mut crate::evidence::ObservationLog::default(),
        )
        .expect("a quarantined group is survivable");

        assert_eq!(planned.assignments["n1"], v2, "n1 stays on the target");
        assert_eq!(
            planned.assignments["n2"], v1,
            "a node that had not advanced is republished on exactly what it is running"
        );
        assert_eq!(planned.assignments["n3"], v1);
        for node in ["n1", "n2", "n3"] {
            assert_eq!(planned.publication.node_groups[node], "edge");
        }
    }

    /// Relabelling a node out of a quarantined group is the ordinary remediation for a broken
    /// group, and it must take effect. Keying the carry-forward on the node's LAST published group
    /// instead of the group it selects now pinned the node to the quarantined group's deployment
    /// and republished it under that group, so the durable routing kept saying so on every
    /// subsequent pass — only fixing or deleting the broken group could ever release it.
    #[test]
    fn a_node_relabelled_out_of_a_quarantined_group_moves_to_its_new_group() {
        let pinned = AdmittedDeployment {
            current: deployment("edge-v1"),
            previous: Vec::new(),
        };
        // `edge` is quarantined (absent from the planned groups, present in `held`); the node now
        // carries `role: core` and selects the healthy, fully-admitted `core`.
        let held = BTreeMap::from([("edge".to_string(), pinned)]);
        let groups = BTreeMap::from([("core".to_string(), resolved("core", "edge", vec![]))]);
        let admitted = BTreeMap::from([(
            "core".to_string(),
            AdmittedDeployment {
                current: deployment("core-v1"),
                previous: Vec::new(),
            },
        )]);
        let routing = BTreeMap::from([("n1".to_string(), "edge".to_string())]);

        let planned = plan(
            &groups,
            &quarantined(&[("edge", "edge")]),
            &held,
            &admitted,
            &routing,
            &BTreeMap::new(),
        )
        .expect("the relabel is plannable");
        assert_eq!(planned.publication.node_groups["n1"], "core");
        assert_eq!(planned.routing["n1"], "core");
    }

    /// The label-REMOVAL form of the same remediation: the operator strips `role=edge` off the
    /// node instead of relabelling it into another group, so it selects nothing and falls to
    /// `default`. Carrying it forward on the LAST routing alone republished it under the broken
    /// group, which rewrote the durable routing to say `edge` again — a pin only fixing or
    /// deleting the group could release. It takes the ungated repository default, like any other
    /// node that matches nothing.
    #[test]
    fn a_node_whose_group_label_was_removed_falls_to_the_repository_default() {
        let pinned = AdmittedDeployment {
            current: deployment("edge-v1"),
            previous: Vec::new(),
        };
        let held = BTreeMap::from([("edge".to_string(), pinned.clone())]);
        let admitted = BTreeMap::from([("edge".to_string(), pinned)]);
        let routing = BTreeMap::from([("n1".to_string(), "edge".to_string())]);
        let assignments = BTreeMap::from([(
            "n1".to_string(),
            crate::deployment_identity(&deployment("edge-v1")).unwrap(),
        )]);
        // The node carries no labels at all now, so `edge`'s real selector no longer matches it.
        let nodes = vec![ResolvedNode {
            name: "n1".into(),
            labels: BTreeMap::new(),
        }];
        let repository = repository();
        let planned = plan_reconcile(
            DesiredState {
                repository: &repository,
                groups: &BTreeMap::new(),
                group_labels: &BTreeMap::new(),
                sets: &[],
                nodes: &nodes,
                quarantined: &quarantined(&[("edge", "edge")]),
                held: &held,
                holds: &BTreeSet::new(),
                cordons: &BTreeSet::new(),
            },
            ObservedState {
                reports: &HashMap::new(),
                public_keys: &HashMap::new(),
                admitted: &admitted,
                routing: &routing,
                assignments: &assignments,
                now: chrono::Utc::now(),
            },
            &mut crate::evidence::ObservationLog::default(),
        )
        .expect("removing the label is plannable");
        assert_eq!(planned.publication.node_groups["n1"], crate::DEFAULT_GROUP);
        assert_eq!(planned.routing["n1"], crate::DEFAULT_GROUP);
    }

    /// The case the carry-forward's quarantine arm exists for: a group quarantined for an EMPTY
    /// selector matches no agent, so its nodes resolve to `default` and are handed the repository
    /// default like any unmatched node. Only their last routing says they belong to it, so that is
    /// what has to hold them on the group's pinned deployment.
    #[test]
    fn a_node_of_a_group_quarantined_for_an_empty_selector_keeps_its_pinned_deployment() {
        let pinned = AdmittedDeployment {
            current: deployment("edge-v1"),
            previous: Vec::new(),
        };
        let held = BTreeMap::from([("edge".to_string(), pinned.clone())]);
        let admitted = BTreeMap::from([("edge".to_string(), pinned)]);
        let routing = BTreeMap::from([("n1".to_string(), "edge".to_string())]);
        let assignments = BTreeMap::from([(
            "n1".to_string(),
            crate::deployment_identity(&deployment("edge-v1")).unwrap(),
        )]);
        let quarantined = BTreeMap::from([("edge".to_string(), BTreeMap::new())]);
        let planned = plan(
            &BTreeMap::new(),
            &quarantined,
            &held,
            &admitted,
            &routing,
            &assignments,
        )
        .expect("an empty-selector quarantine is survivable");
        assert_eq!(planned.publication.node_groups["n1"], "edge");
        assert_eq!(planned.routing["n1"], "edge");
    }

    /// A group quarantined before it was ever admitted — a typo'd digest, a bad `maxUnavailable`,
    /// the reserved name — has no pin, and its machines may still be on the pseudo-group
    /// `default`. Withholding them from the ungated default swap and then handing them the CURRENT
    /// `default_deployment` from the carry-forward is the same swap by another door: a different
    /// application and install root, fleet-wide, in one signed generation, taken precisely because
    /// the group is broken. Withheld means withheld: republish the body they are recorded on, or
    /// fault the generation and leave the last publication live.
    #[test]
    fn a_withheld_node_last_routed_to_default_never_takes_the_current_default() {
        let default = DesiredDeployment::try_from(repository().default_deployment).unwrap();
        let routing = BTreeMap::from([("n1".to_string(), crate::DEFAULT_GROUP.to_string())]);
        // The node is recorded on the default body the last generation published, and `edge` is
        // quarantined with no pin at all (`held`/`admitted` empty). It is republished on exactly
        // that body, unchanged.
        let assignments = BTreeMap::from([(
            "n1".to_string(),
            crate::deployment_identity(&default).unwrap(),
        )]);
        let planned = plan(
            &BTreeMap::new(),
            &quarantined(&[("edge", "edge")]),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &routing,
            &assignments,
        )
        .expect("a quarantine over unchanged default routing is survivable");
        assert_eq!(planned.publication.node_groups["n1"], crate::DEFAULT_GROUP);
        assert_eq!(
            planned.publication.node_assignments["n1"],
            crate::deployment_identity(&default).unwrap(),
            "the withheld node keeps the body it was published with"
        );

        // Now the operator also edits `default_deployment`, so the node's recorded body is one the
        // control plane no longer has. The generation faults closed — the node is neither swapped
        // onto the new default nor dropped from the plan.
        let stale = BTreeMap::from([(
            "n1".to_string(),
            crate::deployment_identity(&deployment("previous-default")).unwrap(),
        )]);
        let error = plan(
            &BTreeMap::new(),
            &quarantined(&[("edge", "edge")]),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &routing,
            &stale,
        )
        .expect_err("a withheld node whose body is gone must not be swapped onto the new default");
        assert!(
            matches!(error, PlanError::UnknownPlacement { ref node, .. } if node == "n1"),
            "unexpected error: {error:?}"
        );
    }

    /// A node relabelled INTO a group is deliberately held on its OLD group's deployment while it
    /// waits for a `maxUnavailable` slot. That deployment is in neither the new group's `current`
    /// nor its `previous`, so searching this group's own pins alone made the ordinary staged case
    /// the unrecognized one: quarantining the group then handed every one of those nodes its
    /// `current` in a single signed generation, ungated — the exact outcome freezing a quarantined
    /// rollout exists to prevent. The node's placement is answered from the FLEET-WIDE body index.
    #[test]
    fn quarantine_never_moves_a_node_held_on_another_groups_deployment() {
        let pinned = AdmittedDeployment {
            current: deployment("edge-v1"),
            previous: Vec::new(),
        };
        let held = BTreeMap::from([("edge".to_string(), pinned.clone())]);
        // `core` still exists and is admitted, so the body these nodes are actually on is one the
        // control plane still has.
        let admitted = BTreeMap::from([
            ("edge".to_string(), pinned),
            (
                "core".to_string(),
                AdmittedDeployment {
                    current: deployment("core-v1"),
                    previous: Vec::new(),
                },
            ),
        ]);
        let nodes: Vec<ResolvedNode> = ["n1", "n2", "n3"]
            .iter()
            .map(|name| ResolvedNode {
                name: (*name).into(),
                labels: BTreeMap::from([("role".to_string(), "edge".to_string())]),
            })
            .collect();
        let routing: BTreeMap<String, String> = nodes
            .iter()
            .map(|node| (node.name.clone(), "edge".to_string()))
            .collect();
        let core_v1 = crate::deployment_identity(&deployment("core-v1")).unwrap();
        let assignments: BTreeMap<String, String> = nodes
            .iter()
            .map(|node| (node.name.clone(), core_v1.clone()))
            .collect();
        let repository = repository();

        let quarantined = quarantined(&[("edge", "edge")]);
        let planned = plan_reconcile(
            DesiredState {
                repository: &repository,
                groups: &BTreeMap::new(),
                group_labels: &BTreeMap::new(),
                sets: &[],
                nodes: &nodes,
                quarantined: &quarantined,
                held: &held,
                holds: &BTreeSet::new(),
                cordons: &BTreeSet::new(),
            },
            ObservedState {
                reports: &HashMap::new(),
                public_keys: &HashMap::new(),
                admitted: &admitted,
                routing: &routing,
                assignments: &assignments,
                now: chrono::Utc::now(),
            },
            &mut crate::evidence::ObservationLog::default(),
        )
        .expect("a quarantined group is survivable");

        for node in ["n1", "n2", "n3"] {
            assert_eq!(
                planned.assignments[node], core_v1,
                "{node} is republished on exactly what it is running; quarantine freezes a rollout \
                 where it stands"
            );
        }
    }

    /// An agent enrolled (or relabelled in) while its group is quarantined has no routing to carry
    /// forward, so nothing rescues it from the unmatched-node pseudo-group — and `default` hands
    /// out the repository's fleet-wide `default_deployment`: a different application, install root
    /// and provider set, unthrottled and ungated. One typo'd digest in one `UpdateGroup` would have
    /// been a deployment swap for every agent that arrived after it. It is withheld instead.
    #[test]
    fn an_agent_that_arrives_while_its_group_is_quarantined_is_withheld_not_defaulted() {
        let held = BTreeMap::from([(
            "edge".to_string(),
            AdmittedDeployment {
                current: deployment("edge-v1"),
                previous: Vec::new(),
            },
        )]);
        let admitted = BTreeMap::from([(
            "edge".to_string(),
            AdmittedDeployment {
                current: deployment("edge-v1"),
                previous: Vec::new(),
            },
        )]);
        // n1 selects `edge` by label but has never been published: `routing` is empty.
        let planned = plan(
            &BTreeMap::new(),
            &quarantined(&[("edge", "edge")]),
            &held,
            &admitted,
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .expect("a quarantined group is survivable");

        assert!(
            !planned.routing.contains_key("n1"),
            "the agent is left out of the generation until its group is fixed, not routed to \
             `default`: {:?}",
            planned.routing
        );
        assert!(
            !planned
                .publication
                .targets
                .iter()
                .any(|target| target.path == "assignments/agents/n1.json"),
            "nothing is published for it, so there is nothing to lose"
        );
    }

    /// A group quarantined BEFORE it was ever admitted has no durable pin, so it is in
    /// `quarantined` but not in `held`. Its agents must still be recognized as its agents:
    /// deciding membership from `held` alone matched none of them, and the already-published ones
    /// were handed the repository's ungated `default_deployment` in a single signed generation —
    /// a different application, install root and provider set, with no `maxUnavailable` staging,
    /// no health gate and no concurrency slot.
    #[test]
    fn a_group_quarantined_before_its_first_admission_still_withholds_the_default() {
        // The operator replaced the admitted `edge` group with a renamed `edge2` carrying the same
        // selector and a typo'd digest, so `edge2` is quarantined with nothing to pin.
        let pinned = AdmittedDeployment {
            current: deployment("edge-v1"),
            previous: Vec::new(),
        };
        let admitted = BTreeMap::from([("edge".to_string(), pinned)]);
        let routing = BTreeMap::from([("n1".to_string(), "edge".to_string())]);
        let edge_v1 = crate::deployment_identity(&deployment("edge-v1")).unwrap();
        let assignments = BTreeMap::from([("n1".to_string(), edge_v1.clone())]);
        let repository = repository();
        let nodes = edge_node();

        let planned = plan_reconcile(
            DesiredState {
                repository: &repository,
                groups: &BTreeMap::new(),
                group_labels: &BTreeMap::new(),
                sets: &[],
                nodes: &nodes,
                quarantined: &quarantined(&[("edge2", "edge")]),
                held: &BTreeMap::new(),
                holds: &BTreeSet::new(),
                cordons: &BTreeSet::new(),
            },
            ObservedState {
                reports: &HashMap::new(),
                public_keys: &HashMap::new(),
                admitted: &admitted,
                routing: &routing,
                assignments: &assignments,
                now: chrono::Utc::now(),
            },
            &mut crate::evidence::ObservationLog::default(),
        )
        .expect("a quarantined group is survivable");

        assert_eq!(
            planned.publication.node_groups["n1"], "edge",
            "the node keeps its published routing; it is never routed to `default`"
        );
        assert_eq!(
            planned.assignments["n1"], edge_v1,
            "the node keeps exactly the deployment it is running, not `default_deployment`"
        );
    }

    #[test]
    fn a_generation_that_would_drop_published_routing_fails_closed() {
        // The node was published under a group that no longer exists in any form, so nothing can be
        // carried forward for it. Signing a generation without its assignment would strand it, so
        // the whole generation fails and the last publication stays live.
        let routing = BTreeMap::from([("n1".to_string(), "gone".to_string())]);
        let error = plan(
            &unadmitted_edge_group(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &BTreeMap::new(),
            &routing,
            &BTreeMap::new(),
        )
        .unwrap_err();
        assert_eq!(error, PlanError::RoutingLoss(vec!["n1".to_string()]));
    }

    /// docs/node-controls-design.md — hold: the recorded body is republished VERBATIM through the
    /// same carry-forward arm quarantine uses, and when the identity index cannot resolve that
    /// body the generation fails closed — a hold can never silently become a move.
    #[test]
    fn a_held_node_keeps_its_recorded_body_and_fails_closed_when_it_is_gone() {
        // `edge` is mid-rollout to edge-v2; n1 is recorded on the predecessor edge-v1 and held.
        let pinned = AdmittedDeployment {
            current: deployment("edge-v2"),
            previous: vec![deployment("edge-v1")],
        };
        let admitted = BTreeMap::from([("edge".to_string(), pinned)]);
        let groups = BTreeMap::from([("edge".to_string(), resolved("edge", "edge", vec![]))]);
        let routing = BTreeMap::from([("n1".to_string(), "edge".to_string())]);
        let v1 = crate::deployment_identity(&deployment("edge-v1")).unwrap();
        let assignments = BTreeMap::from([("n1".to_string(), v1.clone())]);
        let repository = repository();
        let nodes = edge_node();
        let holds = BTreeSet::from(["n1".to_string()]);
        let mut groups_for_plan = groups.clone();
        // The group's desired deployment IS the admitted current, so an unheld node would be
        // handed edge-v2 immediately.
        groups_for_plan.get_mut("edge").unwrap().deployment = deployment("edge-v2");

        let planned = plan_reconcile(
            DesiredState {
                repository: &repository,
                groups: &groups_for_plan,
                group_labels: &BTreeMap::new(),
                sets: &[],
                nodes: &nodes,
                quarantined: &BTreeMap::new(),
                holds: &holds,
                cordons: &BTreeSet::new(),
                held: &BTreeMap::new(),
            },
            ObservedState {
                reports: &HashMap::new(),
                public_keys: &HashMap::new(),
                admitted: &admitted,
                routing: &routing,
                assignments: &assignments,
                now: chrono::Utc::now(),
            },
            &mut crate::evidence::ObservationLog::default(),
        )
        .expect("a held node is plannable");
        assert_eq!(
            planned.assignments["n1"], v1,
            "the held node is republished on exactly the body its recorded assignment names"
        );
        assert_eq!(planned.publication.node_groups["n1"], "edge");

        // The recorded body can no longer be resolved: the generation fails closed for this node,
        // exactly as the quarantine carry-forward does.
        let gone = BTreeMap::from([(
            "n1".to_string(),
            crate::deployment_identity(&deployment("long-retired")).unwrap(),
        )]);
        let error = plan_reconcile(
            DesiredState {
                repository: &repository,
                groups: &groups_for_plan,
                group_labels: &BTreeMap::new(),
                sets: &[],
                nodes: &nodes,
                quarantined: &BTreeMap::new(),
                holds: &holds,
                cordons: &BTreeSet::new(),
                held: &BTreeMap::new(),
            },
            ObservedState {
                reports: &HashMap::new(),
                public_keys: &HashMap::new(),
                admitted: &admitted,
                routing: &routing,
                assignments: &gone,
                now: chrono::Utc::now(),
            },
            &mut crate::evidence::ObservationLog::default(),
        )
        .expect_err("a hold whose body is gone must never become a move");
        assert!(
            matches!(error, PlanError::UnknownPlacement { ref node, .. } if node == "n1"),
            "unexpected error: {error:?}"
        );
    }

    /// A hold on an UNMATCHED node survives the operator editing `default_deployment`: the default
    /// lineage is recorded in the admitted map under the reserved pseudo-group name, so the held
    /// node's recorded body stays resolvable and is republished verbatim — instead of one hold
    /// plus one default edit faulting every generation fleet-wide with nothing able to clear it.
    /// An unheld node keeps following the default switch, exactly as before.
    #[test]
    fn a_held_default_node_survives_a_default_deployment_change() {
        let repository_v1 = repository();
        let old_default =
            DesiredDeployment::try_from(repository_v1.default_deployment.clone()).unwrap();
        let nodes = edge_node();
        // Pass 1: no groups at all — the node is unmatched and published under `default`.
        let first = plan_reconcile(
            DesiredState {
                repository: &repository_v1,
                groups: &BTreeMap::new(),
                group_labels: &BTreeMap::new(),
                sets: &[],
                nodes: &nodes,
                quarantined: &BTreeMap::new(),
                holds: &BTreeSet::new(),
                cordons: &BTreeSet::new(),
                held: &BTreeMap::new(),
            },
            ObservedState {
                reports: &HashMap::new(),
                public_keys: &HashMap::new(),
                admitted: &BTreeMap::new(),
                routing: &BTreeMap::new(),
                assignments: &BTreeMap::new(),
                now: chrono::Utc::now(),
            },
            &mut crate::evidence::ObservationLog::default(),
        )
        .unwrap();
        let old_identity = crate::deployment_identity(&old_default).unwrap();
        assert_eq!(first.assignments["n1"], old_identity);
        assert!(
            first.admitted.contains_key(crate::DEFAULT_GROUP),
            "the default lineage is recorded under the reserved name"
        );

        // Pass 2: the operator edits the default AND holds the node. The recorded body resolves
        // through the lineage and is republished verbatim.
        let mut repository_v2 = repository();
        repository_v2.default_deployment.application.sha256 = "3".repeat(64);
        let holds = BTreeSet::from(["n1".to_string()]);
        let second = plan_reconcile(
            DesiredState {
                repository: &repository_v2,
                groups: &BTreeMap::new(),
                group_labels: &BTreeMap::new(),
                sets: &[],
                nodes: &nodes,
                quarantined: &BTreeMap::new(),
                holds: &holds,
                cordons: &BTreeSet::new(),
                held: &BTreeMap::new(),
            },
            ObservedState {
                reports: &HashMap::new(),
                public_keys: &HashMap::new(),
                admitted: &first.admitted,
                routing: &first.routing,
                assignments: &first.assignments,
                now: chrono::Utc::now(),
            },
            &mut crate::evidence::ObservationLog::default(),
        )
        .expect("a held default node with a recorded lineage is plannable");
        assert_eq!(
            second.assignments["n1"], old_identity,
            "the held node keeps exactly the body its recorded assignment names"
        );

        // Pass 3: the hold is cleared and the node follows the fleet-wide default switch.
        let third = plan_reconcile(
            DesiredState {
                repository: &repository_v2,
                groups: &BTreeMap::new(),
                group_labels: &BTreeMap::new(),
                sets: &[],
                nodes: &nodes,
                quarantined: &BTreeMap::new(),
                holds: &BTreeSet::new(),
                cordons: &BTreeSet::new(),
                held: &BTreeMap::new(),
            },
            ObservedState {
                reports: &HashMap::new(),
                public_keys: &HashMap::new(),
                admitted: &second.admitted,
                routing: &second.routing,
                assignments: &second.assignments,
                now: chrono::Utc::now(),
            },
            &mut crate::evidence::ObservationLog::default(),
        )
        .unwrap();
        let new_default =
            DesiredDeployment::try_from(repository_v2.default_deployment.clone()).unwrap();
        assert_eq!(
            third.assignments["n1"],
            crate::deployment_identity(&new_default).unwrap(),
            "a cleared hold releases the node back onto the current default"
        );
    }

    /// An `UpdateGroup` literally named `default` is quarantined for its reserved name, and the
    /// runtime hands every quarantined group's durable entry over as a `held` pin — which for that
    /// name is not a pin at all, it is the repository's default LINEAGE. Restoring it would put the
    /// pre-compaction copy back over the one the planner had just compacted, every pass, so
    /// `previous` would grow one whole deployment body per `default_deployment` edit with nothing
    /// able to prune it, until the admitted-state ConfigMap outgrew the apiserver's object limit
    /// and no generation could publish again. The reserved key is not restorable.
    #[test]
    fn a_held_entry_under_the_reserved_name_never_resurrects_the_default_lineage() {
        let nodes = edge_node();
        let repository_v1 = repository();
        let mut repository_v2 = repository();
        repository_v2.default_deployment.application.sha256 = "3".repeat(64);
        let plan = |repository: &crate::UpdateRepositorySpec,
                    held: &BTreeMap<String, crate::rollout::AdmittedDeployment>,
                    quarantined: &BTreeMap<String, BTreeMap<String, String>>,
                    previous: Option<&ReconcilePlan>| {
            let empty_admitted = BTreeMap::new();
            let empty_map = BTreeMap::new();
            plan_reconcile(
                DesiredState {
                    repository,
                    groups: &BTreeMap::new(),
                    group_labels: &BTreeMap::new(),
                    sets: &[],
                    nodes: &nodes,
                    quarantined,
                    holds: &BTreeSet::new(),
                    cordons: &BTreeSet::new(),
                    held,
                },
                ObservedState {
                    reports: &HashMap::new(),
                    public_keys: &HashMap::new(),
                    admitted: previous.map_or(&empty_admitted, |plan| &plan.admitted),
                    routing: previous.map_or(&empty_map, |plan| &plan.routing),
                    assignments: previous.map_or(&empty_map, |plan| &plan.assignments),
                    now: chrono::Utc::now(),
                },
                &mut crate::evidence::ObservationLog::default(),
            )
            .unwrap()
        };
        // Two default edits, so the lineage carries a superseded body the node has since left.
        let first = plan(&repository_v1, &BTreeMap::new(), &BTreeMap::new(), None);
        let second = plan(
            &repository_v2,
            &BTreeMap::new(),
            &BTreeMap::new(),
            Some(&first),
        );
        assert!(
            !second.admitted[crate::DEFAULT_GROUP].previous.is_empty(),
            "the setup this test exists for: the lineage still carries the old default while the \
             node is on it"
        );
        // Now an UpdateGroup named `default` appears. It is quarantined on sight (an empty
        // selector claims no node) and the runtime offers its durable entry — the lineage — as a
        // held pin. The node has meanwhile moved onto the new default, so the old body is
        // retirable, and the restore must not bring it back.
        let third = plan(
            &repository_v2,
            &BTreeMap::from([(
                crate::DEFAULT_GROUP.to_string(),
                second.admitted[crate::DEFAULT_GROUP].clone(),
            )]),
            &BTreeMap::from([(crate::DEFAULT_GROUP.to_string(), BTreeMap::new())]),
            Some(&second),
        );
        assert!(
            third.admitted[crate::DEFAULT_GROUP].previous.is_empty(),
            "a held entry under the reserved name must not undo the lineage's compaction: {:?}",
            third.admitted[crate::DEFAULT_GROUP].previous
        );
    }
}
