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
}

pub fn plan_reconcile(
    desired: DesiredState<'_>,
    observed: ObservedState<'_>,
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
        },
        &mut admitted,
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
        if selected == crate::DEFAULT_GROUP && !quarantined.contains_key(node) {
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
    for (name, state) in desired.held {
        admitted.insert(name.clone(), state.clone());
    }

    // Every deployment body the control plane still has, by identity — quarantined pins and the
    // retained bodies of deleted groups included, because the held states were restored just above.
    // Built by the one function `assign_nodes` builds its index with, so "where is this node?" is
    // answered identically here and there.
    let mut bodies = crate::rollout::bodies_by_identity(admitted.values());
    // The repository default is a body nodes are published with too, so it belongs in the index
    // that answers "which body is this node actually on?". Without it a withheld node last routed
    // to `default` had no recoverable placement at all, and the carry-forward reached for the
    // CURRENT default instead — the swap the withholding exists to prevent.
    if let Some(identity) = crate::deployment_identity(&default) {
        bodies.insert(identity, &default);
    }

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
            Some(last) if quarantined.contains_key(node) || admitted.contains_key(last) => {
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
        if !report.healthy || Some(&report.assignment_sha256) != identity.as_ref() {
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
            },
            ObservedState {
                reports: &HashMap::new(),
                public_keys: &HashMap::new(),
                admitted,
                routing,
                assignments,
                now: chrono::Utc::now(),
            },
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
            },
            ObservedState {
                reports: &HashMap::new(),
                public_keys: &HashMap::new(),
                admitted: &admitted,
                routing: &routing,
                assignments: &assignments,
                now: chrono::Utc::now(),
            },
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
            },
            ObservedState {
                reports: &HashMap::new(),
                public_keys: &HashMap::new(),
                admitted: &admitted,
                routing: &routing,
                assignments: &assignments,
                now: chrono::Utc::now(),
            },
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
            },
            ObservedState {
                reports: &HashMap::new(),
                public_keys: &HashMap::new(),
                admitted: &admitted,
                routing: &routing,
                assignments: &assignments,
                now: chrono::Utc::now(),
            },
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
            },
            ObservedState {
                reports: &HashMap::new(),
                public_keys: &HashMap::new(),
                admitted: &admitted,
                routing: &routing,
                assignments: &assignments,
                now: chrono::Utc::now(),
            },
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
}
