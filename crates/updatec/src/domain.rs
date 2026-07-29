//! Pure control-plane reconciliation.
//!
//! This is the only path from desired inventory plus observed telemetry to a publication and a
//! new durable admission state. Kubernetes, object storage, signing, and status writes live in
//! adapters; none of them participate in rollout decisions.

use std::collections::{BTreeMap, HashMap};

use updated_contracts::telemetry::Envelope;

use crate::rollout::{plan_rollouts, AdmittedDeployment, RolloutInputs, SetStatus};
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
    /// Groups quarantined by validation this pass, with the deployment each is still pinned to.
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
    pub now: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconcilePlan {
    pub publication: PublicationPlan,
    pub admitted: BTreeMap<String, AdmittedDeployment>,
    /// The routing this generation publishes, to be persisted alongside `admitted`.
    pub routing: BTreeMap<String, String>,
    pub set_statuses: Vec<SetStatus>,
}

pub fn plan_reconcile(
    desired: DesiredState<'_>,
    observed: ObservedState<'_>,
) -> Result<ReconcilePlan, PlanError> {
    crate::validate_dependency_graph(desired.groups)?;
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
    for (node, selected) in &node_groups {
        if selected == crate::DEFAULT_GROUP {
            rollout
                .node_deployments
                .insert(node.clone(), default.clone());
        }
    }

    // A quarantined group is absent from the plan, so `plan_rollouts` pruned its admitted entry and
    // its nodes resolved to `default`. Restore both: the pin stays durable, and every node the
    // group was published for is republished under it, unchanged.
    for (name, state) in desired.held {
        admitted.insert(name.clone(), state.clone());
    }

    // A node whose group has not been admitted even once has no deployment of its own to publish.
    // It must NOT simply be left out: publication replaces the whole target set, so omitting a node
    // deletes its `agents/<node>.json` and strands it with no routing at all. Instead it is
    // republished under the group it was last routed to — for most nodes that is the pseudo-group
    // `default`, which is exactly what they ran before this group existed. Only a node that has
    // never been published anywhere is left out, and there is nothing there to lose.
    let mut published_nodes = BTreeMap::new();
    for (node, group) in &node_groups {
        // Carry the node's last routing forward in exactly two situations: the group it was
        // published under is quarantined (it is absent from the plan, so this node resolved to
        // `default` and would otherwise be swapped onto it), or its selected group has produced no
        // deployment at all this pass (never admitted — waiting on inputs or prerequisites).
        let last = observed.routing.get(node).filter(|last| {
            desired.held.contains_key(*last) || !rollout.node_deployments.contains_key(node)
        });
        let carried = last.and_then(|last| {
            if last == crate::DEFAULT_GROUP {
                Some((last.clone(), default.clone()))
            } else {
                admitted
                    .get(last)
                    .map(|state| (last.clone(), state.current.clone()))
            }
        });
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
    Ok(ReconcilePlan {
        publication,
        admitted,
        routing,
        set_statuses: rollout.sets,
    })
}

fn resolve_group_inputs(
    groups: &mut BTreeMap<String, ResolvedGroup>,
    node_groups: &BTreeMap<String, String>,
    reports: &HashMap<String, Envelope>,
    public_keys: &HashMap<String, Vec<u8>>,
    now_ms: u64,
) {
    let snapshot = groups.clone();
    for group in groups.values_mut() {
        if group.inputs.is_empty() {
            group.inputs_ready = true;
            continue;
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
            let producer = &snapshot[&reference.group];
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
                            aggregation: crate::OutputAggregation::One,
                        },
                    )]),
                    inputs_ready: false,
                    deployment: deployment("join-v1"),
                    max_unavailable: 1,
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

    fn plan(
        groups: &BTreeMap<String, ResolvedGroup>,
        held: &BTreeMap<String, AdmittedDeployment>,
        admitted: &BTreeMap<String, AdmittedDeployment>,
        routing: &BTreeMap<String, String>,
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
                held,
            },
            ObservedState {
                reports: &HashMap::new(),
                public_keys: &HashMap::new(),
                admitted,
                routing,
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
            previous: None,
        };
        let held = BTreeMap::from([("edge".to_string(), pinned.clone())]);
        let admitted = BTreeMap::from([("edge".to_string(), pinned)]);
        let routing = BTreeMap::from([("n1".to_string(), "edge".to_string())]);

        // The quarantined group is absent from the planned groups entirely.
        let planned = plan(&BTreeMap::new(), &held, &admitted, &routing)
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
            &routing,
        )
        .unwrap_err();
        assert_eq!(error, PlanError::RoutingLoss(vec!["n1".to_string()]));
    }
}
