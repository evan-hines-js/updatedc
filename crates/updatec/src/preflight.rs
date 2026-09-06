//! Whole-generation release preflight, before any new assignment is published.
use std::collections::{BTreeMap, BTreeSet};

use crate::domain::{DesiredState, ObservedState};
use crate::{DesiredDeployment, PlanError};

pub(crate) struct PreparedRollout {
    pub deployment: DesiredDeployment,
    pub versions: BTreeSet<String>,
    pub sources: BTreeSet<String>,
}

/// Inspect all cohorts first. A missing route on the last node cannot leave the first admitted.
pub(crate) fn routes(
    desired: &DesiredState<'_>,
    observed: &ObservedState<'_>,
    plan: &crate::domain::ReconcilePlan,
    verified: &mut crate::evidence::VerifiedReports,
) -> Result<Vec<PreparedRollout>, PlanError> {
    let node_groups = crate::resolve_node_groups(
        desired.groups.values().cloned(),
        desired.nodes.iter().cloned(),
    )?;
    verified.verify_fleet(observed.reports, observed.public_keys);
    let default = DesiredDeployment::try_from(desired.repository.default_deployment.clone())
        .map_err(PlanError::InvalidDeployment)?;
    let mut pending: BTreeMap<String, PreparedRollout> = BTreeMap::new();
    let published =
        crate::rollout::bodies_by_identity(observed.admitted.values().chain(desired.held.values()));
    for node in desired.nodes {
        let group = &node_groups[&node.name];
        if desired.holds.contains(&node.name) || desired.quarantined_group(node, group).is_some() {
            continue;
        }
        let deployment = plan.desired_deployments.get(group).unwrap_or(&default);
        // A durable regression response supersedes the refused forward intent. Preflight the
        // entire returning cohort, including nodes outside this pass's throttled batch.
        let deployment = if crate::deployment_identity(deployment)
            .is_some_and(|identity| plan.vetoed.contains_key(&identity))
        {
            plan.admitted
                .get(group)
                .map(|state| &state.current)
                .unwrap_or(deployment)
        } else {
            deployment
        };
        check_node(
            &node.name,
            deployment,
            observed,
            verified,
            &published,
            &mut pending,
        )?;
    }
    let deployments = &plan.desired_deployments;
    for group in crate::rollout::rollback_groups(desired.sets, deployments, desired.group_labels) {
        let deployment = &deployments[&group];
        let identity = crate::deployment_identity(deployment).expect("validated deployment");
        if plan.vetoed.contains_key(&identity) {
            continue;
        }
        let Some(forward) = pending.get(&identity) else {
            continue;
        };
        let Some(state) = observed.admitted.get(&group) else {
            continue;
        };
        let previous: Vec<_> = (state.current != *deployment)
            .then_some(&state.current)
            .into_iter()
            .chain(state.previous.iter())
            .collect();
        if previous.is_empty() {
            continue;
        }
        let (_, restored) = crate::rollout::rollback_target(deployment, previous, &plan.blocked)
            .ok_or_else(|| PlanError::ReleasePreflight {
                node: format!("group {group}"),
                message:
                    "automatic rollback has no permitted, immutable baseline in the release catalog"
                        .into(),
            })?;
        let mut versions = BTreeSet::new();
        // A failure can leave any completed hop installed. Validate the whole return topology
        // before admitting the forward rollout, including its actual installed starting versions.
        for source in forward.sources.union(&forward.versions) {
            versions.extend(
                restored
                    .application
                    .route_versions(Some(source))
                    .map_err(|message| PlanError::ReleasePreflight {
                        node: format!("group {group}"),
                        message: format!("automatic rollback: {message}"),
                    })?
                    .into_iter()
                    .map(str::to_string),
            );
        }
        pending
            .entry(crate::deployment_identity(&restored).expect("validated restoration"))
            .or_insert_with(|| PreparedRollout {
                deployment: restored,
                versions: BTreeSet::new(),
                sources: BTreeSet::new(),
            })
            .versions
            .extend(versions);
    }
    // Also check the concrete publication, including automatic rollback/configuration changes.
    // No planner response may introduce an unchecked assignment after cohort preflight.
    let targets: BTreeMap<&str, &crate::PublicationTarget> = plan
        .publication
        .targets
        .iter()
        .map(|target| (target.sha256.as_str(), target))
        .collect();
    for (node, identity) in &plan.publication.node_assignments {
        if observed.assignments.get(node) == Some(identity) {
            continue;
        }
        let target = targets.get(identity.as_str()).ok_or_else(|| {
            PlanError::InvalidDeployment("publication has no matching configuration".into())
        })?;
        let deployment = DesiredDeployment::from_bounded_json(&target.bytes)
            .map_err(PlanError::InvalidDeployment)?;
        check_node(
            node,
            &deployment,
            observed,
            verified,
            &published,
            &mut pending,
        )?;
    }
    Ok(pending.into_values().collect())
}

fn check_node(
    node: &str,
    deployment: &DesiredDeployment,
    observed: &ObservedState<'_>,
    verified: &crate::evidence::VerifiedReports,
    published: &std::collections::HashMap<String, &DesiredDeployment>,
    pending: &mut BTreeMap<String, PreparedRollout>,
) -> Result<(), PlanError> {
    let identity = crate::deployment_identity(deployment)
        .ok_or_else(|| PlanError::InvalidDeployment("cannot encode release graph".into()))?;
    if observed.assignments.get(node) == Some(&identity) {
        return Ok(());
    }
    let report = observed
        .reports
        .get(node)
        .zip(observed.public_keys.get(node))
        .and_then(|(envelope, key)| {
            verified.fresh(
                node,
                envelope,
                key,
                observed.now.timestamp_millis().max(0) as u64,
            )
        });
    let graph = &deployment.application;
    let source = report
        .as_ref()
        .map(|report| &report.version)
        .filter(|version| !version.is_empty())
        .cloned();
    let mut versions = match report.as_ref() {
        Some(report) if !report.version.is_empty() => graph.check_source(&report.version, &report.archive_sha256).and_then(|()| graph.route_versions(Some(&report.version))),
        Some(_) => graph.route_versions(None),
        None if !observed.assignments.contains_key(node) => graph.route_versions(None),
        None => Err(format!("cannot verify installed version before rollout to {}: a fresh authenticated report is required", graph.target)),
    }.map_err(|message| PlanError::ReleasePreflight {node: node.into(), message})?;
    let mut sources: BTreeSet<String> = source.iter().cloned().collect();
    // A report is a snapshot, not a fence around execution. Until the agent observes the new
    // assignment it can finish any remaining hop of its published route. Every such landing
    // must retain both its immutable identity and a complete route under the replacement.
    let active: BTreeSet<&String> = observed
        .assignments
        .get(node)
        .into_iter()
        .chain(
            report
                .as_ref()
                .filter(|_| observed.assignments.contains_key(node))
                .map(|report| &report.assignment_sha256),
        )
        .collect();
    for identity in active {
        let prior = published
            .get(identity)
            .ok_or_else(|| PlanError::ReleasePreflight {
                node: node.into(),
                message: "cannot verify in-flight route: published assignment body is missing"
                    .into(),
            })?;
        // A prior assignment with no executable route cannot advance this node. In particular,
        // do not prevent a corrected graph from rescuing an already stranded installation.
        if report
            .as_ref()
            .filter(|report| !report.version.is_empty())
            .is_some_and(|report| {
                prior
                    .application
                    .check_source(&report.version, &report.archive_sha256)
                    .is_err()
            })
        {
            continue;
        }
        let remaining = prior
            .application
            .route_versions(source.as_deref())
            .unwrap_or_default();
        for landing in remaining {
            let package = &prior.application.releases[landing].package;
            let route = graph
                .check_source(landing, &package.sha256)
                .and_then(|()| graph.route_versions(Some(landing)))
                .map_err(|message| PlanError::ReleasePreflight {
                    node: node.into(),
                    message: format!("in-flight release {landing}: {message}"),
                })?;
            sources.insert(landing.into());
            versions.extend(route);
        }
    }
    let prepared = pending.entry(identity).or_insert_with(|| PreparedRollout {
        deployment: deployment.clone(),
        versions: BTreeSet::new(),
        sources: BTreeSet::new(),
    });
    prepared.sources.extend(sources);
    prepared
        .versions
        .extend(versions.into_iter().map(str::to_string));
    Ok(())
}

/// Authenticate signed metadata and check required objects without downloading bundle bodies.
pub(crate) async fn packages(
    plans: &[PreparedRollout],
    datastore: &std::path::Path,
    admission: &crate::admission::AdmissionEvaluation,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::time::timeout(updated_tuf::RELEASE_PREFLIGHT_BUDGET, async {
    // One metadata refresh and one availability request per repository/object in this pass,
    // even when many cohorts share releases. Nothing here retains bundle bytes or cross-pass trust.
    let mut repositories = BTreeMap::new();
    let mut targets = BTreeMap::new();
    for plan in plans {
        let deployment = &plan.deployment;
        let repository_key = updated_contracts::digest::sha256_bytes(&serde_json::to_vec(&(
            &deployment.metadata_url,
            &deployment.targets_url,
            &deployment.release_root,
            &deployment.runtime.repository,
        ))?);
        if !repositories.contains_key(&repository_key) {
            let repository = updated_tuf::TrustedRepository::load_release_repository(
                deployment, datastore, None,
            )
            .await?;
            repositories.insert(repository_key.clone(), repository);
        }
        let repository = &repositories[&repository_key];
        let graph = &plan.deployment.application;
        let target = repository.exact_target(graph.target_reference()?)?;
        let field = |name: &str| {
            target
                .custom
                .get(name)
                .and_then(|value| value.as_str())
                .ok_or("package platform metadata is missing")
        };
        let policy = updated_tuf::DefaultPolicy {
            product: plan.deployment.runtime.product.clone(),
            channel: plan.deployment.runtime.channel.clone(),
            os: field("os")?.into(),
            arch: field("arch")?.into(),
        };
        // Resolving a changed assignment requires its target metadata even when the node already
        // runs that version. Configuration-only rollouts must not bypass repository preflight.
        let mut versions = plan.versions.clone();
        versions.insert(graph.target.clone());
        for version in &versions {
            let release = &graph.releases[version];
            if let Some(status) = admission
                .package_status(&release.package.sha256)
                .filter(|status| !status.allowed)
            {
                return Err(PlanError::ReleasePreflight {
                    node: format!("deployment {}", plan.deployment.deployment),
                    message: format!(
                        "release {version} is blocked by admission ({})",
                        status.reason
                    ),
                }
                .into());
            }
            let selected = repository.verify_release(&policy, version, &release.package)?;
            targets.entry((
                repository_key.clone(),
                selected.target.path.clone(),
                selected.sha256,
            )).or_insert(selected.target);
        }
    }
    updated_tuf::check_targets_available(targets.iter().map(|((repository_key, _, _), target)| {
        (&repositories[repository_key], target)
    })).await?;
    Ok(())
    })
    .await
    .map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "release preflight exceeded its health-report freshness budget; no assignments published",
        )
    })?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retargets_cover_in_flight_landings_and_their_immutable_packages() {
        use std::collections::HashMap;
        for can_advance in [true, false] {
            let mut prior =
                DesiredDeployment::try_from(crate::tests::deployment_spec("prior")).unwrap();
            for (version, from) in [("2.0.0", "1.0.0"), ("3.0.0", "2.0.0")] {
                prior.application.releases.insert(
                    version.into(),
                    updated_contracts::releases::Release {
                        package: updated_contracts::artifact::TargetReference {
                            path: format!("app/{version}"),
                            sha256: version[..1].repeat(64),
                        },
                        installable: false,
                        upgrade_from: BTreeSet::from([from.into()]),
                        rollback_from: Default::default(),
                    },
                );
            }
            prior.application.target = "3.0.0".into();
            if !can_advance {
                prior
                    .application
                    .releases
                    .get_mut("3.0.0")
                    .unwrap()
                    .upgrade_from
                    .clear();
            }
            let identity = crate::deployment_identity(&prior).unwrap();
            let key = updated::csr::generate_key().unwrap();
            let private = updated::csr::key_pem_to_pkcs8_der(&key).unwrap();
            let public =
                crate::join::csr_public_key(&updated::csr::csr_for(&key, "n1").unwrap()).unwrap();
            let mut report = updated_contracts::telemetry::NodeReport::new(
                "n1",
                "prior",
                &identity,
                "1.0.0",
                &prior.application.releases["1.0.0"].package.sha256,
                "f".repeat(64),
                true,
            )
            .unwrap();
            let reports = HashMap::from([(
                "n1".into(),
                crate::test_support::sign_report(&mut report, &private),
            )]);
            let keys = HashMap::from([("n1".into(), public)]);
            // A newer assignment has been published, but the agent still reports executing the
            // older route. Checking only the publication would miss its in-flight landings.
            let mut delivered = prior.clone();
            delivered.application.target = "1.0.0".into();
            let delivered_identity = crate::deployment_identity(&delivered).unwrap();
            let observed = ObservedState {
                reports: &reports,
                public_keys: &keys,
                assignments: &BTreeMap::from([("n1".into(), delivered_identity.clone())]),
                admitted: &BTreeMap::new(),
                vetoed: &BTreeMap::new(),
                routing: &BTreeMap::new(),
                outputs: &HashMap::new(),
                dataflow_key: b"test",
                now: chrono::Utc::now(),
            };
            let published = HashMap::from([(identity, &prior), (delivered_identity, &delivered)]);
            let mut verified = crate::evidence::VerifiedReports::default();
            verified.verify_fleet(&reports, &keys);
            let mut replacement = prior.clone();
            replacement.application.target = "4.0.0".into();
            replacement.application.releases.insert(
                "4.0.0".into(),
                updated_contracts::releases::Release {
                    package: updated_contracts::artifact::TargetReference {
                        path: "app/4.0.0".into(),
                        sha256: "4".repeat(64),
                    },
                    installable: false,
                    upgrade_from: BTreeSet::from(["1.0.0".into()]),
                    rollback_from: Default::default(),
                },
            );
            // The reported source has a route, but the currently executing hop can land at 2 or 3.
            assert!(replacement
                .application
                .route_versions(Some("1.0.0"))
                .is_ok());
            let check = |deployment: &DesiredDeployment| {
                let mut pending = BTreeMap::new();
                check_node(
                    "n1",
                    deployment,
                    &observed,
                    &verified,
                    &published,
                    &mut pending,
                )
                .map(|()| pending)
            };
            assert_eq!(
                check(&replacement).is_err(),
                can_advance,
                "a stranded prior graph must not prevent a valid correction"
            );
            replacement
                .application
                .releases
                .get_mut("4.0.0")
                .unwrap()
                .upgrade_from
                .insert("3.0.0".into());
            let prepared = check(&replacement).expect("both possible landings can now reach 4");
            assert_eq!(
                prepared.values().next().unwrap().sources,
                if can_advance {
                    BTreeSet::from(["1.0.0".into(), "2.0.0".into(), "3.0.0".into()])
                } else {
                    BTreeSet::from(["1.0.0".into()])
                }
            );
            replacement
                .application
                .releases
                .get_mut("2.0.0")
                .unwrap()
                .package
                .sha256 = "e".repeat(64);
            assert_eq!(
                check(&replacement).is_err(),
                can_advance,
                "a future landing cannot be relabelled as different bytes"
            );
        }
    }

    #[tokio::test]
    async fn a_stalled_repository_cannot_spend_the_health_report_window() {
        let tmp = tempfile::tempdir().unwrap();
        let repository_dir = tmp.path().join("repository");
        let keys = updated_tuf::repo::generate_keys(&tmp.path().join("keys"))
            .await
            .unwrap();
        updated_tuf::repo::init(&repository_dir, &keys, 365)
            .await
            .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (accepted, mut observed) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (_connection, _) = listener.accept().await.unwrap();
            accepted.send(()).unwrap();
            // Accept TCP but never complete TLS. No certificate or global CA override is needed.
            std::future::pending::<()>().await;
        });
        let mut deployment = crate::tests::deployment_spec("slow-repository");
        deployment.release_repository = crate::ReleaseRepositorySpec {
            metadata_url: format!("https://{address}/metadata/"),
            targets_url: format!("https://{address}/targets/"),
            root_json: std::fs::read_to_string(repository_dir.join("metadata/1.root.json"))
                .unwrap(),
        };
        let mut deployment = DesiredDeployment::try_from(deployment).unwrap();
        deployment.runtime.repository.transport_timeout_seconds = 300;
        let plan = PreparedRollout {
            versions: BTreeSet::from([deployment.application.target.clone()]),
            sources: BTreeSet::new(),
            deployment,
        };
        let error = packages(
            &[plan],
            &tmp.path().join("preflight"),
            &crate::admission::AdmissionEvaluation::disabled(),
        )
        .await
        .unwrap_err();
        server.abort();
        observed
            .try_recv()
            .expect("preflight reached the stalled server");
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert!(error.to_string().contains("health-report freshness budget"));
    }
}
