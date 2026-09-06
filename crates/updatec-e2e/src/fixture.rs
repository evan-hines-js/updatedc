//! The one typed resource constructor shared by every updatec fleet fixture.
//!
//! KIND and the permanent chaos soak differ in fleet size and orchestration, not in what a
//! deployment means. Keeping the signed release repository, target, runtime, and storage
//! contracts here makes those environments compile against one definition.

use std::collections::BTreeMap;

use crate::layout::NAMESPACE;
use updatec::{
    DeploymentSpec, EnrollmentMode, EnrollmentSpec, LabelSelector, LocalObjectReference,
    LocalSecretReference, RegressionResponse, ReleaseRepositorySpec, RepositoryStorage,
    RuntimeSpec, UpdateGroup, UpdateGroupSet, UpdateGroupSetSpec, UpdateGroupSpec,
    UpdateRepository, UpdateRepositorySpec,
};

pub(crate) const REPOSITORY_NAME: &str = "default";
pub(crate) const RELEASE_ENDPOINT: &str = "http://minio:9000";
pub(crate) const RELEASE_PUBLIC_ENDPOINT: &str = "https://minio-direct.updated-system.svc";
pub(crate) const RELEASE_BUCKET: &str = "updates";
pub(crate) const RELEASE_PREFIX: &str = "releases";
pub(crate) const RELEASE_REGION: &str = "us-east-1";
pub(crate) const SIGNING_SECRET: &str = "tuf-signing-keys";
pub(crate) const STORAGE_SECRET: &str = "s3-credentials";
pub(crate) const ASSIGNMENT_PREFIX: &str = "assignments";
pub(crate) const STATE_MAX_SHARDS: u8 = 8;

pub(crate) fn runtime() -> RuntimeSpec {
    RuntimeSpec {
        product: "app".into(),
        channel: "stable".into(),
        install_root: "/var/lib/updated".into(),
        repository: updated_contracts::assignment::ManagedRepositoryLimits {
            metadata_limit: 1_048_576,
            target_limit: 536_870_912,
            transport_timeout_seconds: 30,
        },
        storage: updated_contracts::assignment::ManagedStorage {
            inactive_releases: 2,
            inactive_bytes: 1_073_741_824,
            inactive_repository_caches: 2,
        },
        timeouts: updated_contracts::assignment::ManagedTimeouts {
            check_interval_seconds: 1,
            health_grace_seconds: 30,
            health_successes: 2,
            health_interval_seconds: 1,
            refresh_retry_seconds: 2,
            confirmation_window_seconds: 2,
        },
    }
}

pub(crate) fn deployment_with_name(
    origin: &str,
    deployment_name: &str,
    version: &str,
    platform: &str,
    app_sha: &str,
    root_json: &str,
) -> DeploymentSpec {
    DeploymentSpec {
        name: deployment_name.into(),
        release_repository: ReleaseRepositorySpec {
            metadata_url: format!("https://release-{origin}/metadata/"),
            targets_url: format!("https://release-{origin}/targets/"),
            root_json: root_json.into(),
        },
        application: updated_contracts::releases::testing::install(
            version,
            updated_contracts::artifact::TargetReference {
                path: format!("products/app/stable/{version}/{platform}/app"),
                sha256: app_sha.into(),
            },
        ),

        runtime: runtime(),
    }
}

pub(crate) fn repository(default_deployment: DeploymentSpec) -> UpdateRepository {
    let mut repository = UpdateRepository::new(
        REPOSITORY_NAME,
        UpdateRepositorySpec {
            default_deployment,
            signing_secret_ref: LocalSecretReference {
                name: SIGNING_SECRET.into(),
            },
            enrollment: EnrollmentSpec {
                mode: EnrollmentMode::Open,
                labels: BTreeMap::new(),
            },
            s3: RepositoryStorage {
                bucket: RELEASE_BUCKET.into(),
                region: RELEASE_REGION.into(),
                credentials_secret_ref: Some(LocalSecretReference {
                    name: STORAGE_SECRET.into(),
                }),
                endpoint: Some(RELEASE_ENDPOINT.into()),
                public_endpoint: Some(RELEASE_PUBLIC_ENDPOINT.into()),
            },
            assignment_prefix: ASSIGNMENT_PREFIX.into(),
            state_max_shards: STATE_MAX_SHARDS,
            admission_policy_ref: None,
        },
    );
    repository.metadata.namespace = Some(NAMESPACE.into());
    repository
}

/// Construct every fleet fixture's set through the typed API. In particular, repository scope is
/// required here rather than repeated in JSON call sites, so a CRD change cannot leave the CI
/// driver's rollout sets orphaned from the controller that owns them.
pub(crate) fn group_set_resource(
    name: &str,
    match_labels: BTreeMap<String, String>,
    max_concurrent: Option<u32>,
) -> UpdateGroupSet {
    let mut set = UpdateGroupSet::new(
        name,
        UpdateGroupSetSpec {
            repository_ref: LocalObjectReference {
                name: REPOSITORY_NAME.into(),
            },
            selector: LabelSelector { match_labels },
            max_concurrent,
            rollout_windows: vec![],
            calendar: vec![],
            max_regressions: None,
            on_regression: RegressionResponse::default(),
            stuck_after_seconds: None,
        },
    );
    set.metadata.namespace = Some(NAMESPACE.into());
    set
}

fn kind_group(name: &str, role: &str, deployment: DeploymentSpec) -> UpdateGroup {
    let mut group = UpdateGroup::new(
        name,
        UpdateGroupSpec {
            repository_ref: LocalObjectReference {
                name: REPOSITORY_NAME.into(),
            },
            selector: LabelSelector {
                match_labels: BTreeMap::from([("updated.dev/role".into(), role.into())]),
            },
            depends_on: vec![],
            inputs: BTreeMap::new(),
            deployment,
            max_unavailable: None,
            emergency_correction: false,
        },
    );
    group.metadata.namespace = Some(NAMESPACE.into());
    group
}

fn emit(resource: &impl serde::Serialize) -> Result<(), Box<dyn std::error::Error>> {
    println!("---\n{}", serde_json::to_string_pretty(resource)?);
    Ok(())
}

// Each cohort declares its supported source: relabeling does not reinstall a bootstrap node.
// Forward compatibility does not imply a supported return to an older release.
fn kind_release_graph(
    platform: &str,
    target: &str,
    digests: [&str; 3],
) -> updated_contracts::releases::ReleaseGraph {
    let releases = [
        ("1.0.0", digests[0], &[][..]),
        ("2.0.0", digests[1], &["1.0.0"][..]),
        ("3.0.0", digests[2], &["1.0.0"][..]),
    ]
    .into_iter()
    .map(|(version, sha256, from)| {
        (
            version.into(),
            updated_contracts::releases::Release {
                package: updated_contracts::artifact::TargetReference {
                    path: format!("products/app/stable/{version}/{platform}/app"),
                    sha256: sha256.into(),
                },
                installable: true,
                upgrade_from: from.iter().map(|v| (*v).into()).collect(),
                rollback_from: Default::default(),
            },
        )
    })
    .collect();
    updated_contracts::releases::ReleaseGraph {
        target: target.into(),
        releases,
    }
}

/// Moving the sample fleet to its publication repository preserves installed package identities.
/// Only the new baseline is executable there; bootstrap packages remain source anchors.
pub(crate) fn fleet_baseline_graph(
    mut bootstrap: updated_contracts::releases::ReleaseGraph,
    package: updated_contracts::artifact::TargetReference,
) -> updated_contracts::releases::ReleaseGraph {
    let upgrade_from = bootstrap.releases.keys().cloned().collect();
    for release in bootstrap.releases.values_mut() {
        release.installable = false;
        release.upgrade_from.clear();
        release.rollback_from.clear();
    }
    bootstrap.target = crate::layout::BASELINE_VERSION.into();
    bootstrap.releases.insert(
        bootstrap.target.clone(),
        updated_contracts::releases::Release {
            package,
            installable: true,
            upgrade_from,
            rollback_from: Default::default(),
        },
    );
    bootstrap
}

/// Print the KIND fixture from the same constructors the permanent campaign reconciles.
pub(crate) fn print_kind_resources(
    args: impl IntoIterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut args = args.into_iter();
    let platform = args.next().ok_or("resources needs a platform")?;
    let v1_sha = args.next().ok_or("resources needs the v1 sha256")?;
    let v2_sha = args.next().ok_or("resources needs the v2 sha256")?;
    let v3_sha = args.next().ok_or("resources needs the v3 sha256")?;
    let root_path = args.next().ok_or("resources needs a root.json path")?;
    let mode = args.next();
    if args.next().is_some() {
        return Err("resources received unexpected arguments".into());
    }
    let root = std::fs::read_to_string(root_path)?;
    let kind_deployment = |origin: &str, identity: &str, version: &str| {
        let application = kind_release_graph(&platform, version, [&v1_sha, &v2_sha, &v3_sha]);
        let sha = &application
            .target_reference()
            .expect("fixture target exists")
            .sha256;
        let mut deployment = deployment_with_name(origin, identity, version, &platform, sha, &root);
        deployment.application = application;
        deployment
    };

    match mode.as_deref() {
        Some("overlap") => emit(&kind_group(
            "overlapping-edge",
            "edge",
            kind_deployment("default", "default", "1.0.0"),
        )),
        None => {
            emit(&kind_group(
                "edge",
                "edge",
                kind_deployment("edge", "edge", "2.0.0"),
            ))?;
            emit(&kind_group(
                "batch",
                "batch",
                kind_deployment("batch", "batch", "3.0.0"),
            ))?;
            emit(&repository(kind_deployment("default", "default", "1.0.0")))
        }
        Some(mode) => Err(format!("unknown resources mode {mode:?}").into()),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn kind_cohorts_upgrade_from_bootstrap_without_inventing_reverse_support() {
        let digests = ["a".repeat(64), "b".repeat(64), "c".repeat(64)];
        for target in ["1.0.0", "2.0.0", "3.0.0"] {
            let graph = kind_release_graph(
                "linux-x86_64",
                target,
                digests.each_ref().map(String::as_str),
            );
            graph.validate().unwrap();
            graph.check_source("1.0.0", &digests[0]).unwrap();
            assert!(graph.route(Some("1.0.0"), |_, _| true).is_ok());
            assert!(graph.route(None, |_, _| true).is_ok());
            for source in ["2.0.0", "3.0.0"] {
                assert_eq!(
                    graph.route(Some(source), |_, _| true).is_ok(),
                    source == target
                );
            }
        }
    }

    #[test]
    fn fleet_repository_move_preserves_sources_without_requiring_old_objects() {
        let digests = ["a".repeat(64), "b".repeat(64), "c".repeat(64)];
        let bootstrap = kind_release_graph(
            "linux-x86_64",
            "2.0.0",
            digests.each_ref().map(String::as_str),
        );
        let graph = fleet_baseline_graph(
            bootstrap,
            updated_contracts::artifact::TargetReference {
                path: "products/app/baseline".into(),
                sha256: "d".repeat(64),
            },
        );
        graph.validate().unwrap();
        for (source, sha) in ["1.0.0", "2.0.0", "3.0.0"].into_iter().zip(digests) {
            graph.check_source(source, &sha).unwrap();
            assert_eq!(
                graph.route_versions(Some(source)).unwrap(),
                std::collections::BTreeSet::from([crate::layout::BASELINE_VERSION])
            );
        }
        assert_eq!(
            graph.route_versions(None).unwrap(),
            std::collections::BTreeSet::from([crate::layout::BASELINE_VERSION])
        );
    }

    #[test]
    fn runtime_bounds_are_shared_by_every_fixture_deployment() {
        let left = deployment_with_name("left", "left", "1.0.0", "linux-x86_64", "a", "{}");
        let right = deployment_with_name("right", "right", "2.0.0", "linux-x86_64", "c", "{}");
        assert_eq!(
            serde_json::to_value(left.runtime).unwrap(),
            serde_json::to_value(right.runtime).unwrap()
        );
    }
}
