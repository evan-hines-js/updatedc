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
    RuntimeSpec, TargetSpec, UpdateGroup, UpdateGroupSet, UpdateGroupSetSpec, UpdateGroupSpec,
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
pub(crate) const SOAK_FLEET_LABEL: &str = "soak.updated.dev/fleet";
pub(crate) const SOAK_FLEET_VALUE: &str = "managed";
pub(crate) const SOAK_COHORT_LABEL: &str = "soak.updated.dev/cohort";
#[cfg(unix)]
pub(crate) const SOAK_NODE_LABEL: &str = "soak.updated.dev/node";
#[cfg(unix)]
pub(crate) const SOAK_CHAOS_LABEL: &str = "soak.updated.dev/campaign";
#[cfg(unix)]
pub(crate) const SOAK_CHAOS_VALUE: &str = "managed";
#[cfg(unix)]
pub(crate) const SOAK_CHAOS_NAME_PREFIX: &str = "soak-round-";
pub(crate) const SOAK_GROUPS: [&str; 3] = ["soak-a", "soak-b", "soak-c"];
pub(crate) const SOAK_GROUP_SET: &str = "soak-fleet";
pub(crate) const SOAK_MAX_UNAVAILABLE: usize = 1;
pub(crate) const SOAK_MAX_CONCURRENT: u32 = 2;
pub(crate) const SOAK_MAX_REGRESSIONS: u32 = 1;
pub(crate) const SOAK_STUCK_AFTER_SECONDS: u64 = 300;

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
            inactive_providers: 2,
            inactive_agents: 2,
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
            agent_check_interval_seconds: 3600,
        },
    }
}

pub(crate) fn deployment(
    name: &str,
    version: &str,
    platform: &str,
    app_sha: &str,
    provider_sha: &str,
    root_json: &str,
) -> DeploymentSpec {
    deployment_with_name(
        name,
        &versioned_deployment_name(name, version),
        version,
        platform,
        app_sha,
        provider_sha,
        root_json,
    )
}

fn deployment_with_name(
    origin: &str,
    deployment_name: &str,
    version: &str,
    platform: &str,
    app_sha: &str,
    provider_sha: &str,
    root_json: &str,
) -> DeploymentSpec {
    DeploymentSpec {
        name: deployment_name.into(),
        release_repository: ReleaseRepositorySpec {
            metadata_url: format!("https://release-{origin}/metadata/"),
            targets_url: format!("https://release-{origin}/targets/"),
            root_json: root_json.into(),
        },
        application: TargetSpec {
            path: format!("products/app/stable/{version}/{platform}/app"),
            sha256: app_sha.into(),
        },
        cold_install_fallback: false,
        provider_set: TargetSpec {
            path: "provider-sets/default.json".into(),
            sha256: provider_sha.into(),
        },
        runtime: runtime(),
    }
}

fn versioned_deployment_name(group: &str, version: &str) -> String {
    let name = format!("{group}-{version}");
    assert!(
        updated_contracts::identity::is_segment(&name),
        "fixture deployment identity {name:?} violates the shared identity grammar"
    );
    name
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

pub(crate) fn group(name: &str, deployment: DeploymentSpec) -> UpdateGroup {
    let mut group = UpdateGroup::new(
        name,
        UpdateGroupSpec {
            repository_ref: LocalObjectReference {
                name: REPOSITORY_NAME.into(),
            },
            selector: LabelSelector {
                match_labels: BTreeMap::from([(SOAK_COHORT_LABEL.into(), name.into())]),
            },
            depends_on: vec![],
            inputs: BTreeMap::new(),
            deployment,
            max_unavailable: Some(SOAK_MAX_UNAVAILABLE),
            emergency_correction: false,
        },
    );
    group.metadata.namespace = Some(NAMESPACE.into());
    group.metadata.labels = Some(BTreeMap::from([(
        SOAK_FLEET_LABEL.into(),
        SOAK_FLEET_VALUE.into(),
    )]));
    group
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

pub(crate) fn group_set() -> UpdateGroupSet {
    let mut set = group_set_resource(
        SOAK_GROUP_SET,
        BTreeMap::from([(SOAK_FLEET_LABEL.into(), SOAK_FLEET_VALUE.into())]),
        Some(SOAK_MAX_CONCURRENT),
    );
    set.spec.max_regressions = Some(SOAK_MAX_REGRESSIONS);
    set.spec.on_regression = RegressionResponse::Rollback;
    set.spec.stuck_after_seconds = Some(SOAK_STUCK_AFTER_SECONDS);
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

/// Print the KIND fixture from the same constructors the permanent campaign reconciles.
pub(crate) fn print_kind_resources(
    args: impl IntoIterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut args = args.into_iter();
    let platform = args.next().ok_or("resources needs a platform")?;
    let v1_sha = args.next().ok_or("resources needs the v1 sha256")?;
    let v2_sha = args.next().ok_or("resources needs the v2 sha256")?;
    let v3_sha = args.next().ok_or("resources needs the v3 sha256")?;
    let provider_sha = args.next().ok_or("resources needs the provider sha256")?;
    let root_path = args.next().ok_or("resources needs a root.json path")?;
    let mode = args.next();
    if args.next().is_some() {
        return Err("resources received unexpected arguments".into());
    }
    let root = std::fs::read_to_string(root_path)?;
    let kind_deployment = |origin: &str, identity: &str, version: &str, sha: &str| {
        deployment_with_name(
            origin,
            identity,
            version,
            &platform,
            sha,
            &provider_sha,
            &root,
        )
    };

    match mode.as_deref() {
        Some("overlap") => emit(&kind_group(
            "overlapping-edge",
            "edge",
            kind_deployment("default", "default", "1.0.0", &v1_sha),
        )),
        None => {
            emit(&kind_group(
                "edge",
                "edge",
                kind_deployment("edge", "edge", "2.0.0", &v2_sha),
            ))?;
            emit(&kind_group(
                "batch",
                "batch",
                kind_deployment("batch", "batch", "3.0.0", &v3_sha),
            ))?;
            emit(&repository(kind_deployment(
                "default", "default", "1.0.0", &v1_sha,
            )))
        }
        Some(mode) => Err(format!("unknown resources mode {mode:?}").into()),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn soak_groups_share_one_safe_regression_boundary() {
        let set = group_set();
        assert_eq!(set.spec.max_concurrent, Some(2));
        assert_eq!(set.spec.max_regressions, Some(1));
        assert_eq!(set.spec.on_regression, RegressionResponse::Rollback);
        for name in SOAK_GROUPS {
            let deployment = deployment(name, "1.0.0", "linux-x86_64", "a", "b", "{}");
            let group = group(name, deployment);
            assert_eq!(
                group
                    .metadata
                    .labels
                    .as_ref()
                    .and_then(|labels| labels.get(SOAK_FLEET_LABEL))
                    .map(String::as_str),
                Some(SOAK_FLEET_VALUE)
            );
        }
    }

    #[test]
    fn runtime_bounds_are_shared_by_every_fixture_deployment() {
        let left = deployment("left", "1.0.0", "linux-x86_64", "a", "b", "{}");
        let right = deployment("right", "2.0.0", "linux-x86_64", "c", "d", "{}");
        assert_eq!(
            serde_json::to_value(left.runtime).unwrap(),
            serde_json::to_value(right.runtime).unwrap()
        );
    }

    #[test]
    fn kind_and_soak_share_bytes_but_keep_their_required_identities() {
        let kind = deployment_with_name("edge", "edge", "2.0.0", "linux-x86_64", "a", "b", "{}");
        let soak = deployment("edge", "2.0.0", "linux-x86_64", "a", "b", "{}");
        assert_eq!(kind.name, "edge");
        assert_eq!(soak.name, "edge-2.0.0");
        assert_eq!(
            serde_json::to_value(&kind.application).unwrap(),
            serde_json::to_value(&soak.application).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&kind.provider_set).unwrap(),
            serde_json::to_value(&soak.provider_set).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&kind.runtime).unwrap(),
            serde_json::to_value(&soak.runtime).unwrap()
        );
        assert_eq!(
            serde_json::to_value(&kind.release_repository).unwrap(),
            serde_json::to_value(&soak.release_repository).unwrap()
        );

        let repository = repository(kind);
        assert_eq!(repository.spec.s3.bucket, RELEASE_BUCKET);
        assert_eq!(
            repository.spec.s3.endpoint.as_deref(),
            Some(RELEASE_ENDPOINT)
        );
        assert_eq!(
            repository.spec.s3.public_endpoint.as_deref(),
            Some(RELEASE_PUBLIC_ENDPOINT)
        );
    }
}
