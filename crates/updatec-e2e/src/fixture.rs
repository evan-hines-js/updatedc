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
        application: TargetSpec {
            path: format!("products/app/stable/{version}/{platform}/app"),
            sha256: app_sha.into(),
        },
        cold_install_fallback: false,
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
    let kind_deployment = |origin: &str, identity: &str, version: &str, sha: &str| {
        deployment_with_name(origin, identity, version, &platform, sha, &root)
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
    fn runtime_bounds_are_shared_by_every_fixture_deployment() {
        let left = deployment_with_name("left", "left", "1.0.0", "linux-x86_64", "a", "{}");
        let right = deployment_with_name("right", "right", "2.0.0", "linux-x86_64", "c", "{}");
        assert_eq!(
            serde_json::to_value(left.runtime).unwrap(),
            serde_json::to_value(right.runtime).unwrap()
        );
    }
}
