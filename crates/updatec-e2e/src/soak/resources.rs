//! Resource definitions owned by the Unix-only resident soak controller.

use std::collections::BTreeMap;

use updatec::{
    DeploymentSpec, LabelSelector, LocalObjectReference, RegressionResponse, UpdateGroup,
    UpdateGroupSet, UpdateGroupSpec,
};

use crate::fixture::{deployment_with_name, group_set_resource, REPOSITORY_NAME};
use crate::layout::NAMESPACE;

pub(crate) const SOAK_FLEET_LABEL: &str = "soak.updated.dev/fleet";
pub(crate) const SOAK_FLEET_VALUE: &str = "managed";
pub(crate) const SOAK_COHORT_LABEL: &str = "soak.updated.dev/cohort";
pub(crate) const SOAK_NODE_LABEL: &str = "soak.updated.dev/node";
pub(crate) const SOAK_CHAOS_LABEL: &str = "soak.updated.dev/campaign";
pub(crate) const SOAK_CHAOS_VALUE: &str = "managed";
pub(crate) const SOAK_CHAOS_NAME_PREFIX: &str = "soak-round-";
pub(crate) const SOAK_GROUPS: [&str; 3] = ["soak-a", "soak-b", "soak-c"];
pub(crate) const SOAK_GROUP_SET: &str = "soak-fleet";
pub(crate) const SOAK_MAX_UNAVAILABLE: usize = 1;
pub(crate) const SOAK_MAX_CONCURRENT: u32 = 2;
pub(crate) const SOAK_MAX_REGRESSIONS: u32 = 1;
pub(crate) const SOAK_STUCK_AFTER_SECONDS: u64 = 300;

pub(crate) fn deployment(
    name: &str,
    version: &str,
    platform: &str,
    app_sha: &str,
    root_json: &str,
) -> DeploymentSpec {
    deployment_with_name(
        name,
        &versioned_deployment_name(name, version),
        version,
        platform,
        app_sha,
        root_json,
    )
}

fn versioned_deployment_name(group: &str, version: &str) -> String {
    let name = format!("{group}-{version}");
    assert!(
        updated_contracts::identity::is_segment(&name),
        "fixture deployment identity {name:?} violates the shared identity grammar"
    );
    name
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

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use crate::fixture::{repository, RELEASE_BUCKET, RELEASE_ENDPOINT, RELEASE_PUBLIC_ENDPOINT};

    #[test]
    fn soak_groups_share_one_safe_regression_boundary() {
        let set = group_set();
        assert_eq!(set.spec.max_concurrent, Some(2));
        assert_eq!(set.spec.max_regressions, Some(1));
        assert_eq!(set.spec.on_regression, RegressionResponse::Rollback);
        for name in SOAK_GROUPS {
            let deployment = deployment(name, "1.0.0", "linux-x86_64", "a", "{}");
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
    fn kind_and_soak_share_bytes_but_keep_their_required_identities() {
        let kind = deployment_with_name("edge", "edge", "2.0.0", "linux-x86_64", "a", "{}");
        let soak = deployment("edge", "2.0.0", "linux-x86_64", "a", "{}");
        assert_eq!(kind.name, "edge");
        assert_eq!(soak.name, "edge-2.0.0");
        assert_eq!(
            serde_json::to_value(&kind.application).unwrap(),
            serde_json::to_value(&soak.application).unwrap()
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
