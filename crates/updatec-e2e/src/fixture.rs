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

/// The relabeling campaign deliberately uses mutually compatible sampleapp releases.
/// Every cohort must carry the same catalog: a node can arrive from any other cohort.
fn fuzz_resources(
    mut resources: serde_json::Value,
    cohort: &str,
    version: &str,
    sha: &str,
    platform: &str,
) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    use updated_contracts::releases::{Release, ReleaseGraph};

    let items = resources["items"]
        .as_array_mut()
        .ok_or("expected a resource List")?;
    let mut releases = BTreeMap::<String, Release>::new();
    let mut fields = Vec::new();
    let mut names = std::collections::BTreeSet::new();
    for item in items.iter() {
        let name = item["metadata"]["name"]
            .as_str()
            .ok_or("missing resource name")?;
        let field = match (item["kind"].as_str(), name) {
            (Some("UpdateGroup"), "edge" | "batch") => "deployment",
            (Some("UpdateRepository"), "default") => "defaultDeployment",
            _ => return Err("unexpected fuzz resource".into()),
        };
        if !names.insert(name.to_owned()) {
            return Err("duplicate fuzz resource".into());
        }
        fields.push(field);
        let graph: ReleaseGraph =
            serde_json::from_value(item["spec"][field]["application"].clone())?;
        graph.validate()?;
        for (version, release) in graph.releases {
            if releases
                .get(&version)
                .is_some_and(|known| known.package != release.package)
            {
                return Err(format!("conflicting fixture package for {version}").into());
            }
            releases.insert(version, release);
        }
    }
    if names.len() != 3 || !names.contains(cohort) {
        return Err("fuzz resources requires edge, batch, and default".into());
    }
    let package = updated_contracts::artifact::TargetReference {
        path: format!("products/app/stable/{version}/{platform}/app"),
        sha256: sha.into(),
    };
    if releases
        .get(version)
        .is_some_and(|known| known.package != package)
    {
        return Err(format!("conflicting fixture package for {version}").into());
    }
    releases.entry(version.into()).or_insert(Release {
        package,
        upgrade_from: Default::default(),
        rollback_from: Default::default(),
        installable: true,
    });
    let versions = releases
        .keys()
        .map(|v| Ok((v.clone(), semver::Version::parse(v)?)))
        .collect::<Result<Vec<_>, semver::Error>>()?;
    // This is an explicit policy for these test payloads, never a production inference.
    for (target, parsed) in &versions {
        let release = releases.get_mut(target).expect("catalog version exists");
        release.upgrade_from = versions
            .iter()
            .filter(|(_, v)| v.cmp_precedence(parsed).is_lt())
            .map(|(v, _)| v.clone())
            .collect();
        release.rollback_from = versions
            .iter()
            .filter(|(_, v)| v.cmp_precedence(parsed).is_gt())
            .map(|(v, _)| v.clone())
            .collect();
    }
    for (item, field) in items.iter_mut().zip(fields) {
        let name = item["metadata"]["name"]
            .as_str()
            .expect("validated name")
            .to_owned();
        let deployment = &mut item["spec"][field];
        if name == cohort {
            deployment["name"] = format!("{cohort}-fuzz-{version}").into();
            deployment["application"]["target"] = version.into();
        }
        let graph = ReleaseGraph {
            target: deployment["application"]["target"]
                .as_str()
                .ok_or("missing target")?
                .into(),
            releases: releases.clone(),
        };
        graph.validate()?;
        deployment["application"] = serde_json::to_value(graph)?;
        // kubectl owns resource application; emit only the desired fields.
        *item = serde_json::json!({
            "apiVersion": item["apiVersion"], "kind": item["kind"],
            "metadata": {"name": name, "namespace": item["metadata"]["namespace"]},
            "spec": item["spec"],
        });
    }
    Ok(resources)
}

pub(crate) fn print_fuzz_resources(
    args: impl IntoIterator<Item = String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = args.into_iter().collect();
    let [cohort, version, sha, platform] = args.as_slice() else {
        return Err("fuzz-resources needs cohort, version, sha256, and platform".into());
    };
    let resources = serde_json::from_reader(std::io::stdin().lock())?;
    emit(&fuzz_resources(resources, cohort, version, sha, platform)?)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn fuzz_fixture() -> serde_json::Value {
        let digests = ["a".repeat(64), "b".repeat(64), "c".repeat(64)];
        serde_json::json!({"apiVersion": "v1", "kind": "List", "items":
            (["edge", "batch", "default"].map(|name| {
                let field = if name == "default" { "defaultDeployment" } else { "deployment" };
                serde_json::json!({
                    "apiVersion": "updated.dev/v1alpha1",
                    "kind": if name == "default" { "UpdateRepository" } else { "UpdateGroup" },
                    "metadata": {"name": name, "namespace": NAMESPACE},
                    "spec": {field: {"name": name, "application": kind_release_graph(
                        "linux-x86_64", "1.0.0", digests.each_ref().map(String::as_str))}},
                })
            }))
        })
    }

    #[test]
    fn relabeling_keeps_every_cohort_source_in_one_explicit_catalog() {
        let mut resources = fuzz_fixture();
        for (cohort, version, sha) in [
            ("edge", "4.0.0", "d".repeat(64)),
            ("batch", "5.0.0", "e".repeat(64)),
            ("default", "6.0.0", "f".repeat(64)),
        ] {
            resources = fuzz_resources(resources, cohort, version, &sha, "linux-x86_64").unwrap();
        }
        let mut catalog = None;
        for item in resources["items"].as_array().unwrap() {
            let field = if item["kind"] == "UpdateRepository" {
                "defaultDeployment"
            } else {
                "deployment"
            };
            let graph: updated_contracts::releases::ReleaseGraph =
                serde_json::from_value(item["spec"][field]["application"].clone()).unwrap();
            if let Some(ref catalog) = catalog {
                assert_eq!(&graph.releases, catalog);
            }
            for source in graph.releases.keys() {
                assert!(
                    graph.route(Some(source), |_, _| true).is_ok(),
                    "{source} -> {}",
                    graph.target
                );
            }
            catalog = Some(graph.releases);
        }
    }

    #[test]
    fn fuzz_catalog_rejects_replaced_package_identities() {
        let mut resources = fuzz_fixture();
        assert!(fuzz_resources(
            resources.clone(),
            "edge",
            "1.0.0",
            &"d".repeat(64),
            "linux-x86_64"
        )
        .is_err());
        resources["items"][0]["spec"]["deployment"]["application"]["releases"]["1.0.0"]
            ["package"]["sha256"] = "d".repeat(64).into();
        assert!(
            fuzz_resources(resources, "edge", "4.0.0", &"e".repeat(64), "linux-x86_64").is_err()
        );
    }

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
