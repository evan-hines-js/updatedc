//! Typed generator for the schema-sensitive control-plane resources used by Kind E2E.

use std::collections::BTreeMap;

use updatec::*;

fn runtime() -> RuntimeSpec {
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

fn deployment(
    name: &str,
    version: &str,
    platform: &str,
    app_sha: &str,
    provider_sha: &str,
    root_json: &str,
) -> DeploymentSpec {
    DeploymentSpec {
        name: name.into(),
        release_repository: ReleaseRepositorySpec {
            metadata_url: format!("https://release-{name}/metadata/"),
            targets_url: format!("https://release-{name}/targets/"),
            root_json: root_json.into(),
        },
        application: TargetSpec {
            path: format!("products/app/stable/{version}/{platform}/app"),
            sha256: app_sha.into(),
        },
        ordered_install_fallback: false,
        provider_set: TargetSpec {
            path: "provider-sets/default.json".into(),
            sha256: provider_sha.into(),
        },
        runtime: runtime(),
    }
}

fn emit(resource: &impl serde::Serialize) {
    println!("---\n{}", serde_json::to_string_pretty(resource).unwrap());
}

fn main() {
    let mut args = std::env::args().skip(1);
    let platform = args.next().expect("platform");
    let v1_sha = args.next().expect("v1 sha256");
    let v2_sha = args.next().expect("v2 sha256");
    let v3_sha = args.next().expect("v3 sha256");
    let provider_sha = args.next().expect("provider sha256");
    let root_path = args.next().expect("root.json path");
    let mode = args.next();
    assert!(args.next().is_none(), "unexpected arguments");
    let root = std::fs::read_to_string(root_path).expect("read root.json");

    if mode.as_deref() == Some("overlap") {
        let mut group = UpdateGroup::new(
            "overlapping-edge",
            UpdateGroupSpec {
                repository_ref: LocalObjectReference {
                    name: "default".into(),
                },
                selector: LabelSelector {
                    match_labels: BTreeMap::from([("updated.dev/role".into(), "edge".into())]),
                },
                depends_on: vec![],
                inputs: BTreeMap::new(),
                deployment: deployment(
                    "default",
                    "1.0.0",
                    &platform,
                    &v1_sha,
                    &provider_sha,
                    &root,
                ),
                max_unavailable: None,
                emergency_correction: false,
            },
        );
        group.metadata.namespace = Some("updated-system".into());
        emit(&group);
        return;
    }
    assert!(mode.is_none(), "unknown output mode");

    for (name, version, sha) in [("edge", "2.0.0", &v2_sha), ("batch", "3.0.0", &v3_sha)] {
        let mut group = UpdateGroup::new(
            name,
            UpdateGroupSpec {
                repository_ref: LocalObjectReference {
                    name: "default".into(),
                },
                selector: LabelSelector {
                    match_labels: BTreeMap::from([("updated.dev/role".into(), name.into())]),
                },
                depends_on: vec![],
                inputs: BTreeMap::new(),
                deployment: deployment(name, version, &platform, sha, &provider_sha, &root),
                max_unavailable: None,
                emergency_correction: false,
            },
        );
        group.metadata.namespace = Some("updated-system".into());
        emit(&group);
    }

    let mut repository = UpdateRepository::new(
        "default",
        UpdateRepositorySpec {
            default_deployment: deployment(
                "default",
                "1.0.0",
                &platform,
                &v1_sha,
                &provider_sha,
                &root,
            ),
            signing_secret_ref: LocalSecretReference {
                name: "tuf-signing-keys".into(),
            },
            enrollment: EnrollmentSpec {
                labels: BTreeMap::new(),
            },
            s3: RepositoryStorage {
                bucket: "updates".into(),
                region: "us-east-1".into(),
                credentials_secret_ref: Some(LocalSecretReference {
                    name: "s3-credentials".into(),
                }),
                endpoint: Some("http://minio:9000".into()),
                public_endpoint: Some("https://minio-direct.updated-system.svc".into()),
            },
            assignment_prefix: "assignments".into(),
            state_max_shards: 8,
            admission_policy_ref: None,
        },
    );
    repository.metadata.namespace = Some("updated-system".into());
    emit(&repository);
}
