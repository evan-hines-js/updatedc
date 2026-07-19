use std::path::Path;
use std::sync::Arc;

use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::api::core::v1::{ConfigMap, Secret};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime;
use kube::api::{Api, ListParams, PostParams};
use kube::{Client, ResourceExt};
use object_store::aws::AmazonS3Builder;
use object_store::path::Path as ObjectPath;
use object_store::{ObjectStore, PutPayload};

use crate::publisher::{upload_order, PublishError};
use crate::S3Destination;
use crate::{
    build_publication_plan, DesiredDeployment, ResolvedGroup, ResolvedNode, UpdatedGroup,
    UpdatedNode, UpdatedRepository,
};
use sha2::{Digest, Sha256};

const LEASE_SECONDS: i32 = 15;

/// Acquire or renew the Kubernetes single-writer lease. Conflicts are ordinary follower
/// outcomes, not reconciliation failures.
pub async fn acquire_or_renew_lease(
    client: Client,
    namespace: &str,
    name: &str,
    identity: &str,
) -> Result<bool, kube::Error> {
    let leases: Api<Lease> = Api::namespaced(client, namespace);
    let now = chrono::Utc::now();
    let Some(mut lease) = leases.get_opt(name).await? else {
        let lease = Lease {
            metadata: kube::api::ObjectMeta {
                name: Some(name.into()),
                namespace: Some(namespace.into()),
                ..Default::default()
            },
            spec: Some(new_lease_spec(identity, now, 0)),
        };
        return match leases.create(&PostParams::default(), &lease).await {
            Ok(_) => Ok(true),
            Err(kube::Error::Api(error)) if error.code == 409 => Ok(false),
            Err(error) => Err(error),
        };
    };

    let spec = lease.spec.get_or_insert_with(Default::default);
    let held_by_us = spec.holder_identity.as_deref() == Some(identity);
    if !held_by_us && !lease_expired(spec, now) {
        return Ok(false);
    }
    let transitions = spec
        .lease_transitions
        .unwrap_or_default()
        .saturating_add(i32::from(!held_by_us));
    *spec = new_lease_spec(identity, now, transitions);
    match leases.replace(name, &PostParams::default(), &lease).await {
        Ok(_) => Ok(true),
        Err(kube::Error::Api(error)) if error.code == 409 => Ok(false),
        Err(error) => Err(error),
    }
}

fn new_lease_spec(
    identity: &str,
    now: chrono::DateTime<chrono::Utc>,
    transitions: i32,
) -> LeaseSpec {
    LeaseSpec {
        holder_identity: Some(identity.into()),
        lease_duration_seconds: Some(LEASE_SECONDS),
        acquire_time: Some(MicroTime(now)),
        renew_time: Some(MicroTime(now)),
        lease_transitions: Some(transitions),
        preferred_holder: None,
        strategy: None,
    }
}

fn lease_expired(spec: &LeaseSpec, now: chrono::DateTime<chrono::Utc>) -> bool {
    let Some(renewed) = spec.renew_time.as_ref().map(|time| time.0) else {
        return true;
    };
    let seconds = spec.lease_duration_seconds.unwrap_or_default().max(0) as i64;
    renewed + chrono::Duration::seconds(seconds) <= now
}

#[derive(Debug)]
pub struct StorageError(String);

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for StorageError {}

pub fn s3_store(
    destination: &S3Destination,
    access_key: Option<&str>,
    secret_key: Option<&str>,
) -> Result<Arc<dyn ObjectStore>, StorageError> {
    validate_object_prefix(&destination.prefix)?;
    if destination.bucket.trim().is_empty() || destination.region.trim().is_empty() {
        return Err(StorageError(
            "S3 bucket and region must not be empty".into(),
        ));
    }
    let mut builder = AmazonS3Builder::new()
        .with_bucket_name(&destination.bucket)
        .with_region(&destination.region);
    if let Some(endpoint) = &destination.endpoint {
        builder = builder
            .with_endpoint(endpoint)
            .with_allow_http(endpoint.starts_with("http://"))
            .with_virtual_hosted_style_request(false);
    }
    if let (Some(access), Some(secret)) = (access_key, secret_key) {
        builder = builder
            .with_access_key_id(access)
            .with_secret_access_key(secret);
    }
    builder
        .build()
        .map(|store| Arc::new(store) as Arc<dyn ObjectStore>)
        .map_err(|e| StorageError(format!("configuring S3 store: {e}")))
}

fn validate_object_prefix(prefix: &str) -> Result<(), StorageError> {
    let trimmed = prefix.trim_matches('/');
    if prefix != trimmed
        || (!trimmed.is_empty()
            && trimmed.split('/').any(|part| {
                part.is_empty()
                    || part == "."
                    || part == ".."
                    || part.contains(['\\', ':'])
                    || part.chars().any(char::is_control)
            }))
    {
        return Err(StorageError(
            "S3 prefix must be a relative, normalized object-key prefix".into(),
        ));
    }
    Ok(())
}

/// Resolve the repository's private object store using the same configuration for both
/// publication and the read-only HTTP gateway.
pub async fn repository_store(
    client: Client,
    namespace: &str,
    repository_name: &str,
) -> Result<(S3Destination, Arc<dyn ObjectStore>), Box<dyn std::error::Error>> {
    let repositories: Api<UpdatedRepository> = Api::namespaced(client.clone(), namespace);
    let secrets: Api<Secret> = Api::namespaced(client, namespace);
    let destination = repositories.get(repository_name).await?.spec.s3;
    let credentials = match &destination.credentials_secret {
        Some(name) => Some(secrets.get(name).await?),
        None => None,
    };
    let access = secret_string(credentials.as_ref(), "AWS_ACCESS_KEY_ID")?;
    let secret = secret_string(credentials.as_ref(), "AWS_SECRET_ACCESS_KEY")?;
    let store = s3_store(&destination, access.as_deref(), secret.as_deref())?;
    Ok((destination, store))
}

/// Mirror a fully signed repository. `timestamp.json` is uploaded last, making it the
/// publication commit point observed by TUF clients.
pub async fn publish_repository(
    store: &dyn ObjectStore,
    destination: &S3Destination,
    repository_dir: &Path,
) -> Result<(), StorageError> {
    for file in upload_order(repository_dir).map_err(from_publish)? {
        let relative = file
            .strip_prefix(repository_dir)
            .map_err(|e| StorageError(format!("invalid repository path: {e}")))?;
        let key = [
            destination.prefix.trim_matches('/'),
            &relative.to_string_lossy(),
        ]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("/");
        let bytes = tokio::fs::read(&file)
            .await
            .map_err(|e| StorageError(format!("reading {}: {e}", file.display())))?;
        store
            .put(&ObjectPath::from(key), PutPayload::from_bytes(bytes.into()))
            .await
            .map_err(|e| StorageError(format!("uploading {}: {e}", file.display())))?;
    }
    Ok(())
}

fn from_publish(error: PublishError) -> StorageError {
    StorageError(error.to_string())
}

pub async fn reconcile_once(
    client: Client,
    namespace: &str,
    repository_name: &str,
    state_dir: &Path,
) -> Result<String, Box<dyn std::error::Error>> {
    let repositories: Api<UpdatedRepository> = Api::namespaced(client.clone(), namespace);
    let repository = repositories.get(repository_name).await?;
    let groups_api: Api<UpdatedGroup> = Api::namespaced(client.clone(), namespace);
    let config_maps: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let nodes_api: Api<UpdatedNode> = Api::namespaced(client, namespace);

    let mut groups = Vec::new();
    for group in groups_api.list(&ListParams::default()).await? {
        let config = config_maps.get(&group.spec.deployment_config_map).await?;
        let json = config
            .data
            .as_ref()
            .and_then(|data| data.get("deployment.json"))
            .ok_or_else(|| format!("ConfigMap {} has no deployment.json", config.name_any()))?;
        groups.push(ResolvedGroup {
            name: group.name_any(),
            match_labels: group.spec.match_labels,
            deployment: serde_json::from_str::<DesiredDeployment>(json)?,
        });
    }
    let nodes = nodes_api
        .list(&ListParams::default())
        .await?
        .into_iter()
        .map(|node| ResolvedNode {
            name: node.name_any(),
            labels: node.spec.labels,
        });
    let plan = build_publication_plan(&repository.spec, groups, nodes)?;
    let desired_digest = desired_publication_digest(&repository.spec, &plan.digest)?;
    let published_digest = state_dir.join("published-plan.sha256");
    if tokio::fs::read_to_string(&published_digest)
        .await
        .ok()
        .as_deref()
        == Some(desired_digest.as_str())
    {
        return Ok(plan.digest);
    }

    let signing = secrets.get(&repository.spec.signing_secret).await?;
    let keys_dir = state_dir.join("keys");
    materialize_signing_keys(&signing, &keys_dir).await?;
    let repo_dir = state_dir.join("repository");
    if !repo_dir.join("metadata/root.json").exists() {
        updated_tuf::repo::init(&repo_dir, &updated_tuf::repo::Keys::in_dir(&keys_dir), 365)
            .await?;
    }
    crate::publisher::sign_plan(&repo_dir, &keys_dir, &plan, 365).await?;

    let credentials = match &repository.spec.s3.credentials_secret {
        Some(name) => Some(secrets.get(name).await?),
        None => None,
    };
    let access = secret_string(credentials.as_ref(), "AWS_ACCESS_KEY_ID")?;
    let secret = secret_string(credentials.as_ref(), "AWS_SECRET_ACCESS_KEY")?;
    let store = s3_store(&repository.spec.s3, access.as_deref(), secret.as_deref())?;
    publish_repository(store.as_ref(), &repository.spec.s3, &repo_dir).await?;
    foundation::durable::atomic_write(&published_digest, ".published-", desired_digest.as_bytes())?;
    Ok(plan.digest)
}

fn desired_publication_digest(
    repository: &crate::UpdatedRepositorySpec,
    plan_digest: &str,
) -> Result<String, serde_json::Error> {
    let mut digest = Sha256::new();
    digest.update(serde_json::to_vec(repository)?);
    digest.update([0]);
    digest.update(plan_digest.as_bytes());
    Ok(format!("{:x}", digest.finalize()))
}

async fn materialize_signing_keys(
    secret: &Secret,
    directory: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    tokio::fs::create_dir_all(directory).await?;
    for name in ["root.pk8", "targets.pk8", "snapshot.pk8", "timestamp.pk8"] {
        let bytes = secret
            .data
            .as_ref()
            .and_then(|data| data.get(name))
            .ok_or_else(|| format!("signing Secret is missing {name}"))?;
        let path = directory.join(name);
        if path.exists() && tokio::fs::read(&path).await? != bytes.0 {
            return Err(format!("signing key {name} changed in place").into());
        }
        if !path.exists() {
            foundation::durable::atomic_write(&path, ".key-", &bytes.0)?;
        }
    }
    Ok(())
}

fn secret_string(
    secret: Option<&Secret>,
    key: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    secret
        .map(|secret| {
            let bytes = secret
                .data
                .as_ref()
                .and_then(|data| data.get(key))
                .ok_or_else(|| format!("credentials Secret is missing {key}"))?;
            String::from_utf8(bytes.0.clone()).map_err(|e| e.into())
        })
        .transpose()
}

#[cfg(test)]
mod lease_tests {
    use super::*;

    fn repository(bucket: &str) -> crate::UpdatedRepositorySpec {
        crate::UpdatedRepositorySpec {
            default_group: "default".into(),
            signing_secret: "keys".into(),
            s3: crate::S3Destination {
                bucket: bucket.into(),
                prefix: String::new(),
                region: "us-east-1".into(),
                credentials_secret: None,
                endpoint: None,
            },
            assignment_prefix: "assignments".into(),
        }
    }

    #[test]
    fn lease_is_available_only_after_its_renewal_deadline() {
        let now = chrono::Utc::now();
        let spec = new_lease_spec("first", now, 0);
        assert!(!lease_expired(&spec, now + chrono::Duration::seconds(14)));
        assert!(lease_expired(&spec, now + chrono::Duration::seconds(15)));
    }

    #[test]
    fn missing_renewal_is_expired() {
        let mut spec = new_lease_spec("first", chrono::Utc::now(), 0);
        spec.renew_time = None;
        assert!(lease_expired(&spec, chrono::Utc::now()));
    }

    #[test]
    fn publication_identity_includes_the_destination() {
        let first = desired_publication_digest(&repository("first"), "plan").unwrap();
        let second = desired_publication_digest(&repository("second"), "plan").unwrap();
        assert_ne!(first, second);
    }

    #[test]
    fn object_prefix_is_normalized_and_confined() {
        for valid in ["", "routing", "tenant/routing"] {
            assert!(validate_object_prefix(valid).is_ok(), "{valid}");
        }
        for invalid in ["/routing", "routing/", "a//b", "a/../b", "a\\b", "a:b"] {
            assert!(validate_object_prefix(invalid).is_err(), "{invalid}");
        }
    }
}
