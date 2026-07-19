use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime;
use k8s_openapi::ByteString;
use kube::api::{Api, ListParams, Patch, PatchParams, PostParams};
use kube::{Client, Resource, ResourceExt};
use object_store::aws::AmazonS3Builder;
use object_store::{ObjectStore, PutPayload};

use crate::publisher::{upload_order, PublishError};
use crate::throttle::{apply_throttle, SetStatus, ThrottleInputs};
use crate::S3Destination;
use crate::{
    build_publication_plan, ResolvedGroup, ResolvedNode, ResourceCondition, UpdateAgent,
    UpdateAgentStatus, UpdateGroup, UpdateGroupSet, UpdateGroupSetStatus, UpdateGroupStatus,
    UpdateRepository, UpdateRepositoryStatus,
};
use sha2::{Digest, Sha256};
use updated::telemetry::NodeReport;

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
    // A renewal preserves the original `acquireTime` — per the coordination.k8s.io lease
    // contract it marks when the current holder *first* acquired, not each heartbeat. Only a
    // takeover (a different identity) stamps a fresh acquisition; `new_lease_spec` sets `now`.
    let prior_acquire = spec.acquire_time.clone();
    let mut next = new_lease_spec(identity, now, transitions);
    if held_by_us {
        if let Some(acquire) = prior_acquire {
            next.acquire_time = Some(acquire);
        }
    }
    *spec = next;
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
    let repositories: Api<UpdateRepository> = Api::namespaced(client.clone(), namespace);
    let secrets: Api<Secret> = Api::namespaced(client, namespace);
    let destination = repositories.get(repository_name).await?.spec.s3;
    let store = build_store(&secrets, &destination).await?;
    Ok((destination, store))
}

/// Build the S3-backed object store for `destination`, reading its optional credentials Secret
/// (`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`) or falling back to workload identity when none is
/// referenced. The single place credential resolution and store construction live, shared by
/// [`repository_store`] and the reconcile loop.
async fn build_store(
    secrets: &Api<Secret>,
    destination: &S3Destination,
) -> Result<Arc<dyn ObjectStore>, Box<dyn std::error::Error>> {
    let credentials = match &destination.credentials_secret_ref {
        Some(reference) => Some(secrets.get(&reference.name).await?),
        None => None,
    };
    let access = secret_string(credentials.as_ref(), "AWS_ACCESS_KEY_ID")?;
    let secret = secret_string(credentials.as_ref(), "AWS_SECRET_ACCESS_KEY")?;
    Ok(s3_store(destination, access.as_deref(), secret.as_deref())?)
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
        let key = crate::object_key(&destination.prefix, &relative.to_string_lossy());
        let bytes = tokio::fs::read(&file)
            .await
            .map_err(|e| StorageError(format!("reading {}: {e}", file.display())))?;
        store
            .put(&key, PutPayload::from_bytes(bytes.into()))
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
    public_url: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let repositories: Api<UpdateRepository> = Api::namespaced(client.clone(), namespace);
    let repository = repositories.get(repository_name).await?;
    let groups_api: Api<UpdateGroup> = Api::namespaced(client.clone(), namespace);
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let nodes_api: Api<UpdateAgent> = Api::namespaced(client.clone(), namespace);
    let sets_api: Api<UpdateGroupSet> = Api::namespaced(client, namespace);

    let mut group_resources = groups_api.list(&ListParams::default()).await?;
    group_resources
        .items
        .retain(|group| group.spec.repository_ref.name == repository_name);
    // Desired groups keyed by name, plus each group's own metadata labels for set
    // membership matching. A single malformed group (empty selector or an unparseable
    // deployment) is quarantined — its own status carries the failure and it is dropped from
    // this generation — rather than aborting publication for every other resource.
    let mut groups = BTreeMap::new();
    let mut group_labels = BTreeMap::new();
    let mut quarantined_groups: HashSet<String> = HashSet::new();
    for group in group_resources.iter() {
        let name = group.name_any();
        if group.spec.selector.match_labels.is_empty() {
            quarantine_group(
                &groups_api,
                group,
                "EmptySelector",
                "This group's selector has no matchLabels; an empty selector would match every agent and is refused.",
            )
            .await?;
            quarantined_groups.insert(name);
            continue;
        }
        let deployment = match group.spec.deployment.clone().try_into() {
            Ok(deployment) => deployment,
            Err(error) => {
                quarantine_group(
                    &groups_api,
                    group,
                    "InvalidDeployment",
                    &format!("This group's deployment is invalid: {error}"),
                )
                .await?;
                quarantined_groups.insert(name);
                continue;
            }
        };
        groups.insert(
            name.clone(),
            ResolvedGroup {
                name: name.clone(),
                match_labels: group.spec.selector.match_labels.clone(),
                deployment,
            },
        );
        group_labels.insert(name, group.labels().clone());
    }
    group_resources
        .items
        .retain(|group| !quarantined_groups.contains(&group.name_any()));

    // Join-mode enrollment: ensure each surviving group has a stable id and a shared join-token
    // Secret, minting or rotating as needed. A failure here withholds new joins for that group
    // until a later reconcile but never blocks the rest of publication.
    for group in group_resources.iter() {
        if let Err(error) =
            ensure_group_join_credentials(&groups_api, &secrets, namespace, group).await
        {
            tracing::warn!(group = %group.name_any(), %error, "ensuring group join credentials failed");
        }
    }

    let mut agent_resources = nodes_api.list(&ListParams::default()).await?;
    agent_resources
        .items
        .retain(|agent| agent.spec.repository_ref.name == repository_name);
    // Quarantine an agent — never the whole reconcile — when its identity is malformed or its
    // labels match more than one non-default group (overlapping selectors). Ambiguity is
    // detected here, exactly as `build_publication_plan` would, so the surviving fleet still
    // publishes and the plan below cannot then fault on this agent.
    let mut quarantined_agents: HashSet<String> = HashSet::new();
    for agent in &agent_resources.items {
        let identity = &agent.spec.identity;
        let valid = match identity.kind {
            crate::AgentIdentityKind::Manual => identity.registration_sha256.is_none(),
            crate::AgentIdentityKind::Enrolled => identity
                .registration_sha256
                .as_deref()
                .is_some_and(updated::hash::is_sha256_hex),
        };
        if !valid {
            quarantine_agent(
                &nodes_api,
                agent,
                "InvalidIdentity",
                "This agent's identity is malformed (registrationSha256 does not match its kind).",
            )
            .await?;
            quarantined_agents.insert(agent.name_any());
            continue;
        }
        let matches: Vec<String> = groups
            .iter()
            .filter(|(_, group)| crate::selector_matches(&group.match_labels, &agent.spec.labels))
            .map(|(name, _)| name.clone())
            .collect();
        if matches.len() > 1 {
            quarantine_agent(
                &nodes_api,
                agent,
                "AmbiguousSelector",
                &format!(
                    "This agent's labels match multiple groups ({}); refine selectors so at most one matches.",
                    matches.join(", ")
                ),
            )
            .await?;
            quarantined_agents.insert(agent.name_any());
        }
    }
    agent_resources
        .items
        .retain(|agent| !quarantined_agents.contains(&agent.name_any()));

    let resolved_nodes: Vec<ResolvedNode> = agent_resources
        .iter()
        .map(|node| ResolvedNode {
            name: node.name_any(),
            labels: node.spec.labels.clone(),
        })
        .collect();

    // The object store is needed every reconcile — not only to publish, but to read the
    // node telemetry that drives throttling — so build it up front.
    let store = build_store(&secrets, &repository.spec.s3).await?;

    // Map nodes to groups from the desired generation (selectors are independent of the
    // throttle), then apply each UpdateGroupSet's throttle so held-back members carry
    // their last-admitted deployment before the plan is signed.
    let mapping_plan = build_publication_plan(
        &repository.spec,
        groups.values().cloned(),
        resolved_nodes.clone(),
    )?;
    let agent_names: Vec<String> = resolved_nodes.iter().map(|node| node.name.clone()).collect();
    let reports =
        read_node_reports(store.as_ref(), &repository.spec.s3.prefix, &agent_names).await;
    let mut set_resources = sets_api.list(&ListParams::default()).await?;
    set_resources.items.sort_by_key(|set| set.name_any());
    // Surface misconfigured schedule entries in the controller log. An invalid window or
    // calendar entry still fails safe (it never opens), so this is observability, not a gate.
    for set in &set_resources.items {
        for window in &set.spec.rollout_windows {
            if let Err(error) = window.validate() {
                tracing::warn!(
                    set = set.name_any(),
                    %error,
                    "UpdateGroupSet rollout window is invalid; it will never open"
                );
            }
        }
        for entry in &set.spec.calendar {
            if let Err(error) = entry.validate() {
                tracing::warn!(
                    set = set.name_any(),
                    %error,
                    "UpdateGroupSet calendar entry is invalid; it will never open"
                );
            }
        }
    }
    let admitted_dir = state_dir.join("admitted");
    let set_statuses = apply_throttle(
        &set_resources.items,
        ThrottleInputs {
            groups: &mut groups,
            group_labels: &group_labels,
            node_groups: &mapping_plan.node_groups,
            reports: &reports,
        },
        &admitted_dir,
        chrono::Utc::now(),
    )?;

    let plan = build_publication_plan(
        &repository.spec,
        groups.into_values(),
        resolved_nodes.clone(),
    )?;
    let desired_digest = desired_publication_digest(&repository.spec, &plan.digest)?;
    let published_digest = state_dir.join("published-plan.sha256");
    if tokio::fs::read_to_string(&published_digest)
        .await
        .ok()
        .as_deref()
        == Some(desired_digest.as_str())
    {
        publish_enrollment_secrets(
            &secrets,
            &repository,
            &agent_resources.items,
            store.as_ref(),
            &repository.spec.s3.prefix,
            public_url,
        )
        .await?;
        publish_resource_statuses(
            ResourceApis {
                repositories: &repositories,
                groups: &groups_api,
                agents: &nodes_api,
            },
            &repository,
            &group_resources.items,
            &agent_resources.items,
            &plan,
            &reports,
        )
        .await?;
        publish_group_set_statuses(&sets_api, &set_resources.items, &set_statuses).await?;
        return Ok(plan.digest);
    }

    let signing = secrets
        .get(&repository.spec.signing_secret_ref.name)
        .await?;
    let keys_dir = state_dir.join("keys");
    materialize_signing_keys(&signing, &keys_dir).await?;
    let repo_dir = state_dir.join("repository");
    if !repo_dir.join("metadata/root.json").exists() {
        updated_tuf::repo::init(&repo_dir, &updated_tuf::repo::Keys::in_dir(&keys_dir), 365)
            .await?;
    }
    crate::publisher::sign_plan(&repo_dir, &keys_dir, &plan, 365).await?;

    publish_repository(store.as_ref(), &repository.spec.s3, &repo_dir).await?;
    publish_enrollment_secrets(
        &secrets,
        &repository,
        &agent_resources.items,
        store.as_ref(),
        &repository.spec.s3.prefix,
        public_url,
    )
    .await?;
    foundation::durable::atomic_write(&published_digest, ".published-", desired_digest.as_bytes())?;
    publish_resource_statuses(
        ResourceApis {
            repositories: &repositories,
            groups: &groups_api,
            agents: &nodes_api,
        },
        &repository,
        &group_resources.items,
        &agent_resources.items,
        &plan,
        &reports,
    )
    .await?;
    publish_group_set_statuses(&sets_api, &set_resources.items, &set_statuses).await?;
    Ok(plan.digest)
}

/// Read the latest report for each *known* agent from `<prefix>/telemetry/<node>.json`, rather
/// than listing the whole telemetry namespace — a node key nobody selected can never gate a
/// rollout, and reading only the fleet we published bounds the per-reconcile cost to the fleet
/// size. Best-effort and bounded in flight: an unreadable, malformed, or misattributed report
/// is skipped, leaving that node absent (its member is treated as not-yet-settled — a slot stays
/// held rather than freeing on bad data).
async fn read_node_reports(
    store: &dyn ObjectStore,
    prefix: &str,
    agents: &[String],
) -> HashMap<String, NodeReport> {
    let prefix = prefix.trim_matches('/');
    let fetches = agents.iter().map(|node| async move {
        let key = crate::object_key(prefix, &updated::telemetry::report_object_key(node));
        let bytes = store.get(&key).await.ok()?.bytes().await.ok()?;
        let report = serde_json::from_slice::<NodeReport>(&bytes).ok()?;
        (report.node == *node).then(|| (node.clone(), report))
    });
    futures::stream::iter(fetches)
        .buffer_unordered(16)
        .filter_map(|entry| async move { entry })
        .collect()
        .await
}

/// Publish each `UpdateGroupSet`'s observed rollout state as its status.
async fn publish_group_set_statuses(
    sets: &Api<UpdateGroupSet>,
    set_resources: &[UpdateGroupSet],
    statuses: &[SetStatus],
) -> Result<(), kube::Error> {
    let params = PatchParams::default();
    let by_name: HashMap<&str, &SetStatus> =
        statuses.iter().map(|status| (status.name.as_str(), status)).collect();
    for set in set_resources {
        let name = set.name_any();
        let Some(status) = by_name.get(name.as_str()) else {
            continue;
        };
        let published = UpdateGroupSetStatus {
            observed_generation: set.metadata.generation,
            member_count: Some(status.member_count as u32),
            max_concurrent: Some(status.max_concurrent as u32),
            rolling_count: Some(status.rolling.len() as u32),
            rolling: status.rolling.clone(),
            settled: status.settled.clone(),
            shared: status.shared.clone(),
            // Emit the explicit bool, never `None`: the status is applied as a JSON *merge*
            // patch, and a merge that omits `frozen` leaves the previous value in place — so a
            // set that unfreezes (its calendar cleared or window reopened) would keep a stale
            // `frozen: true` forever. Writing `false` overwrites it and the gate reads open.
            frozen: Some(status.frozen),
            // Same merge-patch reasoning as `frozen`: write the explicit bool so a set that
            // re-gates (a new approved window added after exhaustion) clears a stale `true`.
            calendar_exhausted: Some(status.calendar_exhausted),
            conditions: vec![ready_condition(
                set.metadata.generation,
                "Reconciled",
                "This set's rollout throttle is reconciled.",
            )],
        };
        sets.patch_status(
            &name,
            &params,
            &Patch::Merge(serde_json::json!({"status": published})),
        )
        .await?;
    }
    Ok(())
}

async fn publish_enrollment_secrets(
    secrets: &Api<Secret>,
    repository: &UpdateRepository,
    agents: &[UpdateAgent],
    store: &dyn ObjectStore,
    prefix: &str,
    public_url: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    for agent in agents {
        if agent.spec.identity.kind != crate::AgentIdentityKind::Manual {
            continue;
        }
        let name = agent.name_any();
        let secret_name = format!("{name}-enrollment");
        let assignment = crate::gateway::agent_assignment(&repository.spec.assignment_prefix, &name);
        // Resolve the exact signed documents this agent pins straight from the published
        // consistent snapshot, through the one walk the gateway's `/enroll` also uses.
        let signed = crate::gateway::resolve_signed_enrollment(store, prefix, &assignment)
            .await
            .map_err(|error| format!("resolving enrollment bundle for {name}: {error}"))?;
        let bundle = signed.into_bundle(name.clone(), public_url, assignment);
        let mut data = std::collections::BTreeMap::new();
        data.insert(
            "enrollment.json".into(),
            ByteString(serde_json::to_vec_pretty(&bundle)?),
        );
        let desired = Secret {
            metadata: kube::api::ObjectMeta {
                name: Some(secret_name.clone()),
                namespace: repository.namespace(),
                owner_references: agent.controller_owner_ref(&()).map(|owner| vec![owner]),
                ..Default::default()
            },
            immutable: Some(true),
            data: Some(data),
            type_: Some("updated.dev/enrollment-bundle".into()),
            ..Default::default()
        };
        match secrets.create(&PostParams::default(), &desired).await {
            Ok(_) => {}
            Err(kube::Error::Api(error)) if error.code == 409 => {
                let existing = secrets.get(&secret_name).await?;
                let existing_bundle = existing
                    .data
                    .as_ref()
                    .and_then(|data| data.get("enrollment.json"))
                    .and_then(|bytes| {
                        serde_json::from_slice::<crate::EnrollmentBundle>(&bytes.0).ok()
                    });
                if existing_bundle.as_ref().is_none_or(|bundle| {
                    bundle.agent_id != name
                        || bundle.assignment
                            != crate::gateway::agent_assignment(
                                &repository.spec.assignment_prefix,
                                &name,
                            )
                }) {
                    return Err(format!(
                        "immutable enrollment Secret {secret_name} is invalid or belongs to another agent"
                    ).into());
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

/// Ensure a group has join-mode credentials: a stable `group_id` (derived once from the resource
/// UID) and a shared join-token Secret (`<group>-join`, key `nonce`). The token is (re)generated
/// only when the Secret is first needed or the spec's `rotateNonce` value changes; the token lives
/// only in the Secret, never in CRD status. The Secret is owned by the group, so deleting the
/// group deletes its token and revokes all future joins.
async fn ensure_group_join_credentials(
    groups: &Api<UpdateGroup>,
    secrets: &Api<Secret>,
    namespace: &str,
    group: &UpdateGroup,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let name = group.name_any();
    let status = group.status.clone().unwrap_or_default();
    let Some(group_id) = status.group_id.clone().or_else(|| group.uid()) else {
        // A persisted resource always has a UID; if it is somehow absent, retry next reconcile.
        return Ok(());
    };
    // Name the Secret from the stable group id so the gateway resolves it with a single GET keyed by
    // the group_id a joining node presents — never an UpdateGroup list. Stash the group name (for the
    // membership label) and repository (for scoping) alongside the token, so that one GET carries
    // everything /join needs to authenticate and route without any further pre-auth apiserver work.
    let secret_name = format!("join-{group_id}");
    let desired_rotation = group.spec.rotate_nonce.clone();
    let needs_token = status.join_secret_ref.is_none() || status.rotated_nonce != desired_rotation;
    if needs_token {
        let nonce = updated::rand::token()?;
        let mut data = std::collections::BTreeMap::new();
        data.insert("nonce".to_string(), ByteString(nonce.into_bytes()));
        data.insert("group".to_string(), ByteString(name.clone().into_bytes()));
        data.insert(
            "repository".to_string(),
            ByteString(group.spec.repository_ref.name.clone().into_bytes()),
        );
        let desired = Secret {
            metadata: kube::api::ObjectMeta {
                name: Some(secret_name.clone()),
                namespace: Some(namespace.to_string()),
                owner_references: group.controller_owner_ref(&()).map(|owner| vec![owner]),
                ..Default::default()
            },
            data: Some(data.clone()),
            type_: Some("updated.dev/group-join-token".into()),
            ..Default::default()
        };
        match secrets.create(&PostParams::default(), &desired).await {
            Ok(_) => {}
            Err(kube::Error::Api(error)) if error.code == 409 => {
                // Rotation: overwrite the token on the existing Secret.
                secrets
                    .patch(
                        &secret_name,
                        &PatchParams::default(),
                        &Patch::Merge(serde_json::json!({ "data": data })),
                    )
                    .await?;
            }
            Err(error) => return Err(error.into()),
        }
    }
    groups
        .patch_status(
            &name,
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({
                "status": {
                    "groupId": group_id,
                    "joinSecretRef": { "name": secret_name },
                    "rotatedNonce": desired_rotation,
                }
            })),
        )
        .await?;
    Ok(())
}

pub(crate) fn metadata_version(metadata: &serde_json::Value, name: &str) -> Result<u64, String> {
    metadata
        .pointer(&format!("/signed/meta/{name}/version"))
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("signed metadata does not declare {name} version"))
}

/// A `Ready` [`ResourceCondition`] for `generation`, reporting success (`status: "True"`) or
/// failure (`status: "False"`). The single place a Ready condition's fields are assembled;
/// [`ready_condition`] and [`failed_condition`] are the two named entry points.
fn condition(ok: bool, generation: Option<i64>, reason: &str, message: &str) -> ResourceCondition {
    ResourceCondition {
        condition_type: "Ready".into(),
        status: if ok { "True" } else { "False" }.into(),
        reason: reason.into(),
        message: message.into(),
        observed_generation: generation,
        last_transition_time: chrono::Utc::now().to_rfc3339(),
    }
}

fn ready_condition(generation: Option<i64>, reason: &str, message: &str) -> ResourceCondition {
    condition(true, generation, reason, message)
}

fn failed_condition(generation: Option<i64>, reason: &str, message: &str) -> ResourceCondition {
    condition(false, generation, reason, message)
}

/// An [`UpdateGroupStatus`] carrying only the generation-scoped fields (matched count, digest,
/// condition). The three join-credential fields are always `None`: [`ensure_group_join_credentials`]
/// owns them and writes them to the same status object, and because they skip-serialize when
/// `None`, a JSON *merge* patch built from this leaves the existing credential values untouched.
/// Centralized so that invariant lives in one place instead of being re-stated at every writer.
fn group_generation_status(
    generation: Option<i64>,
    matched_agents: Option<u32>,
    published_digest: Option<String>,
    condition: ResourceCondition,
) -> UpdateGroupStatus {
    UpdateGroupStatus {
        observed_generation: generation,
        matched_agents,
        published_digest,
        group_id: None,
        join_secret_ref: None,
        rotated_nonce: None,
        conditions: vec![condition],
    }
}

/// Fail a single misconfigured `UpdateGroup`'s own status and log it, so the rest of the
/// repository still publishes. The prior published digest is carried forward; the group simply
/// takes no part in this generation until it is fixed.
async fn quarantine_group(
    groups: &Api<UpdateGroup>,
    group: &UpdateGroup,
    reason: &str,
    message: &str,
) -> Result<(), kube::Error> {
    tracing::warn!(group = %group.name_any(), reason, message, "quarantining UpdateGroup for this generation");
    let status = group_generation_status(
        group.metadata.generation,
        None,
        group
            .status
            .as_ref()
            .and_then(|status| status.published_digest.clone()),
        failed_condition(group.metadata.generation, reason, message),
    );
    groups
        .patch_status(
            &group.name_any(),
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({"status": status})),
        )
        .await?;
    Ok(())
}

/// Fail a single misconfigured `UpdateAgent`'s own status and log it, leaving the rest of the
/// fleet to publish. The agent's assignment and enrollment Secret are withheld until it is
/// fixed; its last reported running state is preserved for observability.
async fn quarantine_agent(
    agents: &Api<UpdateAgent>,
    agent: &UpdateAgent,
    reason: &str,
    message: &str,
) -> Result<(), kube::Error> {
    tracing::warn!(agent = %agent.name_any(), reason, message, "quarantining UpdateAgent for this generation");
    let prior = agent.status.as_ref();
    let status = UpdateAgentStatus {
        observed_generation: agent.metadata.generation,
        selected_group: None,
        assignment_path: None,
        published_digest: prior.and_then(|status| status.published_digest.clone()),
        enrollment_secret_ref: None,
        reported_version: prior.and_then(|status| status.reported_version.clone()),
        reported_ready: prior.and_then(|status| status.reported_ready),
        conditions: vec![failed_condition(agent.metadata.generation, reason, message)],
    };
    agents
        .patch_status(
            &agent.name_any(),
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({"status": status})),
        )
        .await?;
    Ok(())
}

/// The three custom-resource API handles the reconcile loop threads together when writing back
/// status. Bundled so the status-publishing helpers take one handle instead of three positional
/// arguments.
struct ResourceApis<'a> {
    repositories: &'a Api<UpdateRepository>,
    groups: &'a Api<UpdateGroup>,
    agents: &'a Api<UpdateAgent>,
}

async fn publish_resource_statuses(
    apis: ResourceApis<'_>,
    repository: &UpdateRepository,
    group_resources: &[UpdateGroup],
    agent_resources: &[UpdateAgent],
    plan: &crate::PublicationPlan,
    reports: &HashMap<String, NodeReport>,
) -> Result<(), kube::Error> {
    let ResourceApis {
        repositories,
        groups,
        agents,
    } = apis;
    let params = PatchParams::default();
    let repository_generation = repository.metadata.generation;
    let repository_status = UpdateRepositoryStatus {
        observed_generation: repository_generation,
        published_digest: Some(plan.digest.clone()),
        agent_count: Some(agent_resources.len() as u32),
        conditions: vec![ready_condition(
            repository_generation,
            "Published",
            "The complete routing generation is published.",
        )],
    };
    repositories
        .patch_status(
            &repository.name_any(),
            &params,
            &Patch::Merge(serde_json::json!({"status": repository_status})),
        )
        .await?;

    for group in group_resources {
        let name = group.name_any();
        let matched = plan
            .node_groups
            .values()
            .filter(|selected| *selected == &name)
            .count();
        let status = group_generation_status(
            group.metadata.generation,
            Some(matched as u32),
            Some(plan.digest.clone()),
            ready_condition(
                group.metadata.generation,
                "Published",
                "This group's deployment is part of the published routing generation.",
            ),
        );
        groups
            .patch_status(
                &name,
                &params,
                &Patch::Merge(serde_json::json!({"status": status})),
            )
            .await?;
    }

    for agent in agent_resources {
        let name = agent.name_any();
        let selected = plan.node_groups[&name].clone();
        let report = reports.get(&name);
        let status = UpdateAgentStatus {
            observed_generation: agent.metadata.generation,
            selected_group: Some(selected),
            assignment_path: Some(crate::gateway::agent_assignment(
                &repository.spec.assignment_prefix,
                &name,
            )),
            published_digest: Some(plan.digest.clone()),
            reported_version: report
                .map(|report| report.version.clone())
                .filter(|version| !version.is_empty()),
            reported_ready: report.map(|report| report.healthy),
            enrollment_secret_ref: (agent.spec.identity.kind == crate::AgentIdentityKind::Manual)
                .then(|| crate::LocalSecretReference {
                    name: format!("{name}-enrollment"),
                }),
            conditions: vec![ready_condition(
                agent.metadata.generation,
                "Published",
                "This agent's exact assignment is published.",
            )],
        };
        agents
            .patch_status(
                &name,
                &params,
                &Patch::Merge(serde_json::json!({"status": status})),
            )
            .await?;
    }
    Ok(())
}

pub async fn record_repository_failure(
    client: Client,
    namespace: &str,
    repository_name: &str,
    message: &str,
) -> Result<(), kube::Error> {
    let repositories: Api<UpdateRepository> = Api::namespaced(client, namespace);
    let repository = repositories.get(repository_name).await?;
    let generation = repository.metadata.generation;
    let status = UpdateRepositoryStatus {
        observed_generation: generation,
        published_digest: repository.status.and_then(|status| status.published_digest),
        agent_count: None,
        conditions: vec![failed_condition(generation, "ReconciliationFailed", message)],
    };
    repositories
        .patch_status(
            repository_name,
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({"status": status})),
        )
        .await?;
    Ok(())
}

fn desired_publication_digest(
    repository: &crate::UpdateRepositorySpec,
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

    #[test]
    fn consistent_snapshot_metadata_versions_are_resolved_from_signed_parents() {
        let timestamp = serde_json::json!({"signed":{"meta":{"snapshot.json":{"version":7}}}});
        let snapshot = serde_json::json!({"signed":{"meta":{"targets.json":{"version":11}}}});
        assert_eq!(metadata_version(&timestamp, "snapshot.json").unwrap(), 7);
        assert_eq!(metadata_version(&snapshot, "targets.json").unwrap(), 11);
        assert!(metadata_version(&snapshot, "missing.json").is_err());
    }

    fn repository(bucket: &str) -> crate::UpdateRepositorySpec {
        crate::UpdateRepositorySpec {
            default_deployment: crate::DeploymentSpec {
                name: "default".into(),
                report_url: None,
                release_repository: crate::ReleaseRepositorySpec {
                    metadata_url: "https://example.test/metadata/".into(),
                    targets_url: "https://example.test/targets/".into(),
                    root_json: serde_json::json!({"signed": {}, "signatures": []}).to_string(),
                },
                application: crate::TargetSpec {
                    path: "app".into(),
                    sha256: "1".repeat(64),
                },
                ordered_install_fallback: false,
                provider_set: crate::TargetSpec {
                    path: "providers".into(),
                    sha256: "2".repeat(64),
                },
                runtime: crate::RuntimeSpec {
                    product: "app".into(),
                    channel: "stable".into(),
                    install_root: "/opt/app".into(),
                    args: vec![],
                    health_checks: vec![crate::HealthCheckSpec {
                        kind: crate::HealthCheckKindSpec::Readiness,
                        url: "http://127.0.0.1:8080/health".into(),
                    }],
                    repository: crate::RepositoryLimitsSpec {
                        metadata_limit: 1_048_576,
                        target_limit: 536_870_912,
                        transport_timeout_seconds: 30,
                    },
                    storage: crate::StorageSpec {
                        inactive_releases: 2,
                        inactive_providers: 2,
                        inactive_supervisors: 2,
                        inactive_bytes: 1_073_741_824,
                        inactive_repository_caches: 2,
                    },
                    timeouts: crate::TimeoutsSpec {
                        check_interval_seconds: 60,
                        health_grace_seconds: 30,
                        health_successes: 2,
                        health_interval_seconds: 1,
                        retry_after_seconds: 60,
                        refresh_retry_seconds: 5,
                        confirmation_window_seconds: 120,
                        supervisor_check_interval_seconds: 3600,
                        drain_hold_seconds: Some(0),
                    },
                },
            },
            signing_secret_ref: crate::LocalSecretReference {
                name: "keys".into(),
            },
            enrollment: crate::EnrollmentSpec {
                labels: Default::default(),
            },
            s3: crate::S3Destination {
                bucket: bucket.into(),
                prefix: String::new(),
                region: "us-east-1".into(),
                credentials_secret_ref: None,
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
