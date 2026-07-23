use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use futures::StreamExt;
use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::api::core::v1::{ConfigMap, Secret};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{MicroTime, OwnerReference};
use k8s_openapi::ByteString;
use kube::api::{Api, ListParams, Patch, PatchParams, PostParams};
use kube::{Client, Resource, ResourceExt};
use object_store::aws::AmazonS3Builder;
use object_store::{ObjectStore, PutPayload};

use crate::publisher::{upload_order, PublishError};
use crate::rollout::SetStatus;
use crate::S3Destination;
use crate::{
    ResolvedGroup, ResolvedNode, ResourceCondition, UpdateAgent, UpdateAgentStatus, UpdateGroup,
    UpdateGroupSet, UpdateGroupSetStatus, UpdateGroupStatus, UpdateRepository,
    UpdateRepositoryStatus, UpdateSubscription,
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
    // `lease` still carries the `resourceVersion` we read, so this PUT is a compare-and-swap: if any
    // other candidate acquired or renewed in the meantime, the apiserver rejects it with a 409 and we
    // become a follower. That makes the lease a strict single writer — two candidates can never both
    // believe they hold it — which, together with the in-cluster admitted set, is what serializes
    // publication across a leader change.
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

/// Read-only check that `identity` still holds the lease `name` and it has not expired. Used to
/// re-verify leadership right before the irreversible S3 publish: the main loop only renews on a 5s
/// tick, and CPU-bound TUF signing can starve that past the lease deadline, so a former leader whose
/// lease was already taken over could otherwise keep uploading.
async fn holds_lease(
    client: &Client,
    namespace: &str,
    name: &str,
    identity: &str,
) -> Result<bool, kube::Error> {
    let leases: Api<Lease> = Api::namespaced(client.clone(), namespace);
    let Some(lease) = leases.get_opt(name).await? else {
        return Ok(false);
    };
    let Some(spec) = lease.spec else {
        return Ok(false);
    };
    Ok(spec.holder_identity.as_deref() == Some(identity)
        && !lease_expired(&spec, chrono::Utc::now()))
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

/// Whether the object store already holds a published TUF generation (its `timestamp.json`). Used
/// to fail closed when the local publisher state is empty but the store is not — re-initializing a
/// fresh v1 TUF repo over an existing higher-versioned one would roll the generation back below the
/// fleet's rollback floor and stall convergence.
async fn store_has_published_metadata(
    store: &dyn ObjectStore,
    destination: &S3Destination,
) -> Result<bool, StorageError> {
    let key = crate::object_key(&destination.prefix, "metadata/timestamp.json");
    match store.head(&key).await {
        Ok(_) => Ok(true),
        Err(object_store::Error::NotFound { .. }) => Ok(false),
        Err(e) => Err(StorageError(format!("probing published metadata: {e}"))),
    }
}

/// The finalizer that keeps a deleted [`UpdateRepository`] in `Terminating` until its published
/// object-storage prefix has been pruned. The signed TUF metadata and bundles under that prefix are
/// durable, external state Kubernetes garbage collection cannot reach, so without this a deleted
/// repository would orphan signed artifacts in the bucket/CDN indefinitely. In-cluster children
/// (enrollment/join Secrets, the admitted-state ConfigMap) instead carry owner references and are
/// reclaimed by ordinary Kubernetes GC — the finalizer is reserved for what GC cannot see.
const REPOSITORY_FINALIZER: &str = "updated.dev/published-artifacts";

/// The finalizer list with ours appended, or `None` if it is already present (so the caller can skip
/// a needless write). A foreign finalizer another controller owns is preserved.
fn finalizers_with(existing: &[String]) -> Option<Vec<String>> {
    if existing.iter().any(|f| f == REPOSITORY_FINALIZER) {
        return None;
    }
    let mut next = existing.to_vec();
    next.push(REPOSITORY_FINALIZER.to_string());
    Some(next)
}

/// The finalizer list with ours removed, retaining any others a different controller owns.
fn finalizers_without(existing: &[String]) -> Vec<String> {
    existing
        .iter()
        .filter(|f| f.as_str() != REPOSITORY_FINALIZER)
        .cloned()
        .collect()
}

/// Add our finalizer to a live repository if it is missing, so a later deletion is held open until
/// the published prefix is pruned. A merge patch of the full finalizer list; skipped when present.
async fn ensure_repository_finalizer(
    repositories: &Api<UpdateRepository>,
    repository: &UpdateRepository,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(finalizers) = finalizers_with(repository.finalizers()) else {
        return Ok(());
    };
    repositories
        .patch(
            &repository.name_any(),
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({ "metadata": { "finalizers": finalizers } })),
        )
        .await?;
    Ok(())
}

/// Prune a deleting repository's published prefix, then drop our finalizer so Kubernetes can complete
/// deletion. Idempotent and resumable: the finalizer holds the object in `Terminating`, so a crash
/// mid-prune simply re-runs next reconcile, and re-pruning an already-empty prefix is a no-op.
async fn finalize_repository(
    repositories: &Api<UpdateRepository>,
    secrets: &Api<Secret>,
    repository: &UpdateRepository,
) -> Result<(), Box<dyn std::error::Error>> {
    if !repository
        .finalizers()
        .iter()
        .any(|f| f == REPOSITORY_FINALIZER)
    {
        // A prior pass already pruned and released the finalizer; nothing left but to let GC finish.
        return Ok(());
    }
    let store = build_store(secrets, &repository.spec.s3).await?;
    let pruned = prune_prefix(store.as_ref(), &repository.spec.s3.prefix).await?;
    tracing::info!(
        repository = %repository.name_any(),
        prefix = %repository.spec.s3.prefix,
        pruned,
        "pruned a deleted repository's published artifacts",
    );
    repositories
        .patch(
            &repository.name_any(),
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({
                "metadata": { "finalizers": finalizers_without(repository.finalizers()) }
            })),
        )
        .await?;
    Ok(())
}

/// Delete every object under `prefix` in `store`, returning the count removed. Locations are collected
/// before deletion so the list connection is not held open across the deletes; a TUF repository's
/// object count is modest (metadata plus a bounded set of bundles), so this stays bounded. An empty
/// prefix scopes to the whole bucket — the repository's contract is that its prefix namespaces exactly
/// its own artifacts.
async fn prune_prefix(store: &dyn ObjectStore, prefix: &str) -> Result<usize, StorageError> {
    let trimmed = prefix.trim_matches('/');
    let scope = (!trimmed.is_empty()).then(|| object_store::path::Path::from(trimmed));
    let mut listing = store.list(scope.as_ref());
    let mut locations = Vec::new();
    while let Some(entry) = listing.next().await {
        let meta = entry.map_err(|e| StorageError(format!("listing objects to prune: {e}")))?;
        locations.push(meta.location);
    }
    drop(listing);
    let pruned = locations.len();
    for location in locations {
        store
            .delete(&location)
            .await
            .map_err(|e| StorageError(format!("deleting {location}: {e}")))?;
    }
    Ok(pruned)
}

pub async fn reconcile_once(
    client: Client,
    namespace: &str,
    repository_name: &str,
    state_dir: &Path,
    public_url: &str,
    identity: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let repositories: Api<UpdateRepository> = Api::namespaced(client.clone(), namespace);
    let repository = repositories.get(repository_name).await?;
    let groups_api: Api<UpdateGroup> = Api::namespaced(client.clone(), namespace);
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let nodes_api: Api<UpdateAgent> = Api::namespaced(client.clone(), namespace);
    let sets_api: Api<UpdateGroupSet> = Api::namespaced(client.clone(), namespace);
    let configmaps: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);

    // Finalizer gate. The published TUF metadata and signed bundles live under this repository's S3
    // prefix — durable, external state Kubernetes GC cannot reach — so a finalizer holds a deleted
    // UpdateRepository in `Terminating` until that prefix is pruned, and is placed on a live one so
    // the guarantee is in effect before anything is ever published.
    if repository.metadata.deletion_timestamp.is_some() {
        finalize_repository(&repositories, &secrets, &repository).await?;
        return Ok(format!("finalized repository {repository_name}"));
    }
    ensure_repository_finalizer(&repositories, &repository).await?;

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
                max_unavailable: match group.spec.max_unavailable {
                    Some(0) => {
                        quarantine_group(
                            &groups_api,
                            group,
                            "InvalidMaxUnavailable",
                            "maxUnavailable must be at least one",
                        )
                        .await?;
                        quarantined_groups.insert(name);
                        continue;
                    }
                    value => value.unwrap_or(1),
                },
            },
        );
        group_labels.insert(name, group.labels().clone());
    }
    group_resources
        .items
        .retain(|group| !quarantined_groups.contains(&group.name_any()));

    let mut agent_resources = nodes_api.list(&ListParams::default()).await?;
    agent_resources
        .items
        .retain(|agent| agent.spec.repository_ref.name == repository_name);
    // Quarantine a malformed-identity agent — never the whole reconcile — and drop it from this
    // generation: a bad identity never resolved to an assignment, so there is nothing to preserve.
    // Overlapping selectors are deliberately NOT handled here. An ambiguous node must hold the last
    // known-good routing (fail safe, never fail open — docs/state-machines.md), so we leave it in
    // the plan and let `build_publication_plan` fault the whole generation closed with
    // `AmbiguousNode`; `reconcile_once` returns that error and the previous publication stays live.
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
    // node telemetry that drives rollout planning — so build it up front.
    let store = build_store(&secrets, &repository.spec.s3).await?;

    let agent_names: Vec<String> = resolved_nodes
        .iter()
        .map(|node| node.name.clone())
        .collect();
    let reports = read_node_reports(store.as_ref(), &repository.spec.s3.prefix, &agent_names).await;
    // Node → pinned public key (raw EC point), decoded from each agent's enrollment identity. The
    // planner verifies every report's signature against it, so only health it can cryptographically
    // attribute to the node itself advances a rollout — a forged or tampered report is ignored.
    let public_keys: HashMap<String, Vec<u8>> = agent_resources
        .iter()
        .filter_map(|agent| {
            let hex_point = agent.spec.identity.public_key.as_ref()?;
            Some((agent.name_any(), hex::decode(hex_point).ok()?))
        })
        .collect();
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
    // The admitted set (each group's currently-pinned deployment) lives durably in-cluster — a
    // ConfigMap keyed by group — NOT on the node-local PVC. That is what survives an HA leader
    // change or a cold/rescheduled PVC: a fresh leader loads the real admitted baseline from etcd
    // instead of re-seeding every group to the current desired and admitting a whole set at once
    // (the `max_concurrent` breach that node-local state allowed). The single publisher lease keeps
    // this a single writer; the write below is a resourceVersion compare-and-swap as a second guard.
    let admitted_name = admitted_configmap_name(repository_name);
    let (mut admitted, admitted_version) = load_admitted_state(&configmaps, &admitted_name).await?;
    let reconcile_now = chrono::Utc::now();
    let outcome = crate::domain::plan_reconcile(
        crate::domain::DesiredState {
            repository: &repository.spec,
            groups: &groups,
            group_labels: &group_labels,
            sets: &set_resources.items,
            nodes: &resolved_nodes,
        },
        crate::domain::ObservedState {
            reports: &reports,
            public_keys: &public_keys,
            admitted: &admitted,
            now: reconcile_now,
        },
    )?;
    let crate::domain::ReconcilePlan {
        publication: plan,
        admitted: planned_admitted,
        set_statuses,
    } = outcome;
    // Reconcile runs every second; only write when the admitted set actually changed so a steady
    // generation makes no apiserver writes.
    if admitted != planned_admitted {
        admitted = planned_admitted;
        store_admitted_state(
            &configmaps,
            &admitted_name,
            namespace,
            &admitted,
            admitted_version,
            repository.controller_owner_ref(&()),
        )
        .await?;
    }

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
            StatusSnapshot {
                repository: &repository,
                groups: &group_resources.items,
                agents: &agent_resources.items,
                plan: &plan,
                reports: &reports,
                admitted: &admitted,
                public_keys: &public_keys,
                now: reconcile_now,
            },
        )
        .await?;
        publish_group_set_statuses(&sets_api, &set_resources.items, &set_statuses).await?;
        deliver_subscriptions(&client, namespace, &repository, state_dir, public_url).await;
        return Ok(plan.digest);
    }

    let signing = secrets
        .get(&repository.spec.signing_secret_ref.name)
        .await?;
    let keys_dir = state_dir.join("keys");
    materialize_signing_keys(&signing, &keys_dir).await?;
    let repo_dir = state_dir.join("repository");
    if !repo_dir.join("metadata/root.json").exists() {
        // A fresh local state_dir (a lost PVC or a replica that never held the lease) must NOT
        // re-init a v1 TUF repo when the object store already holds a published generation: clients
        // enforce a rollback floor, so a v1 (< their current) would be rejected and the fleet would
        // stop converging until numbering caught back up. Fail closed — refuse rather than roll back.
        if store_has_published_metadata(store.as_ref(), &repository.spec.s3).await? {
            return Err(Box::new(StorageError(
                "local publisher state is empty but the object store already holds a published \
                 generation; refusing to re-initialize a v1 TUF repo (restore the state volume)"
                    .into(),
            )));
        }
        updated_tuf::repo::init(&repo_dir, &updated_tuf::repo::Keys::in_dir(&keys_dir), 365)
            .await?;
    }
    crate::publisher::sign_plan(&repo_dir, &keys_dir, &plan, 365).await?;

    // Re-verify leadership right before the irreversible S3 publish. The CPU-bound signing above can
    // starve the main loop's 5s lease renewal past the 15s deadline; without this a former leader
    // whose lease already expired (and was taken over by another replica) would still upload here,
    // double-writing the generation. This closes the largest window (post-signing); the residual
    // check→PUT gap is one request wide. Fail closed — skip the publish rather than split-brain write.
    if !holds_lease(&client, namespace, "updatec-publisher", identity).await? {
        return Err(Box::new(StorageError(
            "publisher lease lost during reconcile; skipping publish to avoid a split-brain write"
                .into(),
        )));
    }

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
        StatusSnapshot {
            repository: &repository,
            groups: &group_resources.items,
            agents: &agent_resources.items,
            plan: &plan,
            reports: &reports,
            admitted: &admitted,
            public_keys: &public_keys,
            now: reconcile_now,
        },
    )
    .await?;
    publish_group_set_statuses(&sets_api, &set_resources.items, &set_statuses).await?;
    deliver_subscriptions(&client, namespace, &repository, state_dir, public_url).await;
    Ok(plan.digest)
}

/// Push change-tracking events to every [`UpdateSubscription`](crate::UpdateSubscription) covering
/// this repository, catching each subscriber up to the currently published generation. Runs on every
/// reconcile — including the no-change path — so a subscription created (or a webhook recovered)
/// after a publish is still caught up on the next tick. Best-effort: a delivery or status-write
/// failure is logged and retried, never allowed to block publication.
async fn deliver_subscriptions(
    client: &Client,
    namespace: &str,
    repository: &UpdateRepository,
    state_dir: &Path,
    public_url: &str,
) {
    let repo_dir = state_dir.join("repository");
    if !repo_dir.join("metadata/timestamp.json").exists() {
        return; // nothing has been published yet — no generation to announce.
    }
    let outcome = async {
        let version = updated_tuf::repo::current_version(&repo_dir).await?;
        let subscriptions: Api<UpdateSubscription> = Api::namespaced(client.clone(), namespace);
        let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
        crate::subscription::deliver_updates(
            &subscriptions,
            &secrets,
            &repository.name_any(),
            namespace,
            &repository.spec.s3.prefix,
            public_url,
            version,
            &chrono::Utc::now().to_rfc3339(),
        )
        .await
    }
    .await;
    if let Err(error) = outcome {
        tracing::warn!(error = %error, "delivering update subscriptions");
    }
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

/// The ConfigMap name that durably holds this repository's admitted set (group → pinned
/// deployment). Named from the repository so two repositories in one namespace never collide;
/// the repository name is itself a valid Kubernetes resource name, so this always is too.
fn admitted_configmap_name(repository_name: &str) -> String {
    format!("updatec-admitted-{repository_name}")
}

/// Load the durable admitted set from its in-cluster ConfigMap. Returns the map (empty the very
/// first time, before the ConfigMap exists) and the ConfigMap's `resourceVersion` for a
/// compare-and-swap on write. The state is one document and fails closed as one document: partial
/// recovery could silently rebaseline a group and violate rollout concurrency.
async fn load_admitted_state(
    configmaps: &Api<ConfigMap>,
    name: &str,
) -> Result<
    (
        BTreeMap<String, crate::rollout::AdmittedDeployment>,
        Option<String>,
    ),
    Box<dyn std::error::Error>,
> {
    let Some(configmap) = configmaps.get_opt(name).await? else {
        return Ok((BTreeMap::new(), None));
    };
    let resource_version = configmap.metadata.resource_version.clone();
    let encoded = configmap
        .data
        .as_ref()
        .and_then(|data| data.get("state.json"))
        .ok_or_else(|| StorageError("admitted-state ConfigMap has no state.json".into()))?;
    let admitted = serde_json::from_str(encoded)
        .map_err(|error| StorageError(format!("invalid admitted state: {error}")))?;
    Ok((admitted, resource_version))
}

/// Persist the admitted set back to its ConfigMap. `resource_version` is `Some` when the ConfigMap
/// already existed: the write is then a `replace` gated on that version, so a second writer that
/// briefly overlapped a leader change cannot clobber the winner's admitted set — a conflicting
/// write is a 409 the caller surfaces and retries, never a silent last-writer-wins. The very first
/// write (`None`) is a `create`, which 409s if another writer created it first.
async fn store_admitted_state(
    configmaps: &Api<ConfigMap>,
    name: &str,
    namespace: &str,
    admitted: &BTreeMap<String, crate::rollout::AdmittedDeployment>,
    resource_version: Option<String>,
    owner: Option<OwnerReference>,
) -> Result<(), Box<dyn std::error::Error>> {
    let data = BTreeMap::from([("state.json".into(), serde_json::to_string(admitted)?)]);
    // Own the ConfigMap by its repository so deleting the repository reclaims this admitted-state
    // through ordinary Kubernetes GC — no finalizer needed for an in-cluster child.
    let configmap = ConfigMap {
        metadata: kube::api::ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            resource_version: resource_version.clone(),
            owner_references: owner.map(|owner| vec![owner]),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };
    if resource_version.is_some() {
        configmaps
            .replace(name, &PostParams::default(), &configmap)
            .await?;
    } else {
        configmaps
            .create(&PostParams::default(), &configmap)
            .await?;
    }
    Ok(())
}

/// Publish each `UpdateGroupSet`'s observed rollout state as its status.
async fn publish_group_set_statuses(
    sets: &Api<UpdateGroupSet>,
    set_resources: &[UpdateGroupSet],
    statuses: &[SetStatus],
) -> Result<(), kube::Error> {
    let params = PatchParams::default();
    let by_name: HashMap<&str, &SetStatus> = statuses
        .iter()
        .map(|status| (status.name.as_str(), status))
        .collect();
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
        let assignment =
            crate::gateway::agent_assignment(&repository.spec.assignment_prefix, &name);
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

/// An [`UpdateGroupStatus`] carrying the generation-scoped fields (matched count, digest,
/// condition). Centralized so the status shape lives in one place instead of being re-stated at
/// every writer.
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

struct StatusSnapshot<'a> {
    repository: &'a UpdateRepository,
    groups: &'a [UpdateGroup],
    agents: &'a [UpdateAgent],
    plan: &'a crate::PublicationPlan,
    reports: &'a HashMap<String, NodeReport>,
    admitted: &'a BTreeMap<String, crate::rollout::AdmittedDeployment>,
    public_keys: &'a HashMap<String, Vec<u8>>,
    now: chrono::DateTime<chrono::Utc>,
}

async fn publish_resource_statuses(
    apis: ResourceApis<'_>,
    snapshot: StatusSnapshot<'_>,
) -> Result<(), kube::Error> {
    let ResourceApis {
        repositories,
        groups,
        agents,
    } = apis;
    let StatusSnapshot {
        repository,
        groups: group_resources,
        agents: agent_resources,
        plan,
        reports,
        admitted,
        public_keys,
        now,
    } = snapshot;
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
        let rolling = admitted
            .get(&name)
            .is_some_and(|state| state.previous.is_some());
        let held = admitted
            .get(&name)
            .is_some_and(|state| state.current.deployment != group.spec.deployment.name);
        let status = group_generation_status(
            group.metadata.generation,
            Some(matched as u32),
            Some(plan.digest.clone()),
            if held || rolling {
                ResourceCondition {
                    condition_type: "Ready".into(),
                    status: "False".into(),
                    reason: if held { "Held" } else { "Rolling" }.into(),
                    message: if held {
                        "This group's desired deployment is waiting for rollout capacity."
                    } else {
                        "This group is incrementally advancing to its admitted deployment."
                    }
                    .into(),
                    observed_generation: group.metadata.generation,
                    last_transition_time: chrono::Utc::now().to_rfc3339(),
                }
            } else {
                ready_condition(
                    group.metadata.generation,
                    "Published",
                    "This group's deployment is fully admitted in the published routing generation.",
                )
            },
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
        let report = reports.get(&name).filter(|report| {
            let now_ms = now.timestamp_millis().max(0) as u64;
            report.node == name
                && report.age_ms(now_ms) <= updated::telemetry::REPORT_FRESHNESS.as_millis() as u64
                && public_keys
                    .get(&name)
                    .is_some_and(|key| updated::telemetry::verify_report(report, key))
        });
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

/// A GENERIC, categorized failure message safe to write into the `UpdateRepository` `.status`,
/// which anyone with `get` on the CR can read. The underlying `object_store`/`kube` error can carry
/// infrastructure detail (bucket, endpoint, object key), so it must NEVER be serialized into status
/// — the caller logs the full `error` at error-level for operators and writes only this category
/// here. Downcast is best-effort; anything unrecognized maps to the fully generic bucket.
pub fn generic_failure_status(error: &(dyn std::error::Error + 'static)) -> &'static str {
    if error.is::<kube::Error>() {
        "reconciliation failed: kubernetes API error (see controller logs)"
    } else if error.is::<StorageError>() {
        "reconciliation failed: repository storage error (see controller logs)"
    } else if error.is::<std::io::Error>() {
        "reconciliation failed: local state error (see controller logs)"
    } else if error.is::<serde_json::Error>() {
        "reconciliation failed: serialization error (see controller logs)"
    } else {
        "reconciliation failed (see controller logs)"
    }
}

/// Write a failure to the `UpdateRepository` `.status`. `message` MUST be a generic, non-sensitive
/// string (see [`generic_failure_status`]); the full error belongs only in the controller log.
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
        conditions: vec![failed_condition(
            generation,
            "ReconciliationFailed",
            message,
        )],
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
                report_url: "https://control.example/v1/telemetry".into(),
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

    #[test]
    fn finalizer_list_adds_once_and_removes_cleanly() {
        // Absent -> appended; already present -> no write needed.
        assert_eq!(
            finalizers_with(&[]),
            Some(vec![REPOSITORY_FINALIZER.to_string()])
        );
        assert_eq!(finalizers_with(&[REPOSITORY_FINALIZER.to_string()]), None);
        // A finalizer another controller owns is preserved when adding and when removing ours.
        let mixed = vec!["other/keep".to_string(), REPOSITORY_FINALIZER.to_string()];
        assert_eq!(finalizers_with(&mixed), None);
        assert_eq!(finalizers_without(&mixed), vec!["other/keep".to_string()]);
        assert_eq!(finalizers_without(&[]), Vec::<String>::new());
    }

    #[tokio::test]
    async fn prune_prefix_removes_only_the_repositorys_objects() {
        use object_store::memory::InMemory;
        use object_store::path::Path as ObjPath;

        let store = InMemory::new();
        let put = |key: &'static str| {
            let store = &store;
            async move {
                store
                    .put(
                        &ObjPath::from(key),
                        PutPayload::from_bytes(b"x".to_vec().into()),
                    )
                    .await
                    .unwrap();
            }
        };
        put("tenant/routing/metadata/timestamp.json").await;
        put("tenant/routing/metadata/root.json").await;
        put("tenant/routing/targets/app/1.0.0").await;
        // A different repository under a sibling prefix must survive.
        put("tenant/other/metadata/timestamp.json").await;

        let pruned = prune_prefix(&store, "tenant/routing").await.unwrap();
        assert_eq!(pruned, 3);

        let mut remaining = store.list(None);
        let mut keys = Vec::new();
        while let Some(entry) = remaining.next().await {
            keys.push(entry.unwrap().location.to_string());
        }
        assert_eq!(
            keys,
            vec!["tenant/other/metadata/timestamp.json".to_string()]
        );

        // Re-pruning an already-clean prefix is a no-op — the resumability the finalizer relies on.
        assert_eq!(prune_prefix(&store, "tenant/routing").await.unwrap(), 0);
    }
}
