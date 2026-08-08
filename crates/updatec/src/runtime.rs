use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
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
use updated_contracts::telemetry::Envelope;

const LEASE_SECONDS: i32 = 15;

/// The point at which the durable rollout-state ConfigMap is reported as approaching the 1 MiB
/// object ceiling the apiserver enforces. A warning threshold with headroom, never a refusal —
/// see [`store_admitted_state`].
const STATE_BYTES_LIMIT: usize = 768 * 1024;

/// The most `UpdateAgent`s one repository will dynamically enrol.
///
/// `/enroll` is authenticated by the fleet-wide bootstrap certificate and the node names itself, so
/// without a ceiling one caller could create agents until the durable rollout state — which is one
/// ConfigMap, and grows with every published agent — passed the apiserver's 1 MiB object limit. At
/// that point NO generation can ever be published again, for any node, and nothing releases it.
/// This cap sits well below that wall (the per-agent cost of the routing and assignment maps is
/// tens of bytes), so the failure is a refused enrolment naming the limit instead of a repository
/// that can no longer publish.
pub(crate) const MAX_ENROLLED_AGENTS: u32 = 10_000;

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

/// Static S3 credentials, or all-`None` to fall back to the environment's workload identity.
#[derive(Default)]
pub struct S3Credentials<'a> {
    pub access_key: Option<&'a str>,
    pub secret_key: Option<&'a str>,
    /// Required by every temporary credential — STS `AssumeRole`, IRSA, an SSO session. Dropping
    /// it turns a valid temporary key pair into one S3 rejects, so an operator publishing with
    /// assumed-role credentials gets an authorization failure with nothing obviously wrong.
    pub session_token: Option<&'a str>,
}

pub fn s3_store(
    destination: &S3Destination,
    credentials: S3Credentials<'_>,
) -> Result<Arc<dyn ObjectStore>, StorageError> {
    let S3Credentials {
        access_key,
        secret_key,
        session_token,
    } = credentials;
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
        if let Some(token) = session_token {
            builder = builder.with_token(token);
        }
    }
    builder
        .build()
        .map(|store| Arc::new(store) as Arc<dyn ObjectStore>)
        .map_err(|e| StorageError(format!("configuring S3 store: {e}")))
}

fn validate_object_prefix(prefix: &str) -> Result<(), StorageError> {
    let trimmed = prefix.trim_matches('/');
    // Empty = bucket root. Otherwise the prefix must already be normalized (no surrounding slashes)
    // and a confined relative path — the one shared traversal guard, so it can never climb out of
    // the bucket's key space.
    if prefix != trimmed
        || (!trimmed.is_empty() && !updated_contracts::path::is_confined_relative(trimmed))
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
    // A session token is present only for temporary credentials, so absence is normal.
    let token = optional_secret_string(credentials.as_ref(), "AWS_SESSION_TOKEN")?;
    Ok(s3_store(
        destination,
        S3Credentials {
            access_key: access.as_deref(),
            secret_key: secret.as_deref(),
            session_token: token.as_deref(),
        },
    )?)
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

/// The generation the object store is currently serving, read from the `version` of its published
/// `timestamp.json`. `None` when the store holds no generation at all.
///
/// The ONE question asked of the store about published state, for every guard that needs it: has
/// anything been published, and how far has it got? Both answers exist for the same reason — TUF
/// clients remember the highest version they accepted and refuse anything lower, so publishing
/// metadata numbered below what the store already serves wedges every node in the fleet
/// permanently.
///
/// Read unverified, deliberately. This is not a trust decision but a rollback guard on this
/// replica's own writes; anyone able to forge the number already holds write access to the prefix,
/// and the worst a forged one can do is make this publisher refuse to publish.
async fn store_published_version(
    store: &dyn ObjectStore,
    destination: &S3Destination,
) -> Result<Option<u64>, StorageError> {
    let key = crate::object_key(&destination.prefix, "metadata/timestamp.json");
    let bytes = match crate::read_object_bounded(store, &key).await {
        Ok(bytes) => bytes,
        Err(object_store::Error::NotFound { .. }) => return Ok(None),
        Err(e) => return Err(StorageError(format!("probing published metadata: {e}"))),
    };
    signed_version(&bytes)
        .ok_or_else(|| StorageError("published timestamp.json has no signed.version".into()))
        .map(Some)
}

/// The ONE rollback guard, asked before a pass signs anything: would the metadata this replica is
/// about to upload be numbered BELOW what the store already serves?
///
/// Clients enforce a rollback floor, so a lower generation is rejected by every node that saw the
/// higher one — forever, and with no self-healing path, because the replica that published it then
/// records its own publication marker and never republishes.
///
/// Both ways of being behind are the same question, so they are answered here together. An EMPTY
/// local state dir (a lost PVC, or a replica that never held the lease) would re-initialize at
/// version 1. A STALE one is worse because it looks healthy: a replica that led up to version 5,
/// lost the lease while another replica advanced the store to 40, and later reacquired it has
/// `root.json` on disk and a stale publication marker — and `replace_release` numbers the next
/// generation from LOCAL metadata, so it would upload version 6 over 40. Fail closed either way;
/// what must be restored is the state volume of the replica holding the newest metadata (or the
/// published prefix deleted to start over).
async fn refuse_generation_rollback(
    store: &dyn ObjectStore,
    destination: &S3Destination,
    repo_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(published) = store_published_version(store, destination).await? else {
        return Ok(()); // nothing is served, so nothing can be rolled back.
    };
    if !repo_dir.join("metadata/root.json").exists() {
        return Err(Box::new(StorageError(
            "local publisher state is empty but the object store already holds a published \
             generation; refusing to re-initialize a v1 TUF repo (restore the state volume)"
                .into(),
        )));
    }
    let local = updated_tuf::repo::current_version(repo_dir).await?;
    if local < published {
        return Err(Box::new(StorageError(format!(
            "local publisher state is at TUF generation {local} but the object store already \
             serves {published}; refusing to publish a lower generation every node would reject as \
             a rollback (restore the state volume of the replica that published {published})"
        ))));
    }
    Ok(())
}

/// The generation a signed TUF role document declares, or `None` if the bytes are not a role
/// document with a `signed.version`.
///
/// The one extractor. Two guards ask this question of the same objects in the same bucket for the
/// same reason — never publish below what the store already serves: this module's rollback guard,
/// and `updatectl`'s republish guard. They differ only in what an unreadable document means to
/// them (a hard error here, a zero there), which is the caller's decision to make, not a reason
/// for a second parser.
pub fn signed_version(bytes: &[u8]) -> Option<u64> {
    serde_json::from_slice::<serde_json::Value>(bytes)
        .ok()?
        .pointer("/signed/version")?
        .as_u64()
}

/// The finalizer that keeps a deleted [`UpdateRepository`] in `Terminating` until its published
/// object-storage prefix has been pruned. The signed TUF metadata and bundles under that prefix are
/// durable, external state Kubernetes garbage collection cannot reach, so without this a deleted
/// repository would orphan signed artifacts in the bucket/CDN indefinitely. In-cluster children
/// (enrollment Secrets and the admitted-state ConfigMap) instead carry owner references and are
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
    client: &Client,
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
    // An empty prefix is not a scope, it is the whole bucket — which routinely also holds the
    // release TUF repository and every published bundle. Deleting a repository must never be able
    // to delete artifacts it does not own, so an unscoped repository is released WITHOUT pruning:
    // leaving objects behind is recoverable, deleting the bucket is not.
    if repository.spec.s3.prefix.trim_matches('/').is_empty() {
        tracing::warn!(
            repository = %repository.name_any(),
            "deleted repository has an empty s3 prefix, which is not a scope this finalizer can \
             safely prune (it would list and delete the entire bucket); releasing the finalizer \
             and leaving its published artifacts in place — remove them by hand",
        );
    } else if let Some(sibling) = overlapping_sibling(client, repository).await? {
        // The same rule one level of nesting deeper: a prefix that is an ancestor of (or equal to)
        // another repository's is not a scope either, because an object-store list is prefix-scoped
        // and would sweep that repository's signed metadata and every published assignment. The
        // sibling OBJECT existing is enough — whether or not it is itself deleting — because
        // leaving objects behind is recoverable and deleting another repository's is not, so two
        // nested repositories deleted together each block the other and both prefixes survive.
        tracing::warn!(
            repository = %repository.name_any(),
            prefix = %repository.spec.s3.prefix,
            sibling = %sibling.0,
            sibling_prefix = %sibling.1,
            "deleted repository's s3 prefix overlaps another repository's in the same bucket, so \
             pruning it would delete that repository's published artifacts; releasing the \
             finalizer and leaving this repository's artifacts in place — remove them by hand",
        );
    } else {
        let store = build_store(secrets, &repository.spec.s3).await?;
        let pruned = prune_prefix(store.as_ref(), &repository.spec.s3.prefix).await?;
        tracing::info!(
            repository = %repository.name_any(),
            prefix = %repository.spec.s3.prefix,
            pruned,
            "pruned a deleted repository's published artifacts",
        );
    }
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

/// The `namespace/name` and prefix of a sibling `UpdateRepository` whose published key space
/// overlaps `repository`'s, if there is one.
///
/// An object-store list is prefix-scoped, so a prune deletes everything BELOW the prefix as well.
/// Nesting one repository's prefix inside another's in the same bucket (`fleet` and `fleet/staging`)
/// is a natural way to divide tenants and nothing refuses it, so deleting the outer one would sweep
/// the inner one's signed metadata and every published assignment while it is still live and Ready.
/// Two repositories are in the same key space when they name the same bucket and their endpoints are
/// not DEFINITIVELY different (see [`endpoints_definitely_differ`]) — the bucket is what scopes the
/// keys, and an endpoint written two ways is one store.
///
/// The rule is purely about STORAGE, so the search is across ALL NAMESPACES: a bucket is not scoped
/// to a namespace, and tenants divided by namespace are exactly the ones that share one. Searching
/// only the deleted repository's own namespace made every cross-namespace nesting invisible —
/// deleting `fleet` in `tenant-a` still pruned `tenant-b`'s live `fleet/staging`, the precise loss
/// this guard exists to prevent. Only the repository being finalized is excluded, matched on
/// namespace AND name, since a same-named repository elsewhere is a different object.
async fn overlapping_sibling(
    client: &Client,
    repository: &UpdateRepository,
) -> Result<Option<(String, String)>, kube::Error> {
    let repositories: Api<UpdateRepository> = Api::all(client.clone());
    Ok(first_overlapping_sibling(
        &repositories.list(&ListParams::default()).await?.items,
        repository,
    ))
}

/// The listing half of [`overlapping_sibling`], split out so the identity and key-space rules are
/// testable without a cluster.
fn first_overlapping_sibling(
    others: &[UpdateRepository],
    repository: &UpdateRepository,
) -> Option<(String, String)> {
    let identity = (repository.namespace(), repository.name_any());
    others
        .iter()
        .find(|other| {
            (other.namespace(), other.name_any()) != identity
                && other.spec.s3.bucket == repository.spec.s3.bucket
                && !endpoints_definitely_differ(
                    &other.spec.s3.endpoint,
                    &repository.spec.s3.endpoint,
                )
                && prefixes_overlap(&other.spec.s3.prefix, &repository.spec.s3.prefix)
        })
        .map(|other| {
            (
                format!(
                    "{}/{}",
                    other.namespace().unwrap_or_default(),
                    other.name_any()
                ),
                other.spec.s3.prefix.clone(),
            )
        })
}

/// Whether two `spec.s3.endpoint` values definitely address DIFFERENT object stores.
///
/// The endpoint is optional and is otherwise a raw operator-written string: `s3_store` hands it
/// straight to `AmazonS3Builder::with_endpoint`, and when it is absent the builder derives the
/// endpoint from `region` instead. So `None` with `region: us-east-1` and an explicit
/// `https://s3.us-east-1.amazonaws.com` are the same host, as are one MinIO address spelled with a
/// trailing slash, in another case, or over `http` rather than `https`.
///
/// This gates an IRREVERSIBLE prune, so it fails closed: two endpoints count as different only when
/// both are explicit and resolve to a different authority. Absent, unparsable, or equal-after-
/// normalization all mean "assume the same store", whose worst outcome is refusing a delete.
fn endpoints_definitely_differ(a: &Option<String>, b: &Option<String>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => endpoint_authority(a) != endpoint_authority(b),
        _ => false,
    }
}

/// The `host[:port]` an endpoint addresses, lowercased, with any path/query dropped and a port that
/// is its scheme's default removed. The scheme itself is not compared: `http` and `https` to one
/// address are one store, and a store reached over both is exactly the case this must not miss.
fn endpoint_authority(endpoint: &str) -> String {
    let endpoint = endpoint.trim();
    let (scheme, rest) = endpoint
        .split_once("://")
        .map_or(("", endpoint), |(scheme, rest)| (scheme, rest));
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(rest)
        .to_ascii_lowercase();
    let default_port = if scheme.eq_ignore_ascii_case("http") {
        "80"
    } else {
        "443"
    };
    // Split only on a trailing all-digit port, so a bare IPv6 host (`[::1]`) is left intact.
    match authority.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
            if port == default_port {
                host.to_string()
            } else {
                authority
            }
        }
        _ => authority,
    }
}

/// Whether two key prefixes in one bucket name overlapping key spaces: identical, or one an ancestor
/// of the other. Compared at path boundaries, so `fleet` does not "contain" `fleet-staging`; an
/// empty prefix is the whole bucket and therefore overlaps every other.
fn prefixes_overlap(a: &str, b: &str) -> bool {
    let (a, b) = (a.trim_matches('/'), b.trim_matches('/'));
    let (shorter, longer) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    shorter.is_empty()
        || longer == shorter
        || longer
            .strip_prefix(shorter)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Delete every object under `prefix` in `store`, returning the count removed. Locations are collected
/// before deletion so the list connection is not held open across the deletes; a TUF repository's
/// object count is modest (metadata plus a bounded set of bundles), so this stays bounded.
///
/// An empty prefix is refused rather than treated as "the whole bucket": callers reach this from a
/// delete path, and an unscoped delete would take out every other tenant of the same bucket.
async fn prune_prefix(store: &dyn ObjectStore, prefix: &str) -> Result<usize, StorageError> {
    let trimmed = prefix.trim_matches('/');
    if trimmed.is_empty() {
        return Err(StorageError(
            "refusing to prune an empty prefix: that is the whole bucket, not this repository"
                .into(),
        ));
    }
    let scope = Some(object_store::path::Path::from(trimmed));
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

/// How long every metadata document this control plane signs stays valid.
const METADATA_EXPIRY_DAYS: i64 = 365;

/// How little of that validity window may remain before the document is signed again.
///
/// A quarter of the window: long enough that renewal is never urgent (a control plane that is down
/// for two months still comes back to a live fleet), short enough that renewal happens roughly
/// three times per validity period, so a single failed attempt is not the failure.
const METADATA_RENEWAL_DAYS: i64 = 90;

/// The metadata this control plane is responsible for keeping fresh.
///
/// Two entries because they are re-signed by two different ceremonies: `sign_plan` re-signs the
/// online roles on every publication and never touches the root, while the root is renewed on its
/// own. They are checked together so freshness is decided in exactly one place.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TufRole {
    Root,
    /// targets, snapshot, and timestamp — one `sign_plan` re-signs all three with one expiry, so
    /// `timestamp.json` speaks for the set.
    Online,
}

/// Which of this repository's signed metadata documents are inside their renewal window at `now`.
///
/// A document that is missing or unreadable is deliberately NOT a renewal: nothing has been signed
/// here yet (the initialization path handles that, with its own rollback guard), and metadata that
/// cannot be parsed must not be re-signed on top of.
async fn expiring_metadata(repo_dir: &Path, now: chrono::DateTime<chrono::Utc>) -> Vec<TufRole> {
    let horizon = now + chrono::Duration::days(METADATA_RENEWAL_DAYS);
    let metadata = repo_dir.join("metadata");
    let mut expiring = Vec::new();
    for (role, file) in [
        (TufRole::Root, "root.json"),
        (TufRole::Online, "timestamp.json"),
    ] {
        if metadata_expiry(&metadata.join(file))
            .await
            .is_some_and(|expires| expires <= horizon)
        {
            expiring.push(role);
        }
    }
    expiring
}

/// Whether this pass must sign and publish a generation.
///
/// FRESHNESS is a trigger in its own right, alongside changed content. The publication digest
/// covers the content and deliberately not time, so a fleet at steady state matched it forever and
/// never re-signed — walking straight into the hard expiry of its own metadata, at which point TUF
/// refresh fails fleet-wide, `/enroll` and `/v1/node/secrets` answer 502, and every reconcile fails
/// on the enrollment publisher. Nothing recovers from inside the loop.
fn publication_required(content_unchanged: bool, renewals: &[TufRole]) -> bool {
    !content_unchanged || !renewals.is_empty()
}

/// What "this repository is already published" means on disk: the content digest AND the digests of
/// the SIGNED METADATA that content is served under — the local `root.json` and, for the online
/// roles, `timestamp.json`.
///
/// The metadata must be part of it because every re-sign rewrites those documents in place BEFORE
/// this pass uploads anything. If the upload then fails — a lost lease, a transient object-store
/// error, the reconcile future dropped mid-upload — the store keeps serving the OLD documents while
/// the local ones have already moved on, and a marker keyed on CONTENT alone matches again on the
/// next pass, so nothing ever republishes:
///
/// * ROOT: `status.routingRootSha256` (read from the local root) then pins every `/enroll` and
///   `/v1/node/secrets` request against a root the store does not serve — 502 fleet-wide until some
///   unrelated content change happens to heal it.
/// * ONLINE roles: `sign_plan` re-signs targets/snapshot/timestamp with a fresh expiry, so the
///   freshness trigger CLEARS ITSELF — `expiring_metadata` reads the freshly signed LOCAL
///   `timestamp.json` and reports nothing expiring — and the store is left serving online metadata
///   that hard-expires ~90 days later, at which point every agent's TUF refresh fails at once.
///
/// With both digests in the marker, a local re-sign that never reached the store IS the mismatch,
/// and it demands the republication that heals it on the very next pass.
async fn publication_marker(state_dir: &Path, digest: &str) -> String {
    let metadata = state_dir.join("repository/metadata");
    format!(
        "{digest} {} {}",
        file_sha256(&metadata.join("root.json"))
            .await
            .unwrap_or_default(),
        file_sha256(&metadata.join("timestamp.json"))
            .await
            .unwrap_or_default()
    )
}

/// The SHA-256 of a file, or `None` when it cannot be read.
async fn file_sha256(path: &Path) -> Option<String> {
    let bytes = tokio::fs::read(path).await.ok()?;
    Some(updated::hash::sha256_bytes(&bytes))
}

/// Renew the TUF root in place when it is inside its renewal window — same key set, next version,
/// fresh expiry. Returns the operator-facing reason when it could not be renewed, having logged the
/// cause; `None` means there was nothing to do or it was done.
///
/// A renewal that fails is NOT a failed reconcile. The root that could not be re-signed is still
/// valid for up to [`METADATA_RENEWAL_DAYS`], and the ordinary cause — the signing Secret no longer
/// holds enough of the keys the current root lists, after a drifted or regenerated Secret — has
/// nothing to do with the content being published. Propagating it stopped every rollout, every
/// admission, and every durable write for the whole ninety-day window, over a condition the fleet
/// was not affected by.
///
/// The failed role is dropped from `renewals` for the same reason it must not abort: `root.json` is
/// unchanged, so it stays inside its window and would otherwise demand a freshly signed and
/// uploaded generation on every reconcile — one per second — until the operator noticed. The
/// operator is told by a status condition instead, and the next pass tries again.
///
/// Only ever called while holding the publisher lease, so two replicas cannot both bump the root.
/// Idempotent by construction: a renewed root is not expiring, so the next pass no longer asks.
async fn renew_expiring_root(
    repo_dir: &Path,
    keys_dir: &Path,
    repository: &str,
    renewals: &mut Vec<TufRole>,
) -> Option<String> {
    if !renewals.contains(&TufRole::Root) {
        return None;
    }
    tracing::info!(
        repository,
        "renewing the TUF root: it is inside its renewal window"
    );
    let outcome = updated_tuf::repo::renew_root(
        repo_dir,
        &updated_tuf::repo::Keys::in_dir(keys_dir).roots,
        METADATA_EXPIRY_DAYS,
    )
    .await;
    let error = outcome.err()?;
    tracing::error!(
        repository,
        %error,
        "could not renew the TUF root; it is inside its renewal window and will HARD EXPIRE, after \
         which every agent's metadata refresh fails at once. Content publication continues. Check \
         that the signing Secret still holds the root keys the current root.json lists."
    );
    renewals.retain(|role| *role != TufRole::Root);
    Some(format!(
        "The TUF root is inside its renewal window and could not be re-signed: {error}"
    ))
}

/// The `expires` instant a signed TUF metadata document declares, or `None` when it cannot be read.
async fn metadata_expiry(path: &Path) -> Option<chrono::DateTime<chrono::Utc>> {
    let bytes = tokio::fs::read(path).await.ok()?;
    let document: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    let expires = document.pointer("/signed/expires")?.as_str()?;
    chrono::DateTime::parse_from_rfc3339(expires)
        .ok()
        .map(|instant| instant.with_timezone(&chrono::Utc))
}

/// Cross-pass controller state the reconcile loop owns and threads through every pass: the alert
/// sink and the in-memory progress marks the `RolloutStuck` condition derives from, plus the
/// consecutive-failure count `ReconcileFailing` reports. Lives in the main loop, not in
/// `reconcile_once`, because all three must survive individual passes.
pub struct ReconcileHooks {
    pub alerts: Option<Arc<crate::alerts::AlertSink>>,
    pub progress: crate::alerts::ProgressTracker,
    /// The regression verdict's observation memory (`rollout::AttemptLog`): which assignments each
    /// node has been seen attempting. Losing it (a restart, a leader change) only delays a halt
    /// until the still-contained nodes' report sequences re-prove it.
    pub regressions: crate::rollout::AttemptLog,
    /// Failed passes in a row WITHIN one leadership epoch. Reset by a successful publish, and by
    /// the loop whenever this replica stops being the leader — a streak that spanned the gap let
    /// one ordinary transient after a handover reach the `ReconcileFailing` threshold on its own.
    pub consecutive_failures: u32,
}

impl ReconcileHooks {
    pub fn new(alerts: Option<Arc<crate::alerts::AlertSink>>) -> Self {
        Self {
            alerts,
            progress: crate::alerts::ProgressTracker::new(),
            regressions: crate::rollout::AttemptLog::new(),
            consecutive_failures: 0,
        }
    }
}

/// What a successful reconcile pass hands back: the published digest, and the fleet snapshot the
/// metrics listener projects at scrape time.
pub struct ReconcileOutcome {
    pub digest: String,
    /// `None` when the pass had no fleet to project (repository finalization) — the caller keeps
    /// the previous snapshot rather than overwriting it with zeros.
    pub snapshot: Option<crate::metrics::FleetSnapshot>,
}

pub async fn reconcile_once(
    client: Client,
    namespace: &str,
    repository_name: &str,
    state_dir: &Path,
    public_url: &str,
    identity: &str,
    hooks: &mut ReconcileHooks,
) -> Result<ReconcileOutcome, Box<dyn std::error::Error>> {
    let pass_started = std::time::Instant::now();
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
        finalize_repository(&client, &repositories, &secrets, &repository).await?;
        hooks.consecutive_failures = 0;
        return Ok(ReconcileOutcome {
            digest: format!("finalized repository {repository_name}"),
            snapshot: None,
        });
    }
    ensure_repository_finalizer(&repositories, &repository).await?;

    // The rollout state (each group's currently-pinned deployment, and the routing the last
    // generation published) lives durably in-cluster — a ConfigMap — NOT on the node-local PVC.
    // That is what survives an HA leader change or a cold/rescheduled PVC: a fresh leader loads the
    // real admitted baseline from etcd instead of re-seeding every group to the current desired and
    // admitting a whole set at once (the `max_concurrent` breach that node-local state allowed).
    // The single publisher lease keeps this a single writer; the write below is a resourceVersion
    // compare-and-swap as a second guard. It is loaded here, before groups are validated, because
    // quarantining a group needs the deployment that group is still pinned to.
    let admitted_name = admitted_configmap_name(repository_name);
    let (durable, admitted_version) = load_admitted_state(&configmaps, &admitted_name).await?;
    // The object store is needed every reconcile — to recover an interrupted publication, to read
    // the node telemetry that drives rollout planning, and to publish — so build it up front.
    let store = build_store(&secrets, &repository.spec.s3).await?;
    // A generation this replica published but never recorded is adopted before anything is planned
    // from the loaded state — planning on a baseline that predates the live generation is what
    // republishes an already-advanced node on its predecessor.
    let (durable, admitted_version) = recover_pending_publication(
        AdmittedRecord {
            configmaps: &configmaps,
            name: &admitted_name,
            namespace,
            owner: repository.controller_owner_ref(&()),
        },
        state_dir,
        store.as_ref(),
        &repository.spec.s3,
        durable,
        admitted_version,
    )
    .await?;

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
    // Every group quarantined this pass, mapped to the selector that says which agents are its
    // agents. The selector travels with the quarantine — not only with the pin below — because a
    // group quarantined BEFORE it was ever admitted has no pin at all, and its agents must still be
    // recognized as belonging to it: otherwise they resolve to the unmatched-node pseudo-group and
    // are handed the repository's fleet-wide default deployment, the exact ungated swap quarantine
    // exists to prevent. An unusable selector is carried as EMPTY, which selects nothing — the
    // group's membership is genuinely unknown, and reading an empty selector as "every agent" would
    // withhold the whole fleet over one broken group.
    let mut quarantined_groups: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    // What each quarantined group is still pinned to. Its nodes must keep exactly that: routing
    // them to the unmatched-node pseudo-group would turn a typo'd digest or a bad `maxUnavailable`
    // into a fleet-wide, unthrottled, ungated deployment swap, and leaving them out of the
    // generation would delete their assignments outright (publication replaces every target).
    let mut held_groups: BTreeMap<String, crate::rollout::AdmittedDeployment> = BTreeMap::new();
    // Only a group that has been admitted at least once has a pin, so this is a SUBSET of
    // `quarantined_groups`; membership — which agents are a quarantined group's agents — is
    // answered from `quarantined_groups` above, which covers the never-admitted ones too.
    let hold_group =
        |name: &str, held: &mut BTreeMap<String, crate::rollout::AdmittedDeployment>| {
            if let Some(state) = durable.admitted.get(name) {
                held.insert(name.to_string(), state.clone());
            }
        };
    for group in group_resources.iter() {
        let name = group.name_any();
        if name == crate::DEFAULT_GROUP {
            quarantine_group(
                &groups_api,
                group,
                "ReservedName",
                "`default` is reserved for agents that match no group; rename this UpdateGroup.",
            )
            .await?;
            hold_group(&name, &mut held_groups);
            quarantined_groups.insert(name, group.spec.selector.match_labels.clone());
            continue;
        }
        if group.spec.selector.match_labels.is_empty() {
            quarantine_group(
                &groups_api,
                group,
                "EmptySelector",
                "This group's selector has no matchLabels; an empty selector would match every agent and is refused.",
            )
            .await?;
            hold_group(&name, &mut held_groups);
            quarantined_groups.insert(name, group.spec.selector.match_labels.clone());
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
                hold_group(&name, &mut held_groups);
                quarantined_groups.insert(name, group.spec.selector.match_labels.clone());
                continue;
            }
        };
        groups.insert(
            name.clone(),
            ResolvedGroup {
                name: name.clone(),
                match_labels: group.spec.selector.match_labels.clone(),
                depends_on: group.spec.depends_on.clone(),
                inputs: group.spec.inputs.clone(),
                inputs_ready: group.spec.inputs.is_empty(),
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
                        hold_group(&name, &mut held_groups);
                        quarantined_groups.insert(name, group.spec.selector.match_labels.clone());
                        continue;
                    }
                    value => value.unwrap_or(1),
                },
                emergency_correction: group.spec.emergency_correction,
            },
        );
        group_labels.insert(name, group.labels().clone());
    }
    group_resources
        .items
        .retain(|group| !quarantined_groups.contains_key(&group.name_any()));

    let mut agent_resources = nodes_api.list(&ListParams::default()).await?;
    agent_resources
        .items
        .retain(|agent| agent.spec.repository_ref.name == repository_name);
    // Quarantine a malformed-identity agent — never the whole reconcile — and drop it from this
    // generation: a bad identity never resolved to an assignment, so there is nothing to preserve.
    // Overlapping selectors are deliberately NOT handled here. An ambiguous node must hold the last
    // known-good routing (fail safe, never fail open), so we leave it in
    // the plan and let `build_publication_plan` fault the whole generation closed with
    // `AmbiguousNode`; `reconcile_once` returns that error and the previous publication stays live.
    let mut quarantined_agents: HashSet<String> = HashSet::new();
    for agent in &agent_resources.items {
        let identity = &agent.spec.identity;
        let valid = match identity.kind {
            crate::AgentIdentityKind::Manual | crate::AgentIdentityKind::Reserved => {
                identity.registration_sha256.is_none()
            }
            crate::AgentIdentityKind::Enrolled => identity
                .registration_sha256
                .as_deref()
                .is_some_and(updated_contracts::is_sha256_hex),
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
        // A name the telemetry write path refuses is quarantined HERE, where the agent is admitted,
        // rather than being placed and published. Kubernetes accepts a dot in a resource name and
        // the traversal rule that gates placement permits one, but a report is a URL segment: the
        // gateway rejects every PUT to `/telemetry/<name>.json` for such a node. It would be
        // placed, published, and enrolled, and then never report for the life of the machine —
        // permanently Silent, spending its group's `maxUnavailable`, holding its set's concurrency
        // slot, and blocking every dependent group, with nothing naming the cause.
        if !crate::node_name_is_reportable(&agent.name_any()) {
            quarantine_agent(
                &nodes_api,
                agent,
                "UnreportableName",
                "This agent's name cannot appear in a telemetry report path (no `.`, `%`, `?` or \
                 `#`), so it could never report its state. Recreate it with a name that can.",
            )
            .await?;
            quarantined_agents.insert(agent.name_any());
        }
    }
    agent_resources
        .items
        .retain(|agent| !quarantined_agents.contains(&agent.name_any()));

    // Every agent stays in the plan. Nodes whose group is quarantined are held on that group's
    // pinned deployment by the planner (`DesiredState::held`) — they are neither re-routed to the
    // ungated default nor dropped from the signed generation.
    let resolved_nodes: Vec<ResolvedNode> = agent_resources
        .iter()
        .map(|node| ResolvedNode {
            name: node.name_any(),
            labels: node.spec.labels.clone(),
        })
        .collect();
    // The per-node operational controls, straight from each agent's spec. Both are pure planner
    // inputs: a hold changes only what is published FOR the node (its recorded body, verbatim) and
    // a cordon changes only what the endpoint projection publishes ABOUT it — the pull model
    // holds, nothing reaches into a machine.
    let holds: BTreeSet<String> = agent_resources
        .iter()
        .filter(|agent| agent.spec.hold)
        .map(|agent| agent.name_any())
        .collect();
    let cordons: BTreeSet<String> = agent_resources
        .iter()
        .filter(|agent| agent.spec.cordon)
        .map(|agent| agent.name_any())
        .collect();

    // An ABSENT admitted-state ConfigMap reads as "no group has ever been admitted", so every group
    // takes the first-admission branch and every group's staging baseline is lost: `previous` is
    // empty for all of them, so nothing is staged away from, and the rollout history each set's
    // concurrency accounting depends on is gone. On a fleet that HAS published, that is the entire
    // inventory re-admitted from a blank baseline in one generation. Deleting (or failing to
    // restore) one ConfigMap must not be a fleet-wide rebaseline, so this fails closed exactly like
    // the analogous "local publisher state is empty but the store has a generation" guard.
    if admitted_version.is_none()
        && durable.admitted.is_empty()
        && store_published_version(store.as_ref(), &repository.spec.s3)
            .await?
            .is_some()
    {
        return Err(Box::new(StorageError(format!(
            "the durable admitted-state ConfigMap {admitted_name} is missing while a published \
             generation exists; refusing to re-admit every group ungated (restore it, or delete \
             the published generation to start over)"
        ))));
    }

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
    let reconcile_now = chrono::Utc::now();
    let outcome = crate::domain::plan_reconcile(
        crate::domain::DesiredState {
            repository: &repository.spec,
            groups: &groups,
            group_labels: &group_labels,
            sets: &set_resources.items,
            nodes: &resolved_nodes,
            quarantined: &quarantined_groups,
            held: &held_groups,
            holds: &holds,
            cordons: &cordons,
        },
        crate::domain::ObservedState {
            reports: &reports,
            public_keys: &public_keys,
            admitted: &durable.admitted,
            routing: &durable.routing,
            assignments: &durable.assignments,
            now: reconcile_now,
        },
        &mut hooks.regressions,
    )?;
    let crate::domain::ReconcilePlan {
        publication: plan,
        admitted: planned_admitted,
        routing: planned_routing,
        assignments: planned_assignments,
        set_statuses,
        groups: group_progress,
        node_counts,
        halted_groups,
    } = outcome;
    let planned = DurableRolloutState {
        admitted: planned_admitted,
        routing: planned_routing,
        assignments: planned_assignments,
    };

    let desired_digest = desired_publication_digest(&repository.spec, &plan.digest)?;
    let published_marker = state_dir.join("published-plan.sha256");
    let content_unchanged = tokio::fs::read_to_string(&published_marker)
        .await
        .ok()
        .as_deref()
        == Some(
            publication_marker(state_dir, &desired_digest)
                .await
                .as_str(),
        );
    let repo_dir = state_dir.join("repository");
    // Re-signing well before expiry is the standard TUF discipline (timestamp exists to prove
    // freshness), and it is ONE mechanism: the same check renews the root, which `replace_release`
    // never touches.
    let mut renewals = expiring_metadata(&repo_dir, reconcile_now).await;
    let initialized = repo_dir.join("metadata/root.json").exists();
    // The root renewal is attempted BEFORE this pass commits to signing a generation, because a
    // renewal that cannot be performed drops back out of `renewals` (see `renew_expiring_root`) and
    // must then not be the reason a generation was signed at all.
    let mut root_renewal_failure = None;
    if publication_required(content_unchanged, &renewals) {
        refuse_generation_rollback(store.as_ref(), &repository.spec.s3, &repo_dir).await?;
        let signing = secrets
            .get(&repository.spec.signing_secret_ref.name)
            .await?;
        let keys_dir = state_dir.join("keys");
        materialize_signing_keys(&signing, &keys_dir).await?;
        if !initialized {
            updated_tuf::repo::init(
                &repo_dir,
                &updated_tuf::repo::Keys::in_dir(&keys_dir),
                METADATA_EXPIRY_DAYS,
            )
            .await?;
        } else {
            root_renewal_failure =
                renew_expiring_root(&repo_dir, &keys_dir, &repository.name_any(), &mut renewals)
                    .await;
        }
        if publication_required(content_unchanged, &renewals) {
            crate::publisher::sign_plan(&repo_dir, &keys_dir, &plan, METADATA_EXPIRY_DAYS).await?;

            // Re-verify leadership right before the irreversible S3 publish. The CPU-bound signing above can
            // starve the main loop's 5s lease renewal past the 15s deadline; without this a former leader
            // whose lease already expired (and was taken over by another replica) would still upload here,
            // double-writing the generation. This closes the largest window (post-signing); the residual
            // check→PUT gap is one request wide. Fail closed — skip the publish rather than split-brain write.
            if !holds_lease(&client, namespace, "updatec-publisher", identity).await? {
                return Err(Box::new(StorageError(
                    "publisher lease lost during reconcile; skipping publish to avoid a split-brain \
                     write"
                        .into(),
                )));
            }

            // The marker this upload commits to, computed from the metadata as it stands NOW —
            // after the root renewal and the online re-sign above — so it always describes the
            // generation the store will serve, and is written only once that upload lands.
            let marker = publication_marker(state_dir, &desired_digest).await;
            // Journalled BEFORE the upload and keyed to that marker, so the state this generation
            // implies survives losing the in-cluster write below (see `recover_pending_publication`)
            // without a failed upload ever being mistaken for a published one.
            foundation::durable::atomic_write(
                &state_dir.join(PENDING_STATE_FILE),
                ".pending-",
                &serde_json::to_vec(&PendingPublication {
                    marker: marker.clone(),
                    // What the store will serve if this upload lands — the second, independent way
                    // the next pass can tell that it did.
                    version: updated_tuf::repo::current_version(&repo_dir).await?,
                    state: planned.clone(),
                })?,
            )?;

            publish_repository(store.as_ref(), &repository.spec.s3, &repo_dir).await?;
            foundation::durable::atomic_write(&published_marker, ".published-", marker.as_bytes())?;
        }
    }

    // The durable state records what WAS published, so it is written only once the generation
    // above is signed and uploaded. Every field of it is a claim about the live generation —
    // notably `assignments`, the node → deployment identity map that is the ONLY staging signal a
    // blind node has — and writing it first turned any failed publish (an object-store error, or
    // the fail-closed lease and rollback guards above) into a durable record that nodes had been
    // handed a deployment nobody ever served. A failed publish now leaves the record untouched and
    // the next pass replans from the same baseline. The reverse gap — losing this write after a
    // successful publish — is covered by the journal `recover_pending_publication` reads, because
    // it is NOT self-healing on its own: the next pass would replan from a baseline that predates
    // the live generation and could republish an advanced node on its predecessor.
    //
    // Reconcile runs every second; only write when the state actually changed, so a steady
    // generation makes no apiserver writes.
    if durable != planned {
        let _ = store_admitted_state(
            &configmaps,
            &admitted_name,
            namespace,
            &planned,
            admitted_version,
            repository.controller_owner_ref(&()),
        )
        .await?;
    }
    // The journal has served its purpose the moment the state it carries is recorded in-cluster.
    tokio::fs::remove_file(state_dir.join(PENDING_STATE_FILE))
        .await
        .ok();

    // The endpoint projection: which nodes the healthproxy must program as drained regardless of
    // their reports — the one channel a cordon travels. Outside the signed generation because it
    // is not desired state (see `updated_contracts::endpoints`), and written read-compare-put so a
    // steady fleet costs one GET per pass, not a PUT. Best-effort like every other post-publication
    // delivery (`deliver_subscriptions`): one unreadable object here must not stall publication for
    // the whole repository, and the write retries on the next pass of its own accord.
    publish_endpoint_projection(store.as_ref(), &repository.spec.s3.prefix, &cordons).await;

    // ONE projection path for both outcomes — a reconcile that reused an unchanged generation and
    // one that just signed a new one expose identical enrollment, status, and subscription state.
    //
    // The trust anchor is read HERE, after any repository init or re-sign in this same pass, and
    // never before: it is the digest that `/enroll` and `/v1/node/secrets` pin the store-served
    // root against, and by this point the store already serves the new root. Reading it earlier
    // recorded the pre-rewrite digest, so every enrollment failed for a full reconcile tick after
    // the initial publish or a root re-sign.
    let projection = ReconcileProjection {
        client: &client,
        namespace,
        state_dir,
        public_url,
        secrets: &secrets,
        repository: &repository,
        store: store.as_ref(),
        apis: ResourceApis {
            repositories: &repositories,
            groups: &groups_api,
            agents: &nodes_api,
        },
        snapshot: StatusSnapshot {
            repository: &repository,
            routing_root_sha256: local_routing_root_sha256(state_dir).await,
            root_renewal_failure,
            groups: &group_resources.items,
            agents: &agent_resources.items,
            plan: &plan,
            reports: &reports,
            group_progress: &group_progress,
            public_keys: &public_keys,
            holds: &holds,
            node_counts: &node_counts,
            halted_groups: &halted_groups,
            now: reconcile_now,
        },
        sets: &sets_api,
        set_resources: &set_resources.items,
        set_statuses: &set_statuses,
    };
    projection.publish(hooks).await?;
    // Everything fallible has now succeeded, so the failure streak resets here — never earlier:
    // resetting before the projection made `ReconcileFailing` blind to any failure inside the
    // projection stage itself, the last third of every pass.
    hooks.consecutive_failures = 0;

    // The metrics snapshot: pure projection of what this pass already computed, handed to the
    // scrape listener by the main loop. The fleet-wide freshness counts are SUMS of the planner's
    // per-group accounting — the one definition of "fresh", not a second derivation — and the
    // deployment labels come from the admitted map, which carries every group's current plus the
    // repository default under its reserved name.
    let mut deployments: Vec<String> = planned
        .admitted
        .values()
        .map(|state| state.current.deployment.clone())
        .collect();
    deployments.sort();
    deployments.dedup();
    let (reports_fresh, reports_observable) = node_counts
        .values()
        .fold((0, 0), |(fresh, observable), counts| {
            (fresh + counts.fresh, observable + counts.observable)
        });
    let snapshot = crate::metrics::FleetSnapshot {
        reconcile_timestamp_seconds: reconcile_now.timestamp().max(0) as u64,
        reconcile_duration_seconds: pass_started.elapsed().as_secs_f64(),
        generation: updated_tuf::repo::current_version(&repo_dir).await.ok(),
        deployments,
        groups: group_progress
            .iter()
            .map(|(name, progress)| {
                (
                    name.clone(),
                    (
                        *progress,
                        node_counts.get(name).cloned().unwrap_or_default(),
                    ),
                )
            })
            .collect(),
        reports_fresh,
        reports_stale: reports_observable.saturating_sub(reports_fresh),
        quarantined_groups: quarantined_groups.len(),
    };
    Ok(ReconcileOutcome {
        digest: plan.digest,
        snapshot: Some(snapshot),
    })
}

/// Publish the endpoint projection — the cordoned set — to the object store the healthproxy polls.
///
/// A cordon is invisible on the node (the application keeps running, the supervisor is unaware),
/// so the ONLY thing it may change is what the control plane publishes about the node: this
/// document, at [`updated_contracts::endpoints::ENDPOINTS_OBJECT_KEY`] under the repository
/// prefix, beside the telemetry namespace the healthproxy already reads. Read-compare-put keeps a
/// steady state at one bounded GET per reconcile.
///
/// Best-effort: a failure is logged and retried next pass, never propagated — the projection is
/// operator convenience, and publication for the whole repository must not stall over it. The
/// unguarded write also means a lame-duck leader can briefly overwrite a new leader's projection;
/// that self-heals on the new leader's next one-second pass, which is the same bound a cordon's
/// ordinary propagation already has.
async fn publish_endpoint_projection(
    store: &dyn ObjectStore,
    prefix: &str,
    cordons: &BTreeSet<String>,
) {
    let key = crate::object_key(prefix, updated_contracts::endpoints::ENDPOINTS_OBJECT_KEY);
    let desired = match serde_json::to_vec(&updated_contracts::endpoints::EndpointProjection::new(
        cordons.clone(),
    )) {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(%error, "encoding the endpoint projection");
            return;
        }
    };
    if desired.len() > updated_contracts::endpoints::MAX_PROJECTION_BYTES {
        // Unreachable at the enrollment ceiling, but the shared bound must hold on the write side
        // too — a reader refuses an oversized document by failing OPEN, which would silently
        // release every cordon.
        tracing::warn!(
            bytes = desired.len(),
            "endpoint projection exceeds the shared bound; not publishing it"
        );
        return;
    }
    match crate::read_object_bounded(store, &key).await {
        Ok(existing) if existing == desired => return,
        Ok(_) | Err(object_store::Error::NotFound { .. }) => {}
        Err(error) => {
            tracing::warn!(%error, "probing the endpoint projection; cordon changes wait for the next pass");
            return;
        }
    }
    match store
        .put(&key, PutPayload::from_bytes(desired.into()))
        .await
    {
        Ok(_) => tracing::info!(
            cordoned = cordons.len(),
            "published the endpoint projection: cordoned nodes are programmed as drained"
        ),
        Err(error) => {
            tracing::warn!(%error, "publishing the endpoint projection; cordon changes wait for the next pass")
        }
    }
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
) -> HashMap<String, Envelope> {
    let prefix = prefix.trim_matches('/');
    let fetches = agents.iter().map(|node| async move {
        let key = crate::object_key(
            prefix,
            &updated_contracts::telemetry::report_object_key(node),
        );
        let bytes = crate::read_object_bounded(store, &key).await.ok()?;
        // The envelope is stored verbatim; it is verified per consumer, not here, so this stays a
        // transport read and the trust gate has exactly one home.
        let envelope = serde_json::from_slice::<Envelope>(&bytes).ok()?;
        Some((node.clone(), envelope))
    });
    futures::stream::iter(fetches)
        .buffer_unordered(16)
        .filter_map(|entry| async move { entry })
        .collect()
        .await
}

/// The digest of the `root.json` this publisher signs with, from its own local repository state.
///
/// Read from disk rather than from the object store: this is the value enrollment pins the
/// store-served root AGAINST, so taking it from the store would compare a document with itself.
/// `None` before this replica has ever signed a generation.
async fn local_routing_root_sha256(state_dir: &Path) -> Option<String> {
    file_sha256(&state_dir.join("repository/metadata/root.json")).await
}

/// The ConfigMap name that durably holds this repository's admitted set (group → pinned
/// deployment). Named from the repository so two repositories in one namespace never collide;
/// the repository name is itself a valid Kubernetes resource name, so this always is too.
fn admitted_configmap_name(repository_name: &str) -> String {
    format!("updatec-admitted-{repository_name}")
}

/// What an operator must do about an admitted-state document this controller cannot read. Nothing
/// in the loop can repair one — every reconcile fails on it, forever — so the error has to name the
/// remedy or it is an outage with no exit. It is a last resort and not automatic because it throws
/// the rollout history away, which is exactly what the durable state exists to keep.
const ADMITTED_STATE_REMEDY: &str =
    "delete this ConfigMap to re-seed every group from its current desired deployment (the \
     rollout is rebaselined: in-flight staging is forgotten and each set's concurrency is counted \
     afresh)";

/// Load the durable admitted set from its in-cluster ConfigMap. Returns the map (empty the very
/// first time, before the ConfigMap exists) and the ConfigMap's `resourceVersion` for a
/// compare-and-swap on write. The state is one document and fails closed as one document: partial
/// recovery could silently rebaseline a group and violate rollout concurrency.
async fn load_admitted_state(
    configmaps: &Api<ConfigMap>,
    name: &str,
) -> Result<(DurableRolloutState, Option<String>), Box<dyn std::error::Error>> {
    let Some(configmap) = configmaps.get_opt(name).await? else {
        return Ok((DurableRolloutState::default(), None));
    };
    let resource_version = configmap.metadata.resource_version.clone();
    let data = configmap.data.as_ref();
    let encoded = data
        .and_then(|data| data.get("state.json"))
        .ok_or_else(|| {
            StorageError(format!(
                "admitted-state ConfigMap {name} has no state.json; {ADMITTED_STATE_REMEDY}"
            ))
        })?;
    let admitted = serde_json::from_str(encoded).map_err(|error| {
        StorageError(format!(
            "invalid admitted state in ConfigMap {name}: {error}; {ADMITTED_STATE_REMEDY}"
        ))
    })?;
    // The published routing (node → group) and assignments (node → deployment identity) are their
    // own keys rather than fields of the first, but they are written in the same document by the
    // same write, so a missing one is unreadable state — not a repository that has published
    // nothing. Reading an absent `assignments.json` as "no node has ever been assigned" told the
    // planner every carried-forward node was unplaceable.
    let encoded = data
        .and_then(|data| data.get("routing.json"))
        .ok_or_else(|| {
            StorageError(format!(
                "admitted-state ConfigMap {name} has no routing.json; {ADMITTED_STATE_REMEDY}"
            ))
        })?;
    let routing = serde_json::from_str(encoded).map_err(|error| {
        StorageError(format!(
            "invalid published routing in ConfigMap {name}: {error}; {ADMITTED_STATE_REMEDY}"
        ))
    })?;
    let encoded = data
        .and_then(|data| data.get("assignments.json"))
        .ok_or_else(|| {
            StorageError(format!(
                "admitted-state ConfigMap {name} has no assignments.json; {ADMITTED_STATE_REMEDY}"
            ))
        })?;
    let assignments = decode_assignments(serde_json::from_str(encoded).map_err(|error| {
        StorageError(format!(
            "invalid published assignments in ConfigMap {name}: {error}; {ADMITTED_STATE_REMEDY}"
        ))
    })?);
    Ok((
        DurableRolloutState {
            admitted,
            routing,
            assignments,
        },
        resource_version,
    ))
}

/// The local journal of the generation this replica is publishing, written between signing and
/// upload and cleared once the durable state that describes it has been recorded in-cluster.
///
/// `version` — the `timestamp.json` version this upload carries — is what decides whether the
/// generation reached the store, because the STORE is the only thing that knows: it serves `version`
/// iff this upload landed. `marker` is journalled beside it purely so the marker file can be
/// FINISHED (it is written after `publish_repository` returns, so a process death in that gap — an
/// OOM kill, an evicted pod — leaves the store serving this generation while the marker still names
/// its predecessor); it is never read as evidence of the upload. Marker equality is neither
/// necessary (that same gap) nor sufficient: the marker covers the content and the signed metadata,
/// so a pass triggered by neither journals a marker already on disk before the upload was attempted.
#[derive(serde::Serialize, serde::Deserialize)]
struct PendingPublication {
    marker: String,
    version: u64,
    state: DurableRolloutState,
}

/// The journal file, alongside the publication marker it is compared against.
const PENDING_STATE_FILE: &str = "pending-state.json";

/// Where the durable rollout state is recorded: the ConfigMap, and the owner reference that ties it
/// to its repository.
struct AdmittedRecord<'a> {
    configmaps: &'a Api<ConfigMap>,
    name: &'a str,
    namespace: &'a str,
    owner: Option<OwnerReference>,
}

/// Record the state a generation published but never got to store in-cluster.
///
/// The durable state is written AFTER the upload, because writing it first turned a failed publish
/// into a record that nodes had been handed a deployment nobody served. The reverse gap is not
/// harmless: reconcile is dropped at any await when the publisher lease renewal fails (a rolling
/// restart), and losing the write after a successful publish leaves `assignments` naming the
/// PREDECESSOR for a node the generation already advanced. If the group's admission gates have
/// since closed, the next pass replans with `current` = the predecessor, reads that node as
/// advanced on it, and publishes it backward — one signed generation, no `maxUnavailable`, no
/// health gate.
///
/// So the state is journalled locally before the upload and adopted here on the next pass. The
/// journal is evaluated at most once — it is removed whatever the verdict — so it can never
/// re-apply itself over a later in-cluster write.
async fn recover_pending_publication(
    record: AdmittedRecord<'_>,
    state_dir: &Path,
    store: &dyn ObjectStore,
    destination: &S3Destination,
    durable: DurableRolloutState,
    resource_version: Option<String>,
) -> Result<(DurableRolloutState, Option<String>), Box<dyn std::error::Error>> {
    let AdmittedRecord {
        configmaps,
        name,
        namespace,
        owner,
    } = record;
    let path = state_dir.join(PENDING_STATE_FILE);
    let Ok(bytes) = tokio::fs::read(&path).await else {
        return Ok((durable, resource_version));
    };
    // The journal is unreadable: there is nothing to recover from it.
    let mut recovered = None;
    if let Ok(pending) = serde_json::from_slice::<PendingPublication>(&bytes) {
        // The STORE is the ONE authority on whether the journalled generation was uploaded: it
        // serves `version` iff this upload landed. The publication marker cannot answer it in
        // either direction. It is not NECESSARY — it is written after the upload, so a death in that
        // gap leaves it naming the predecessor while the store genuinely serves this generation —
        // and it is not SUFFICIENT either: the marker describes the content and the signed metadata,
        // so a pass triggered by neither (an admission that moves no node, over unchanged content
        // and metadata) journals a marker that was ALREADY on disk before the upload was attempted,
        // and reading that equality as proof adopted the state of an upload that never happened.
        if store_published_version(store, destination).await? == Some(pending.version) {
            let marker_path = state_dir.join("published-plan.sha256");
            if tokio::fs::read_to_string(&marker_path)
                .await
                .ok()
                .as_deref()
                != Some(pending.marker.as_str())
            {
                // The upload landed and the process died before the marker write. Finish it, so the
                // local record and the store agree again instead of the next pass republishing
                // identical content under a new version.
                tracing::warn!(
                    version = pending.version,
                    "the object store serves a generation whose local publication marker was never \
                     written (the process died between the upload and the marker); adopting the \
                     journalled state rather than discarding a live generation's rollout state"
                );
                foundation::durable::atomic_write(
                    &marker_path,
                    ".published-",
                    pending.marker.as_bytes(),
                )?;
            }
            recovered = Some(pending.state);
        }
        // Otherwise the upload never completed: the store does not serve this generation, so nothing
        // was ever handed to a node and there is nothing to record.
    }
    let outcome = match recovered {
        Some(state) if state != durable => {
            tracing::warn!(
                configmap = name,
                "a published generation was never recorded in-cluster (the reconcile was cancelled \
                 or the process restarted between the upload and the write); adopting it from the \
                 local journal so no already-advanced node is republished on its predecessor"
            );
            let version =
                store_admitted_state(configmaps, name, namespace, &state, resource_version, owner)
                    .await?;
            (state, version)
        }
        _ => (durable, resource_version),
    };
    tokio::fs::remove_file(&path).await.ok();
    Ok(outcome)
}

/// The control plane's durable rollout state: what each group is pinned to, and which group each
/// node was routed to in the last published generation.
///
/// Every field is a claim about a generation that WAS published, so it is written only after the
/// signing and upload of that generation succeed (see `reconcile_once`). Recording it first left a
/// record saying nodes had been handed a deployment that a failed publish never served — and for a
/// blind node, `assignments` is the only staging signal there is.
///
/// The routing half exists because publication REPLACES the whole target set: a node left out of a
/// generation does not keep its old assignment, its `agents/<node>.json` target simply stops
/// existing. Knowing what a node was last published under is what lets a group that cannot be
/// planned this pass (quarantined, or waiting on its inputs) leave that node exactly where it was.
#[derive(Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct DurableRolloutState {
    pub admitted: BTreeMap<String, crate::rollout::AdmittedDeployment>,
    pub routing: BTreeMap<String, String>,
    /// Node → the deployment identity the last generation published for it. A staged rollout reads
    /// it to tell a node it has already advanced from one it has not, so a node that goes quiet
    /// while rebooting into its update is never republished under the predecessor.
    ///
    /// Rebuilt from each publication, so it holds exactly the nodes of the current generation and
    /// never accumulates. It is stored INVERTED (see [`encode_assignments`]) because the document
    /// shares a ConfigMap's single 1 MiB object budget with `routing`.
    pub assignments: BTreeMap<String, String>,
}

/// The stored form of the published assignments: deployment identity → the nodes it was published
/// to. Inverted from the in-memory node → identity map deliberately. Identities are per-GROUP — a
/// fleet has at most two live ones per group — so writing a 64-character digest against every node
/// name doubled the per-node cost of a document that must fit, together with the routing map, in
/// one ConfigMap.
fn encode_assignments(assignments: &BTreeMap<String, String>) -> BTreeMap<String, Vec<String>> {
    let mut inverted: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (node, identity) in assignments {
        inverted
            .entry(identity.clone())
            .or_default()
            .push(node.clone());
    }
    inverted
}

fn decode_assignments(stored: BTreeMap<String, Vec<String>>) -> BTreeMap<String, String> {
    stored
        .into_iter()
        .flat_map(|(identity, nodes)| nodes.into_iter().map(move |node| (node, identity.clone())))
        .collect()
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
    state: &DurableRolloutState,
    resource_version: Option<String>,
    owner: Option<OwnerReference>,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let data = BTreeMap::from([
        ("state.json".into(), serde_json::to_string(&state.admitted)?),
        (
            "routing.json".into(),
            serde_json::to_string(&state.routing)?,
        ),
        (
            "assignments.json".into(),
            serde_json::to_string(&encode_assignments(&state.assignments))?,
        ),
    ]);
    // A ConfigMap is one etcd object with a hard 1 MiB ceiling, and every per-node map here grows
    // with the fleet. Past the ceiling the apiserver rejects EVERY write, so the control plane can
    // neither record an admission nor advance a rollout — and it does so with an error that says
    // nothing about fleet size.
    //
    // The 768 KiB mark is therefore a WARNING, not a refusal. Refusing here bricked the repository
    // for every already-admitted node — no publication ever completed again, and it never
    // self-healed — which is a strictly worse outcome than writing a document the apiserver still
    // accepts. What actually bounds the growth is [`MAX_ENROLLED_AGENTS`], enforced where agents are
    // created; this reports how close a fleet is to the wall so the operator sees it coming.
    let bytes: usize = data.values().map(String::len).sum();
    if bytes > STATE_BYTES_LIMIT {
        tracing::warn!(
            configmap = name,
            bytes,
            limit = STATE_BYTES_LIMIT,
            "the durable rollout state for this repository is approaching the 1 MiB ceiling a \
             ConfigMap can hold; split this fleet across UpdateRepositories (the state is \
             proportional to the number of published agents)"
        );
    }
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
    let written = if resource_version.is_some() {
        configmaps
            .replace(name, &PostParams::default(), &configmap)
            .await?
    } else {
        configmaps
            .create(&PostParams::default(), &configmap)
            .await?
    };
    Ok(written.metadata.resource_version)
}

/// Publish each `UpdateGroupSet`'s observed rollout state as its status.
async fn publish_group_set_statuses(
    sets: &Api<UpdateGroupSet>,
    set_resources: &[UpdateGroupSet],
    statuses: &[SetStatus],
    alerts: Option<&Arc<crate::alerts::AlertSink>>,
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
        // Edge-triggered logging, from the ONE place that knows both the value just computed and
        // the one last published. Freezing and calendar exhaustion are steady states that last for
        // days; logged from the planner they emitted a line per reconcile (one second) per set.
        let last = set.status.as_ref();
        if last.and_then(|status| status.frozen) != Some(status.frozen) {
            tracing::info!(
                set = %name,
                frozen = status.frozen,
                "UpdateGroupSet crossed its rollout schedule boundary (windows/calendar)"
            );
        }
        if status.calendar_exhausted
            && last.and_then(|status| status.calendar_exhausted) != Some(true)
        {
            tracing::warn!(
                set = %name,
                "UpdateGroupSet calendar has run out; it is now UNGATED and will roll at any hour \
                 — add a future approved window (or a rollout window) to re-gate it"
            );
        }
        if status.emergency
            != last
                .map(|status| status.emergency.clone())
                .unwrap_or_default()
        {
            tracing::warn!(
                set = %name,
                emergency = ?status.emergency,
                "members declaring spec.emergencyCorrection changed; these members bypass this \
                 set's rollout schedule until the flag is cleared"
            );
        }
        // Edge-triggered like `frozen`: a halt is a steady state that persists until the operator
        // stages corrected bytes, and the regression verdict is recomputed once per second.
        if status.halted != last.map(|status| status.halted.clone()).unwrap_or_default() {
            tracing::warn!(
                set = %name,
                halted = ?status.halted,
                "the regression verdict changed: enough nodes proved a staged deployment bad. \
                 Admission to each halted deployment is stopped in every member group until a \
                 deployment with a different identity is published."
            );
        }
        // The alertable set conditions, beside Ready: the regression verdict, and whether the
        // reconcile loop itself is converging. Transitions only reach the webhook.
        let previous = last
            .map(|status| status.conditions.as_slice())
            .unwrap_or_default();
        let mut conditions = vec![ready_condition(
            set.metadata.generation,
            "Reconciled",
            "This set's rollout throttle is reconciled.",
        )];
        let mut fired_events = Vec::new();
        for next in [
            crate::alerts::deployment_halted(
                set.metadata.generation,
                &status.halted,
                chrono::Utc::now(),
            ),
            // This writer only runs on a pass that has succeeded this far, so the streak it
            // reports is zero by construction; the failing loop's own writer
            // (`record_reconcile_failing`) is the only place a non-zero streak can come from.
            crate::alerts::reconcile_failing(set.metadata.generation, 0),
        ] {
            let condition_type = next.condition_type.clone();
            let (published, fired) = crate::alerts::carry_transition(
                crate::alerts::existing(previous, &condition_type),
                next,
            );
            if fired {
                fired_events.push(crate::alerts::AlertEvent::from_condition(
                    "UpdateGroupSet",
                    &name,
                    &published,
                ));
            }
            conditions.push(published);
        }
        let published = UpdateGroupSetStatus {
            observed_generation: set.metadata.generation,
            member_count: Some(status.member_count as u32),
            max_concurrent: Some(status.max_concurrent as u32),
            rolling_count: Some(status.rolling.len() as u32),
            rolling: status.rolling.clone(),
            settled: status.settled.clone(),
            unobservable: status.unobservable.clone(),
            shared: status.shared.clone(),
            emergency: status.emergency.clone(),
            // Emit the explicit bool, never `None`: the status is applied as a JSON *merge*
            // patch, and a merge that omits `frozen` leaves the previous value in place — so a
            // set that unfreezes (its calendar cleared or window reopened) would keep a stale
            // `frozen: true` forever. Writing `false` overwrites it and the gate reads open.
            frozen: Some(status.frozen),
            // Same merge-patch reasoning as `frozen`: write the explicit bool so a set that
            // re-gates (a new approved window added after exhaustion) clears a stale `true`.
            calendar_exhausted: Some(status.calendar_exhausted),
            halted: status.halted.clone(),
            conditions,
        };
        sets.patch_status(
            &name,
            &params,
            &Patch::Merge(serde_json::json!({"status": published})),
        )
        .await?;
        if let Some(sink) = alerts {
            sink.spawn(fired_events);
        }
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
    trust_anchor: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let offline: Vec<&UpdateAgent> = agents
        .iter()
        .filter(|agent| agent.spec.identity.kind == crate::AgentIdentityKind::Manual)
        .collect();
    let Some(trust_anchor) = offline_enrollment_anchor(offline.len(), trust_anchor)? else {
        return Ok(());
    };
    for agent in offline {
        let name = agent.name_any();
        let secret_name = format!("{name}-enrollment");
        let assignment = updated_contracts::telemetry::assignment_object_key(
            &repository.spec.assignment_prefix,
            &name,
        );
        // An existing Secret is final: it is immutable, so nothing below could rewrite it anyway.
        // Check that first, with one apiserver read. Resolving the signed bundle costs a metadata
        // walk plus several object-store reads PER AGENT, and this runs on every reconcile — for a
        // steady fleet of manual agents that is a continuous stream of requests producing a 409.
        if let Some(existing) = secrets.get_opt(&secret_name).await? {
            report_unusable_enrollment_secret(
                check_enrollment_secret(&existing, &name, &assignment),
                &name,
                &secret_name,
            );
            continue;
        }
        // Resolve the exact signed documents this agent pins straight from the published
        // consistent snapshot, through the one walk the gateway's `/enroll` also uses.
        // A single agent's bundle may legitimately be unresolvable right now: a manual agent whose
        // group has not been admitted yet (closed window, exhausted maxConcurrent, unresolved
        // inputs) is deliberately left out of this generation, so no assignment target exists. That
        // is a per-agent condition, not a publication failure — failing here would abort the rest
        // of the projection, including the very status that explains why the group is gated.
        let signed = match crate::gateway::resolve_signed_enrollment(
            store,
            prefix,
            &assignment,
            trust_anchor,
        )
        .await
        {
            Ok(signed) => signed,
            Err(error) => {
                tracing::warn!(
                    agent = %name,
                    assignment = %assignment,
                    %error,
                    "no enrollment bundle can be resolved for this agent yet, so its Secret is not \
                     issued on this pass; this is expected while the agent's group is waiting to \
                     be admitted. Every other agent, and publication, are unaffected."
                );
                continue;
            }
        };
        let bundle = signed.into_bundle(name.clone(), public_url, assignment.clone());
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
            // Lost a race with another writer (or our own earlier pass): re-read and validate.
            Err(kube::Error::Api(error)) if error.code == 409 => {
                let existing = secrets.get(&secret_name).await?;
                report_unusable_enrollment_secret(
                    check_enrollment_secret(&existing, &name, &assignment),
                    &name,
                    &secret_name,
                );
            }
            // The apiserver refused to create this one agent's Secret — a derived name over 253
            // characters, an RBAC denial, a transient 5xx. Propagating it aborts the whole
            // post-publication projection for the repository (set statuses, subscription delivery)
            // on every pass, forever, over one agent's Secret; see
            // [`report_unusable_enrollment_secret`]. It is one agent's offline provisioning that is
            // stuck, so it is reported as such and the pass carries on — a transient cause retries
            // next reconcile of its own accord.
            Err(error) => tracing::error!(
                agent = %name,
                secret = %secret_name,
                %error,
                "this agent's enrollment Secret could not be created; offline provisioning for this \
                 agent is stopped until the cause is cleared. Every other agent, and publication, \
                 are unaffected."
            ),
        }
    }
    Ok(())
}

/// The trust anchor offline enrollment must use, or the reason there is nothing to do.
///
/// `Ok(None)` — no offline-provisioned agent needs a bundle, so the anchor is irrelevant.
/// `Ok(Some(anchor))` — issue bundles pinned against this anchor.
/// `Err` — bundles are needed and cannot be issued. Without an anchor there is nothing to verify a
/// store-served root against, and an unverifiable bundle must never be handed out; but that also
/// means offline provisioning has STOPPED, so it is reported as the failure it is. Returning `Ok`
/// there left an operator watching for a Secret that would never appear, with nothing logged to
/// say why.
fn offline_enrollment_anchor(
    offline_agents: usize,
    trust_anchor: Option<&str>,
) -> Result<Option<&str>, StorageError> {
    match (offline_agents, trust_anchor) {
        (0, _) => Ok(None),
        (_, Some(anchor)) => Ok(Some(anchor)),
        (waiting, None) => Err(StorageError(format!(
            "{waiting} offline-provisioned agent(s) need an enrollment bundle, but this \
             repository's status carries no routingRootSha256 to pin the published root against; \
             no bundle can be issued until a generation is signed and its anchor recorded"
        ))),
    }
}

/// Confirm an existing immutable enrollment Secret really is this agent's, for this assignment.
/// A name collision with another agent's bundle is never silently accepted.
fn check_enrollment_secret(existing: &Secret, agent: &str, assignment: &str) -> Result<(), String> {
    let bundle = existing
        .data
        .as_ref()
        .and_then(|data| data.get("enrollment.json"))
        .and_then(|bytes| serde_json::from_slice::<crate::EnrollmentBundle>(&bytes.0).ok());
    match bundle {
        Some(bundle) if bundle.agent_id == agent && bundle.assignment == assignment => Ok(()),
        Some(bundle) => Err(format!(
            "it carries a bundle for agent {:?} and assignment {:?}, not {agent:?} and \
             {assignment:?}",
            bundle.agent_id, bundle.assignment
        )),
        None => Err("it carries no readable enrollment.json".into()),
    }
}

/// Report an enrollment Secret this controller cannot use, WITHOUT failing the reconcile.
///
/// The Secret is created immutable, so nothing here can ever repair or overwrite one that is
/// foreign, unreadable, or names a stale assignment — the ordinary cause being a changed
/// `spec.assignmentPrefix` under a correctly owned bundle. Propagating it aborted the whole
/// post-publication projection: every later step (set statuses, subscription delivery) was skipped
/// and every reconcile failed, once per second, forever, over one agent's Secret. It is one agent's
/// offline provisioning that is stuck, so it is reported as such and the pass carries on.
fn report_unusable_enrollment_secret(outcome: Result<(), String>, agent: &str, secret_name: &str) {
    if let Err(problem) = outcome {
        tracing::error!(
            agent,
            secret = secret_name,
            %problem,
            "this agent's enrollment Secret cannot be used and is immutable, so this controller \
             cannot reissue it; offline provisioning for this agent is stopped until an operator \
             deletes the Secret. Every other agent, and publication, are unaffected."
        );
    }
}

pub(crate) fn metadata_version(metadata: &serde_json::Value, name: &str) -> Result<u64, String> {
    metadata
        .pointer(&format!("/signed/meta/{name}/version"))
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("signed metadata does not declare {name} version"))
}

/// Whether this repository can still enrol nodes, reported alongside `Ready` so the ceiling is
/// visible long before it is reached — `/enroll` refuses at exactly the same number, and a fleet
/// that has hit it must be split across repositories rather than left to fill one ConfigMap.
fn enrollment_capacity_condition(generation: Option<i64>, agents: usize) -> ResourceCondition {
    let full = agents >= MAX_ENROLLED_AGENTS as usize;
    condition(
        "EnrollmentCapacity",
        !full,
        generation,
        if full { "AtCapacity" } else { "Available" },
        &format!("{agents} of at most {MAX_ENROLLED_AGENTS} agents are enrolled."),
    )
}

/// The condition type [`ready_condition`] and [`failed_condition`] both report on. Named because a
/// writer that replaces the conditions array has to be able to say which entry is its own.
const READY_CONDITION: &str = "Ready";

/// A `Ready` [`ResourceCondition`] for `generation`, reporting success (`status: "True"`) or
/// failure (`status: "False"`). The single place a Ready condition's fields are assembled;
/// [`ready_condition`] and [`failed_condition`] are the two named entry points.
fn condition(
    condition_type: &str,
    ok: bool,
    generation: Option<i64>,
    reason: &str,
    message: &str,
) -> ResourceCondition {
    ResourceCondition {
        condition_type: condition_type.into(),
        status: if ok { "True" } else { "False" }.into(),
        reason: reason.into(),
        message: message.into(),
        observed_generation: generation,
        last_transition_time: chrono::Utc::now().to_rfc3339(),
    }
}

/// Whether this repository's trust anchor is being kept fresh, reported unconditionally alongside
/// `Ready`. A root renewal that fails deliberately does not stop content publication (see
/// [`renew_expiring_root`]), so without a condition of its own the only symptom would be the root
/// silently marching to its hard expiry — at which point every agent's metadata refresh fails at
/// once, and nothing recovers from inside the loop.
fn root_renewal_condition(generation: Option<i64>, failure: Option<&str>) -> ResourceCondition {
    condition(
        "RootRenewal",
        failure.is_none(),
        generation,
        if failure.is_some() {
            "RenewalFailed"
        } else {
            "Current"
        },
        failure.unwrap_or("The TUF root is signed and outside its renewal window."),
    )
}

fn ready_condition(generation: Option<i64>, reason: &str, message: &str) -> ResourceCondition {
    condition(READY_CONDITION, true, generation, reason, message)
}

fn failed_condition(generation: Option<i64>, reason: &str, message: &str) -> ResourceCondition {
    condition(READY_CONDITION, false, generation, reason, message)
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
        held_agents: None,
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
    let mut status = group_generation_status(
        group.metadata.generation,
        None,
        group
            .status
            .as_ref()
            .and_then(|status| status.published_digest.clone()),
        failed_condition(group.metadata.generation, reason, message),
    );
    // A merge patch replaces the conditions array wholesale, so this writer speaks only for Ready
    // and carries every other condition forward untouched — the same rule `failure_status`
    // documents. Rewriting the array bare deleted the group's alert conditions, losing their
    // transition times and re-firing their webhooks when the group healed.
    status.conditions.extend(
        group
            .status
            .as_ref()
            .map(|status| status.conditions.as_slice())
            .unwrap_or_default()
            .iter()
            .filter(|condition| condition.condition_type != READY_CONDITION)
            .cloned(),
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
        held: Some(agent.spec.hold),
        cordoned: Some(agent.spec.cordon),
        // Same wholesale-replacement rule as `quarantine_group`: speak for Ready alone, carry
        // every foreign condition forward.
        conditions: std::iter::once(failed_condition(agent.metadata.generation, reason, message))
            .chain(
                prior
                    .map(|status| status.conditions.as_slice())
                    .unwrap_or_default()
                    .iter()
                    .filter(|condition| condition.condition_type != READY_CONDITION)
                    .cloned(),
            )
            .collect(),
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
    /// SHA-256 of the `root.json` this publisher signs with, recorded into the repository's status
    /// so enrollment can pin the store-served root against a value only the control plane writes.
    routing_root_sha256: Option<String>,
    /// Why this pass could not renew the TUF root, when it tried and failed. Carried into the
    /// repository's status because the failure is deliberately not fatal: publication continues and
    /// this condition is the only thing that tells the operator the trust anchor is going stale.
    root_renewal_failure: Option<String>,
    groups: &'a [UpdateGroup],
    agents: &'a [UpdateAgent],
    plan: &'a crate::PublicationPlan,
    reports: &'a HashMap<String, Envelope>,
    /// Each group's verdict for this generation as the rollout planner decided it — the single
    /// source for whether a group is held, rolling, settled, or unobservable.
    group_progress: &'a BTreeMap<String, crate::rollout::GroupProgress>,
    public_keys: &'a HashMap<String, Vec<u8>>,
    /// Agents the operator is holding (`spec.hold`), for the per-group `heldAgents` projection.
    holds: &'a BTreeSet<String>,
    /// Per-group node accounting from the planner, for the alert conditions.
    node_counts: &'a BTreeMap<String, crate::rollout::GroupNodes>,
    /// Groups bound by the regression verdict, for the per-group `DeploymentHalted` condition —
    /// the one place a halted SET-LESS group is operator-visible.
    halted_groups: &'a BTreeMap<String, crate::HaltedDeployment>,
    now: chrono::DateTime<chrono::Utc>,
}

/// The one post-publication projection path. A reconcile that reuses an unchanged signed
/// generation and one that publishes a new generation must expose exactly the same enrollment,
/// status, and subscription state; keeping that sequence here prevents the two paths drifting.
struct ReconcileProjection<'a> {
    client: &'a Client,
    namespace: &'a str,
    state_dir: &'a Path,
    public_url: &'a str,
    secrets: &'a Api<Secret>,
    repository: &'a UpdateRepository,
    store: &'a dyn ObjectStore,
    apis: ResourceApis<'a>,
    snapshot: StatusSnapshot<'a>,
    sets: &'a Api<UpdateGroupSet>,
    set_resources: &'a [UpdateGroupSet],
    set_statuses: &'a [SetStatus],
}

impl ReconcileProjection<'_> {
    /// The trust anchor this generation publishes under: the freshly recorded one when this pass
    /// signed, else whatever the repository's status already carries.
    fn published_root_sha256(&self) -> Option<String> {
        self.snapshot.routing_root_sha256.clone().or_else(|| {
            self.repository
                .status
                .as_ref()
                .and_then(|status| status.routing_root_sha256.clone())
        })
    }

    async fn publish(&self, hooks: &mut ReconcileHooks) -> Result<(), Box<dyn std::error::Error>> {
        // Statuses first, enrollment Secrets second. The repository status is where the trust
        // anchor this pass signed with is recorded, and a missing anchor makes offline enrollment
        // fail loudly below — so the anchor must be written before anything is allowed to fail on
        // its absence.
        publish_resource_statuses(
            ResourceApis {
                repositories: self.apis.repositories,
                groups: self.apis.groups,
                agents: self.apis.agents,
            },
            StatusSnapshot {
                repository: self.snapshot.repository,
                routing_root_sha256: self.snapshot.routing_root_sha256.clone(),
                root_renewal_failure: self.snapshot.root_renewal_failure.clone(),
                groups: self.snapshot.groups,
                agents: self.snapshot.agents,
                plan: self.snapshot.plan,
                reports: self.snapshot.reports,
                group_progress: self.snapshot.group_progress,
                public_keys: self.snapshot.public_keys,
                holds: self.snapshot.holds,
                node_counts: self.snapshot.node_counts,
                halted_groups: self.snapshot.halted_groups,
                now: self.snapshot.now,
            },
            self.set_resources,
            &mut hooks.progress,
            hooks.alerts.as_ref(),
        )
        .await?;
        publish_enrollment_secrets(
            self.secrets,
            self.repository,
            self.snapshot.agents,
            self.store,
            &self.repository.spec.s3.prefix,
            self.public_url,
            self.published_root_sha256().as_deref(),
        )
        .await?;
        publish_group_set_statuses(
            self.sets,
            self.set_resources,
            self.set_statuses,
            hooks.alerts.as_ref(),
        )
        .await?;
        deliver_subscriptions(
            self.client,
            self.namespace,
            self.repository,
            self.state_dir,
            self.public_url,
        )
        .await;
        Ok(())
    }
}

/// The `stuckAfterSeconds` governing a group: the tightest value among the sets whose selectors
/// claim it, else the default. A group in no set still gets the default — a stuck rollout is worth
/// naming whether or not a set throttles it.
fn stuck_after_seconds(sets: &[UpdateGroupSet], group: &UpdateGroup) -> u64 {
    sets.iter()
        .filter(|set| crate::selector_matches(&set.spec.selector.match_labels, group.labels()))
        .filter_map(|set| set.spec.stuck_after_seconds)
        .min()
        .unwrap_or(crate::alerts::DEFAULT_STUCK_AFTER_SECONDS)
}

async fn publish_resource_statuses(
    apis: ResourceApis<'_>,
    snapshot: StatusSnapshot<'_>,
    sets: &[UpdateGroupSet],
    progress_marks: &mut crate::alerts::ProgressTracker,
    alerts: Option<&Arc<crate::alerts::AlertSink>>,
) -> Result<(), kube::Error> {
    let ResourceApis {
        repositories,
        groups,
        agents,
    } = apis;
    let StatusSnapshot {
        repository,
        routing_root_sha256,
        root_renewal_failure,
        groups: group_resources,
        agents: agent_resources,
        plan,
        reports,
        group_progress,
        public_keys,
        holds,
        node_counts,
        halted_groups,
        now,
    } = snapshot;
    // The stuck clock only tracks groups that still exist; a deleted group's mark must not linger.
    progress_marks.retain(|name| group_progress.contains_key(name));
    let params = PatchParams::default();
    let repository_generation = repository.metadata.generation;
    let repository_status = UpdateRepositoryStatus {
        observed_generation: repository_generation,
        published_digest: Some(plan.digest.clone()),
        agent_count: Some(agent_resources.len() as u32),
        routing_root_sha256: routing_root_sha256.clone().or_else(|| {
            repository
                .status
                .as_ref()
                .and_then(|status| status.routing_root_sha256.clone())
        }),
        conditions: vec![
            ready_condition(
                repository_generation,
                "Published",
                "The complete routing generation is published.",
            ),
            enrollment_capacity_condition(repository_generation, agent_resources.len()),
            root_renewal_condition(repository_generation, root_renewal_failure.as_deref()),
        ],
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
        // The verdict is the planner's, never re-derived here. Deciding it locally — `previous` for
        // "rolling" and a deployment-NAME comparison for "held" — reported a group Ready while a
        // change to its digest, arguments, or resolved inputs was still unadmitted, because the
        // planner deliberately compares the whole desired deployment and this did not.
        // Every group reaching here has a verdict: `reconcile_once` retained `group_resources` to
        // exactly the non-quarantined groups, and the planner decides one for every planned group
        // — a group waiting on its inputs or a prerequisite is classified `Held`, not omitted. A
        // group with none is one this pass cannot speak for, so its status is left as it stands
        // rather than given a locally invented verdict.
        let Some(progress) = group_progress.get(&name).copied() else {
            continue;
        };
        let condition = match progress {
            crate::rollout::GroupProgress::Held => failed_condition(
                group.metadata.generation,
                "Held",
                "This group's desired deployment is waiting for rollout capacity, a rollout \
                 window, its inputs, or a prerequisite group.",
            ),
            crate::rollout::GroupProgress::Rolling => failed_condition(
                group.metadata.generation,
                "Rolling",
                "This group is incrementally advancing to its admitted deployment.",
            ),
            crate::rollout::GroupProgress::Settled => ready_condition(
                group.metadata.generation,
                "Published",
                "This group's deployment is fully admitted in the published routing generation.",
            ),
            // Published in full, but nothing can confirm it: every agent this group selects was
            // provisioned offline (no pinned key) or it selects none at all. Ready — it is not
            // waiting on anything — but the reason says what the claim rests on.
            crate::rollout::GroupProgress::Unobservable => ready_condition(
                group.metadata.generation,
                "PublishedUnobservable",
                "This group's deployment is published to every agent it selects, but none of them \
                 can report telemetry, so its health is unconfirmed.",
            ),
        };
        let mut status = group_generation_status(
            group.metadata.generation,
            Some(matched as u32),
            Some(plan.digest.clone()),
            condition,
        );
        // A forgotten hold must be a visible condition, not a mystery: the count of this group's
        // held agents rides its status every pass, keyed on the published routing so it counts
        // exactly the agents this group is accountable for.
        status.held_agents = Some(
            plan.node_groups
                .iter()
                .filter(|(node, selected)| *selected == &name && holds.contains(*node))
                .count() as u32,
        );
        // The alertable conditions, appended beside Ready every pass and cleared the same way —
        // standard condition semantics, never deleted. Each is a projection of a verdict computed
        // above (the planner's progress, the freshness counts admission already read); no new
        // detection logic lives here. The previous value is read off the resource itself, so a
        // transition time survives a leader change and only genuine flips reach the webhook.
        let previous = group
            .status
            .as_ref()
            .map(|status| status.conditions.as_slice())
            .unwrap_or_default();
        let counts = node_counts.get(&name).cloned().unwrap_or_default();
        let progressed_at =
            progress_marks.observe(&name, counts.target.clone(), counts.on_target, now);
        // A halted group's own status carries the verdict — the fleet-wide halt binds set-less
        // groups too, and a freeze with no visible cause is not a control.
        let bound = halted_groups
            .get(&name)
            .map(std::slice::from_ref)
            .unwrap_or(&[]);
        let alertable = [
            crate::alerts::rollout_stuck(
                group.metadata.generation,
                progress == crate::rollout::GroupProgress::Rolling,
                progressed_at,
                stuck_after_seconds(sets, group),
                now,
            ),
            crate::alerts::reports_stale(
                group.metadata.generation,
                counts.fresh,
                counts.observable,
                group.spec.max_unavailable.unwrap_or(1),
            ),
            crate::alerts::deployment_halted(group.metadata.generation, bound, now),
        ];
        let mut fired_events = Vec::new();
        for next in alertable {
            let condition_type = next.condition_type.clone();
            let (published, fired) = crate::alerts::carry_transition(
                crate::alerts::existing(previous, &condition_type),
                next,
            );
            if fired {
                fired_events.push(crate::alerts::AlertEvent::from_condition(
                    "UpdateGroup",
                    &name,
                    &published,
                ));
            }
            status.conditions.push(published);
        }
        groups
            .patch_status(
                &name,
                &params,
                &Patch::Merge(serde_json::json!({"status": status})),
            )
            .await?;
        // Enqueued the moment the condition is durably written, never later: transitions that
        // waited for the whole projection were silently lost when a later stage failed, and the
        // edge trigger meant they never re-fired.
        if let Some(sink) = alerts {
            sink.spawn(fired_events);
        }
    }

    for agent in agent_resources {
        let name = agent.name_any();
        // A node withheld from this generation (its group is quarantined, or awaiting its first
        // admission) is not in `plan.node_groups`, and no assignment target was signed for it.
        let selected = plan.node_groups.get(&name).cloned();
        // So it must not claim one. Reporting `Ready=True`/`Published` with a concrete
        // assignmentPath here showed a withheld agent as healthy and published while its machine's
        // TUF fetch of that exact target 404s forever, and left the operator no signal at all that
        // it is blocked on a quarantined group. The published fields are omitted with the same
        // discipline a failed reconcile omits them (see [`UpdateRepositoryStatus`]): a claim only a
        // published assignment can make is not made.
        let (assignment_path, published_digest, condition) = if selected.is_some() {
            (
                Some(updated_contracts::telemetry::assignment_object_key(
                    &repository.spec.assignment_prefix,
                    &name,
                )),
                Some(plan.digest.clone()),
                ready_condition(
                    agent.metadata.generation,
                    "Published",
                    "This agent's exact assignment is published.",
                ),
            )
        } else {
            (
                None,
                None,
                failed_condition(
                    agent.metadata.generation,
                    "Withheld",
                    "This agent is not routed in the published generation: its group is waiting \
                     for rollout capacity, a rollout window, its inputs, or a prerequisite group, \
                     or it is held out of admission entirely.",
                ),
            )
        };
        // The gate returns the report only when it is authentic, so a status can never be written from
        // an unverified envelope: there is no report value to read unless verification succeeded.
        let report = public_keys.get(&name).and_then(|key| {
            let now_ms = now.timestamp_millis().max(0) as u64;
            reports.get(&name).and_then(|envelope| {
                updated_contracts::telemetry::report_is_authentic_and_fresh(
                    envelope, &name, key, now_ms,
                )
            })
        });
        let status = UpdateAgentStatus {
            observed_generation: agent.metadata.generation,
            selected_group: selected,
            assignment_path,
            published_digest,
            reported_version: report
                .as_ref()
                .map(|report| report.version.clone())
                .filter(|version| !version.is_empty()),
            reported_ready: report.as_ref().map(|report| report.healthy),
            // Explicit bools, never omitted: this status is a merge patch, and omitting the field
            // would leave a cleared hold or cordon reading `true` forever.
            held: Some(agent.spec.hold),
            cordoned: Some(agent.spec.cordon),
            enrollment_secret_ref: (agent.spec.identity.kind == crate::AgentIdentityKind::Manual)
                .then(|| crate::LocalSecretReference {
                    name: format!("{name}-enrollment"),
                }),
            conditions: vec![condition],
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
    let observed = repository
        .status
        .as_ref()
        .map(|status| status.conditions.as_slice())
        .unwrap_or_default();
    let status = failure_status(repository.metadata.generation, message, observed);
    repositories
        .patch_status(
            repository_name,
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({"status": status})),
        )
        .await?;
    Ok(())
}

/// Record a failed pass against every `UpdateGroupSet`: bump the failure streak and write the
/// `ReconcileFailing` condition, which rises on CONSECUTIVE failures (one failed pass is an
/// ordinary transient the next second retries). Called from the loop's failure branch, where
/// `publish_group_set_statuses` — the success-path writer of the same condition — never runs; the
/// conditions array is patched alone, with every foreign condition carried forward, so a failing
/// loop can still raise the one condition that says so. Transitions go to the same webhook sink.
pub async fn record_reconcile_failing(
    client: Client,
    namespace: &str,
    hooks: &mut ReconcileHooks,
) -> Result<(), kube::Error> {
    hooks.consecutive_failures = hooks.consecutive_failures.saturating_add(1);
    let sets: Api<UpdateGroupSet> = Api::namespaced(client, namespace);
    for set in sets.list(&ListParams::default()).await? {
        let name = set.name_any();
        let observed = set
            .status
            .as_ref()
            .map(|status| status.conditions.as_slice())
            .unwrap_or_default();
        let next =
            crate::alerts::reconcile_failing(set.metadata.generation, hooks.consecutive_failures);
        let (published, fired) = crate::alerts::carry_transition(
            crate::alerts::existing(observed, crate::alerts::RECONCILE_FAILING),
            next,
        );
        // The condition's message is streak-independent, so once it has stabilized every further
        // failed pass would patch an identical document: skip the write — a failing loop must not
        // also be an apiserver write per set per second.
        if !fired
            && crate::alerts::existing(observed, crate::alerts::RECONCILE_FAILING)
                == Some(&published)
        {
            continue;
        }
        let event = crate::alerts::AlertEvent::from_condition("UpdateGroupSet", &name, &published);
        // A merge patch replaces the conditions array wholesale, so every condition this writer
        // does not speak for is carried forward untouched — the same rule `failure_status` applies.
        let mut conditions: Vec<ResourceCondition> = observed
            .iter()
            .filter(|condition| condition.condition_type != crate::alerts::RECONCILE_FAILING)
            .cloned()
            .collect();
        conditions.push(published);
        sets.patch_status(
            &name,
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({"status": {"conditions": conditions}})),
        )
        .await?;
        // Enqueued per set, after ITS durable write: a later set's failed patch must not lose an
        // earlier set's already-recorded transition.
        if fired {
            if let Some(sink) = &hooks.alerts {
                sink.spawn(vec![event]);
            }
        }
    }
    Ok(())
}

/// The status document a failed reconcile patches in. A failure observes the generation and nothing
/// else: the published digest, the agent count, and the trust anchor are all claims only a
/// SUCCESSFUL publish can make, so they are omitted and the last successful reconcile's values
/// survive the merge patch (see [`UpdateRepositoryStatus`]). Pure, so that omission is testable —
/// sending `null` for the agent count deleted the field `gateway::at_enrollment_capacity` reads,
/// which silently uncapped enrollment for as long as the failure lasted.
///
/// `observed` is the conditions array the repository currently carries. A merge patch REPLACES an
/// array wholesale, so the same omission rule applies to the entries of this one: a failure speaks
/// only for [`READY_CONDITION`] and carries every other condition forward untouched. Rewriting the
/// array with just its own entry deleted `EnrollmentCapacity` — the only operator-visible sign that
/// `/enroll` is at its ceiling — for the entire duration of any reconcile failure.
fn failure_status(
    generation: Option<i64>,
    message: &str,
    observed: &[ResourceCondition],
) -> UpdateRepositoryStatus {
    let mut conditions = vec![failed_condition(
        generation,
        "ReconciliationFailed",
        message,
    )];
    conditions.extend(
        observed
            .iter()
            .filter(|condition| condition.condition_type != READY_CONDITION)
            .cloned(),
    );
    UpdateRepositoryStatus {
        observed_generation: generation,
        published_digest: None,
        agent_count: None,
        routing_root_sha256: None,
        conditions,
    }
}

fn desired_publication_digest(
    repository: &crate::UpdateRepositorySpec,
    plan_digest: &str,
) -> Result<String, serde_json::Error> {
    let mut digest = updated::hash::Sha256Hasher::new();
    digest.update(&serde_json::to_vec(repository)?);
    digest.update(&[0]);
    digest.update(plan_digest.as_bytes());
    Ok(digest.finish_hex())
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

/// A Secret entry that may legitimately be absent, unlike [`secret_string`] which requires it.
fn optional_secret_string(
    secret: Option<&Secret>,
    key: &str,
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    let Some(bytes) = secret
        .and_then(|secret| secret.data.as_ref())
        .and_then(|data| data.get(key))
    else {
        return Ok(None);
    };
    Ok(Some(String::from_utf8(bytes.0.clone())?))
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

    /// Write a metadata document that declares nothing but when it expires — the only field the
    /// renewal trigger reads.
    fn signed_until(dir: &Path, file: &str, expires: chrono::DateTime<chrono::Utc>) {
        std::fs::create_dir_all(dir.join("metadata")).unwrap();
        std::fs::write(
            dir.join("metadata").join(file),
            serde_json::json!({"signed": {"expires": expires.to_rfc3339()}}).to_string(),
        )
        .unwrap();
    }

    #[tokio::test]
    async fn metadata_inside_its_renewal_window_is_re_signed_before_it_expires() {
        let repo = tempfile::tempdir().unwrap();
        let now = chrono::Utc::now();

        // Freshly signed: the content digest is the only publication trigger.
        signed_until(
            repo.path(),
            "root.json",
            now + chrono::Duration::days(METADATA_EXPIRY_DAYS),
        );
        signed_until(
            repo.path(),
            "timestamp.json",
            now + chrono::Duration::days(METADATA_EXPIRY_DAYS),
        );
        let renewals = expiring_metadata(repo.path(), now).await;
        assert!(renewals.is_empty());
        assert!(!publication_required(true, &renewals), "nothing to do");
        assert!(
            publication_required(false, &renewals),
            "changed content always publishes"
        );

        // Only the online metadata is inside its window, and the fleet is at steady state. It must
        // still publish — the published-plan digest matches forever, so without this nothing is
        // ever re-signed and the whole fleet stops loading the repository the day it expires — and
        // it must NOT renew the root, which is a version bump of the fleet's trust anchor.
        signed_until(
            repo.path(),
            "timestamp.json",
            now + chrono::Duration::days(METADATA_RENEWAL_DAYS - 1),
        );
        let renewals = expiring_metadata(repo.path(), now).await;
        assert_eq!(renewals, vec![TufRole::Online]);
        assert!(publication_required(true, &renewals));
        assert!(!renewals.contains(&TufRole::Root));

        // The root inside its own window is what selects the renewal branch.
        signed_until(
            repo.path(),
            "root.json",
            now + chrono::Duration::days(METADATA_RENEWAL_DAYS - 1),
        );
        let renewals = expiring_metadata(repo.path(), now).await;
        assert_eq!(renewals, vec![TufRole::Root, TufRole::Online]);
        assert!(publication_required(true, &renewals));

        // Already expired is still a renewal, not a special case.
        signed_until(repo.path(), "root.json", now - chrono::Duration::days(1));
        assert!(expiring_metadata(repo.path(), now)
            .await
            .contains(&TufRole::Root));

        // Absent or unreadable is never a renewal: there is nothing signed to re-sign, and the
        // initialization path (with its rollback guard) owns that case.
        std::fs::write(repo.path().join("metadata/root.json"), b"not json").unwrap();
        std::fs::remove_file(repo.path().join("metadata/timestamp.json")).unwrap();
        assert!(expiring_metadata(repo.path(), now).await.is_empty());
    }

    /// A root that cannot be re-signed is an operator emergency, not a reason to stop publishing.
    /// Propagating the error halted every rollout, admission, and durable write for the whole
    /// ninety-day renewal window over a signing-Secret key set that has nothing to do with the
    /// content — and dropping the role from `renewals` is what stops the un-renewable root
    /// demanding a freshly signed generation on every reconcile for the same ninety days.
    #[tokio::test]
    async fn a_root_that_cannot_be_renewed_reports_itself_without_stopping_publication() {
        let tmp = tempfile::tempdir().unwrap();
        let repo_dir = tmp.path().join("repository");
        let keys_dir = tmp.path().join("keys");
        let keys = updated_tuf::repo::generate_keys(&keys_dir).await.unwrap();
        updated_tuf::repo::init(&repo_dir, &keys, METADATA_EXPIRY_DAYS)
            .await
            .unwrap();

        // The signing Secret was regenerated: its root keys are well formed but none of them is in
        // the root role the live root.json lists, so the renewal cannot meet the role's threshold.
        let backup = tmp.path().join("backup");
        std::fs::create_dir_all(&backup).unwrap();
        for name in ["root.pk8", "root.next.pk8"] {
            std::fs::copy(keys_dir.join(name), backup.join(name)).unwrap();
            std::fs::remove_file(keys_dir.join(name)).unwrap();
            updated_tuf::repo::generate_root_key(&keys_dir.join(name))
                .await
                .unwrap();
        }
        assert!(
            updated_tuf::repo::renew_root(&repo_dir, &keys.roots, METADATA_EXPIRY_DAYS)
                .await
                .is_err(),
            "the drifted key set must genuinely fail the renewal — this is what used to abort the \
             whole reconcile"
        );

        let mut renewals = vec![TufRole::Root];
        let failure = renew_expiring_root(&repo_dir, &keys_dir, "repo", &mut renewals)
            .await
            .expect("the failure is reported, not propagated");
        assert!(renewals.is_empty(), "{renewals:?}");
        assert!(
            !publication_required(true, &renewals),
            "an un-renewable root must stop forcing a re-signed generation every reconcile"
        );
        let condition = root_renewal_condition(Some(7), Some(&failure));
        assert_eq!(condition.condition_type, "RootRenewal");
        assert_eq!(condition.status, "False");
        assert_eq!(condition.reason, "RenewalFailed");
        assert_eq!(root_renewal_condition(Some(7), None).status, "True");

        // Nothing was half-committed: the trust anchor is untouched, so the fleet keeps verifying
        // against the root it already pinned.
        let root: serde_json::Value =
            serde_json::from_slice(&std::fs::read(repo_dir.join("metadata/root.json")).unwrap())
                .unwrap();
        assert_eq!(root["signed"]["version"], 1);

        // The operator restores the real signing Secret: the renewal now succeeds and KEEPS its
        // role, so this pass signs and uploads the generation carrying the new root.
        for name in ["root.pk8", "root.next.pk8"] {
            std::fs::copy(backup.join(name), keys_dir.join(name)).unwrap();
        }
        let mut renewals = vec![TufRole::Root];
        assert!(
            renew_expiring_root(&repo_dir, &keys_dir, "repo", &mut renewals)
                .await
                .is_none()
        );
        assert_eq!(renewals, vec![TufRole::Root]);
        let root: serde_json::Value =
            serde_json::from_slice(&std::fs::read(repo_dir.join("metadata/root.json")).unwrap())
                .unwrap();
        assert_eq!(root["signed"]["version"], 2);
    }

    /// A root renewal rewrites `root.json` BEFORE the pass signs and uploads, so a publish that
    /// then fails leaves the local root ahead of the one the store serves. Keyed on the content
    /// digest alone, the next pass saw unchanged content and a no-longer-expiring root and never
    /// published again — while `status.routingRootSha256` (read from the LOCAL root) pinned every
    /// `/enroll` and `/v1/node/secrets` request against a root the store does not serve. The marker
    /// carries the root, so the mismatch itself demands the republication that heals it.
    #[tokio::test]
    async fn a_renewed_root_that_was_never_uploaded_forces_the_next_pass_to_publish() {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path();
        let repo_dir = state_dir.join("repository");
        let keys_dir = state_dir.join("keys");
        let keys = updated_tuf::repo::generate_keys(&keys_dir).await.unwrap();
        updated_tuf::repo::init(&repo_dir, &keys, METADATA_EXPIRY_DAYS)
            .await
            .unwrap();

        // The last successful publication recorded this content under this root.
        let digest = "content-digest";
        let published = publication_marker(state_dir, digest).await;
        let unchanged =
            |marker: String| async move { marker == publication_marker(state_dir, digest).await };
        assert!(unchanged(published.clone()).await, "nothing has moved yet");
        assert!(
            !publication_required(true, &[]),
            "a steady generation publishes nothing"
        );

        // This pass renews the root and then fails to upload: the marker still describes the old
        // root, and the root is no longer inside its renewal window, so `renewals` is empty.
        let mut renewals = vec![TufRole::Root];
        assert!(
            renew_expiring_root(&repo_dir, &keys_dir, "repo", &mut renewals)
                .await
                .is_none()
        );
        assert!(expiring_metadata(&repo_dir, chrono::Utc::now())
            .await
            .is_empty());
        assert!(
            !unchanged(published.clone()).await,
            "the local root moved, so this repository is NOT the one that was published"
        );
        assert!(
            publication_required(unchanged(published.clone()).await, &[]),
            "the next pass must sign and upload the renewed root"
        );

        // Once that publish succeeds the marker is rewritten from the root as it now stands, and
        // the fleet is back at steady state.
        let published = publication_marker(state_dir, digest).await;
        assert!(unchanged(published.clone()).await);
        assert!(!publication_required(
            unchanged(published.clone()).await,
            &[]
        ));
    }

    /// The same defect on the ONLINE roles, which is worse because the trigger clears ITSELF:
    /// `sign_plan` re-signs targets/snapshot/timestamp in place with a fresh expiry BEFORE the
    /// upload, so after a failed upload `expiring_metadata` reads the freshly signed LOCAL
    /// `timestamp.json` and reports nothing expiring. Keyed on content (and the root) alone, the
    /// publish block was never entered again and the store kept serving the OLD online metadata
    /// until it hard-expired ~90 days later — at which point every agent's TUF refresh fails at
    /// once and `/enroll` answers 502 fleet-wide, with nothing inside the loop to recover. The
    /// marker carries the online metadata too, so the local re-sign that never landed IS the
    /// mismatch that demands the republication.
    #[tokio::test]
    async fn online_metadata_re_signed_but_never_uploaded_forces_the_next_pass_to_publish() {
        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path();
        let repo_dir = state_dir.join("repository");
        let now = chrono::Utc::now();
        let digest = "content-digest";
        signed_until(
            &repo_dir,
            "root.json",
            now + chrono::Duration::days(METADATA_EXPIRY_DAYS),
        );
        // The online roles are inside their renewal window; the root, renewed earlier, is not. The
        // last successful publication recorded this content under this metadata.
        signed_until(
            &repo_dir,
            "timestamp.json",
            now + chrono::Duration::days(METADATA_RENEWAL_DAYS - 1),
        );
        let published = publication_marker(state_dir, digest).await;
        let renewals = expiring_metadata(&repo_dir, now).await;
        assert_eq!(renewals, vec![TufRole::Online]);
        assert!(
            publication_required(true, &renewals),
            "freshness alone must trigger a publication at steady state"
        );

        // That pass re-signs the online roles in place and then fails to upload them.
        signed_until(
            &repo_dir,
            "timestamp.json",
            now + chrono::Duration::days(METADATA_EXPIRY_DAYS),
        );
        let renewals = expiring_metadata(&repo_dir, now).await;
        assert!(
            renewals.is_empty(),
            "the re-sign cleared its own trigger, so freshness cannot ask again"
        );
        let unchanged = published == publication_marker(state_dir, digest).await;
        assert!(
            !unchanged,
            "the local online metadata moved, so this repository is NOT the one the store serves"
        );
        assert!(
            publication_required(unchanged, &renewals),
            "the next pass must sign and upload the re-signed online metadata"
        );

        // Once that publish succeeds the marker is rewritten from the metadata as it now stands,
        // and the fleet is back at steady state.
        let published = publication_marker(state_dir, digest).await;
        assert!(!publication_required(
            published == publication_marker(state_dir, digest).await,
            &expiring_metadata(&repo_dir, now).await
        ));
    }

    /// An enrollment Secret this controller cannot use is one agent's problem. It is immutable, so
    /// nothing here can repair it — and propagating the verdict aborted the whole post-publication
    /// projection, so set statuses stopped being written and no subscription webhook was ever
    /// delivered again, every pass, over one Secret (a changed `spec.assignmentPrefix` is enough).
    #[test]
    fn an_unusable_enrollment_secret_is_reported_and_does_not_fail_the_pass() {
        let bundle = |agent: &str, assignment: &str| Secret {
            data: Some(std::collections::BTreeMap::from([(
                "enrollment.json".to_string(),
                ByteString(
                    serde_json::to_vec(&serde_json::json!({
                        "schema": 1,
                        "agentId": agent,
                        "routingBaseUrl": "https://control/",
                        "assignment": assignment,
                        "routingRoot": "{}",
                        "initial": {
                            "timestamp": "{}",
                            "snapshot": "{}",
                            "targets": "{}",
                            "agentDocument": "{}",
                            "managedConfiguration": "{}",
                        },
                    }))
                    .unwrap(),
                ),
            )])),
            ..Default::default()
        };
        assert!(check_enrollment_secret(
            &bundle("web-01", "a/web-01.json"),
            "web-01",
            "a/web-01.json"
        )
        .is_ok());
        // Another agent's bundle under this agent's Secret name.
        assert!(check_enrollment_secret(
            &bundle("web-02", "a/web-02.json"),
            "web-01",
            "a/web-01.json"
        )
        .is_err());
        // The agent's own bundle, but for the assignment path a since-changed prefix produced.
        assert!(check_enrollment_secret(
            &bundle("web-01", "a/web-01.json"),
            "web-01",
            "b/web-01.json"
        )
        .is_err());
        // Arbitrary bytes under the name, which any principal with `create` on Secrets can place.
        assert!(check_enrollment_secret(&Secret::default(), "web-01", "a/web-01.json").is_err());
        // Reporting one is a log line, never a value the projection can fail on.
        report_unusable_enrollment_secret(Err("unreadable".into()), "web-01", "web-01-enrollment");
    }

    #[test]
    fn the_agent_ceiling_is_reported_on_the_repository_before_it_is_reached() {
        let available = enrollment_capacity_condition(Some(3), 12);
        assert_eq!(available.condition_type, "EnrollmentCapacity");
        assert_eq!(available.status, "True");
        assert!(available.message.contains("12 of at most"));
        let full = enrollment_capacity_condition(Some(3), MAX_ENROLLED_AGENTS as usize);
        assert_eq!(full.status, "False");
        assert_eq!(full.reason, "AtCapacity");
    }

    #[test]
    fn a_failed_reconcile_does_not_erase_what_the_last_successful_one_published() {
        let observed = [
            ready_condition(Some(3), "Published", "the last generation is live"),
            enrollment_capacity_condition(Some(3), MAX_ENROLLED_AGENTS as usize),
        ];
        let patch =
            serde_json::to_value(failure_status(Some(4), "reconciliation failed", &observed))
                .unwrap();
        // The status is a MERGE patch: a serialized `null` DELETES the field. Sending one for the
        // agent count dropped `at_enrollment_capacity`'s only input, so `/enroll` ran uncapped from
        // the first S3 outage or lost lease until a reconcile succeeded again.
        for erased in ["agentCount", "publishedDigest", "routingRootSha256"] {
            assert!(
                patch.get(erased).is_none(),
                "a failure claims nothing about {erased}, so it must be omitted, not nulled: \
                 {patch}"
            );
        }
        assert_eq!(patch["observedGeneration"], 4);
        assert_eq!(patch["conditions"][0]["reason"], "ReconciliationFailed");
        // A merge patch replaces the whole array, so the same rule applies inside it: the failure
        // owns `Ready` and nothing else. Rewriting the array with only its own entry hid the
        // enrollment ceiling for as long as the failure lasted.
        let types: Vec<&str> = patch["conditions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|condition| condition["type"].as_str().unwrap())
            .collect();
        assert_eq!(types, vec!["Ready", "EnrollmentCapacity"], "{patch}");
        assert_eq!(patch["conditions"][1]["reason"], "AtCapacity");
    }

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
                    mode: crate::RuntimeModeSpec::Managed,
                    product: "app".into(),
                    channel: "stable".into(),
                    install_root: "/opt/app".into(),
                    args: vec![],
                    secrets: vec![],
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
                        check_interval_seconds: 15,
                        health_grace_seconds: 30,
                        health_successes: 2,
                        health_interval_seconds: 1,
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

    #[test]
    fn a_prefix_nested_under_another_is_recognized_as_overlapping() {
        // A prune is prefix-scoped, so deleting `fleet` takes `fleet/staging` with it: nesting one
        // tenant inside another is what the finalizer must refuse to prune, in either direction and
        // whichever of the two is being deleted.
        assert!(prefixes_overlap("fleet", "fleet/staging"));
        assert!(prefixes_overlap("fleet/staging", "fleet"));
        assert!(prefixes_overlap("/fleet/", "fleet/staging/deep"));
        // Identical prefixes are the same key space, so one repository's prune destroys the other's.
        assert!(prefixes_overlap("fleet", "fleet"));
        // An empty prefix is the whole bucket and therefore overlaps everything.
        assert!(prefixes_overlap("", "fleet"));
        // Compared at path boundaries: a shared leading STRING is not a shared key space.
        assert!(!prefixes_overlap("fleet", "fleet-staging"));
        assert!(!prefixes_overlap("tenant/routing", "tenant/other"));
    }

    /// A bucket is not scoped to a namespace, so the sibling search must not be either: the nesting
    /// that costs another tenant its published artifacts is exactly the one drawn along a namespace
    /// boundary. Listing only the deleted repository's own namespace let `tenant-a`'s `fleet` prune
    /// `tenant-b`'s live `fleet/staging`.
    #[test]
    fn an_overlapping_sibling_in_another_namespace_is_found() {
        fn repo(
            namespace: &str,
            name: &str,
            bucket: &str,
            prefix: &str,
        ) -> crate::UpdateRepository {
            let mut spec = repository(bucket);
            spec.s3.prefix = prefix.into();
            let mut object = crate::UpdateRepository::new(name, spec);
            object.metadata.namespace = Some(namespace.into());
            object
        }

        let deleting = repo("tenant-a", "fleet", "artifacts", "fleet");
        let nested = repo("tenant-b", "fleet-staging", "artifacts", "fleet/staging");
        assert_eq!(
            first_overlapping_sibling(std::slice::from_ref(&nested), &deleting),
            Some(("tenant-b/fleet-staging".to_string(), "fleet/staging".into()))
        );
        // ...and in the other direction, whichever of the two is the one being deleted.
        assert_eq!(
            first_overlapping_sibling(std::slice::from_ref(&deleting), &nested),
            Some(("tenant-a/fleet".to_string(), "fleet".into()))
        );

        // The repository being finalized is matched on namespace AND name, so it never blocks its
        // own prune — but a same-named repository in another namespace is a different object and
        // does.
        assert_eq!(
            first_overlapping_sibling(std::slice::from_ref(&deleting), &deleting),
            None
        );
        assert_eq!(
            first_overlapping_sibling(
                &[repo("tenant-b", "fleet", "artifacts", "fleet")],
                &deleting
            )
            .map(|sibling| sibling.0),
            Some("tenant-b/fleet".to_string())
        );

        // A different bucket is a different key space, however the prefixes are drawn.
        assert_eq!(
            first_overlapping_sibling(
                &[repo("tenant-b", "other", "elsewhere", "fleet/staging")],
                &deleting
            ),
            None
        );
        // Same bucket, disjoint prefixes: each prune stays inside its own scope.
        assert_eq!(
            first_overlapping_sibling(
                &[repo("tenant-b", "other", "artifacts", "fleet-staging")],
                &deleting
            ),
            None
        );
    }

    /// The endpoint half of the key-space rule fails CLOSED. It used to be exact `Option<String>`
    /// equality, so every cosmetic way of spelling one host — omitted and left to `region`, a
    /// trailing slash, a different case, `http` vs `https` — made a live nested sibling invisible
    /// and pruned its published artifacts.
    #[test]
    fn a_sibling_is_shielded_unless_its_endpoint_is_definitively_different() {
        fn repo(name: &str, prefix: &str, endpoint: Option<&str>) -> crate::UpdateRepository {
            let mut spec = repository("artifacts");
            spec.s3.prefix = prefix.into();
            spec.s3.endpoint = endpoint.map(Into::into);
            let mut object = crate::UpdateRepository::new(name, spec);
            object.metadata.namespace = Some(format!("ns-{name}"));
            object
        }

        // An absent endpoint is derived from `region`, so it is the same host as that region's URL
        // written out in full: the two repositories share a key space.
        let deleting = repo("fleet", "fleet", None);
        let explicit = repo(
            "staging",
            "fleet/staging",
            Some("https://s3.us-east-1.amazonaws.com"),
        );
        assert_eq!(
            first_overlapping_sibling(std::slice::from_ref(&explicit), &deleting)
                .map(|sibling| sibling.0),
            Some("ns-staging/staging".to_string())
        );
        assert!(first_overlapping_sibling(std::slice::from_ref(&deleting), &explicit).is_some());

        // Two explicit spellings of one MinIO deployment: trailing slash, host case, scheme, and a
        // port left implicit rather than written out are all the same store.
        for other in [
            "https://MinIO.internal:9000",
            "https://minio.internal:9000/",
            "http://minio.internal:9000",
            "https://minio.internal:9000/bucketpath",
        ] {
            let deleting = repo("fleet", "fleet", Some("https://minio.internal:9000"));
            assert!(
                first_overlapping_sibling(
                    &[repo("staging", "fleet/staging", Some(other))],
                    &deleting
                )
                .is_some(),
                "{other} must be treated as the same store"
            );
        }
        let deleting = repo("fleet", "fleet", Some("https://minio.internal"));
        assert!(first_overlapping_sibling(
            &[repo(
                "staging",
                "fleet/staging",
                Some("https://minio.internal:443")
            )],
            &deleting
        )
        .is_some());

        // Genuinely different hosts (or ports) are different key spaces, so the prune proceeds.
        for other in ["https://minio.other:9000", "https://minio.internal:9001"] {
            let deleting = repo("fleet", "fleet", Some("https://minio.internal:9000"));
            assert_eq!(
                first_overlapping_sibling(
                    &[repo("staging", "fleet/staging", Some(other))],
                    &deleting
                ),
                None,
                "{other} is a different store"
            );
        }
    }

    /// A replica whose local metadata is BEHIND the store must never publish. It led up to
    /// generation 5, lost the lease while another replica advanced the store to 40, and reacquired
    /// it: `root.json` is on disk so it looks healthy, its publication marker is stale so it
    /// believes a publish is due, and `replace_release` numbers the next generation from LOCAL
    /// metadata — so it would upload 6 over 40 and every node that ever saw 40 would reject the
    /// fleet's routing as a rollback, permanently.
    #[tokio::test]
    async fn a_local_repository_behind_the_store_refuses_to_publish() {
        use object_store::memory::InMemory;
        use object_store::path::Path as ObjPath;

        let tmp = tempfile::tempdir().unwrap();
        let repo_dir = tmp.path().join("repository");
        let keys = updated_tuf::repo::generate_keys(&tmp.path().join("keys"))
            .await
            .unwrap();
        updated_tuf::repo::init(&repo_dir, &keys, METADATA_EXPIRY_DAYS)
            .await
            .unwrap();
        assert_eq!(
            updated_tuf::repo::current_version(&repo_dir).await.unwrap(),
            1
        );
        let mut destination = repository("updates").s3;
        destination.prefix = "routing".into();
        let store = InMemory::new();
        let publish = |version: u64| {
            let store = &store;
            async move {
                store
                    .put(
                        &ObjPath::from("routing/metadata/timestamp.json"),
                        PutPayload::from_bytes(
                            serde_json::json!({ "signed": { "version": version } })
                                .to_string()
                                .into_bytes()
                                .into(),
                        ),
                    )
                    .await
                    .unwrap();
            }
        };

        // An empty store: nothing published, so nothing can be rolled back.
        refuse_generation_rollback(&store, &destination, &repo_dir)
            .await
            .expect("a store with no generation cannot be rolled back");

        publish(40).await;
        assert_eq!(
            store_published_version(&store, &destination).await.unwrap(),
            Some(40)
        );
        let error = refuse_generation_rollback(&store, &destination, &repo_dir)
            .await
            .expect_err("a local repository at 1 must not republish over 40");
        assert!(
            error
                .to_string()
                .contains("refusing to publish a lower generation"),
            "{error}"
        );

        // The same guard covers an EMPTY local state dir, which would re-initialize at version 1.
        let empty = tmp.path().join("fresh");
        let error = refuse_generation_rollback(&store, &destination, &empty)
            .await
            .expect_err("a fresh state dir must not re-init over a published generation");
        assert!(
            error.to_string().contains("refusing to re-initialize"),
            "{error}"
        );

        // Caught up (or ahead) is exactly what publishing is for.
        publish(1).await;
        refuse_generation_rollback(&store, &destination, &repo_dir)
            .await
            .expect("a local repository level with the store publishes normally");
    }

    /// A generation that reached the store but whose durable record was lost — reconcile is dropped
    /// at any await when the publisher lease renewal fails — must be recovered before anything is
    /// planned. Planning from a baseline that predates the live generation reads an already-advanced
    /// node as still on its predecessor and republishes it there: one signed generation backwards,
    /// no `maxUnavailable`, no health gate.
    #[tokio::test]
    async fn a_published_generation_whose_record_was_lost_is_recovered_before_planning() {
        use axum::http::{Method, StatusCode};
        use object_store::memory::InMemory;
        use object_store::path::Path as ObjPath;

        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path();
        let advanced = DurableRolloutState {
            admitted: BTreeMap::new(),
            routing: BTreeMap::from([("n1".to_string(), "g".to_string())]),
            assignments: BTreeMap::from([("n1".to_string(), "b".repeat(64))]),
        };
        let stale = || DurableRolloutState {
            admitted: BTreeMap::new(),
            routing: BTreeMap::from([("n1".to_string(), "g".to_string())]),
            assignments: BTreeMap::from([("n1".to_string(), "a".repeat(64))]),
        };
        let journal = |marker: &str, version: u64, state: &DurableRolloutState| {
            std::fs::write(
                state_dir.join(PENDING_STATE_FILE),
                serde_json::to_vec(&PendingPublication {
                    marker: marker.to_string(),
                    version,
                    state: DurableRolloutState {
                        admitted: state.admitted.clone(),
                        routing: state.routing.clone(),
                        assignments: state.assignments.clone(),
                    },
                })
                .unwrap(),
            )
            .unwrap();
        };
        let mut destination = repository("updates").s3;
        destination.prefix = "routing".into();
        let store = InMemory::new();
        let serve = |version: u64| {
            let store = &store;
            async move {
                store
                    .put(
                        &ObjPath::from("routing/metadata/timestamp.json"),
                        PutPayload::from_bytes(
                            serde_json::json!({ "signed": { "version": version } })
                                .to_string()
                                .into_bytes()
                                .into(),
                        ),
                    )
                    .await
                    .unwrap();
            }
        };
        let recorded: std::sync::Arc<std::sync::Mutex<Vec<serde_json::Value>>> = Default::default();
        let client = crate::tests::apiserver({
            let recorded = recorded.clone();
            move |method: &Method, _: &str, body: Vec<u8>| {
                if method != Method::GET {
                    recorded
                        .lock()
                        .unwrap()
                        .push(serde_json::from_slice(&body).unwrap());
                }
                (
                    StatusCode::OK,
                    serde_json::json!({ "metadata": { "name": "state", "resourceVersion": "9" } }),
                )
            }
        });
        let configmaps: Api<ConfigMap> = Api::namespaced(client, "prod");
        let recover = |durable: DurableRolloutState| {
            recover_pending_publication(
                AdmittedRecord {
                    configmaps: &configmaps,
                    name: "state",
                    namespace: "prod",
                    owner: None,
                },
                state_dir,
                &store,
                &destination,
                durable,
                Some("7".to_string()),
            )
        };

        // The upload never completed: the marker for that generation was never written AND the
        // store does not serve it, so nothing was served and the journal is discarded rather than
        // recorded.
        serve(39).await;
        journal(
            "marker-of-a-generation-that-was-never-uploaded",
            40,
            &advanced,
        );
        let (durable, version) = recover(stale()).await.unwrap();
        assert_eq!(durable.assignments["n1"], "a".repeat(64));
        assert_eq!(version.as_deref(), Some("7"));
        assert!(recorded.lock().unwrap().is_empty(), "nothing to record");
        assert!(!state_dir.join(PENDING_STATE_FILE).exists());

        // Marker equality is NOT proof of upload. A pass triggered by neither changed content nor
        // expiring metadata — an admission whose nodes are all blocked by `maxUnavailable`, so the
        // plan digest is unchanged — journals a marker that is ALREADY on disk from the previous
        // successful generation. Its upload failed all the same, and the store still serves 39, so
        // adopting on the marker recorded a generation no signed metadata ever carried.
        std::fs::write(state_dir.join("published-plan.sha256"), "marker-v40").unwrap();
        journal("marker-v40", 40, &advanced);
        let (durable, version) = recover(stale()).await.unwrap();
        assert_eq!(
            durable.assignments["n1"],
            "a".repeat(64),
            "the store serves 39, so this journal describes an upload that never landed"
        );
        assert_eq!(version.as_deref(), Some("7"));
        assert!(recorded.lock().unwrap().is_empty(), "nothing to record");
        assert!(!state_dir.join(PENDING_STATE_FILE).exists());

        // The upload DID complete — the store serves the exact generation the journal describes —
        // but the record was lost. The published state is adopted and written back, and planning
        // proceeds from it.
        serve(40).await;
        journal("marker-v40", 40, &advanced);
        let (durable, version) = recover(stale()).await.unwrap();
        assert_eq!(
            durable.assignments["n1"],
            "b".repeat(64),
            "the node the lost generation advanced is never planned as still on its predecessor"
        );
        assert_eq!(
            version.as_deref(),
            Some("9"),
            "and the new resourceVersion is carried forward"
        );
        let recorded = recorded.lock().unwrap().clone();
        let [patch] = recorded.as_slice() else {
            panic!("exactly one in-cluster write, got {recorded:?}");
        };
        assert!(patch["data"]["assignments.json"]
            .as_str()
            .expect("the published assignments")
            .contains(&"b".repeat(64)));
        assert!(
            !state_dir.join(PENDING_STATE_FILE).exists(),
            "the journal is evaluated once, so it can never re-apply itself over a later write"
        );
    }

    /// The publication marker is written AFTER the upload returns, so a process death in that gap
    /// (an OOM kill, an evicted pod) leaves the store serving generation N while the marker still
    /// names N-1. Deciding on the marker alone read that as "never uploaded" and DELETED the
    /// journal, so planning fell back to a baseline predating the live generation and republished
    /// an already-advanced node on its predecessor. The store is asked instead: it serves the
    /// journalled version, so the state is adopted and the interrupted marker write is finished.
    #[tokio::test]
    async fn a_generation_the_store_serves_is_recovered_even_when_the_marker_never_landed() {
        use axum::http::{Method, StatusCode};
        use object_store::memory::InMemory;
        use object_store::path::Path as ObjPath;

        let tmp = tempfile::tempdir().unwrap();
        let state_dir = tmp.path();
        // The marker still names the PREDECESSOR: the process died before it was rewritten.
        std::fs::write(state_dir.join("published-plan.sha256"), "marker-v39").unwrap();
        std::fs::write(
            state_dir.join(PENDING_STATE_FILE),
            serde_json::to_vec(&PendingPublication {
                marker: "marker-v40".into(),
                version: 40,
                state: DurableRolloutState {
                    admitted: BTreeMap::new(),
                    routing: BTreeMap::from([("n1".to_string(), "g".to_string())]),
                    assignments: BTreeMap::from([("n1".to_string(), "b".repeat(64))]),
                },
            })
            .unwrap(),
        )
        .unwrap();

        let mut destination = repository("updates").s3;
        destination.prefix = "routing".into();
        let store = InMemory::new();
        // The store genuinely serves generation 40: `publish_repository` uploads timestamp.json
        // last, so on return the generation IS being served.
        store
            .put(
                &ObjPath::from("routing/metadata/timestamp.json"),
                PutPayload::from_bytes(
                    serde_json::json!({ "signed": { "version": 40 } })
                        .to_string()
                        .into_bytes()
                        .into(),
                ),
            )
            .await
            .unwrap();

        let client = crate::tests::apiserver(move |_: &Method, _: &str, _: Vec<u8>| {
            (
                StatusCode::OK,
                serde_json::json!({ "metadata": { "name": "state", "resourceVersion": "9" } }),
            )
        });
        let configmaps: Api<ConfigMap> = Api::namespaced(client, "prod");
        let (durable, version) = recover_pending_publication(
            AdmittedRecord {
                configmaps: &configmaps,
                name: "state",
                namespace: "prod",
                owner: None,
            },
            state_dir,
            &store,
            &destination,
            DurableRolloutState {
                admitted: BTreeMap::new(),
                routing: BTreeMap::from([("n1".to_string(), "g".to_string())]),
                assignments: BTreeMap::from([("n1".to_string(), "a".repeat(64))]),
            },
            Some("7".to_string()),
        )
        .await
        .unwrap();
        assert_eq!(
            durable.assignments["n1"],
            "b".repeat(64),
            "the live generation's state is adopted, not discarded as never-uploaded"
        );
        assert_eq!(version.as_deref(), Some("9"));
        assert_eq!(
            std::fs::read_to_string(state_dir.join("published-plan.sha256")).unwrap(),
            "marker-v40",
            "and the interrupted marker write is finished, so no identical republish follows"
        );
        assert!(!state_dir.join(PENDING_STATE_FILE).exists());
    }

    #[test]
    fn offline_enrollment_without_a_trust_anchor_is_an_error_not_a_silent_skip() {
        assert_eq!(offline_enrollment_anchor(0, None).unwrap(), None);
        assert_eq!(offline_enrollment_anchor(0, Some("anchor")).unwrap(), None);
        assert_eq!(
            offline_enrollment_anchor(3, Some("anchor")).unwrap(),
            Some("anchor")
        );
        let error = offline_enrollment_anchor(3, None).unwrap_err();
        assert!(
            error.0.contains("routingRootSha256"),
            "the operator must be told exactly what is missing: {error}"
        );
    }

    /// The durable state shares ONE ConfigMap object budget across every per-node map, so the
    /// published assignments are stored inverted: a 64-character digest is written once per
    /// deployment instead of once per node.
    #[test]
    fn published_assignments_round_trip_and_intern_their_digests() {
        let identity = "a".repeat(64);
        let assignments: BTreeMap<String, String> = (0..50)
            .map(|index| (format!("node-{index:03}"), identity.clone()))
            .collect();
        let encoded = encode_assignments(&assignments);
        assert_eq!(encoded.len(), 1);
        assert_eq!(decode_assignments(encoded.clone()), assignments);
        let inverted = serde_json::to_string(&encoded).unwrap().len();
        let flat = serde_json::to_string(&assignments).unwrap().len();
        assert!(
            inverted * 2 < flat,
            "storing one digest per deployment must be far smaller than one per node \
             ({inverted} vs {flat} bytes)"
        );
    }
}
