//! An `UpdateRepository`'s reconciler: binding storage ownership, holding the finalizer, and
//! draining local, admitted and object state before a deleted repository is allowed to go away.

use super::*;

/// The finalizer that keeps a deleted [`UpdateRepository`] in `Terminating` until all three durable
/// locations owned by that incarnation are empty: its object-storage prefix, admitted-state
/// ConfigMaps, and node-local TUF state. Owner references remain defense in depth for Kubernetes
/// GC, but GC is asynchronous; releasing the name while its fixed-name ConfigMaps still exist lets
/// an immediately recreated CR inherit the deleted repository's rollout baseline.
pub(crate) const REPOSITORY_FINALIZER: &str = "updated.dev/repository-state";

/// The finalizer list with `ours` appended, or `None` if it is already present (so the caller can
/// skip a needless write). A foreign finalizer another controller owns is preserved. Every
/// finalizer this controller owns — the repository's and the backend's — is added through here;
/// spelling the append out again per resource is how one of them comes to drop a foreign entry.
pub(crate) fn finalizers_with(existing: &[String], ours: &str) -> Option<Vec<String>> {
    if existing.iter().any(|f| f == ours) {
        return None;
    }
    let mut next = existing.to_vec();
    next.push(ours.to_string());
    Some(next)
}

/// The finalizer list with `ours` removed, retaining any others a different controller owns.
pub(crate) fn finalizers_without(existing: &[String], ours: &str) -> Vec<String> {
    existing
        .iter()
        .filter(|f| f.as_str() != ours)
        .cloned()
        .collect()
}

/// One optimistic-concurrency patch for every finalizer mutation this controller performs.
/// Finalizers are an atomic list: replacing a list computed from a stale object can silently erase
/// an entry another controller added after our GET. Including the observed resourceVersion makes
/// that race a 409/retry instead of stealing another controller's deletion guarantee.
pub(crate) fn finalizer_patch<T: ResourceExt>(
    resource: &T,
    finalizers: Vec<String>,
) -> serde_json::Value {
    let mut metadata = serde_json::json!({ "finalizers": finalizers });
    if let Some(resource_version) = resource.resource_version() {
        metadata["resourceVersion"] = resource_version.into();
    }
    serde_json::json!({ "metadata": metadata })
}

/// Bind the repository's irreversible deletion scope into controller-owned status before either
/// the finalizer or any external object exists. A later spec mismatch is a hard stop; deletion uses
/// the status record rather than trusting the mutable object presented on the delete path.
pub(crate) async fn ensure_repository_storage_ownership(
    repositories: &Api<UpdateRepository>,
    repository: &UpdateRepository,
    destination: &S3Destination,
) -> Result<UpdateRepository, Box<dyn std::error::Error>> {
    let desired = RepositoryStorageOwnership::from(destination);
    if !repository_storage_ownership_needs_binding(repository, &desired)? {
        return Ok(repository.clone());
    }
    Ok(repositories
        .patch_status(
            &repository.name_any(),
            &PatchParams::default(),
            &Patch::Merge(serde_json::json!({
                "status": { "storageOwnership": desired }
            })),
        )
        .await?)
}

/// Decide the status transition before touching the API server. `Ok(true)` is the sole fresh-object
/// bind path; `Ok(false)` is the sole already-bound path. Every other historical shape is an
/// invariant violation and fails closed rather than being adopted or orphaned.
pub(crate) fn repository_storage_ownership_needs_binding(
    repository: &UpdateRepository,
    desired: &RepositoryStorageOwnership,
) -> Result<bool, StorageError> {
    if let Some(bound) = repository
        .status
        .as_ref()
        .and_then(|status| status.storage_ownership.as_ref())
    {
        if bound == desired {
            return Ok(false);
        }
        return Err(StorageError::Operation(format!(
            "repository storage coordinates differ from the controller-owned deletion scope in status; refusing to publish (bound bucket={:?}, prefix={:?}, region={:?}, endpoint={:?}, credentialsSecretRef={:?})",
            bound.bucket,
            bound.prefix,
            bound.region,
            bound.endpoint,
            bound.credentials_secret_ref.as_ref().map(|reference| &reference.name),
        )));
    }
    if repository
        .finalizers()
        .iter()
        .any(|finalizer| finalizer == REPOSITORY_FINALIZER)
        || repository.status.as_ref().is_some_and(|status| {
            status.published_digest.is_some() || status.routing_root_sha256.is_some()
        })
    {
        return Err(StorageError::Operation(
            "repository has its state finalizer or published state but no controller-owned storage scope; refusing to invent an irreversible deletion target"
                .into(),
        ));
    }
    Ok(true)
}

pub(crate) fn repository_storage_ownership(
    repository: &UpdateRepository,
) -> Option<&RepositoryStorageOwnership> {
    repository.status.as_ref()?.storage_ownership.as_ref()
}

/// The status-bound deletion destination, retaining only the current access credentials.
pub(crate) fn repository_deletion_destination(
    repository: &UpdateRepository,
) -> Option<S3Destination> {
    repository_storage_ownership(repository)
        .map(|ownership| ownership.destination_with_access(&repository.spec.s3))
}

/// Add our finalizer to a live repository if it is missing, so a later deletion is held open until
/// every durable part of its epoch is gone. The resourceVersion-guarded patch is skipped when
/// present.
pub(crate) async fn ensure_repository_finalizer(
    repositories: &Api<UpdateRepository>,
    repository: &UpdateRepository,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(finalizers) = finalizers_with(repository.finalizers(), REPOSITORY_FINALIZER) else {
        return Ok(());
    };
    repositories
        .patch(
            &repository.name_any(),
            &PatchParams::default(),
            &Patch::Merge(finalizer_patch(repository, finalizers)),
        )
        .await?;
    Ok(())
}

/// Remove every piece of controller-local state that belongs to one repository incarnation.
///
/// The controller process is configured for exactly one repository, but its PVC outlives the CR.
/// Leaving these paths behind after the finalizer pruned S3 makes a same-name replacement inherit
/// the deleted repository's TUF keys, rollback marker and crash journal. In particular, a fresh
/// signing Secret then fails forever as an in-place key mutation. Remove only the four literal
/// children this module owns; never recursively target the configured state root itself.
pub(crate) async fn clear_local_repository_state(state_dir: &Path) -> std::io::Result<()> {
    let owned = [
        state_dir.join("repository"),
        state_dir.join("keys"),
        state_dir.join(PUBLISHED_GENERATION_FILE),
        state_dir.join(PENDING_STATE_FILE),
    ];
    tokio::task::spawn_blocking(move || {
        for path in owned {
            foundation::durable::remove_path(&path)?;
        }
        Ok(())
    })
    .await
    .map_err(std::io::Error::other)?
}

/// Every ConfigMap name one repository epoch can own, in deletion order: shards first, index last.
pub(crate) fn admitted_state_configmap_names(repository_name: &str) -> Vec<String> {
    let base = admitted_configmap_name(repository_name);
    let mut names = Vec::with_capacity(1 + 2 * MAX_ADMITTED_STATE_SHARDS);
    for slot in [AdmittedStateSlot::A, AdmittedStateSlot::B] {
        for index in 0..MAX_ADMITTED_STATE_SHARDS {
            names.push(admitted_state_shard_name(&base, slot, index));
        }
    }
    names.push(base);
    names
}

/// Read only the deterministic names the controller's Role grants. A namespace-wide ConfigMap
/// LIST would be shorter code, but it would also let signing-key-bearing controller credentials
/// read every workload's configuration. Keep the same least-authority boundary during deletion as
/// during ordinary CAS reads.
pub(crate) async fn existing_named_configmaps(
    configmaps: &Api<ConfigMap>,
    names: &[String],
) -> Result<Vec<String>, kube::Error> {
    let checks = futures::stream::iter(names.iter().cloned())
        .map(|name| {
            let configmaps = configmaps.clone();
            async move {
                configmaps
                    .get_opt(&name)
                    .await
                    .map(|value| value.map(|_| name))
            }
        })
        // Cleanup is rare, but the fixed set is 129 names. Bound concurrency so deletion neither
        // serializes a full apiserver round trip per absent shard nor creates an unbounded burst.
        .buffer_unordered(16)
        .collect::<Vec<_>>()
        .await;
    let mut existing = Vec::new();
    for check in checks {
        if let Some(name) = check? {
            existing.push(name);
        }
    }
    existing.sort();
    Ok(existing)
}

/// Delete this repository's exact fixed-name admitted-state projection and prove it is gone before
/// allowing the CR name to be reused. Exact GETs preserve the controller's resourceName-constrained
/// RBAC. The deletion branch is the only writer path once the CR has a deletion timestamp, and the
/// publisher lease admits one such branch, so names absent from the first complete scan cannot
/// appear between that scan and finalizer release.
pub(crate) async fn clear_admitted_repository_state(
    configmaps: &Api<ConfigMap>,
    repository_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let names = admitted_state_configmap_names(repository_name);
    let index = names.last().expect("the canonical set always has an index");
    let mut owned = existing_named_configmaps(configmaps, &names).await?;
    // Even if a peer observes the intermediate state, it cannot see an index that claims a
    // projection still exists after the final shard delete succeeds.
    owned.sort_by_key(|name| name == index);
    for name in &owned {
        delete_named(configmaps, name).await?;
    }
    let remaining = existing_named_configmaps(configmaps, &owned).await?;
    if !remaining.is_empty() {
        return Err(StorageError::Operation(format!(
            "waiting for admitted-state ConfigMaps to terminate: {}",
            remaining.join(", ")
        ))
        .into());
    }
    Ok(())
}

/// How much longer a deleting repository must keep its old object namespace alive before the last
/// capability minted for that incarnation is unspendable. The timestamp is API-server-owned and
/// survives controller restarts and leader changes; restarting a local timer must never shorten
/// this security boundary.
pub(crate) fn repository_capability_drain_remaining(
    repository: &UpdateRepository,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<Duration, StorageError> {
    let deleted_at = repository
        .metadata
        .deletion_timestamp
        .as_ref()
        .ok_or_else(|| {
            StorageError::Operation("repository finalization requires a deletion timestamp".into())
        })?
        .0;
    let drain = chrono::Duration::from_std(updated_contracts::dataflow::OBJECT_CAPABILITY_DRAIN)
        .map_err(|_| StorageError::Operation("repository capability drain is invalid".into()))?;
    Ok((deleted_at + drain - now)
        .to_std()
        .unwrap_or(Duration::ZERO))
}

/// Drain capabilities and clear a deleting repository's three durable projections, then drop our
/// finalizer so Kubernetes can complete deletion. Idempotent and resumable: the finalizer holds the
/// object in `Terminating`, so a crash re-enters the same API-timestamp-anchored path.
pub(crate) async fn finalize_repository(
    repositories: &Api<UpdateRepository>,
    secrets: &Api<Secret>,
    configmaps: &Api<ConfigMap>,
    repository: &UpdateRepository,
    state_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if !repository
        .finalizers()
        .iter()
        .any(|f| f == REPOSITORY_FINALIZER)
    {
        // A never-published object has no external work. Local state may still exist after a prior
        // process released the finalizer but died before this cleanup existed, so the reset is
        // intentionally unconditional.
        clear_admitted_repository_state(configmaps, &repository.name_any()).await?;
        clear_local_repository_state(state_dir).await?;
        return Ok(());
    }
    // The gateway refuses every fresh authorization once deletionTimestamp exists, but one cached
    // authorization can still begin one bounded request and mint one final short-lived S3 bearer.
    // Pruning before that shared drain closes lets a live agent recreate telemetry after cleanup
    // and after the CR name has been released. Wait first, then perform the one authoritative
    // prune. The outer controller loop renews its publisher Lease while this future is pending.
    let remaining = repository_capability_drain_remaining(repository, chrono::Utc::now())?;
    if !remaining.is_zero() {
        tracing::info!(
            repository = %repository.name_any(),
            seconds = remaining.as_secs(),
            "draining repository object capabilities before finalization",
        );
        tokio::time::sleep(remaining).await;
    }
    let destination = repository_deletion_destination(repository).ok_or_else(|| {
        StorageError::Operation(
            "repository carries its state finalizer without its controller-owned storage scope; refusing to guess a deletion target"
                .into(),
        )
    })?;
    let store = build_store(secrets, &destination).await?;
    let pruned = prune_prefix(store.objects.as_ref(), &destination.prefix).await?;
    tracing::info!(
        repository = %repository.name_any(),
        prefix = %destination.prefix,
        pruned,
        "pruned a deleted repository's published artifacts",
    );
    // The finalizer remains present until all durable locations are empty. If either cleanup fails,
    // keep the CR in Terminating and retry; if the following patch conflicts, every deletion is
    // idempotent.
    clear_admitted_repository_state(configmaps, &repository.name_any()).await?;
    clear_local_repository_state(state_dir).await?;
    repositories
        .patch(
            &repository.name_any(),
            &PatchParams::default(),
            &Patch::Merge(finalizer_patch(
                repository,
                finalizers_without(repository.finalizers(), REPOSITORY_FINALIZER),
            )),
        )
        .await?;
    Ok(())
}

/// Delete every object under `prefix` in `store`, returning the count removed. Deletion streams so
/// historical content cannot turn finalization into an unbounded allocation. The total operation is
/// time-bounded and idempotent; an interrupted finalizer resumes on its next reconcile.
///
/// An empty prefix is refused rather than treated as "the whole bucket": callers reach this from a
/// delete path, and an unscoped delete would take out every other tenant of the same bucket.
pub(crate) async fn prune_prefix(
    store: &dyn ObjectStore,
    prefix: &str,
) -> Result<usize, StorageError> {
    let trimmed = prefix.trim_matches('/');
    if trimmed.is_empty() {
        return Err(StorageError::Operation(
            "refusing to prune an empty prefix: that is the whole bucket, not this repository"
                .into(),
        ));
    }
    let scope = Some(object_store::path::Path::from(trimmed));
    let mut listing = store.list(scope.as_ref());
    let prune = async {
        let mut pruned = 0usize;
        while let Some(entry) = listing.next().await {
            let meta = entry
                .map_err(|e| StorageError::Operation(format!("listing objects to prune: {e}")))?;
            if !crate::object_in_namespace(
                scope.as_ref().expect("scope is present"),
                &meta.location,
            ) {
                continue;
            }
            match store.delete(&meta.location).await {
                Ok(()) | Err(object_store::Error::NotFound { .. }) => {
                    pruned = pruned.saturating_add(1);
                }
                Err(error) => {
                    return Err(StorageError::Operation(format!(
                        "deleting {}: {error}",
                        meta.location
                    )));
                }
            }
        }
        Ok(pruned)
    };
    tokio::time::timeout(crate::OBJECT_STORE_MAINTENANCE_TIMEOUT, prune)
        .await
        .map_err(|_| {
            StorageError::Operation(format!("pruning object prefix {trimmed} timed out"))
        })?
}
