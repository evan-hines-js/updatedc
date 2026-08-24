//! The per-node enrollment objects published to the store for the gateway to serve, and the sweep
//! that removes the ones no live agent generation claims.

use super::*;

pub(crate) const ENROLLMENT_OBJECT_ROOT: &str = "enrollments";

pub(crate) fn enrollment_generation_sha256(
    desired_sha256: &str,
    root_sha256: &str,
    public_url: &str,
) -> String {
    let mut digest = updated_contracts::digest::Sha256Hasher::new();
    for input in [desired_sha256, root_sha256, public_url] {
        digest.update(input.as_bytes());
        digest.update(&[0]);
    }
    digest.finish_hex()
}

pub(crate) fn enrollment_generation_prefix(node: &str, generation_sha256: &str) -> String {
    format!(
        "{ENROLLMENT_OBJECT_ROOT}/{}/{generation_sha256}/",
        updated_contracts::telemetry::node_object_digest(node)
    )
}

/// Extract the content digest only after validating the complete, node-bound enrollment key.
/// This is the one parser shared by status reuse and capability authorization.
pub(crate) fn enrollment_object_sha256_for_node<'a>(
    relative: &'a str,
    node: &str,
) -> Option<&'a str> {
    let mut parts = relative.split('/');
    let root = parts.next()?;
    let node_digest = parts.next()?;
    let generation_digest = parts.next()?;
    let bundle_digest = parts.next()?.strip_suffix(".json")?;
    (parts.next().is_none()
        && root == ENROLLMENT_OBJECT_ROOT
        && node_digest == updated_contracts::telemetry::node_object_digest(node)
        && updated_contracts::is_canonical_sha256(generation_digest)
        && updated_contracts::is_canonical_sha256(bundle_digest))
    .then_some(bundle_digest)
}

pub(crate) fn enrollment_object_matches(
    relative: &str,
    generation_prefix: &str,
    bytes: &[u8],
    agent: &str,
    assignment: &str,
) -> bool {
    enrollment_object_sha256_for_node(relative, agent).is_some_and(|digest| {
        relative.starts_with(generation_prefix)
            && digest == updated_contracts::digest::sha256_bytes(bytes)
    }) && updated_contracts::enrollment::EnrollmentBundle::from_bounded_json(bytes)
        .is_ok_and(|bundle| bundle.agent_id == agent && bundle.assignment == assignment)
}

pub(crate) async fn publish_enrollment_objects(
    repository: &UpdateRepository,
    agents: &[Arc<UpdateAgent>],
    store: &dyn ObjectStore,
    prefix: &str,
    public_url: &str,
    trust_anchor: Option<&str>,
    generation_sha256: &str,
) -> Result<BTreeMap<String, String>, Box<dyn std::error::Error>> {
    let Some(trust_anchor) = enrollment_anchor(agents.len(), trust_anchor)? else {
        return Ok(BTreeMap::new());
    };
    let mut published = BTreeMap::new();
    for agent in agents {
        let name = agent.name_any();
        let assignment = updated_contracts::telemetry::assignment_object_key(
            &repository.spec.assignment_prefix,
            &name,
        );
        let generation_prefix = enrollment_generation_prefix(&name, generation_sha256);

        // A status pointer into this exact repository generation is a cheap steady-state path.
        // The object remains self-authenticating: its suffix is the SHA-256 of its bytes, and its
        // decoded identity/path must still match this agent before the pointer is reused.
        if let Some(relative) = agent
            .status
            .as_ref()
            .and_then(|status| status.enrollment_object_key.as_deref())
            .filter(|relative| relative.starts_with(&generation_prefix))
        {
            let key = crate::object_key(prefix, relative);
            if let Ok(bytes) = crate::read_object_bounded(
                store,
                &key,
                updated_contracts::enrollment::MAX_DOCUMENT_BYTES as u64,
            )
            .await
            {
                if enrollment_object_matches(
                    relative,
                    &generation_prefix,
                    &bytes,
                    &name,
                    &assignment,
                ) {
                    published.insert(name.clone(), relative.to_string());
                    continue;
                }
            }
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
                    "no enrollment bundle can be resolved for this agent yet, so its S3 object is not \
                     issued on this pass; this is expected while the agent's group is waiting to \
                     be admitted. Every other agent, and publication, are unaffected."
                );
                continue;
            }
        };
        let bundle = match signed.into_bundle(name.clone(), public_url, assignment.clone()) {
            Ok(bundle) => bundle,
            Err(error) => {
                tracing::error!(agent = %name, %error, "resolved enrollment assignment is invalid");
                continue;
            }
        };
        let bytes = match bundle.to_bounded_json() {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::error!(agent = %name, %error, "enrollment bootstrap exceeds its shared contract");
                continue;
            }
        };
        let digest = updated_contracts::digest::sha256_bytes(&bytes);
        let relative = format!("{generation_prefix}{digest}.json");
        let key = crate::object_key(prefix, &relative);
        let result = store
            .put_opts(
                &key,
                PutPayload::from(bytes.clone()),
                PutOptions {
                    mode: PutMode::Create,
                    ..Default::default()
                },
            )
            .await;
        match result {
            Ok(_) => {
                published.insert(name, relative);
            }
            Err(
                object_store::Error::Precondition { .. }
                | object_store::Error::AlreadyExists { .. },
            ) => match crate::read_object_bounded(
                store,
                &key,
                updated_contracts::enrollment::MAX_DOCUMENT_BYTES as u64,
            )
            .await
            {
                Ok(existing) if existing == bytes => {
                    published.insert(name, relative);
                }
                Ok(_) => tracing::error!(
                    agent = %name,
                    object = %key,
                    "content-addressed enrollment object already contains different bytes"
                ),
                Err(error) => tracing::error!(
                    agent = %name,
                    object = %key,
                    %error,
                    "reading an existing enrollment object failed"
                ),
            },
            Err(error) => tracing::error!(
                agent = %name,
                object = %key,
                %error,
                "publishing this agent's offline enrollment object failed"
            ),
        }
    }
    Ok(published)
}

/// Retain the S3 enrollment objects current agent statuses name and retire older superseded
/// objects. Called only after statuses are durable; `cutoff` additionally covers an operator that
/// read the previous pointer just before the status update.
pub(crate) async fn sweep_enrollment_objects(
    store: &dyn ObjectStore,
    prefix: &str,
    live: &BTreeMap<String, String>,
    cutoff: chrono::DateTime<chrono::Utc>,
) -> Result<usize, StorageError> {
    let live: BTreeSet<_> = live
        .values()
        .map(|relative| crate::object_key(prefix, relative))
        .collect();
    let root = crate::object_key(prefix, ENROLLMENT_OBJECT_ROOT);
    let exact_prefix = format!("{root}/");
    let mut objects = store.list(Some(&root));
    let sweep = async {
        let mut removed = 0usize;
        while let Some(next) = objects.next().await {
            let object = next.map_err(|error| {
                StorageError(format!("listing obsolete enrollment objects: {error}"))
            })?;
            // Object-store prefix implementations are not required to agree about segment
            // boundaries. Never let `enrollments-old/...` become part of this namespace merely
            // because its bytes share the same textual prefix.
            if !object.location.as_ref().starts_with(&exact_prefix)
                || object.last_modified > cutoff
                || live.contains(&object.location)
            {
                continue;
            }
            match store.delete(&object.location).await {
                Ok(()) | Err(object_store::Error::NotFound { .. }) => {
                    removed = removed.saturating_add(1);
                }
                Err(error) => {
                    return Err(StorageError(format!(
                        "deleting obsolete enrollment object {}: {error}",
                        object.location
                    )));
                }
            }
        }
        Ok(removed)
    };
    tokio::time::timeout(crate::OBJECT_STORE_MAINTENANCE_TIMEOUT, sweep)
        .await
        .map_err(|_| StorageError("sweeping obsolete enrollment objects timed out".into()))?
}

/// The trust anchor enrollment publication must use, or the reason there is nothing to do.
///
/// `Ok(None)` — no agent needs a bundle, so the anchor is irrelevant.
/// `Ok(Some(anchor))` — issue bundles pinned against this anchor.
/// `Err` — bundles are needed and cannot be issued. Without an anchor there is nothing to verify a
/// store-served root against, and an unverifiable bundle must never be handed out; but that also
/// means registration and offline provisioning have STOPPED, so it is reported as the failure it
/// is. Returning `Ok` there left nodes waiting for an object that would never appear, with nothing
/// logged to say why.
pub(crate) fn enrollment_anchor(
    agents: usize,
    trust_anchor: Option<&str>,
) -> Result<Option<&str>, StorageError> {
    match (agents, trust_anchor) {
        (0, _) => Ok(None),
        (_, Some(anchor)) => Ok(Some(anchor)),
        (waiting, None) => Err(StorageError(format!(
            "{waiting} agent(s) need an enrollment bundle, but this \
             repository's status carries no routingRootSha256 to pin the published root against; \
             no bundle can be issued until a generation is signed and its anchor recorded"
        ))),
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
/// that has hit it must be split across repositories. The limit is a product bound independent of
/// the separately configurable durable-state shard capacity.
pub(crate) fn enrollment_capacity_condition(
    generation: Option<i64>,
    agents: usize,
) -> ResourceCondition {
    let full = agents >= updated_contracts::backend::MAX_BACKEND_INVENTORY_MEMBERS;
    condition(
        "EnrollmentCapacity",
        !full,
        generation,
        if full { "AtCapacity" } else { "Available" },
        &format!(
            "{agents} of at most {} agents are enrolled.",
            updated_contracts::backend::MAX_BACKEND_INVENTORY_MEMBERS
        ),
    )
}
