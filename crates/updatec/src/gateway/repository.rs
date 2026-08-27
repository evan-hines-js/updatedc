//! Serving the release repository to nodes: redirecting to signed objects, and resolving the
//! enrollment documents whose signatures are verified once and then remembered.

use super::*;

/// Convert one canonical repository path into an exact short-lived S3 capability. Authorization is
/// deliberately absent from this storage primitive: the only HTTP caller is [`repo_get`], which
/// first passes through [`authorize_node`].
pub(crate) async fn repository_redirect(
    destination: &Destination,
    method: Method,
    uri: &axum::http::Uri,
) -> Response {
    // Repository objects are content-addressed and take no query parameters; a query string is a
    // signed-URL-style request we do not serve.
    if uri.query().is_some() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(key) = repository_key(&destination.prefix, uri.path()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match signed_object_url(destination, method, &key).await {
        Ok(url) => redirect_to(url),
        Err(status) => status.into_response(),
    }
}

/// Authorize one exact repository object and redirect the request to S3. GET, HEAD, ranges,
/// metadata, assignments, configs, and artifacts all use the same live identity and signed
/// assignment path as private inputs and telemetry writes; there is no byte proxy or SAN-only
/// authorization shortcut.
pub(crate) async fn repo_get(
    State(state): State<AuthorizationState>,
    Extension(identity): Extension<ClientIdentity>,
    method: Method,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let authorized = match authorize_node(&state, &identity, None).await {
        Ok(authorized) => authorized,
        Err(status) => return status.into_response(),
    };
    repository_redirect(&authorized.destination, method, &uri).await
}

/// The signed documents an [`crate::EnrollmentBundle`] pins for one agent, resolved from a
/// published repository's consistent snapshot.
/// The routing root digest this repository has published, from its status in etcd. `None` before
/// the first publish — there is no anchor yet, so nothing may be enrolled against it.
pub(crate) fn published_root_sha256(repository: &crate::UpdateRepository) -> Option<String> {
    repository
        .status
        .as_ref()?
        .routing_root_sha256
        .clone()
        .filter(|digest| updated_contracts::is_canonical_sha256(digest))
}

/// The four TUF role documents of one published generation.
///
/// Every agent in a generation pins the SAME four, and `targets.json` alone carries an entry per
/// published agent — so it is O(fleet) on its own. Owning a copy of it per agent made the verified
/// enrollment cache O(fleet²) resident, tens of gigabytes at the documented
/// `MAX_BACKEND_INVENTORY_MEMBERS`
/// ceiling, and the gateway was OOM-killed at exactly the fleet size it claims to support. It is a
/// property of the generation, like the generation's expiry beside it, so it is held once and
/// shared.
pub(crate) struct SignedMetadata {
    pub root: String,
    pub timestamp: String,
    pub snapshot: String,
    pub targets: String,
}

#[derive(Clone)]
pub(crate) struct SignedEnrollment {
    pub metadata: std::sync::Arc<SignedMetadata>,
    pub agent_document: String,
    pub managed_configuration: String,
}

impl SignedEnrollment {
    /// Assemble the small [`crate::EnrollmentBundle`] object. The large shared TUF roles and
    /// node-specific configuration remain ordinary repository objects; only the root, routing
    /// identity, assignment path, and immutable install-root pin are duplicated per node.
    pub(crate) fn into_bundle(
        self,
        agent_id: String,
        public_url: &str,
        assignment: String,
    ) -> Result<crate::EnrollmentBundle, String> {
        let managed = updated_contracts::assignment::RepositoryAssignment::from_bounded_json(
            self.managed_configuration.as_bytes(),
        )?;
        let agent_id = updated_contracts::identity::ResourceName::new(agent_id)
            .map_err(|_| "enrollment bundle has invalid agent identity".to_string())?;
        Ok(crate::EnrollmentBundle {
            schema: 1,
            agent_id,
            routing_base_url: format!("{}/", public_url.trim_end_matches('/')),
            assignment,
            install_root: managed.runtime.install_root,
            routing_root: self.metadata.root.clone(),
        })
    }
}

pub(crate) enum EnrollmentResolveError {
    /// A required object is not in the published repository yet (registration races publication) or
    /// could not be read — the safe, retryable direction.
    Unavailable(String),
    /// A signed document is present but malformed: bad JSON, a missing version pointer, or a target
    /// the `targets` metadata does not list.
    Malformed(String),
}

impl EnrollmentResolveError {
    /// The HTTP status a failed enrollment resolution maps to: `Unavailable`
    /// is a retryable 503 (the object races publication), `Malformed` is a 502 (a published
    /// document is broken).
    pub(crate) fn status_code(&self) -> StatusCode {
        match self {
            Self::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Malformed(_) => StatusCode::BAD_GATEWAY,
        }
    }
}

impl std::fmt::Display for EnrollmentResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable(what) => {
                write!(f, "{what} is not yet available in the published repository")
            }
            Self::Malformed(what) => write!(f, "{what} is malformed in the published repository"),
        }
    }
}

/// Walk the consistent-snapshot metadata chain in `store` and resolve the signed documents an
/// enrollment bundle pins for `assignment`: timestamp → snapshot(version) → targets(version) → the
/// agent's signed assignment document → its managed configuration, each target addressed by the
/// sha256 the `targets` role signs. This is the single copy of that walk, shared by the gateway's
/// `/enroll` handler and `runtime::publish_enrollment_objects`.
pub(crate) async fn resolve_signed_enrollment(
    store: &dyn ObjectStore,
    prefix: &str,
    assignment: &str,
    expected_root_sha256: &str,
) -> Result<SignedEnrollment, EnrollmentResolveError> {
    use EnrollmentResolveError::{Malformed, Unavailable};

    let root = object_text(store, prefix, "metadata/root.json")
        .await
        .map_err(|_| Unavailable("root metadata".into()))?;
    // The object store is NOT a trust boundary — anything with write access to this prefix can put
    // its own `root.json` there. The trust anchor is the digest the controller recorded in etcd
    // when it published, so the root is pinned against that before a single byte of the chain is
    // interpreted. Without this, an attacker who can write the prefix substitutes a root of their
    // own, signs a matching chain under it, and every node that enrolls afterwards pins THEIR root
    // as its routing anchor — the whole fleet's trust chain, replaced silently.
    if !updated_contracts::digest::digests_match(
        &updated_contracts::digest::sha256_bytes(root.as_bytes()),
        expected_root_sha256,
    ) {
        return Err(Malformed(
            "published routing root does not match the control plane's trust anchor".into(),
        ));
    }
    let timestamp = object_text(store, prefix, "metadata/timestamp.json")
        .await
        .map_err(|_| Unavailable("timestamp metadata".into()))?;
    // Everything below — three more object reads, four role signature/threshold checks, every
    // metafile and target digest — is a pure function of (prefix, anchor, timestamp, assignment)
    // AND of the current time, through the chain's expiries. So it is computed once per published
    // generation per agent instead of once per request, and re-computed the moment that
    // generation's earliest expiry passes.
    let generation = generation_key(prefix, expected_root_sha256, &timestamp);
    let now = chrono::Utc::now();
    if let Some(cached) = VERIFIED_ENROLLMENTS.get(&generation, assignment, now) {
        return Ok(cached);
    }
    let timestamp_value: serde_json::Value =
        serde_json::from_str(&timestamp).map_err(|_| Malformed("timestamp metadata".into()))?;
    let snapshot_version =
        crate::runtime::metadata_version(&timestamp_value, "snapshot.json").map_err(Malformed)?;
    let snapshot = object_text(
        store,
        prefix,
        &format!("metadata/{snapshot_version}.snapshot.json"),
    )
    .await
    .map_err(|_| Unavailable("snapshot metadata".into()))?;
    let snapshot_value: serde_json::Value =
        serde_json::from_str(&snapshot).map_err(|_| Malformed("snapshot metadata".into()))?;
    let targets_version =
        crate::runtime::metadata_version(&snapshot_value, "targets.json").map_err(Malformed)?;
    let targets = object_text(
        store,
        prefix,
        &format!("metadata/{targets_version}.targets.json"),
    )
    .await
    .map_err(|_| Unavailable("targets metadata".into()))?;
    let targets_value: serde_json::Value =
        serde_json::from_str(&targets).map_err(|_| Malformed("targets metadata".into()))?;

    let agent_object = consistent_target_object(&targets_value, assignment)
        .ok_or_else(|| Unavailable(format!("assignment target {assignment}")))?;
    let agent_document = object_text(store, prefix, &agent_object)
        .await
        .map_err(|_| Unavailable(format!("assignment document {assignment}")))?;
    let parsed =
        updated_contracts::artifact::AgentDocument::from_bounded_json(agent_document.as_bytes())
            .map_err(|_| Malformed(format!("assignment document {assignment}")))?;
    let config_path = parsed.config.path;
    let config_object = consistent_target_object(&targets_value, &config_path)
        .ok_or_else(|| Malformed(format!("managed configuration target {config_path}")))?;
    let managed_configuration = object_text(store, prefix, &config_object)
        .await
        .map_err(|_| Unavailable(format!("managed configuration {config_path}")))?;

    let resolved = SignedEnrollment {
        metadata: std::sync::Arc::new(SignedMetadata {
            root,
            timestamp,
            snapshot,
            targets,
        }),
        agent_document,
        managed_configuration,
    };
    // Then the full TUF chain, through the same verifier a node runs on the bundle it receives:
    // every role signature and threshold, every expiry, each metafile digest, each target digest.
    // Following JSON pointers from document to document — as this walk did — authenticates
    // nothing; it only reads what the store happens to contain.
    updated_tuf::verify_enrollment_publication(
        resolved.metadata.root.as_bytes(),
        resolved.metadata.timestamp.as_bytes(),
        resolved.metadata.snapshot.as_bytes(),
        resolved.metadata.targets.as_bytes(),
        assignment,
        resolved.agent_document.as_bytes(),
        resolved.managed_configuration.as_bytes(),
    )
    .map_err(|error| Malformed(format!("published enrollment chain ({error})")))?;
    // Cacheable only for as long as the chain that was just verified stays valid. If any role's
    // expiry cannot be read, nothing is memoized and every request re-verifies — slower, never
    // wrong.
    if let Some(expires) = chain_expiry(&resolved.metadata) {
        VERIFIED_ENROLLMENTS.insert(&generation, assignment, &resolved, expires);
    }
    Ok(resolved)
}

/// The earliest `signed.expires` across the four TUF role documents of one generation — the instant
/// at which `verify_enrollment_publication` starts rejecting this chain.
///
/// The metadata chain is identical for every agent in a generation, so this is a property of the
/// generation and is stored once alongside its key. `None` when any role's expiry is missing or
/// unparseable, which makes the chain uncacheable rather than cacheable forever.
pub(crate) fn chain_expiry(metadata: &SignedMetadata) -> Option<chrono::DateTime<chrono::Utc>> {
    [
        &metadata.root,
        &metadata.timestamp,
        &metadata.snapshot,
        &metadata.targets,
    ]
    .into_iter()
    .map(|document| {
        let value: serde_json::Value = serde_json::from_str(document).ok()?;
        let expires = value.get("signed")?.get("expires")?.as_str()?;
        chrono::DateTime::parse_from_rfc3339(expires)
            .ok()
            .map(|stamp| stamp.with_timezone(&chrono::Utc))
    })
    .try_fold(None::<chrono::DateTime<chrono::Utc>>, |earliest, expiry| {
        let expiry = expiry?;
        Some(Some(earliest.map_or(expiry, |held| held.min(expiry))))
    })
    .flatten()
}

/// Identifies one published generation as this walk sees it: the prefix it is served from, the
/// trust anchor it is pinned against, and the `timestamp` role — the TUF document that is re-signed
/// on every publish, so a new generation can never collide with an old key.
pub(crate) fn generation_key(prefix: &str, expected_root_sha256: &str, timestamp: &str) -> String {
    let mut digest = updated_contracts::digest::Sha256Hasher::new();
    for part in [prefix, expected_root_sha256, timestamp] {
        digest.update(part.as_bytes());
        digest.update(&[0]);
    }
    digest.finish_hex()
}

/// Verified enrollment chains, memoized for as long as the published generation they came from is
/// current.
///
/// `resolve_signed_enrollment` performs a full TUF verification. Node capability endpoints would
/// otherwise repeat that work on every request, multiplying it by the fleet's report cadence and
/// saturating a large gateway. This is the same reason the rollout planner memoizes report
/// verification.
///
/// A hit is bounded by BOTH: the key (a publish re-signs `timestamp`, which changes the generation
/// key and drops every entry in one step) and the generation's own earliest role expiry. The expiry
/// half is not an optimization — a hit skips `verify_enrollment_publication`, whose expiry check is the
/// only thing standing between a publisher that has stopped re-signing and a gateway serving an
/// expired chain forever. It is a property of the generation, not of an entry: every agent's bundle
/// carries the same four role documents, so it is stored once beside the key and compared with one
/// integer comparison per request. Only successful verifications are stored, and only for assignment
/// paths derived from an already authenticated caller, so the map is bounded by the fleet's own
/// agent count.
///
/// The generation's four ROLE DOCUMENTS are stored the same way, once beside the key, for the same
/// reason and one harder one: `targets.json` carries an entry per published agent, so a per-agent
/// copy of it makes this map O(fleet²) BYTES — the gateway is OOM-killed at its own supported fleet
/// size, precisely in the steady state (nothing publishing, so nothing evicting) the cache exists to
/// serve. An entry holds only what is genuinely per-agent.
#[derive(Default)]
pub(crate) struct Generation {
    pub(crate) key: String,
    pub(crate) expires: Option<chrono::DateTime<chrono::Utc>>,
    /// This generation's role documents, shared by every entry below. `None` only before the first
    /// insert into a fresh generation.
    pub(crate) metadata: Option<std::sync::Arc<SignedMetadata>>,
    pub(crate) entries: std::collections::HashMap<String, AgentDocuments>,
}

/// The part of a verified enrollment that is genuinely per-agent: its signed assignment document
/// and the managed configuration that document names.
#[derive(Clone)]
pub(crate) struct AgentDocuments {
    pub(crate) agent_document: String,
    pub(crate) managed_configuration: String,
}

pub(crate) struct VerifiedEnrollments {
    pub(crate) inner: std::sync::Mutex<Generation>,
}

pub(crate) static VERIFIED_ENROLLMENTS: std::sync::LazyLock<VerifiedEnrollments> =
    std::sync::LazyLock::new(|| VerifiedEnrollments {
        inner: std::sync::Mutex::new(Generation::default()),
    });

impl VerifiedEnrollments {
    pub(crate) fn get(
        &self,
        generation: &str,
        assignment: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<SignedEnrollment> {
        let guard = self.lock();
        if guard.key != generation || guard.expires.is_none_or(|expires| now >= expires) {
            return None;
        }
        let metadata = guard.metadata.as_ref()?;
        let entry = guard.entries.get(assignment)?;
        Some(SignedEnrollment {
            metadata: std::sync::Arc::clone(metadata),
            agent_document: entry.agent_document.clone(),
            managed_configuration: entry.managed_configuration.clone(),
        })
    }

    pub(crate) fn insert(
        &self,
        generation: &str,
        assignment: &str,
        resolved: &SignedEnrollment,
        expires: chrono::DateTime<chrono::Utc>,
    ) {
        let mut guard = self.lock();
        if guard.key != generation {
            // A new generation invalidates every entry at once; nothing from the old one can be
            // served afterwards.
            *guard = Generation {
                key: generation.to_string(),
                expires: Some(expires),
                metadata: None,
                entries: std::collections::HashMap::new(),
            };
        }
        // The role documents are stored for the generation, not for this agent: the first insert
        // after a publish contributes them and every later one drops its own copy, so N agents cost
        // one chain, not N.
        guard
            .metadata
            .get_or_insert_with(|| std::sync::Arc::clone(&resolved.metadata));
        guard.entries.insert(
            assignment.to_string(),
            AgentDocuments {
                agent_document: resolved.agent_document.clone(),
                managed_configuration: resolved.managed_configuration.clone(),
            },
        );
    }

    pub(crate) fn lock(&self) -> std::sync::MutexGuard<'_, Generation> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

pub(crate) fn consistent_target_object(
    targets: &serde_json::Value,
    logical_path: &str,
) -> Option<String> {
    let digest = targets
        .get("signed")?
        .get("targets")?
        .get(logical_path)?
        .get("hashes")?
        .get("sha256")?
        .as_str()?;
    if !updated_contracts::is_canonical_sha256(digest) {
        return None;
    }
    Some(format!("targets/{digest}.{logical_path}"))
}

pub(crate) async fn object_text(
    store: &dyn ObjectStore,
    prefix: &str,
    relative: &str,
) -> Result<String, object_store::Error> {
    let key = crate::object_key(prefix, relative);
    let bytes = crate::read_object_bounded(store, &key, crate::OBJECT_BYTES_LIMIT).await?;
    String::from_utf8(bytes).map_err(|error| object_store::Error::Generic {
        store: "enrollment",
        source: Box::new(error),
    })
}

pub(crate) fn repository_key(prefix: &str, request_path: &str) -> Option<ObjectPath> {
    // The grammar — which paths name a repository object — is `crate::served`'s, shared with the
    // development fixtures so production and tests accept exactly the same object names.
    let object = crate::served::repository_object(request_path)?;
    // This listener serves only the signed TUF repository. Telemetry is an S3 data-plane concern,
    // and load-balancer topology/cordons use the controller-owned Kubernetes inventory.
    if !matches!(object.namespace, "metadata" | "targets") {
        return None;
    }
    Some(crate::object_key(prefix, &object.key()))
}
