//! The steady-state routes an enrolled node calls: download and upload capabilities, dataflow
//! inputs and outputs, and the signed report it files each cycle. Every one of them resolves the
//! caller's identity to a node in this gateway's own repository before it answers.

use super::*;

pub(crate) fn data_router(state: DataState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/enroll", post(enroll))
        .route("/renew", post(renew))
        .route(updated_contracts::dataflow::INPUTS_ROUTE, get(node_inputs))
        .route(updated_contracts::dataflow::OUTPUTS_PATH, get(node_outputs))
        .route(updated_contracts::dataflow::REPORT_PATH, get(node_report))
        .route("/metadata/{*rest}", get(repo_get).head(repo_get))
        .route("/targets/{*rest}", get(repo_get).head(repo_get))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        // Bound the whole request (header parse is already bounded by the connection's
        // header_read_timeout; this covers a slow-drip control body and any handler or capability-
        // signer stall). Repository payloads never traverse this router: `repo_get` returns an S3
        // redirect, while the private dataflow handlers return bounded capability documents.
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            IO_TIMEOUT,
        ))
        .with_state(state)
}

pub(crate) struct AuthorizedNode {
    pub(crate) node: String,
    pub(crate) assignment_sha256: String,
    pub(crate) input_object_sha256: Option<String>,
    pub(crate) destination: Arc<Destination>,
}

/// Preserve the only meaningful distinction in a live identity lookup: an absent object is a
/// standing authorization refusal, while an apiserver failure is transient and must not be cached
/// by the node as an identity verdict.
pub(crate) fn identity_object<T>(result: Result<T, kube::Error>) -> Result<T, StatusCode> {
    match result {
        Ok(value) => Ok(value),
        Err(kube::Error::Api(response)) if response.code == 404 => Err(StatusCode::FORBIDDEN),
        Err(_) => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

/// Classify one certificate-backed request using the complete identity policy.
///
/// Enrolled and manually provisioned nodes use every steady-state capability only while their live
/// object still pins the leaf's key. Reserved identities have not become machines and authorize
/// nothing. Keeping the name, repository, kind, field shape, and key check together prevents a
/// handler from accidentally treating mTLS authentication as authorization.
pub(crate) fn authorized_identity(
    identity: &ClientIdentity,
    agent: &crate::UpdateAgent,
    repository: &str,
) -> bool {
    let Some(node) = identity.node_in(repository) else {
        return false;
    };
    if agent.metadata.name.as_deref() != Some(node)
        || agent.spec.repository_ref.name != repository
        || !agent.spec.identity.is_well_formed_for(node)
    {
        return false;
    }
    is_pinned_leaf(identity, agent, repository)
}

pub(crate) struct LiveAuthorizedIdentity {
    pub(crate) node: String,
    pub(crate) agent: crate::UpdateAgent,
    pub(crate) repository: crate::UpdateRepository,
}

/// Read the repository authority behind every enrollment, renewal, and fresh capability decision.
/// A terminating object still exists at the Kubernetes API, but it authorizes no new identity or
/// bearer capability. Missing is a standing refusal; an apiserver failure remains retryable.
pub(crate) async fn live_repository(
    authority: &IdentityAuthority,
) -> Result<crate::UpdateRepository, StatusCode> {
    let repositories: Api<crate::UpdateRepository> =
        Api::namespaced(authority.client.clone(), &authority.namespace);
    let repository = identity_object(repositories.get(&authority.repository).await)?;
    if repository.metadata.deletion_timestamp.is_some() {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(repository)
}

/// Resolve the sole live definition of a steady-state node identity: repository-scoped mTLS leaf,
/// same-named object, provisioned identity kind, and an exact public-key pin. Missing or mismatched
/// objects are authorization failures; apiserver failures remain retryable service failures.
pub(crate) async fn authorize_identity(
    authority: &IdentityAuthority,
    identity: &ClientIdentity,
) -> Result<LiveAuthorizedIdentity, StatusCode> {
    let Some(node) = identity.node_in(&authority.repository) else {
        return Err(StatusCode::FORBIDDEN);
    };
    let agents: Api<crate::UpdateAgent> =
        Api::namespaced(authority.client.clone(), &authority.namespace);
    let agent = identity_object(agents.get(node).await)?;
    if !authorized_identity(identity, &agent, &authority.repository) {
        return Err(StatusCode::FORBIDDEN);
    }
    let repository = live_repository(authority).await?;
    Ok(LiveAuthorizedIdentity {
        node: node.to_string(),
        agent,
        repository,
    })
}

/// The one authorization and assignment-resolution path for sensitive node APIs. Both runtime
/// reads and output writes are bound to the mTLS leaf, the live UpdateAgent's operation-specific
/// identity policy, this repository, and the exact currently published TUF assignment.
pub(crate) async fn authorize_node(
    state: &AuthorizationState,
    identity: &ClientIdentity,
    expected_assignment_sha256: Option<&str>,
) -> Result<AuthorizedNode, StatusCode> {
    let Some(node) = identity.node_in(&state.identity.repository) else {
        return Err(StatusCode::FORBIDDEN);
    };
    let now = tokio::time::Instant::now();
    // A memo entry is a recent successful live-object/key-pin decision. Its lookup key includes
    // the leaf public key, so replacing a node's pin cannot authorize a different certificate.
    if let Some(assignment) = state
        .memo
        .get(node, identity, expected_assignment_sha256, now)
    {
        return Ok(AuthorizedNode {
            node: node.to_string(),
            assignment_sha256: assignment.assignment_sha256,
            input_object_sha256: assignment.input_object_sha256,
            destination: state.content.destination(),
        });
    }
    // The certificate says who the caller is; the `UpdateAgent` object says whether it is still one
    // of ours. Every provisioned node must present the key the name is pinned to; the only
    // difference between manual and enrolled identities is how that key first reached the object.
    // A leaf outlives the object that justified it (up to `LEAF_CERT_TTL_DAYS`), so a
    // decommissioned, re-homed or superseded node kept reading its deployment's database passwords
    // and API tokens from here for as long as no new generation was published — while `/renew`,
    // which gates on the same pin, answered 403. Every endpoint that mints an object capability
    // applies the same check as the one that mints certificates.
    let authorized = authorize_identity(&state.identity, identity).await?;
    let assignment = updated_contracts::telemetry::assignment_object_key(
        &authorized.repository.spec.assignment_prefix,
        node,
    );
    let Some(trust_anchor) = published_root_sha256(&authorized.repository) else {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    };
    let destination = state.content.destination();
    let signed = match resolve_signed_enrollment(
        destination.store.as_ref(),
        &destination.prefix,
        &assignment,
        &trust_anchor,
    )
    .await
    {
        Ok(signed) => signed,
        Err(error) => return Err(error.status_code()),
    };
    let assignment_sha256 =
        updated_contracts::digest::sha256_bytes(signed.managed_configuration.as_bytes());
    let configuration = updated_contracts::assignment::RepositoryAssignment::from_bounded_json(
        signed.managed_configuration.as_bytes(),
    )
    .map_err(|_| StatusCode::BAD_GATEWAY)?;
    if expected_assignment_sha256.is_some_and(|expected| expected != assignment_sha256.as_str()) {
        return Err(StatusCode::CONFLICT);
    }
    // The exact private-object commitment comes from the assignment just resolved through TUF,
    // never Kubernetes status or S3 metadata. The committed object contains a private keyed
    // blinding, so this public digest authenticates storage without becoming a guessing oracle for
    // low-entropy secrets.
    let input_object_sha256 = (!configuration.runtime.inputs.is_empty())
        .then(|| configuration.runtime.inputs.object_sha256.clone());
    let assignment = AuthorizedAssignment {
        assignment_sha256: assignment_sha256.clone(),
        input_object_sha256: input_object_sha256.clone(),
    };
    state.memo.insert(node, identity, assignment, now);
    Ok(AuthorizedNode {
        node: authorized.node,
        assignment_sha256,
        input_object_sha256,
        destination,
    })
}

pub(crate) async fn signed_object_url(
    destination: &Destination,
    method: Method,
    key: &ObjectPath,
) -> Result<reqwest::Url, StatusCode> {
    match timeout(
        IO_TIMEOUT,
        destination
            .signer
            .signed_url(method, key, OBJECT_CAPABILITY_TTL),
    )
    .await
    {
        Ok(Ok(url)) if updated_contracts::dataflow::capability_url(url.as_str()).is_ok() => Ok(url),
        Ok(Ok(_)) | Ok(Err(_)) => Err(StatusCode::SERVICE_UNAVAILABLE),
        Err(_) => Err(StatusCode::GATEWAY_TIMEOUT),
    }
}

pub(crate) async fn exact_download_capability(
    destination: &Destination,
    key: &ObjectPath,
    sha256: &str,
) -> Result<updated_contracts::dataflow::DownloadCapability, StatusCode> {
    if !updated_contracts::is_canonical_sha256(sha256) {
        return Err(StatusCode::SERVICE_UNAVAILABLE);
    }
    let url = signed_object_url(destination, Method::GET, key).await?;
    let capability = updated_contracts::dataflow::DownloadCapability {
        schema: updated_contracts::dataflow::DownloadCapability::SCHEMA,
        url: url.to_string(),
        sha256: sha256.to_string(),
    };
    capability
        .validate()
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(capability)
}

pub(crate) async fn enrollment_download_capability(
    content: &ContentState,
    agent: &crate::UpdateAgent,
) -> Result<updated_contracts::dataflow::DownloadCapability, StatusCode> {
    let node = agent.name_any();
    let relative = agent
        .status
        .as_ref()
        .and_then(|status| status.enrollment_object_key.as_deref())
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let sha256 = crate::runtime::enrollment_object_sha256_for_node(relative, &node)
        .ok_or(StatusCode::SERVICE_UNAVAILABLE)?;
    let destination = content.destination();
    let key = crate::object_key(&destination.prefix, relative);
    exact_download_capability(&destination, &key, sha256).await
}

pub(crate) fn redirect_to(url: reqwest::Url) -> Response {
    let Ok(location) = header::HeaderValue::from_str(url.as_str()) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    Response::builder()
        .status(StatusCode::TEMPORARY_REDIRECT)
        .header(header::LOCATION, location)
        .header(header::CACHE_CONTROL, "private, no-store")
        .header(header::PRAGMA, "no-cache")
        .header("referrer-policy", "no-referrer")
        .header(header::CONTENT_LENGTH, 0)
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

pub(crate) fn private_json<T: serde::Serialize>(value: T) -> Response {
    let mut response = Json(value).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("private, no-store"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, header::HeaderValue::from_static("no-cache"));
    response.headers_mut().insert(
        "referrer-policy",
        header::HeaderValue::from_static("no-referrer"),
    );
    response
}

pub(crate) async fn upload_capability(
    destination: &Destination,
    key: &ObjectPath,
    max_bytes: usize,
) -> Response {
    let capability = match timeout(
        IO_TIMEOUT,
        destination
            .upload_signer
            .signed_upload(key, max_bytes, OBJECT_CAPABILITY_TTL),
    )
    .await
    {
        Ok(Ok(capability)) if capability.validate().is_ok() => capability,
        Ok(Ok(_)) | Ok(Err(_)) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        Err(_) => return StatusCode::GATEWAY_TIMEOUT.into_response(),
    };
    private_json(capability)
}

/// Authorize the signed input selection, then return one exact-object capability for its immutable
/// private S3 object. The gateway never reads or returns payload bytes; the TUF-signed blinded
/// object commitment authenticates the anonymous object-store response before the node parses it.
pub(crate) async fn node_inputs(
    State(state): State<AuthorizationState>,
    Path(assignment_sha256): Path<String>,
    Extension(identity): Extension<ClientIdentity>,
) -> Response {
    if !updated_contracts::is_canonical_sha256(&assignment_sha256) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let authorized = match authorize_node(&state, &identity, Some(&assignment_sha256)).await {
        Ok(authorized) => authorized,
        Err(status) => return status.into_response(),
    };
    let dataflow = crate::dataflow::RepositoryDataflow::new(
        authorized.destination.store.clone(),
        authorized.destination.prefix.clone(),
    );
    let key = dataflow.input_key(&authorized.assignment_sha256);
    let Some(input_object_sha256) = authorized.input_object_sha256.as_deref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match exact_download_capability(&authorized.destination, &key, input_object_sha256).await {
        Ok(capability) => private_json(capability),
        Err(status) => status.into_response(),
    }
}

/// Mint the one exact, size-bounded POST capability for this node's private output object. The
/// controller later validates its assignment identity and joins its generation to signed health
/// evidence.
pub(crate) async fn node_outputs(
    State(state): State<AuthorizationState>,
    Extension(identity): Extension<ClientIdentity>,
) -> Response {
    let authorized = match authorize_node(&state, &identity, None).await {
        Ok(authorized) => authorized,
        Err(status) => return status.into_response(),
    };
    let dataflow = crate::dataflow::RepositoryDataflow::new(
        authorized.destination.store.clone(),
        authorized.destination.prefix.clone(),
    );
    upload_capability(
        &authorized.destination,
        &dataflow.output_key(&authorized.node),
        updated_contracts::dataflow::MAX_DATAFLOW_BODY_BYTES,
    )
    .await
}

/// Mint the one exact, size-bounded POST capability for this node's raw end-to-end signed report
/// object.
pub(crate) async fn node_report(
    State(state): State<AuthorizationState>,
    Extension(identity): Extension<ClientIdentity>,
) -> Response {
    let authorized = match authorize_node(&state, &identity, None).await {
        Ok(authorized) => authorized,
        Err(status) => return status.into_response(),
    };
    let dataflow = crate::dataflow::RepositoryDataflow::new(
        authorized.destination.store.clone(),
        authorized.destination.prefix.clone(),
    );
    upload_capability(
        &authorized.destination,
        &dataflow.report_key(&authorized.node),
        updated_contracts::telemetry::MAX_REPORT_ENVELOPE_BYTES,
    )
    .await
}
