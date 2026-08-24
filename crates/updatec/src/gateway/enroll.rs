//! `/enroll` and `/renew`. Enrollment is serialised fleet-wide by a Lease so two nodes cannot
//! claim one name concurrently, and it is the only route reachable with the shared bootstrap
//! identity — every other route requires the per-node identity minted here.

use super::*;

pub(crate) async fn enroll(
    State(state): State<DataState>,
    Extension(identity): Extension<ClientIdentity>,
    body: Bytes,
) -> Response {
    // The listener trusts the fleet CA for both the shared bootstrap certificate and minted
    // per-node leaves. Authentication alone is therefore insufficient here: require the exact
    // configured bootstrap identity so a compromised steady-state node cannot mint Sybil nodes.
    if !is_enrollment_identity(&identity, &state.enrollment_client_cn) {
        return StatusCode::FORBIDDEN.into_response();
    }
    // The node self-asserts its name in the body; an approval gate on the resulting UpdateAgent is
    // the place to require a human to authorize that name.
    let Ok(request) =
        serde_json::from_slice::<updated_contracts::enrollment::EnrollmentRequest>(&body)
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !request.name_is_wellformed() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if !is_distinct_from_bootstrap_identity(&request.name, &state.enrollment_client_cn) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let name = request.name.as_str();
    // A stable per-node identifier for idempotent re-enrollment, derived from the self-asserted name:
    // the same node coming back on the same name is the same UpdateAgent.
    let registration_sha256 = updated_contracts::telemetry::node_object_digest(name);
    // Pin the CSR's public key so the throttle can later verify this node's signed telemetry, then
    // sign the CSR into a per-node leaf (CN=<name>). The CP certifies only the CSR's public key; a
    // malformed CSR is the caller's fault (400). `register_agent` runs `sign` only after the
    // create/conflict check passes, so a conflicting name never mints a certificate.
    let Ok(public_key) = crate::join::csr_public_key(&request.csr) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    match register_enrollment(
        &state,
        name,
        registration_sha256,
        public_key.to_hex(),
        &request.csr,
    )
    .await
    {
        Ok((bundle_download, leaf)) => bounded_enrollment_json(
            updated_contracts::enrollment::EnrollResponse {
                leaf,
                bundle_download,
            }
            .to_bounded_json(),
        ),
        Err(response) => response,
    }
}

pub(crate) fn is_enrollment_identity(
    identity: &ClientIdentity,
    enrollment_client_cn: &str,
) -> bool {
    !enrollment_client_cn.is_empty()
        && identity.common_name.as_deref() == Some(enrollment_client_cn)
        && identity.node.is_none()
}

pub(crate) fn is_distinct_from_bootstrap_identity(name: &str, enrollment_client_cn: &str) -> bool {
    !enrollment_client_cn.is_empty() && name != enrollment_client_cn
}

pub(crate) async fn renew(
    State(state): State<DataState>,
    Extension(identity): Extension<ClientIdentity>,
    body: Bytes,
) -> Response {
    // Renewal is a steady-state operation: only an already-minted per-node leaf scoped to THIS
    // repository may re-sign its own identity. The shared fleet bootstrap certificate mints leaves
    // at `/enroll` and nothing else.
    let authority = IdentityAuthority::from(&state.enrollment);
    let authorized = match authorize_identity(&authority, &identity).await {
        Ok(authorized) => authorized,
        Err(status) => return status.into_response(),
    };
    let Ok(request) =
        serde_json::from_slice::<updated_contracts::enrollment::RenewalRequest>(&body)
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(public_key) = crate::join::csr_public_key(&request.csr) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !is_pinned_identity(
        &authorized.agent,
        &state.enrollment.repository,
        &public_key.to_hex(),
    ) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match state.ca.get().sign_client_csr(
        &state.enrollment.repository,
        &authorized.node,
        &request.csr,
    ) {
        Ok(leaf) => {
            tracing::info!(
                node = %authorized.node,
                repository = %state.enrollment.repository,
                "renewed node certificate"
            );
            bounded_enrollment_json(
                updated_contracts::enrollment::RenewalResponse { leaf }.to_bounded_json(),
            )
        }
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

/// The single check that an existing `UpdateAgent` is a provisioned identity in the same repository
/// presenting its pinned public key. Renewal and every certificate-authenticated data-plane route
/// gate on this, so "is this really that node?" has one definition those paths cannot drift apart
/// on. Enrollment idempotency adds the enrolled registration digest check at its call site.
pub(crate) fn is_pinned_identity(
    agent: &crate::UpdateAgent,
    repository: &str,
    public_key: &str,
) -> bool {
    agent.spec.identity.is_well_formed_for(&agent.name_any())
        && matches!(
            agent.spec.identity.kind,
            crate::AgentIdentityKind::Manual | crate::AgentIdentityKind::Enrolled
        )
        && agent.spec.repository_ref.name == repository
        && agent.spec.identity.public_key.as_deref() == Some(public_key)
}

/// The same rule for a route that presents no key in its body: the key comes from the connection's
/// own leaf, which the handshake proved possession of.
///
/// Membership alone is not enough here. A leaf outlives the object that justified it (up to
/// `LEAF_CERT_TTL_DAYS`), and re-provisioning a machine under its existing hostname means deleting
/// the `UpdateAgent` and letting the replacement enroll fresh — which pins a NEW key under the SAME
/// name. Authorizing on name plus membership would hand the replacement's secrets, bundle and
/// telemetry slot to any surviving holder of the old leaf for the rest of its 90-day life, and
/// there is no revocation path. Binding to the pin makes a node's identity its key, so a superseded
/// holder loses access the instant the replacement enrolls.
pub(crate) fn is_pinned_leaf(
    identity: &ClientIdentity,
    agent: &crate::UpdateAgent,
    repository: &str,
) -> bool {
    identity
        .public_key
        .as_deref()
        .is_some_and(|public_key| is_pinned_identity(agent, repository, public_key))
}

pub(crate) fn at_enrollment_capacity(count: usize) -> bool {
    count >= updated_contracts::backend::MAX_BACKEND_INVENTORY_MEMBERS
}

/// One held instance of the chart-precreated enrollment Lease. Its resourceVersion is the
/// distributed compare-and-swap that makes `list current inventory -> create one agent` one
/// transaction across every gateway replica. The gateway has get/update on this exact name and no
/// Lease create permission, so a compromised listener cannot manufacture locks elsewhere.
pub(crate) struct EnrollmentLock {
    pub(crate) leases: Api<Lease>,
    pub(crate) name: String,
    pub(crate) holder: String,
}

impl EnrollmentLock {
    pub(crate) async fn release(self) -> Result<(), kube::Error> {
        let mut lease = self.leases.get(&self.name).await?;
        let Some(spec) = lease.spec.as_mut() else {
            return Ok(());
        };
        if !release_enrollment_lock_spec(spec, &self.holder, chrono::Utc::now()) {
            return Ok(());
        }
        match self
            .leases
            .replace(&self.name, &PostParams::default(), &lease)
            .await
        {
            Ok(_) => Ok(()),
            // A concurrent writer changed the Lease after our final read. Never overwrite it; our
            // old claim is either already gone or expires without granting this request authority.
            Err(kube::Error::Api(error)) if error.code == 409 => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// Clear only our own claim while retaining a Kubernetes-valid positive duration. A missing holder
/// makes the lock immediately available; setting the duration to zero is both unnecessary and
/// rejected by Lease validation, which used to strand every concurrent enrollment until expiry.
pub(crate) fn release_enrollment_lock_spec(
    spec: &mut LeaseSpec,
    holder: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    if spec.holder_identity.as_deref() != Some(holder) {
        return false;
    }
    spec.holder_identity = None;
    spec.lease_duration_seconds = Some(ENROLLMENT_LOCK_SECONDS);
    spec.renew_time = Some(MicroTime(now));
    true
}

pub(crate) fn enrollment_lock_available(
    spec: &LeaseSpec,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    spec.holder_identity.as_deref().is_none_or(str::is_empty)
        || crate::runtime::lease_expired(spec, now)
}

pub(crate) fn enrollment_lock_spec(
    holder: &str,
    now: chrono::DateTime<chrono::Utc>,
    transitions: i32,
) -> LeaseSpec {
    LeaseSpec {
        holder_identity: Some(holder.into()),
        lease_duration_seconds: Some(ENROLLMENT_LOCK_SECONDS),
        acquire_time: Some(MicroTime(now)),
        renew_time: Some(MicroTime(now)),
        lease_transitions: Some(transitions),
        preferred_holder: None,
        strategy: None,
    }
}

pub(crate) async fn acquire_enrollment_lock(
    context: &EnrollmentContext,
) -> Result<EnrollmentLock, String> {
    let holder =
        updated::rand::token().map_err(|error| format!("naming enrollment lock: {error}"))?;
    let leases: Api<Lease> = Api::namespaced(context.client.clone(), &context.namespace);
    let acquire = async {
        loop {
            let mut lease = leases
                .get(&context.lock_name)
                .await
                .map_err(|error| format!("reading enrollment lock: {error}"))?;
            let now = chrono::Utc::now();
            let spec = lease.spec.get_or_insert_with(Default::default);
            if !enrollment_lock_available(spec, now) {
                sleep(ENROLLMENT_LOCK_RETRY).await;
                continue;
            }
            let transitions = spec.lease_transitions.unwrap_or_default().saturating_add(1);
            *spec = enrollment_lock_spec(&holder, now, transitions);
            match leases
                .replace(&context.lock_name, &PostParams::default(), &lease)
                .await
            {
                Ok(_) => {
                    return Ok(EnrollmentLock {
                        leases: leases.clone(),
                        name: context.lock_name.clone(),
                        holder: holder.clone(),
                    });
                }
                Err(kube::Error::Api(error)) if error.code == 409 => {
                    sleep(ENROLLMENT_LOCK_RETRY).await;
                }
                Err(error) => return Err(format!("acquiring enrollment lock: {error}")),
            }
        }
    };
    timeout(ENROLLMENT_LOCK_WAIT, acquire)
        .await
        .map_err(|_| "timed out waiting for the enrollment lock".to_string())?
}

/// The single enrollment transaction: create the exact enrolled identity idempotently, wait for
/// the controller's one enrollment-object publisher to project it, then mint its leaf and authorize
/// that exact S3 object. A conflicting name is rejected before certificate issuance, and there is
/// no alternate registration or bundle transport mode.
pub(crate) async fn register_enrollment(
    state: &DataState,
    name: &str,
    registration_sha256: String,
    public_key: String,
    csr: &str,
) -> Result<(updated_contracts::dataflow::DownloadCapability, String), Response> {
    let context = &state.enrollment;
    let authority = IdentityAuthority::from(context);
    let repository = live_repository(&authority)
        .await
        .map_err(|status| status.into_response())?;
    let agents: Api<crate::UpdateAgent> =
        Api::namespaced(context.client.clone(), &context.namespace);
    let desired = crate::UpdateAgent::new(
        name,
        crate::UpdateAgentSpec {
            repository_ref: crate::LocalObjectReference {
                name: context.repository.clone(),
            },
            identity: crate::AgentIdentity {
                kind: crate::AgentIdentityKind::Enrolled,
                registration_sha256: Some(registration_sha256.clone()),
                public_key: Some(public_key),
            },
            hold: false,
            cordon: false,
            labels: repository.spec.enrollment.labels.clone(),
            backend_address: None,
        },
    );
    // Idempotent re-enrollment must be the SAME pinned identity (via the one shared predicate, so it
    // can never drift from renewal) AND the same registration digest. Binding to the pinned key is
    // what stops a shared-fleet-cert holder from re-enrolling an existing name with an attacker key:
    // a different key fails this match, falls through to CONFLICT, and no `CN=<name>` leaf is minted
    // (which would otherwise spend another node's exact input/output/report capabilities). A
    // genuine retry reuses the node's durable key, so it still matches and stays idempotent.
    let pinned_key = desired
        .spec
        .identity
        .public_key
        .as_deref()
        .unwrap_or_default();
    let matches = |existing: &crate::UpdateAgent| {
        is_pinned_identity(existing, &context.repository, pinned_key)
            && existing.spec.identity.registration_sha256.as_deref()
                == Some(registration_sha256.as_str())
    };
    // The status count used here previously was an asynchronous observation: every request in one
    // burst could read 9,999 and then create, overshooting without bound. Serialize the LIVE list
    // and create through one pre-created Lease. Existing identities and reservations do not grow
    // the inventory, so they remain completable when the fleet is full.
    let lock = acquire_enrollment_lock(context).await.map_err(|error| {
        tracing::error!(%error, "enrollment capacity lock is unavailable");
        StatusCode::SERVICE_UNAVAILABLE.into_response()
    })?;
    let registration = timeout(ENROLLMENT_TRANSACTION_TIMEOUT, async {
        let existing = agents
            .get_opt(name)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if let Some(existing) = existing {
            return accept_existing_agent(&agents, name, &desired, &existing, &matches).await;
        }
        let live = agents
            .list(&ListParams::default())
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
            .items
            .into_iter()
            .filter(|agent| agent.spec.repository_ref.name == context.repository)
            .count();
        if at_enrollment_capacity(live) {
            tracing::warn!(
                node = %name,
                repository = %context.repository,
                limit = updated_contracts::backend::MAX_BACKEND_INVENTORY_MEMBERS,
                "refusing enrollment: this repository is at its agent ceiling. Split the fleet \
                 across UpdateRepositories, or remove decommissioned UpdateAgents."
            );
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }
        create_agent_idempotent(&agents, name, &desired, &matches).await
    })
    .await
    .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)
    .and_then(|result| result);
    if let Err(error) = lock.release().await {
        tracing::error!(%error, "releasing enrollment capacity lock failed; it will expire");
        if registration.is_ok() {
            return Err(StatusCode::SERVICE_UNAVAILABLE.into_response());
        }
    }
    if let Err(status) = registration {
        return Err(status.into_response());
    }
    // Creation and publication are deliberately separate commits. A new dynamic identity may race
    // the controller pass that writes its content-addressed bundle; answer 503 and let the node
    // retry with its durable CSR. The retry is idempotent and no second gateway-side bundle writer
    // exists. A pre-reserved identity whose object is already published completes immediately.
    let agent = agents
        .get(name)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE.into_response())?;
    let bundle_download = enrollment_download_capability(&state.content, &agent)
        .await
        .map_err(|status| status.into_response())?;
    let leaf = state
        .ca
        .get()
        .sign_client_csr(&context.repository, name, csr)
        .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
    Ok((bundle_download, leaf))
}

/// Serialize every enrollment-family response through the shared document ceiling. Returning a
/// generic 500 keeps internal metadata out of the wire response; the log carries the cause.
pub(crate) fn bounded_enrollment_json(bytes: std::io::Result<Vec<u8>>) -> Response {
    match bytes {
        Ok(bytes) => ([(header::CONTENT_TYPE, "application/json")], bytes).into_response(),
        Err(error) => {
            tracing::error!(%error, "enrollment response violates the shared document contract");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Create `desired` (named `name`), treating a 409 as success iff the existing agent `matches`
/// (an idempotent re-registration); a 409 whose existing agent does not match is a real `CONFLICT`,
/// and any other API error is `500`.
pub(crate) async fn create_agent_idempotent(
    agents: &Api<crate::UpdateAgent>,
    name: &str,
    desired: &crate::UpdateAgent,
    matches: impl Fn(&crate::UpdateAgent) -> bool,
) -> Result<(), StatusCode> {
    match agents.create(&PostParams::default(), desired).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(error)) if error.code == 409 => {
            let existing = agents
                .get(name)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            accept_existing_agent(agents, name, desired, &existing, &matches).await
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Accept an idempotent retry or atomically complete one operator-reserved identity, but never
/// create. Keeping this separate lets the enrollment transaction inspect an existing name without
/// a create/delete race accidentally turning that path into uncounted inventory growth.
pub(crate) async fn accept_existing_agent(
    agents: &Api<crate::UpdateAgent>,
    name: &str,
    desired: &crate::UpdateAgent,
    existing: &crate::UpdateAgent,
    matches: &impl Fn(&crate::UpdateAgent) -> bool,
) -> Result<(), StatusCode> {
    if matches(existing) {
        // An idempotent re-registration of the same already-enrolled node.
        return Ok(());
    }
    if !adopts_preapproval(existing, desired) {
        return Err(StatusCode::CONFLICT);
    }
    // The operator reserved this exact name for dynamic enrollment — an intentional admission
    // gate — but deferred identity to the node. Stamp ONLY the identity onto the object the
    // operator created, preserving labels, finalizers and all other metadata.
    let mut completed = existing.clone();
    completed.spec.identity = desired.spec.identity.clone();
    match agents
        .replace(name, &PostParams::default(), &completed)
        .await
    {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(conflict)) if conflict.code == 409 => {
            let now = agents
                .get(name)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            if matches(&now) {
                Ok(())
            } else {
                Err(StatusCode::CONFLICT)
            }
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Whether `existing` is a name the operator explicitly RESERVED for dynamic enrollment and this
/// request may therefore complete in place: `kind: reserved`, identity still deferred to the node
/// (hence no `registration_sha256`), in the same repository the node is enrolling into.
///
/// The reservation must be explicit. Authentication for `/enroll` is the fleet-wide bootstrap
/// certificate every node already holds and the name is self-asserted, so any agent this predicate
/// accepts can be claimed — with whatever labels, and therefore whatever group and deployment, the
/// operator attached to it — by whichever fleet member asks first. Accepting a plain `manual` agent
/// would mean the ordinary "declare your inventory" workflow silently produced hijackable names: any
/// one compromised fleet member could POST /enroll with a declared machine's name before that
/// machine is ever built, pin its OWN key, and receive a `CN=<name>` leaf that reads that node's
/// secrets. A `manual` agent is the OFFLINE path — it receives its bundle through
/// `runtime::publish_enrollment_objects`, never through a CSR here — and is never completed here.
/// Any other state — a different repository, or an already-`Enrolled` agent whose registration
/// differs — is a real conflict and is never overwritten, so a node can never seize another node's
/// established identity.
///
/// A manual identity is excluded here precisely because its key is already operator-pinned; it
/// needs no completion and uses the same steady-state authorization as the resulting enrolled
/// identity.
pub(crate) fn adopts_preapproval(
    existing: &crate::UpdateAgent,
    desired: &crate::UpdateAgent,
) -> bool {
    // What a reserved identity LOOKS like (no registration digest, no pinned key) is
    // `AgentIdentity::is_well_formed_for`'s rule, so it is asked rather than restated here. Spelled
    // out a second time, this predicate was a copy of that rule that nothing kept in step: relaxing
    // the shape of a `Reserved` identity in one place would have left the other still admitting the
    // old shape, and this is the predicate that decides who may claim a name over the fleet-wide
    // bootstrap certificate. Its sibling `is_pinned_identity` already gates this way.
    existing.spec.identity.kind == crate::AgentIdentityKind::Reserved
        && existing
            .spec
            .identity
            .is_well_formed_for(&existing.name_any())
        && existing.spec.repository_ref.name == desired.spec.repository_ref.name
}
