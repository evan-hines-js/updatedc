//! `/enroll` and `/renew`. Enrollment is serialised fleet-wide by a Lease so two nodes cannot
//! claim one name concurrently, and it is the only route reachable with the shared bootstrap
//! identity — every other route requires the per-node identity minted here.

use super::*;

pub(crate) async fn enroll(
    State(state): State<DataState>,
    Extension(identity): Extension<ClientIdentity>,
    Extension(materials): Extension<Arc<GatewayMaterials>>,
    body: Bytes,
) -> Response {
    // The listener trusts the fleet CA for both the shared bootstrap certificate and minted
    // per-node leaves. Authentication alone is therefore insufficient here: require the exact
    // configured bootstrap identity so a compromised steady-state node cannot mint Sybil nodes.
    if !is_enrollment_identity(&identity, &state.enrollment_client_cn) {
        return StatusCode::FORBIDDEN.into_response();
    }
    // The node self-asserts its name in the body. The repository's enrollment mode decides below
    // whether an absent name may become inventory or must already be operator-reserved.
    let Ok(request) =
        serde_json::from_slice::<updated_contracts::enrollment::EnrollmentRequest>(&body)
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !is_distinct_from_bootstrap_identity(request.name.as_str(), &state.enrollment_client_cn) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let name = request.name.as_str();
    // The transaction derives both durable identity bindings from this name and CSR itself. Its
    // API cannot be called with one key in the object and another key in the certificate.
    match register_enrollment(&state, &materials.issuing_ca, name, &request.csr).await {
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
    !enrollment_client_cn.is_empty() && identity.enrollment_name() == Some(enrollment_client_cn)
}

pub(crate) fn is_distinct_from_bootstrap_identity(name: &str, enrollment_client_cn: &str) -> bool {
    !enrollment_client_cn.is_empty() && name != enrollment_client_cn
}

pub(crate) async fn renew(
    State(state): State<DataState>,
    Extension(identity): Extension<ClientIdentity>,
    Extension(materials): Extension<Arc<GatewayMaterials>>,
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
    if !agent_authorizes_key(
        &authorized.agent,
        &state.enrollment.repository,
        &authorized.node,
        &public_key.to_hex(),
    ) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match materials.issuing_ca.sign_client_csr(
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

/// The one identity an enrollment transaction may admit and issue credentials for. Carrying the
/// four bound values as one claim makes it impossible for admission, 409 recovery, post-lock
/// revalidation, and certificate signing to select their own subtly different identity inputs.
#[derive(Clone, Copy)]
struct EnrollmentClaim<'a> {
    name: &'a str,
    repository: &'a str,
    public_key: &'a str,
    registration_sha256: &'a str,
}

impl EnrollmentClaim<'_> {
    fn matches(self, agent: &crate::UpdateAgent) -> bool {
        agent_authorizes_key(agent, self.repository, self.name, self.public_key)
            && agent.spec.identity.registration_sha256.as_deref() == Some(self.registration_sha256)
    }

    fn desired(self, labels: std::collections::BTreeMap<String, String>) -> crate::UpdateAgent {
        crate::UpdateAgent::new(
            self.name,
            crate::UpdateAgentSpec {
                repository_ref: crate::LocalObjectReference {
                    name: self.repository.into(),
                },
                identity: crate::AgentIdentity {
                    kind: crate::AgentIdentityKind::Enrolled,
                    registration_sha256: Some(self.registration_sha256.into()),
                    public_key: Some(self.public_key.into()),
                },
                hold: false,
                cordon: false,
                labels,
                backend_address: None,
            },
        )
    }
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
    issuing_ca: &crate::join::IssuingCa,
    name: &str,
    csr: &str,
) -> Result<(updated_contracts::dataflow::DownloadCapability, String), Response> {
    // A malformed CSR is the caller's fault (400), and is rejected before taking the fleet-wide
    // admission lock. The public key pinned in the object and the CSR signed below are now one
    // input, not independently supplied values that could drift.
    let public_key = crate::join::csr_public_key(csr)
        .map_err(|_| StatusCode::BAD_REQUEST.into_response())?
        .to_hex();
    // Enrollment gives this field exactly one meaning: the canonical digest of the validated node
    // name. Derive it here at the only object-construction boundary.
    let registration_sha256 = updated_contracts::telemetry::node_object_digest(name);
    let context = &state.enrollment;
    let claim = EnrollmentClaim {
        name,
        repository: &context.repository,
        public_key: &public_key,
        registration_sha256: &registration_sha256,
    };
    let authority = IdentityAuthority::from(context);
    let agents: Api<crate::UpdateAgent> =
        Api::namespaced(context.client.clone(), &context.namespace);
    // The status count used here previously was an asynchronous observation: every request in one
    // burst could read 9,999 and then create, overshooting without bound. Serialize the LIVE list
    // and create through one pre-created Lease. Existing identities and reservations do not grow
    // the inventory, so they remain completable when the fleet is full.
    let lock = acquire_enrollment_lock(context).await.map_err(|error| {
        tracing::error!(%error, "enrollment capacity lock is unavailable");
        StatusCode::SERVICE_UNAVAILABLE.into_response()
    })?;
    let registration = timeout(ENROLLMENT_TRANSACTION_TIMEOUT, async {
        // Read the policy only after owning the enrollment lock. An operator may switch modes or
        // labels while a request waits; the create/completion decision must use one live
        // repository generation rather than a pre-lock snapshot.
        let repository = live_repository(&authority).await?;
        let desired = claim.desired(repository.spec.enrollment.labels.clone());
        // Idempotent re-enrollment must be the SAME pinned identity (via the one shared predicate,
        // so it cannot drift from renewal) AND the same registration digest. A different key
        // conflicts before any `CN=<name>` leaf can be minted; a genuine retry reuses its key.
        let existing = agents
            .get_opt(claim.name)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        if let Some(existing) = existing {
            return accept_existing_agent(&agents, &desired, &existing, claim).await;
        }
        if repository.spec.enrollment.mode == crate::EnrollmentMode::ReservedOnly {
            tracing::warn!(
                node = %name,
                repository = %context.repository,
                "refusing enrollment for a name that is not reserved"
            );
            return Err(StatusCode::FORBIDDEN);
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
        create_agent_idempotent(&agents, &desired, claim).await
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
        .get(claim.name)
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE.into_response())?;
    // The Lease serialized admission and inventory growth, but an operator does not participate in
    // that lock and may replace this name after it is released. Authorize the SAME live snapshot
    // whose status pointer is about to reach the bearer-capability signer. A different repository,
    // key, or registration is a conflict, never an invitation to hand the replacement's enrollment
    // object to the request that was validated against its predecessor.
    if !claim.matches(&agent) {
        return Err(StatusCode::CONFLICT.into_response());
    }
    let bundle_download = enrollment_download_capability(&state.content, &agent)
        .await
        .map_err(|status| status.into_response())?;
    let leaf = issuing_ca
        .sign_client_csr(claim.repository, claim.name, csr)
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

/// Create `desired`, treating a 409 as success iff the existing agent matches the claim
/// (an idempotent re-registration); a 409 whose existing agent does not match is a real `CONFLICT`,
/// and any other API error is `500`.
async fn create_agent_idempotent(
    agents: &Api<crate::UpdateAgent>,
    desired: &crate::UpdateAgent,
    claim: EnrollmentClaim<'_>,
) -> Result<(), StatusCode> {
    match agents.create(&PostParams::default(), desired).await {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(error)) if error.code == 409 => {
            let existing = agents
                .get(claim.name)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            accept_existing_agent(agents, desired, &existing, claim).await
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Accept an idempotent retry or atomically complete one operator-reserved identity, but never
/// create. Keeping this separate lets the enrollment transaction inspect an existing name without
/// a create/delete race accidentally turning that path into uncounted inventory growth.
async fn accept_existing_agent(
    agents: &Api<crate::UpdateAgent>,
    desired: &crate::UpdateAgent,
    existing: &crate::UpdateAgent,
    claim: EnrollmentClaim<'_>,
) -> Result<(), StatusCode> {
    if claim.matches(existing) {
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
        .replace(claim.name, &PostParams::default(), &completed)
        .await
    {
        Ok(_) => Ok(()),
        Err(kube::Error::Api(conflict)) if conflict.code == 409 => {
            let now = agents
                .get(claim.name)
                .await
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            if claim.matches(&now) {
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
    // Admission and steady-state authority share the live object and identity-shape rules.
    existing.spec.identity.kind == crate::AgentIdentityKind::Reserved
        && desired.metadata.name.as_deref().is_some_and(|node| {
            agent_has_live_identity(existing, &desired.spec.repository_ref.name, node)
        })
}
