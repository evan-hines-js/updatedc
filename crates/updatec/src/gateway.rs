//! Read-only HTTP data plane for repositories published by `updatec`.
//!
//! The transport is Axum over hyper, one `Router` per listener role, but the TLS accept loops stay
//! ours (`tokio-rustls`) so the crypto provider remains aws-lc-rs and the mTLS client-certificate
//! requirement is enforced at the handshake exactly as before. Two listeners:
//!
//! * **data** (mTLS, client cert required): repository content, `/enroll` (the shared fleet
//!   enrollment cert authenticates it), telemetry `PUT`.
//! * **health** (plaintext): `/healthz` only, for orchestrator probes that cannot present a cert.
//!
//! Each listener is a different `Router`, so a route it must not expose simply is not mounted.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, FromRef, OriginalUri, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Extension, Json, Router};
use futures::StreamExt;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use k8s_openapi::api::core::v1::Secret;
use kube::api::{Api, PostParams};
use kube::Client;
use object_store::path::Path as ObjectPath;
use object_store::{GetOptions, GetRange, ObjectStore, PutPayload};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tower_http::timeout::TimeoutLayer;

/// Bound on a single blocking store operation (a `head`/`get`/`put`) — not the whole streamed
/// response body, which hyper backpressures. A hung backend must not pin a connection forever.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// Upper bound on a request body. Contract bodies (enrollment request, node report) are tiny; this
/// only bounds a hostile or broken client, never a legitimate one.
const BODY_LIMIT: usize = 64 * 1024;

/// Max concurrent connections on the authenticated data listener.
const DATA_CONNECTIONS: usize = 256;
/// The plaintext health listener is unauthenticated; bound it so a slow-loris there cannot exhaust
/// process file descriptors and starve the mTLS data listener's `accept` calls.
const HEALTH_CONNECTIONS: usize = 64;

/// The verified per-connection client identity: the Common Name of the mTLS leaf that rustls has
/// already validated against the fleet CA before any handler runs. `None` on a connection with no
/// client certificate (the health listener) or a leaf carrying no CN. The node cannot forge
/// this — it is read from the CA-signed certificate, not from anything the node puts in the request
/// — so it is the trusted answer to "who is this?" that per-node authorization checks against.
#[derive(Clone, Debug)]
struct ClientIdentity(Option<String>);

/// Extract the leaf certificate's Common Name from a completed server-side TLS connection.
fn peer_common_name(conn: &tokio_rustls::rustls::ServerConnection) -> Option<String> {
    let leaf = conn.peer_certificates()?.first()?;
    let (_, cert) = x509_parser::parse_x509_certificate(leaf.as_ref()).ok()?;
    let cn = cert.subject().iter_common_name().next()?.as_str().ok()?;
    Some(cn.to_owned())
}

#[derive(Clone)]
pub struct EnrollmentContext {
    pub client: Client,
    pub namespace: String,
    pub repository: String,
    pub public_url: String,
}

/// The gateway's server TLS material, mounted from a cert-manager-issued secret. The gateway
/// presents `cert`/`key` and admits a connection only if the client presents a certificate the
/// fleet `client_ca` signed — that mutual TLS *is* the enrollment authentication.
pub struct GatewayTls {
    pub cert: std::path::PathBuf,
    pub key: std::path::PathBuf,
    pub client_ca: std::path::PathBuf,
}

/// The two TCP addresses the gateway binds: the mTLS data listener and the plaintext health listener.
pub struct GatewayAddresses {
    pub data: String,
    pub health: String,
}

/// Store + prefix — everything the repository and telemetry handlers need. The data router derives
/// it (via [`FromRef`]), so those handlers require no Kubernetes context and stay trivially testable.
#[derive(Clone)]
struct ContentState {
    store: Arc<dyn ObjectStore>,
    prefix: Arc<str>,
}

impl ContentState {
    fn store(&self) -> &dyn ObjectStore {
        self.store.as_ref()
    }
    fn prefix(&self) -> &str {
        &self.prefix
    }
}

#[derive(Clone)]
struct DataState {
    content: ContentState,
    enrollment: EnrollmentContext,
    /// The fleet CA that signs per-node leaves at `/enroll`.
    ca: Arc<crate::join::IssuingCa>,
}

#[async_trait::async_trait]
trait SecretStore: Send + Sync {
    async fn value(&self, name: &str, key: &str) -> Result<Vec<u8>, ()>;
}

#[derive(Clone)]
struct KubernetesSecretStore {
    client: Client,
    namespace: String,
}

#[async_trait::async_trait]
impl SecretStore for KubernetesSecretStore {
    async fn value(&self, name: &str, key: &str) -> Result<Vec<u8>, ()> {
        let secret = Api::<Secret>::namespaced(self.client.clone(), &self.namespace)
            .get(name)
            .await
            .map_err(|_| ())?;
        secret
            .data
            .and_then(|data| data.get(key).cloned())
            .map(|value| value.0)
            .ok_or(())
    }
}

impl FromRef<DataState> for ContentState {
    fn from_ref(state: &DataState) -> Self {
        state.content.clone()
    }
}

fn data_router(state: DataState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/enroll", post(enroll))
        .route("/telemetry/{file}", put(telemetry_put))
        .route("/v1/node/secrets", get(node_secrets))
        .route("/metadata/{*rest}", get(repo_get).head(repo_get))
        .route("/targets/{*rest}", get(repo_get).head(repo_get))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        // Bound the whole request (header parse is already bounded by the connection's
        // header_read_timeout; this covers a slow-drip body read and any handler stall). Streaming
        // repository responses are unaffected — the handler returns the Body before this fires; the
        // stream itself is bounded per-chunk in `repo_get`.
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            IO_TIMEOUT,
        ))
        .with_state(state)
}

#[derive(Serialize)]
struct SecretBundle {
    deployment: String,
    generation: String,
    values: std::collections::BTreeMap<String, String>,
}

#[derive(Debug)]
enum SecretBundleError {
    Unavailable,
    Invalid,
}

async fn resolve_secret_bundle(
    assignment: &updated::config::RepositoryAssignment,
    store: &dyn SecretStore,
) -> Result<SecretBundle, SecretBundleError> {
    const MAX_SECRET_BYTES: usize = 64 * 1024;
    const MAX_BUNDLE_BYTES: usize = 1024 * 1024;

    let mut values = std::collections::BTreeMap::new();
    let mut digest = Sha256::new();
    let mut total = 0usize;
    digest.update(assignment.deployment.as_bytes());
    for reference in &assignment.runtime.secrets {
        let bytes = store
            .value(&reference.secret, &reference.key)
            .await
            .map_err(|()| SecretBundleError::Unavailable)?;
        total = total.saturating_add(bytes.len());
        if bytes.len() > MAX_SECRET_BYTES || total > MAX_BUNDLE_BYTES {
            return Err(SecretBundleError::Invalid);
        }
        let value = String::from_utf8(bytes).map_err(|_| SecretBundleError::Invalid)?;
        if value.contains('\0') {
            return Err(SecretBundleError::Invalid);
        }
        digest.update(reference.environment.as_bytes());
        digest.update([0]);
        digest.update(value.as_bytes());
        digest.update([0]);
        values.insert(reference.environment.clone(), value);
    }
    Ok(SecretBundle {
        deployment: assignment.deployment.clone(),
        generation: hex::encode(digest.finalize()),
        values,
    })
}

/// Return exactly the secrets declared by the authenticated node's active signed assignment.
/// The request contains no secret names: authorization is derived entirely from the verified
/// certificate identity and the control plane's current assignment.
async fn node_secrets(
    State(state): State<DataState>,
    Extension(identity): Extension<ClientIdentity>,
) -> Response {
    let Some(node) = identity.0 else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let repositories: Api<crate::UpdateRepository> =
        Api::namespaced(state.enrollment.client.clone(), &state.enrollment.namespace);
    let Ok(repository) = repositories.get(&state.enrollment.repository).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let assignment = agent_assignment(&repository.spec.assignment_prefix, &node);
    let signed =
        match resolve_signed_enrollment(state.content.store(), state.content.prefix(), &assignment)
            .await
        {
            Ok(signed) => signed,
            Err(error) => return error.status_code().into_response(),
        };
    let assignment: updated::config::RepositoryAssignment =
        match serde_json::from_str(&signed.managed_configuration) {
            Ok(assignment) => assignment,
            Err(_) => return StatusCode::BAD_GATEWAY.into_response(),
        };
    if assignment.validate().is_err() {
        return StatusCode::BAD_GATEWAY.into_response();
    }
    let store = KubernetesSecretStore {
        client: state.enrollment.client.clone(),
        namespace: state.enrollment.namespace.clone(),
    };
    let bundle = match resolve_secret_bundle(&assignment, &store).await {
        Ok(bundle) => bundle,
        Err(SecretBundleError::Unavailable) => {
            return StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
        Err(SecretBundleError::Invalid) => return StatusCode::BAD_GATEWAY.into_response(),
    };
    let mut response = Json(bundle).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        header::HeaderValue::from_static("no-store"),
    );
    response
        .headers_mut()
        .insert(header::PRAGMA, header::HeaderValue::from_static("no-cache"));
    response
}

/// The plaintext health router: `/healthz` (and `/`) → 200, everything else 404. It serves no
/// repository content, so exposing it without mTLS reveals nothing — it exists only for the
/// orchestrator's probes, which cannot present a client certificate.
fn health_router() -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/", get(healthz))
}

pub async fn serve(
    addresses: GatewayAddresses,
    store: Arc<dyn ObjectStore>,
    prefix: String,
    enrollment: EnrollmentContext,
    ca: Arc<crate::join::IssuingCa>,
    tls: GatewayTls,
) -> std::io::Result<()> {
    let acceptor = TlsAcceptor::from(Arc::new(updated::tls::server_config(
        &tls.cert,
        &tls.key,
        &tls.client_ca,
    )?));

    let data_listener = TcpListener::bind(&addresses.data).await?;
    let health_listener = TcpListener::bind(&addresses.health).await?;
    tracing::info!(
        data = %addresses.data, health = %addresses.health,
        "repository gateway listening (mTLS data + plaintext health)"
    );

    let content = ContentState {
        store,
        prefix: Arc::from(prefix),
    };
    // Enrollment is a route on the one mTLS data listener now: the shared fleet enrollment cert
    // authenticates it, so there is no separate client-cert-less listener.
    let data_router = data_router(DataState {
        content,
        enrollment,
        ca,
    });

    // Health: plaintext, no TLS, its own small connection budget.
    tokio::spawn(serve_plain(
        health_listener,
        health_router(),
        Arc::new(Semaphore::new(HEALTH_CONNECTIONS)),
    ));
    // Data: mTLS, runs on this task so `serve` stays alive for the whole process.
    serve_tls(
        data_listener,
        acceptor,
        data_router,
        Arc::new(Semaphore::new(DATA_CONNECTIONS)),
        "data",
    )
    .await;
    Ok(())
}

/// Accept TLS connections and serve `app` on each. A transient `accept` error logs and continues —
/// never tears the listener down (that would crash-loop the gateway precisely when it is
/// resource-starved). A client that fails the handshake never reaches a handler.
async fn serve_tls(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    app: Router,
    budget: Arc<Semaphore>,
    label: &'static str,
) {
    loop {
        let (tcp, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(error) => {
                tracing::warn!(%error, listener = label, "gateway accept failed");
                continue;
            }
        };
        let Ok(permit) = budget.clone().acquire_owned().await else {
            return;
        };
        let acceptor = acceptor.clone();
        let app = app.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let tls = match acceptor.accept(tcp).await {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::debug!(%peer, %error, listener = label, "rejected client at the TLS handshake");
                    return;
                }
            };
            // Bind the CA-verified client identity to every request on this connection, so a
            // per-node authorization check (e.g. telemetry) reads the trusted cert CN rather than
            // the node's self-claimed path. `None` on the client-cert-less join/health listeners.
            let identity = ClientIdentity(peer_common_name(tls.get_ref().1));
            let app = app.layer(Extension(identity));
            serve_http(TokioIo::new(tls), app).await;
        });
    }
}

/// The plaintext accept loop (health only), bounded by its own connection budget.
async fn serve_plain(listener: TcpListener, app: Router, budget: Arc<Semaphore>) {
    loop {
        match listener.accept().await {
            Ok((tcp, _)) => {
                let Ok(permit) = budget.clone().acquire_owned().await else {
                    return;
                };
                let app = app.clone();
                tokio::spawn(async move {
                    let _permit = permit;
                    serve_http(TokioIo::new(tcp), app).await;
                });
            }
            Err(error) => tracing::warn!(%error, "gateway health accept failed"),
        }
    }
}

/// Serve one connection's requests with hyper, dispatching into the Axum `Router`. HTTP/1 only —
/// matching the original hand-rolled server and, deliberately, refusing the HTTP/2 prior-knowledge
/// path (the TLS configs advertise no h2 ALPN), so there is no h2 frame-read phase left unbounded.
/// `header_read_timeout` bounds the request-line/header phase so a client that completes the
/// handshake and then trickles (or withholds) its headers cannot pin the connection — and thus its
/// budget permit — indefinitely (slow-loris).
async fn serve_http<I>(io: I, app: Router)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let service = TowerToHyperService::new(app);
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(IO_TIMEOUT);
    if let Err(error) = builder.serve_connection(io, service).await {
        tracing::debug!(%error, "gateway connection error");
    }
}

async fn healthz() -> &'static str {
    "ok"
}

async fn enroll(State(state): State<DataState>, body: Bytes) -> Response {
    // Authentication already happened at the mTLS handshake: this connection exists only because the
    // client presented the shared fleet enrollment certificate the fleet CA signed. There is no
    // bearer secret; the node self-asserts its name in the body, and an approval gate on the
    // resulting UpdateAgent is the place to require a human to authorize that name.
    let Ok(request) = serde_json::from_slice::<updated::enrollment::EnrollmentRequest>(&body)
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !request.name_is_wellformed() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let name = request.name.as_str();
    // A stable per-node identifier for idempotent re-enrollment, derived from the self-asserted name:
    // the same node coming back on the same name is the same UpdateAgent.
    let registration_sha256 = sha256(name.as_bytes());
    let context = &state.enrollment;
    let matches = |existing: &crate::UpdateAgent| {
        existing.spec.identity.kind == crate::AgentIdentityKind::Enrolled
            && existing.spec.identity.registration_sha256.as_deref()
                == Some(registration_sha256.as_str())
            && existing.spec.repository_ref.name == context.repository
    };
    // Pin the CSR's public key so the throttle can later verify this node's signed telemetry, then
    // sign the CSR into a per-node leaf (CN=<name>). The CP certifies only the CSR's public key; a
    // malformed CSR is the caller's fault (400). `register_agent` runs `sign` only after the
    // create/conflict check passes, so a conflicting name never mints a certificate.
    let Ok(public_key) = crate::join::csr_public_key(&request.csr) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let sign = || {
        state
            .ca
            .sign_client_csr(&context.repository, name, &request.csr)
            .map_err(|_| StatusCode::BAD_REQUEST)
    };
    match register_agent(
        context,
        state.content.store(),
        state.content.prefix(),
        name,
        registration_sha256.clone(),
        Some(hex::encode(public_key)),
        // Enrollment stamps the repository's trusted enrollment labels.
        |repository| repository.spec.enrollment.labels.clone(),
        matches,
        sign,
    )
    .await
    {
        Ok((bundle, leaf)) => Json(updated::enrollment::EnrollResponse {
            leaf,
            chain: String::new(),
            bundle,
        })
        .into_response(),
        Err(response) => response,
    }
}

/// The registration flow shared by `/enroll` and `/join`: resolve the `UpdateRepository`, create
/// this agent's `UpdateAgent` idempotently (treating a matching existing agent as success via
/// `matches`), run `after_create` — the point at which `/join` mints the node certificate, so a
/// conflicting registration never yields a leaf — and resolve the signed enrollment bundle the
/// agent pins. `labels` builds the agent's control-plane labels from the resolved repository
/// (mount enrollment uses the repository's labels directly; join adds the group-membership label).
/// Returns the assembled bundle alongside whatever `after_create` produced (`()` for `/enroll`, the
/// signed leaf for `/join`).
#[allow(clippy::too_many_arguments)]
async fn register_agent<T>(
    context: &EnrollmentContext,
    store: &dyn ObjectStore,
    prefix: &str,
    name: &str,
    registration_sha256: String,
    public_key: Option<String>,
    labels: impl FnOnce(&crate::UpdateRepository) -> std::collections::BTreeMap<String, String>,
    matches: impl Fn(&crate::UpdateAgent) -> bool,
    after_create: impl FnOnce() -> Result<T, StatusCode>,
) -> Result<(crate::EnrollmentBundle, T), Response> {
    let repositories: Api<crate::UpdateRepository> =
        Api::namespaced(context.client.clone(), &context.namespace);
    let Ok(repository) = repositories.get(&context.repository).await else {
        return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
    };
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
                registration_sha256: Some(registration_sha256),
                public_key,
            },
            labels: labels(&repository),
        },
    );
    if let Err(status) = create_agent_idempotent(&agents, name, &desired, matches).await {
        return Err(status.into_response());
    }
    let extra = after_create().map_err(IntoResponse::into_response)?;
    let assignment = agent_assignment(&repository.spec.assignment_prefix, name);
    // The consistent-snapshot metadata walk is shared with the operator's enrollment-Secret
    // publisher so this security-sensitive resolution lives in exactly one place. A newly
    // registered agent can legitimately race publication: an object that is not there yet is
    // `Unavailable` (503, retry), while a present-but-malformed document is `Malformed` (502).
    let signed = match resolve_signed_enrollment(store, prefix, &assignment).await {
        Ok(signed) => signed,
        Err(error) => return Err(error.status_code().into_response()),
    };
    let bundle = signed.into_bundle(name.to_string(), &context.public_url, assignment);
    Ok((bundle, extra))
}

/// Create `desired` (named `name`), treating a 409 as success iff the existing agent `matches`
/// (an idempotent re-registration); a 409 whose existing agent does not match is a real `CONFLICT`,
/// and any other API error is `500`. Shared by `/enroll` and `/join`, which differ only in the
/// `matches` predicate.
async fn create_agent_idempotent(
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
            if matches(&existing) {
                // An idempotent re-registration of the same already-enrolled node.
                Ok(())
            } else if adopts_preapproval(&existing, desired) {
                // The operator pre-approved this exact name as a `manual` agent — an intentional
                // admission gate — but deferred identity to the node. The node has now presented its
                // CSR over the shared fleet cert, so complete the pre-approval in place: stamp ONLY
                // the identity (pinned public key + registration, flipped to `Enrolled`) onto the
                // object the operator created, preserving the labels/finalizers/metadata it set —
                // the operator's labels drive group membership, so enrollment must not rewrite them.
                // `replace` carries the fetched `resourceVersion`, so concurrent completions leave
                // exactly one winner; the loser re-reads and, if the name is now a settled match,
                // accepts (its own leaf is still minted in the caller's `after_create`, so a write
                // that never lands never yields a cert).
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
            } else {
                Err(StatusCode::CONFLICT)
            }
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// Whether `existing` is an operator pre-approval this enrollment may complete in place: a `manual`
/// agent (admission-gated by the operator, with identity deferred to the node — hence no
/// `registration_sha256`) bound to the same repository the node is enrolling into. Any other state —
/// a different repository, or an already-`Enrolled` agent whose registration differs — is a real
/// conflict and is never overwritten, so a node can never seize another node's established identity.
fn adopts_preapproval(existing: &crate::UpdateAgent, desired: &crate::UpdateAgent) -> bool {
    existing.spec.identity.kind == crate::AgentIdentityKind::Manual
        && existing.spec.identity.registration_sha256.is_none()
        && existing.spec.repository_ref.name == desired.spec.repository_ref.name
}

/// The routing assignment target path for an agent: `<prefix>/agents/<name>.json`.
pub(crate) fn agent_assignment(assignment_prefix: &str, name: &str) -> String {
    format!("{}/agents/{name}.json", assignment_prefix.trim_matches('/'))
}

/// Store a node's running-state report at `<prefix>/telemetry/<node>.json`. The report must be
/// well-formed and name the same node as the path — a report can only release a rollout throttle
/// slot, so a malformed or misattributed one is rejected, not stored.
///
/// Trust model: authenticated AND authorized per node. Steady-state traffic carries the minted
/// per-node client certificate (its `CN` is the agent name; see `updated::enrollment`), so the
/// mTLS leaf identity rustls verified is bound against the `node` in the path below: a node may
/// write ONLY its own report. Without that check any fleet member could forge another node's
/// settled/healthy report and drive its rollout past unhealthy peers, defeating the throttle.
async fn telemetry_put(
    State(state): State<ContentState>,
    Extension(identity): Extension<ClientIdentity>,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> Response {
    let Some(node) = updated::telemetry::node_from_path(uri.path()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // Per-node authorization: the mTLS leaf CN rustls verified is the trusted identity; the path
    // node is the caller's claim. A node may write ONLY its own report — otherwise any fleet member
    // could forge another node's healthy/settled report and drive its rollout past unhealthy peers.
    if identity.0.as_deref() != Some(node) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(report) = serde_json::from_slice::<updated::telemetry::NodeReport>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if report.node != node {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let key = crate::object_key(state.prefix(), &updated::telemetry::report_object_key(node));
    match timeout(
        IO_TIMEOUT,
        state
            .store()
            .put(&key, PutPayload::from_bytes(body.to_vec().into())),
    )
    .await
    {
        Ok(Ok(_)) => StatusCode::OK.into_response(),
        Ok(Err(_)) => StatusCode::BAD_GATEWAY.into_response(),
        Err(_) => StatusCode::GATEWAY_TIMEOUT.into_response(),
    }
}

/// Serve a TUF metadata/target object from the store, with `Range`, `ETag`, and `HEAD` support.
async fn repo_get(
    State(state): State<ContentState>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Response {
    // Repository objects are content-addressed and take no query parameters; a query string is a
    // signed-URL-style request we do not serve.
    if uri.query().is_some() {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(key) = repository_key(state.prefix(), uri.path()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let range = match parse_range(&headers) {
        Ok(range) => range,
        Err(()) => return StatusCode::BAD_REQUEST.into_response(),
    };
    if let Some(range) = &range {
        let metadata = match timeout(IO_TIMEOUT, state.store().head(&key)).await {
            Err(_) => return StatusCode::GATEWAY_TIMEOUT.into_response(),
            Ok(Err(object_store::Error::NotFound { .. })) => {
                return StatusCode::NOT_FOUND.into_response()
            }
            Ok(Err(_)) => return StatusCode::BAD_GATEWAY.into_response(),
            Ok(Ok(metadata)) => metadata,
        };
        // `as_range` rejects a start at or beyond EOF (and an inconsistent bound); a suffix that
        // overshoots the object is clamped, not an error.
        if range.as_range(metadata.size).is_err() {
            return range_not_satisfiable(metadata.size);
        }
    }
    let partial = range.is_some();
    let options = GetOptions {
        range: range.clone(),
        head: method == Method::HEAD,
        ..Default::default()
    };
    let result = match timeout(IO_TIMEOUT, state.store().get_opts(&key, options)).await {
        Err(_) => return StatusCode::GATEWAY_TIMEOUT.into_response(),
        Ok(Err(object_store::Error::NotFound { .. })) => {
            return StatusCode::NOT_FOUND.into_response()
        }
        Ok(Err(_)) => return StatusCode::BAD_GATEWAY.into_response(),
        Ok(Ok(result)) => result,
    };
    let length = result.range.end.saturating_sub(result.range.start);
    let mut builder = Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, length)
        .header(header::ACCEPT_RANGES, "bytes");
    let status = if partial {
        builder = builder.header(
            header::CONTENT_RANGE,
            format!(
                "bytes {}-{}/{}",
                result.range.start,
                result.range.end.saturating_sub(1),
                result.meta.size
            ),
        );
        StatusCode::PARTIAL_CONTENT
    } else {
        StatusCode::OK
    };
    // A backend ETag that is not a valid header value is skipped, not fatal — the object is still
    // served (the original wrote it into a raw response line; here an invalid value would otherwise
    // fail response construction and 500 the whole fetch).
    if let Some(etag) = result
        .meta
        .e_tag
        .as_deref()
        .and_then(safe_etag)
        .and_then(|etag| header::HeaderValue::from_str(etag).ok())
    {
        builder = builder.header(header::ETAG, etag);
    }
    let body = if method == Method::HEAD {
        Body::empty()
    } else {
        // Bound each streamed chunk: a backend that returns headers fast then stalls mid-body must
        // not pin the connection (and its budget permit) forever. Restores the original per-chunk
        // 30s bound the hand-rolled writer had.
        Body::from_stream(timed_object_stream(result.into_stream()))
    };
    builder
        .status(status)
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Wrap an object stream so each chunk is bounded by [`IO_TIMEOUT`]. On a stall it yields a final
/// error item and ends the stream (hyper aborts the connection), rather than blocking indefinitely.
fn timed_object_stream<S>(stream: S) -> impl futures::Stream<Item = Result<Bytes, std::io::Error>>
where
    S: futures::Stream<Item = object_store::Result<Bytes>> + Unpin + Send + 'static,
{
    futures::stream::unfold(Some(stream), |state| async move {
        let mut stream = state?;
        match timeout(IO_TIMEOUT, stream.next()).await {
            Ok(Some(item)) => Some((item.map_err(std::io::Error::other), Some(stream))),
            Ok(None) => None,
            Err(_) => Some((
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "object stream timeout",
                )),
                None,
            )),
        }
    })
}

fn range_not_satisfiable(length: u64) -> Response {
    Response::builder()
        .status(StatusCode::RANGE_NOT_SATISFIABLE)
        .header(header::CONTENT_RANGE, format!("bytes */{length}"))
        .header(header::CONTENT_LENGTH, 0)
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// The signed documents an [`crate::EnrollmentBundle`] pins for one agent, resolved from a
/// published repository's consistent snapshot.
pub(crate) struct SignedEnrollment {
    pub root: String,
    pub timestamp: String,
    pub snapshot: String,
    pub targets: String,
    pub agent_document: String,
    pub managed_configuration: String,
}

impl SignedEnrollment {
    /// Assemble the [`crate::EnrollmentBundle`] a node receives, pairing the resolved signed
    /// documents with the node's `agent_id`, its routing `assignment` path, and the gateway's
    /// `public_url` base. This is the single place the bundle's schema and field mapping are
    /// defined, so the gateway's live `/enroll` and `/join` responses and the operator's published
    /// enrollment Secret cannot drift apart.
    pub(crate) fn into_bundle(
        self,
        agent_id: String,
        public_url: &str,
        assignment: String,
    ) -> crate::EnrollmentBundle {
        crate::EnrollmentBundle {
            schema: 1,
            agent_id,
            routing_base_url: format!("{}/", public_url.trim_end_matches('/')),
            assignment,
            routing_root: self.root,
            initial: crate::InitialSignedConfiguration {
                timestamp: self.timestamp,
                snapshot: self.snapshot,
                targets: self.targets,
                agent_document: self.agent_document,
                managed_configuration: self.managed_configuration,
            },
        }
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
    /// The HTTP status a failed resolution maps to, shared by `/enroll` and `/join`: `Unavailable`
    /// is a retryable 503 (the object races publication), `Malformed` is a 502 (a published
    /// document is broken).
    fn status_code(&self) -> StatusCode {
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
/// `/enroll` handler and `runtime::publish_enrollment_secrets`.
pub(crate) async fn resolve_signed_enrollment(
    store: &dyn ObjectStore,
    prefix: &str,
    assignment: &str,
) -> Result<SignedEnrollment, EnrollmentResolveError> {
    use EnrollmentResolveError::{Malformed, Unavailable};

    let root = object_text(store, prefix, "metadata/root.json")
        .await
        .map_err(|_| Unavailable("root metadata".into()))?;
    let timestamp = object_text(store, prefix, "metadata/timestamp.json")
        .await
        .map_err(|_| Unavailable("timestamp metadata".into()))?;
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
    let parsed: updated::config::AgentDocument = serde_json::from_str(&agent_document)
        .map_err(|_| Malformed(format!("assignment document {assignment}")))?;
    let config_path = parsed.config.path;
    let config_object = consistent_target_object(&targets_value, &config_path)
        .ok_or_else(|| Malformed(format!("managed configuration target {config_path}")))?;
    let managed_configuration = object_text(store, prefix, &config_object)
        .await
        .map_err(|_| Unavailable(format!("managed configuration {config_path}")))?;

    Ok(SignedEnrollment {
        root,
        timestamp,
        snapshot,
        targets,
        agent_document,
        managed_configuration,
    })
}

fn consistent_target_object(targets: &serde_json::Value, logical_path: &str) -> Option<String> {
    let digest = targets
        .get("signed")?
        .get("targets")?
        .get(logical_path)?
        .get("hashes")?
        .get("sha256")?
        .as_str()?;
    if !updated::hash::is_sha256_hex(digest) {
        return None;
    }
    Some(format!("targets/{digest}.{logical_path}"))
}

async fn object_text(
    store: &dyn ObjectStore,
    prefix: &str,
    relative: &str,
) -> Result<String, object_store::Error> {
    let key = crate::object_key(prefix, relative);
    let bytes = store.get(&key).await?.bytes().await?;
    String::from_utf8(bytes.to_vec()).map_err(|error| object_store::Error::Generic {
        store: "enrollment",
        source: Box::new(error),
    })
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn repository_key(prefix: &str, request_path: &str) -> Option<ObjectPath> {
    if request_path.contains(['?', '#', '%', '\\']) || !request_path.starts_with('/') {
        return None;
    }
    let mut parts = request_path[1..].split('/');
    let namespace = parts.next()?;
    if !matches!(namespace, "metadata" | "targets") {
        return None;
    }
    let tail: Vec<_> = parts.collect();
    if tail.is_empty()
        || tail
            .iter()
            .any(|part| part.is_empty() || *part == "." || *part == ".." || part.starts_with('.'))
    {
        return None;
    }
    let key = [prefix.trim_matches('/'), namespace, &tail.join("/")]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("/");
    ObjectPath::parse(key).ok()
}

/// Read the single `Range` header (if any). A duplicate `Range` header, a non-ASCII value, or a
/// malformed range is refused (`Err`), matching the read path's conservative framing.
fn parse_range(headers: &HeaderMap) -> Result<Option<GetRange>, ()> {
    let mut values = headers.get_all(header::RANGE).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    Ok(Some(parse_range_value(value.trim())?))
}

/// Parse a single HTTP byte range: open-ended (`bytes=100-`), bounded (`bytes=0-99`, end
/// inclusive), or suffix (`bytes=-500`, the last N bytes). Multi-range requests and any malformed
/// value are refused (`Err`), matching the read path's conservative framing.
fn parse_range_value(value: &str) -> Result<GetRange, ()> {
    let spec = value.strip_prefix("bytes=").ok_or(())?;
    if spec.contains(',') {
        return Err(());
    }
    let (start, end) = spec.split_once('-').ok_or(())?;
    let range = match (start.trim(), end.trim()) {
        ("", "") => return Err(()),
        // Suffix: the last N bytes. A zero-length suffix is unsatisfiable.
        ("", suffix) => {
            let n: u64 = suffix.parse().map_err(|_| ())?;
            if n == 0 {
                return Err(());
            }
            GetRange::Suffix(n)
        }
        // Open-ended: everything from `start` onward.
        (start, "") => GetRange::Offset(start.parse().map_err(|_| ())?),
        // Bounded: `start`..=`end` inclusive, so the exclusive upper bound is `end + 1`.
        (start, end) => {
            let start: u64 = start.parse().map_err(|_| ())?;
            let end: u64 = end.parse().map_err(|_| ())?;
            if end < start {
                return Err(());
            }
            GetRange::Bounded(start..end.saturating_add(1))
        }
    };
    Ok(range)
}

fn safe_etag(value: &str) -> Option<&str> {
    (!value.contains(['\r', '\n'])).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use object_store::memory::InMemory;
    use tower::ServiceExt;

    struct MemorySecrets {
        values: std::collections::BTreeMap<(String, String), Vec<u8>>,
        calls: std::sync::Mutex<Vec<(String, String)>>,
    }

    #[async_trait::async_trait]
    impl SecretStore for MemorySecrets {
        async fn value(&self, name: &str, key: &str) -> Result<Vec<u8>, ()> {
            self.calls
                .lock()
                .unwrap()
                .push((name.to_owned(), key.to_owned()));
            self.values
                .get(&(name.to_owned(), key.to_owned()))
                .cloned()
                .ok_or(())
        }
    }

    fn secret_assignment() -> updated::config::RepositoryAssignment {
        let runtime = crate::tests::managed_runtime();
        updated::config::RepositoryAssignment {
            schema: 2,
            deployment: "deployment".into(),
            metadata_url: "https://control/metadata/".into(),
            targets_url: "https://control/targets/".into(),
            report_url: Some("https://control/telemetry/node.json".into()),
            application: updated::config::TargetReference {
                path: "releases/app/1/app.bundle".into(),
                sha256: "a".repeat(64),
            },
            ordered_install_fallback: false,
            provider_set: updated::config::TargetReference {
                path: "provider-sets/default.json".into(),
                sha256: "b".repeat(64),
            },
            release_root: serde_json::json!({}),
            runtime,
        }
    }

    #[tokio::test]
    async fn secret_resolution_reads_only_assignment_authorized_keys() {
        let mut assignment = secret_assignment();
        assignment.runtime.secrets = vec![
            updated::config::SecretReference {
                environment: "DATABASE_PASSWORD".into(),
                secret: "database".into(),
                key: "password".into(),
            },
            updated::config::SecretReference {
                environment: "API_TOKEN".into(),
                secret: "api".into(),
                key: "token".into(),
            },
        ];
        let store = MemorySecrets {
            values: std::collections::BTreeMap::from([
                (("database".into(), "password".into()), b"db-value".to_vec()),
                (("api".into(), "token".into()), b"api-value".to_vec()),
                (
                    ("unassigned".into(), "root".into()),
                    b"must-not-be-read".to_vec(),
                ),
            ]),
            calls: std::sync::Mutex::new(Vec::new()),
        };
        let bundle = resolve_secret_bundle(&assignment, &store).await.unwrap();
        assert_eq!(bundle.values.get("DATABASE_PASSWORD").unwrap(), "db-value");
        assert_eq!(bundle.values.get("API_TOKEN").unwrap(), "api-value");
        assert_eq!(
            *store.calls.lock().unwrap(),
            vec![
                ("database".into(), "password".into()),
                ("api".into(), "token".into())
            ]
        );
        assert!(!serde_json::to_string(&bundle.values)
            .unwrap()
            .contains("must-not-be-read"));
    }

    #[tokio::test]
    async fn secret_resolution_fails_closed_on_missing_invalid_or_oversized_values() {
        let mut assignment = secret_assignment();
        assignment.runtime.secrets = vec![updated::config::SecretReference {
            environment: "TOKEN".into(),
            secret: "secret".into(),
            key: "key".into(),
        }];
        for value in [None, Some(vec![0xff]), Some(vec![b'x'; 64 * 1024 + 1])] {
            let store = MemorySecrets {
                values: value
                    .map(|value| {
                        std::collections::BTreeMap::from([(("secret".into(), "key".into()), value)])
                    })
                    .unwrap_or_default(),
                calls: std::sync::Mutex::new(Vec::new()),
            };
            assert!(resolve_secret_bundle(&assignment, &store).await.is_err());
        }
    }

    /// A content-only router (repository + telemetry) over an in-memory store at prefix `routing`.
    /// The repository and telemetry handlers need no Kubernetes context, so this needs no client.
    fn router(store: Arc<InMemory>) -> Router {
        // `axum::routing::get` is fully qualified here because this test module also defines a
        // request-building helper named `get`.
        Router::new()
            .route("/telemetry/{file}", axum::routing::put(telemetry_put))
            .route(
                "/metadata/{*rest}",
                axum::routing::get(repo_get).head(repo_get),
            )
            .route(
                "/targets/{*rest}",
                axum::routing::get(repo_get).head(repo_get),
            )
            .layer(DefaultBodyLimit::max(BODY_LIMIT))
            .with_state(ContentState {
                store,
                prefix: Arc::from("routing"),
            })
    }

    async fn seeded() -> Arc<InMemory> {
        let store = Arc::new(InMemory::new());
        store
            .put(
                &ObjectPath::from("routing/targets/nested/app"),
                PutPayload::from_static(b"hello"),
            )
            .await
            .unwrap();
        store
    }

    async fn send(
        store: Arc<InMemory>,
        request: Request<Body>,
    ) -> (StatusCode, HeaderMap, Vec<u8>) {
        let response = router(store).oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec();
        (status, headers, body)
    }

    fn get(path: &str, range: Option<&str>) -> Request<Body> {
        let mut builder = Request::builder().method("GET").uri(path);
        if let Some(range) = range {
            builder = builder.header("range", range);
        }
        builder.body(Body::empty()).unwrap()
    }

    #[test]
    fn enrollment_resolves_consistent_snapshot_target_objects() {
        let digest = "a".repeat(64);
        let metadata = serde_json::json!({
            "signed": {"targets": {
                "assignments/agents/node.json": {"hashes": {"sha256": digest}}
            }}
        });
        assert_eq!(
            consistent_target_object(&metadata, "assignments/agents/node.json"),
            Some(format!(
                "targets/{}.assignments/agents/node.json",
                "a".repeat(64)
            ))
        );
        assert_eq!(consistent_target_object(&metadata, "missing"), None);
    }

    #[tokio::test]
    async fn serves_nested_repository_objects() {
        let (status, _, body) = send(seeded().await, get("/targets/nested/app", None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, b"hello");
    }

    #[tokio::test]
    async fn supports_resume_ranges() {
        let (status, _, body) =
            send(seeded().await, get("/targets/nested/app", Some("bytes=2-"))).await;
        assert_eq!(status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(body, b"llo");
    }

    #[tokio::test]
    async fn supports_bounded_and_suffix_ranges() {
        // Bounded `bytes=0-2` is the inclusive first three bytes of "hello".
        let (status, headers, body) = send(
            seeded().await,
            get("/targets/nested/app", Some("bytes=0-2")),
        )
        .await;
        assert_eq!(status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(headers[header::CONTENT_RANGE], "bytes 0-2/5");
        assert_eq!(body, b"hel");
        // Suffix `bytes=-2` is the last two bytes.
        let (status, _, body) =
            send(seeded().await, get("/targets/nested/app", Some("bytes=-2"))).await;
        assert_eq!(status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(body, b"lo");
    }

    #[test]
    fn parse_range_accepts_open_bounded_and_suffix() {
        assert_eq!(parse_range_value("bytes=100-"), Ok(GetRange::Offset(100)));
        assert_eq!(
            parse_range_value("bytes=0-99"),
            Ok(GetRange::Bounded(0..100))
        );
        assert_eq!(parse_range_value("bytes=-500"), Ok(GetRange::Suffix(500)));
        for invalid in [
            "bytes=-",
            "bytes=-0",
            "bytes=5-2",
            "bytes=0-1,3-4",
            "1-2",
            "bytes=",
        ] {
            assert_eq!(parse_range_value(invalid), Err(()), "{invalid}");
        }
    }

    #[tokio::test]
    async fn rejects_a_range_at_or_beyond_eof() {
        for start in [5, 6] {
            let (status, headers, _) = send(
                seeded().await,
                get("/targets/nested/app", Some(&format!("bytes={start}-"))),
            )
            .await;
            assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
            assert_eq!(headers[header::CONTENT_RANGE], "bytes */5");
        }
    }

    #[tokio::test]
    async fn rejects_non_repository_and_ambiguous_paths() {
        for path in [
            "/routing/targets/app",
            "/targets/../app",
            "/targets/%2e%2e/app",
            "/targets/app?signature=x",
            "/targets//app",
        ] {
            let (status, _, _) = send(seeded().await, get(path, None)).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        }
    }

    #[tokio::test]
    async fn rejects_a_put_to_a_repository_path() {
        // A PUT outside the telemetry namespace matches only the GET/HEAD repository routes, so it
        // is Method Not Allowed (405) — never a repository write.
        let request = Request::builder()
            .method("PUT")
            .uri("/targets/nested/app")
            .body(Body::from("hi"))
            .unwrap();
        let (status, _, _) = send(seeded().await, request).await;
        assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    }

    /// A telemetry PUT carrying a verified client identity (the mTLS leaf CN `serve_tls` would
    /// inject). `identity == None` models a connection with no client cert.
    fn telemetry_request(node_path: &str, identity: Option<&str>, body: Vec<u8>) -> Request<Body> {
        let mut request = Request::builder()
            .method("PUT")
            .uri(format!("/telemetry/{node_path}"))
            .body(Body::from(body))
            .unwrap();
        request
            .extensions_mut()
            .insert(ClientIdentity(identity.map(str::to_owned)));
        request
    }

    #[tokio::test]
    async fn stores_a_well_formed_node_report() {
        let store = Arc::new(InMemory::new());
        let report = updated::telemetry::NodeReport::new("agent-9", "deploy-2", "2.0.0", true);
        let body = serde_json::to_vec(&report).unwrap();
        let request = telemetry_request("agent-9.json", Some("agent-9"), body.clone());
        let (status, _, _) = send(store.clone(), request).await;
        assert_eq!(status, StatusCode::OK);
        let stored = store
            .get(&ObjectPath::from("routing/telemetry/agent-9.json"))
            .await
            .unwrap()
            .bytes()
            .await
            .unwrap();
        assert_eq!(stored.as_ref(), body.as_slice());
    }

    #[tokio::test]
    async fn rejects_misattributed_or_malformed_reports() {
        // The report names a different node than the path it was written to (identity matches the
        // path, so it passes the mTLS check and fails the body/path consistency check).
        let mismatched = serde_json::to_vec(&updated::telemetry::NodeReport::new(
            "other", "d", "1.0.0", true,
        ))
        .unwrap();
        let request = telemetry_request("agent-9.json", Some("agent-9"), mismatched);
        let (status, _, _) = send(Arc::new(InMemory::new()), request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // Not a node report at all.
        let request = telemetry_request("agent-9.json", Some("agent-9"), b"not json".to_vec());
        let (status, _, _) = send(Arc::new(InMemory::new()), request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn rejects_a_report_for_a_node_other_than_the_verified_client() {
        // The connection's verified leaf CN is `agent-attacker`, but it writes to `agent-9`'s
        // telemetry key with a well-formed report that even self-consistently names `agent-9`.
        // Per-node authorization must reject it (403) BEFORE the object is stored — otherwise any
        // fleet member could forge another node's healthy/settled report and unblock its rollout.
        let store = Arc::new(InMemory::new());
        let forged = serde_json::to_vec(&updated::telemetry::NodeReport::new(
            "agent-9", "deploy-2", "2.0.0", true,
        ))
        .unwrap();
        let request = telemetry_request("agent-9.json", Some("agent-attacker"), forged);
        let (status, _, _) = send(store.clone(), request).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        // Nothing was written.
        assert!(store
            .get(&ObjectPath::from("routing/telemetry/agent-9.json"))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn rejects_telemetry_with_no_verified_client_identity() {
        // A connection with no client certificate (identity None) cannot write any node's report.
        let report = serde_json::to_vec(&updated::telemetry::NodeReport::new(
            "agent-9", "d", "1.0.0", true,
        ))
        .unwrap();
        let request = telemetry_request("agent-9.json", None, report);
        let (status, _, _) = send(Arc::new(InMemory::new()), request).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
}
