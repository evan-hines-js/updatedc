//! Read-only HTTP data plane for repositories published by `updatec`.
//!
//! The transport is Axum over hyper, one `Router` per listener role, but the TLS accept loops stay
//! ours (`tokio-rustls`) so the crypto provider remains aws-lc-rs and the mTLS client-certificate
//! requirement is enforced at the handshake exactly as before. Three listeners:
//!
//! * **data** (mTLS, client cert required): repository content, `/enroll`, telemetry `PUT`.
//! * **health** (plaintext): `/healthz` only, for orchestrator probes that cannot present a cert.
//! * **join** (server-TLS, no client cert): `/join` only — a join-mode node has no cert yet.
//!
//! Each listener is a different `Router`, so a route it must not expose simply is not mounted.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, FromRef, OriginalUri, State};
use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
use axum::{Json, Router};
use futures::StreamExt;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use kube::api::{Api, PostParams};
use kube::Client;
use object_store::path::Path as ObjectPath;
use object_store::{GetOptions, GetRange, ObjectStore, PutPayload};
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
/// The join listener is unauthenticated at the transport layer, so it gets its own, smaller budget:
/// a flood of join connections must not consume the data plane's permits and starve the
/// authenticated mTLS clients the fleet depends on.
const JOIN_CONNECTIONS: usize = 64;
/// The plaintext health listener is unauthenticated too; bound it so a slow-loris there cannot
/// exhaust process file descriptors and starve the mTLS/join listeners' `accept` calls.
const HEALTH_CONNECTIONS: usize = 64;

#[derive(Clone)]
pub struct EnrollmentContext {
    pub client: Client,
    pub namespace: String,
    pub repository: String,
    pub public_url: String,
}

/// Everything the `/join` endpoint needs beyond the shared repository data plane: the same
/// Kubernetes/publication context as enrollment, plus the fleet CA that signs join-mode node CSRs.
/// The CA is the very cert-manager CA the gateway trusts as its mTLS `client_ca`, so a leaf minted
/// here is accepted on the steady-state gateway exactly like a mount-mode client cert.
#[derive(Clone)]
pub struct JoinContext {
    pub enrollment: EnrollmentContext,
    pub ca: Arc<crate::join::IssuingCa>,
}

/// The gateway's server TLS material, mounted from a cert-manager-issued secret. The gateway
/// presents `cert`/`key` and admits a connection only if the client presents a certificate the
/// fleet `client_ca` signed — that mutual TLS *is* the enrollment authentication. The join
/// listener reuses the same server identity but requires no client certificate.
pub struct GatewayTls {
    pub cert: std::path::PathBuf,
    pub key: std::path::PathBuf,
    pub client_ca: std::path::PathBuf,
}

/// The three TCP addresses the gateway binds: the mTLS data listener, the plaintext health
/// listener, and the server-auth-only join listener.
pub struct GatewayAddresses {
    pub data: String,
    pub health: String,
    pub join: String,
}

/// Store + prefix — everything the repository and telemetry handlers need. Both the data and join
/// routers derive it (via [`FromRef`]), so those handlers require no Kubernetes context and stay
/// trivially testable.
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
}

#[derive(Clone)]
struct JoinState {
    content: ContentState,
    join: JoinContext,
}

impl FromRef<DataState> for ContentState {
    fn from_ref(state: &DataState) -> Self {
        state.content.clone()
    }
}
impl FromRef<JoinState> for ContentState {
    fn from_ref(state: &JoinState) -> Self {
        state.content.clone()
    }
}

fn data_router(state: DataState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/enroll", post(enroll))
        .route("/telemetry/{file}", put(telemetry_put))
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

fn join_router(state: JoinState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/join", post(join))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            IO_TIMEOUT,
        ))
        .with_state(state)
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
    join: JoinContext,
    tls: GatewayTls,
) -> std::io::Result<()> {
    let acceptor = TlsAcceptor::from(Arc::new(updated::tls::server_config(
        &tls.cert,
        &tls.key,
        &tls.client_ca,
    )?));
    // The join listener presents the same server certificate but requires no client cert: a
    // join-mode node reaches it before it has any identity, and proves itself with the group token.
    let join_acceptor = TlsAcceptor::from(Arc::new(updated::tls::server_config_no_client_auth(
        &tls.cert, &tls.key,
    )?));

    let data_listener = TcpListener::bind(&addresses.data).await?;
    let health_listener = TcpListener::bind(&addresses.health).await?;
    let join_listener = TcpListener::bind(&addresses.join).await?;
    tracing::info!(
        data = %addresses.data, health = %addresses.health, join = %addresses.join,
        "repository gateway listening (mTLS data + plaintext health + join)"
    );

    let content = ContentState {
        store,
        prefix: Arc::from(prefix),
    };
    let data_router = data_router(DataState {
        content: content.clone(),
        enrollment,
    });
    let join_router = join_router(JoinState {
        content,
        join,
    });

    // Health: plaintext, no TLS, its own small connection budget.
    tokio::spawn(serve_plain(
        health_listener,
        health_router(),
        Arc::new(Semaphore::new(HEALTH_CONNECTIONS)),
    ));
    // Join: server-TLS, no client cert, its own connection budget.
    tokio::spawn(serve_tls(
        join_listener,
        join_acceptor,
        join_router,
        Arc::new(Semaphore::new(JOIN_CONNECTIONS)),
        "join",
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
    builder.timer(TokioTimer::new()).header_read_timeout(IO_TIMEOUT);
    if let Err(error) = builder.serve_connection(io, service).await {
        tracing::debug!(%error, "gateway connection error");
    }
}

async fn healthz() -> &'static str {
    "ok"
}

async fn enroll(State(state): State<DataState>, body: Bytes) -> Response {
    // Authentication already happened at the mTLS handshake: this connection exists only because
    // the client presented a certificate the fleet CA signed. There is no bearer secret.
    let Ok(request) = serde_json::from_slice::<updated::enrollment::EnrollmentRequest>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !request.registration_is_wellformed() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let registration_sha256 = sha256(request.registration.as_bytes());
    // Mount and join mode name agents the same way; `agent_name` is the single source of that rule.
    let name = crate::join::agent_name(&request.registration);
    let context = &state.enrollment;
    let matches = |existing: &crate::UpdateAgent| {
        existing.spec.identity.kind == crate::AgentIdentityKind::Enrolled
            && existing.spec.identity.registration_sha256.as_deref()
                == Some(registration_sha256.as_str())
            && existing.spec.repository_ref.name == context.repository
    };
    match register_agent(
        context,
        state.content.store(),
        state.content.prefix(),
        &name,
        registration_sha256.clone(),
        // Mount enrollment stamps only the repository's trusted enrollment labels.
        |repository| repository.spec.enrollment.labels.clone(),
        matches,
        || Ok::<(), StatusCode>(()),
    )
    .await
    {
        Ok((bundle, ())) => Json(bundle).into_response(),
        Err(response) => response,
    }
}

/// Join-mode enrollment. Unlike `/enroll` there is no client-certificate handshake to authenticate
/// the peer: the request carries a group join token, which the control plane checks against the
/// group's Secret before signing the node's CSR. The control plane sets the certificate identity
/// itself (see [`crate::join::IssuingCa::sign_client_csr`]); the CSR contributes only its public
/// key. On success the node is registered as a member of the joined group and receives the same
/// enrollment bundle a mount-mode node would.
async fn join(State(state): State<JoinState>, body: Bytes) -> Response {
    let Ok(request) = serde_json::from_slice::<updated::enrollment::JoinRequest>(&body) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if request.group_id.is_empty() || request.nonce.is_empty() || !request.instance_is_wellformed() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let context = &state.join.enrollment;
    // Authenticate the join against the group token, resolved by a single keyed GET. An unknown
    // group id and a wrong token are both 401 with no distinguishing detail, so a caller cannot
    // probe which group ids exist.
    let (group_name, expected) = match lookup_group_nonce(context, &request.group_id).await {
        Ok(Some(found)) => found,
        Ok(None) => return StatusCode::UNAUTHORIZED.into_response(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    if !crate::join::nonce_matches(&request.nonce, &expected) {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let instance_sha256 = sha256(request.instance.as_bytes());
    let name = crate::join::agent_name(&request.instance);

    // A re-join with the same durable instance into the same group is idempotent. A different
    // registration, repository, or *group* under the same name is a genuine conflict — the group
    // check is the isolation boundary: a caller holding one group's token must not be handed
    // another group's node bundle/leaf merely by knowing its instance value.
    let matches = |existing: &crate::UpdateAgent| {
        existing.spec.identity.registration_sha256.as_deref() == Some(instance_sha256.as_str())
            && existing.spec.repository_ref.name == context.repository
            && existing.spec.labels.get(crate::GROUP_LABEL) == Some(&group_name)
    };
    // Sign the node CSR only after the create/conflict check passes, so a conflicting request (wrong
    // group or instance) never mints a certificate. A malformed CSR is the caller's fault (400); the
    // CP sets the subject/SAN and certifies only the CSR's public key. `register_agent` runs this
    // between its create and its bundle resolution.
    let sign = || {
        state
            .join
            .ca
            .sign_client_csr(&request.group_id, &name, &request.csr)
            .map_err(|_| StatusCode::BAD_REQUEST)
    };
    let (bundle, leaf) = match register_agent(
        context,
        state.content.store(),
        state.content.prefix(),
        &name,
        instance_sha256.clone(),
        // Stamp the group-membership label so the group's selector routes this agent to its
        // deployment, on top of the repository's trusted enrollment labels.
        |repository| {
            let mut labels = repository.spec.enrollment.labels.clone();
            labels.insert(crate::GROUP_LABEL.to_string(), group_name.clone());
            labels
        },
        matches,
        sign,
    )
    .await
    {
        Ok(pair) => pair,
        Err(response) => return response,
    };
    // The fleet CA signs leaves directly, so there is no intermediate chain to return; the node
    // already pins the CA via its bootstrap.
    Json(updated::enrollment::JoinResponse {
        leaf,
        chain: String::new(),
        bundle,
    })
    .into_response()
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
                Ok(())
            } else {
                Err(StatusCode::CONFLICT)
            }
        }
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
}

/// The routing assignment target path for an agent: `<prefix>/agents/<name>.json`.
pub(crate) fn agent_assignment(assignment_prefix: &str, name: &str) -> String {
    format!("{}/agents/{name}.json", assignment_prefix.trim_matches('/'))
}

/// Store a node's running-state report at `<prefix>/telemetry/<node>.json`. The report must be
/// well-formed and name the same node as the path — a report can only release a rollout throttle
/// slot, so a malformed or misattributed one is rejected, not stored.
async fn telemetry_put(
    State(state): State<ContentState>,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> Response {
    let Some(node) = updated::telemetry::node_from_path(uri.path()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
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

/// Resolve a group's join token by the presented `group_id`. The token Secret is named
/// `join-<group_id>`, so this is a single GET by a deterministic key — never a list/scan — which is
/// what keeps the transport-unauthenticated `/join` from being amplified into a full apiserver
/// `UpdateGroup` scan on every (even bogus) request. Returns the group's name (for the membership
/// label) and its shared nonce; `None` when no such token exists or it belongs to another
/// repository (both surface to the caller as an indistinguishable 401).
async fn lookup_group_nonce(
    context: &EnrollmentContext,
    group_id: &str,
) -> std::io::Result<Option<(String, String)>> {
    let secrets: Api<k8s_openapi::api::core::v1::Secret> =
        Api::namespaced(context.client.clone(), &context.namespace);
    let secret = match secrets.get(&format!("join-{group_id}")).await {
        Ok(secret) => secret,
        Err(kube::Error::Api(error)) if error.code == 404 => return Ok(None),
        Err(error) => return Err(std::io::Error::other(error)),
    };
    let field = |key: &str| {
        secret
            .data
            .as_ref()
            .and_then(|data| data.get(key))
            .and_then(|bytes| String::from_utf8(bytes.0.clone()).ok())
    };
    let (Some(nonce), Some(group), Some(repository)) =
        (field("nonce"), field("group"), field("repository"))
    else {
        return Ok(None);
    };
    if nonce.is_empty() || repository != context.repository {
        return Ok(None);
    }
    Ok(Some((group, nonce)))
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
    let snapshot_version = crate::runtime::metadata_version(&timestamp_value, "snapshot.json")
        .map_err(Malformed)?;
    let snapshot = object_text(store, prefix, &format!("metadata/{snapshot_version}.snapshot.json"))
        .await
        .map_err(|_| Unavailable("snapshot metadata".into()))?;
    let snapshot_value: serde_json::Value =
        serde_json::from_str(&snapshot).map_err(|_| Malformed("snapshot metadata".into()))?;
    let targets_version =
        crate::runtime::metadata_version(&snapshot_value, "targets.json").map_err(Malformed)?;
    let targets = object_text(store, prefix, &format!("metadata/{targets_version}.targets.json"))
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
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
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

    async fn send(store: Arc<InMemory>, request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
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
        let (status, headers, body) =
            send(seeded().await, get("/targets/nested/app", Some("bytes=0-2"))).await;
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
        assert_eq!(parse_range_value("bytes=0-99"), Ok(GetRange::Bounded(0..100)));
        assert_eq!(parse_range_value("bytes=-500"), Ok(GetRange::Suffix(500)));
        for invalid in ["bytes=-", "bytes=-0", "bytes=5-2", "bytes=0-1,3-4", "1-2", "bytes="] {
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

    #[tokio::test]
    async fn stores_a_well_formed_node_report() {
        let store = Arc::new(InMemory::new());
        let report = updated::telemetry::NodeReport::new("agent-9", "deploy-2", "2.0.0", true);
        let body = serde_json::to_vec(&report).unwrap();
        let request = Request::builder()
            .method("PUT")
            .uri("/telemetry/agent-9.json")
            .body(Body::from(body.clone()))
            .unwrap();
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
        // The report names a different node than the path it was written to.
        let mismatched =
            serde_json::to_vec(&updated::telemetry::NodeReport::new("other", "d", "1.0.0", true))
                .unwrap();
        let request = Request::builder()
            .method("PUT")
            .uri("/telemetry/agent-9.json")
            .body(Body::from(mismatched))
            .unwrap();
        let (status, _, _) = send(Arc::new(InMemory::new()), request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        // Not a node report at all.
        let request = Request::builder()
            .method("PUT")
            .uri("/telemetry/agent-9.json")
            .body(Body::from("not json"))
            .unwrap();
        let (status, _, _) = send(Arc::new(InMemory::new()), request).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}
