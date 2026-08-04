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

/// The verified per-connection client identity, read from the mTLS leaf rustls already validated
/// against the fleet CA before any handler runs. The node cannot forge either field — both come
/// from the CA-signed certificate, not from anything the node puts in the request — so this is the
/// trusted answer to "who is this?" that every authorization check gates on.
#[derive(Clone, Debug)]
struct ClientIdentity {
    /// The leaf's Common Name. `None` on a connection with no client certificate (the health
    /// listener), a leaf carrying no CN, or an ambiguous leaf carrying more than one.
    common_name: Option<String>,
    /// The per-node SPIFFE identity the leaf's URI SAN names — repository scope *and* node —
    /// present only on a certificate minted at `/enroll`, absent on the shared fleet bootstrap
    /// certificate. Enrollment requires it to be absent; every steady-state route requires it to
    /// name this gateway's own repository.
    node: Option<crate::join::NodeSpiffeId>,
}

impl ClientIdentity {
    /// The node this connection is authorized to act as **within `repository`**.
    ///
    /// Naming the repository is not optional, and that is the point: the fleet CA is shared across
    /// every repository in a namespace, so a leaf minted by one repository's `/enroll` is a valid,
    /// CA-verified certificate on another repository's listener. Authorizing on the node name alone
    /// let a staging node read the production node of the same name's secrets and forge its
    /// telemetry. There is no way to obtain a node name here without saying which repository the
    /// answer is for.
    ///
    /// The shared fleet bootstrap certificate carries no node SAN, so it resolves to no node in any
    /// repository — it authenticates the one `/enroll` handshake and nothing else.
    fn node_in(&self, repository: &str) -> Option<&str> {
        let identity = self.node.as_ref()?;
        (identity.repository == repository).then_some(identity.node.as_str())
    }
}

/// Extract the leaf certificate's Common Name from a completed server-side TLS connection.
fn peer_identity(conn: &tokio_rustls::rustls::ServerConnection) -> ClientIdentity {
    use x509_parser::extensions::GeneralName;

    let anonymous = ClientIdentity {
        common_name: None,
        node: None,
    };
    let Some(leaf) = conn.peer_certificates().and_then(|certs| certs.first()) else {
        return anonymous;
    };
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(leaf.as_ref()) else {
        return anonymous;
    };
    let mut common_names = cert.subject().iter_common_name();
    let cn = common_names
        .next()
        .and_then(|name| name.as_str().ok())
        .map(str::to_owned);
    // An ambiguous subject is not an identity. Issued node and bootstrap certificates each carry
    // exactly one CN; fail closed if an external issuer supplies more.
    if common_names.next().is_some() {
        return anonymous;
    }
    // Every node leaf minted by this control plane carries a SPIFFE URI SAN naming its repository
    // scope and node. It is a cryptographic marker that the certificate is an ordinary node
    // identity — so it can never regain bootstrap authority merely by choosing the bootstrap
    // certificate's CN — and it is the ONLY thing that says which repository the leaf belongs to.
    let node = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .and_then(|san| {
            san.value.general_names.iter().find_map(|name| match name {
                GeneralName::URI(uri) => crate::join::NodeSpiffeId::parse(uri),
                _ => None,
            })
        })
        // The subject and the SAN are minted together from one name, so a leaf whose two identity
        // fields disagree was not minted by this control plane and is not an identity at all.
        .filter(|identity| Some(identity.node.as_str()) == cn.as_deref());
    ClientIdentity {
        common_name: cn,
        node,
    }
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
    /// Exact Common Name of the fleet-wide bootstrap certificate allowed to call `/enroll`.
    /// Ordinary per-node leaves use their node name and must never inherit enrollment authority.
    pub enrollment_client_cn: String,
}

/// Where the fleet CA that signs node CSRs is mounted (cert-manager keys `tls.crt` / `tls.key`).
/// Paths, not contents: the gateway re-reads them, so a rotation is picked up without a restart.
pub struct IssuingCaPaths {
    pub cert: std::path::PathBuf,
    pub key: std::path::PathBuf,
}

/// How often the gateway re-reads its mounted certificate material.
///
/// Every one of these files is a cert-manager Secret that is rotated IN PLACE, on the issuer's
/// schedule, with no restart of this process. Loading them once means the gateway keeps presenting
/// a certificate that eventually expires — at which point every agent's handshake fails and the
/// whole fleet loses metadata, telemetry, and enrollment at the same moment.
const MATERIAL_RELOAD_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// A value rebuilt from files on disk while the gateway runs. Readers take the current value; a
/// reload that fails to parse leaves the last good one in place, so a half-written rotation is a
/// logged warning rather than an outage.
struct Reloadable<T> {
    current: std::sync::RwLock<Arc<T>>,
}

impl<T> Reloadable<T> {
    fn new(initial: T) -> Self {
        Self {
            current: std::sync::RwLock::new(Arc::new(initial)),
        }
    }

    fn get(&self) -> Arc<T> {
        self.current
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn set(&self, value: T) {
        *self
            .current
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Arc::new(value);
    }
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
    /// The repository this gateway serves. Carried here because it is an AUTHORIZATION input, not
    /// merely configuration: a client leaf is scoped to the repository that minted it, and a
    /// handler must compare that scope against this before it acts on the caller's node name.
    repository: Arc<str>,
}

impl ContentState {
    fn store(&self) -> &dyn ObjectStore {
        self.store.as_ref()
    }
    fn prefix(&self) -> &str {
        &self.prefix
    }
    fn repository(&self) -> &str {
        &self.repository
    }
}

#[derive(Clone)]
struct DataState {
    content: ContentState,
    enrollment: EnrollmentContext,
    enrollment_client_cn: Arc<str>,
    /// The fleet CA that signs per-node leaves at `/enroll`. Reloaded from its mounted files, so a
    /// rotated CA key signs the next leaf instead of the process needing a restart.
    ca: Arc<Reloadable<crate::join::IssuingCa>>,
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
        .route("/renew", post(renew))
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
    assignment: &updated_contracts::assignment::RepositoryAssignment,
    store: &dyn SecretStore,
) -> Result<SecretBundle, SecretBundleError> {
    const MAX_SECRET_BYTES: usize = 64 * 1024;
    const MAX_BUNDLE_BYTES: usize = 1024 * 1024;

    let mut values = std::collections::BTreeMap::new();
    let mut digest = updated::hash::Sha256Hasher::new();
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
        digest.update(&[0]);
        digest.update(value.as_bytes());
        digest.update(&[0]);
        values.insert(reference.environment.clone(), value);
    }
    Ok(SecretBundle {
        deployment: assignment.deployment.clone(),
        generation: digest.finish_hex(),
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
    let Some(node) = identity.node_in(state.content.repository()) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let repositories: Api<crate::UpdateRepository> =
        Api::namespaced(state.enrollment.client.clone(), &state.enrollment.namespace);
    let Ok(repository) = repositories.get(&state.enrollment.repository).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let assignment = agent_assignment(&repository.spec.assignment_prefix, node);
    let Some(trust_anchor) = published_root_sha256(&repository) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let signed = match resolve_signed_enrollment(
        state.content.store(),
        state.content.prefix(),
        &assignment,
        &trust_anchor,
    )
    .await
    {
        Ok(signed) => signed,
        Err(error) => return error.status_code().into_response(),
    };
    let assignment: updated_contracts::assignment::RepositoryAssignment =
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
    issuing_ca: IssuingCaPaths,
    tls: GatewayTls,
) -> std::io::Result<()> {
    if tls.enrollment_client_cn.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the enrollment client Common Name must not be empty",
        ));
    }
    // Both the listener identity and the issuing CA are cert-manager Secrets rotated in place. They
    // are loaded here and then re-read on a timer, so a rotation lands in a running gateway.
    let server_config = Arc::new(Reloadable::new(updated::tls::server_config(
        &tls.cert,
        &tls.key,
        &tls.client_ca,
    )?));
    let ca = Arc::new(Reloadable::new(load_issuing_ca(&issuing_ca)?));
    tokio::spawn(reload_materials(
        tls.cert.clone(),
        tls.key.clone(),
        tls.client_ca.clone(),
        issuing_ca,
        server_config.clone(),
        ca.clone(),
    ));

    let data_listener = TcpListener::bind(&addresses.data).await?;
    let health_listener = TcpListener::bind(&addresses.health).await?;
    tracing::info!(
        data = %addresses.data, health = %addresses.health,
        "repository gateway listening (mTLS data + plaintext health)"
    );

    let content = ContentState {
        store,
        prefix: Arc::from(prefix),
        repository: Arc::from(enrollment.repository.as_str()),
    };
    // Enrollment is a route on the one mTLS data listener now: the shared fleet enrollment cert
    // authenticates it, so there is no separate client-cert-less listener.
    let data_router = data_router(DataState {
        content,
        enrollment,
        enrollment_client_cn: Arc::from(tls.enrollment_client_cn),
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
        server_config,
        data_router,
        Arc::new(Semaphore::new(DATA_CONNECTIONS)),
        "data",
    )
    .await;
    Ok(())
}

fn load_issuing_ca(paths: &IssuingCaPaths) -> std::io::Result<crate::join::IssuingCa> {
    let cert = std::fs::read_to_string(&paths.cert).map_err(|error| {
        std::io::Error::other(format!("reading issuing CA certificate: {error}"))
    })?;
    let key = std::fs::read_to_string(&paths.key)
        .map_err(|error| std::io::Error::other(format!("reading issuing CA key: {error}")))?;
    crate::join::IssuingCa::load(&cert, &key)
}

/// Re-read the mounted certificate material forever, swapping in each new value that loads cleanly.
///
/// Rebuilding unconditionally rather than diffing bytes keeps this to one code path; the work is a
/// few file reads a minute. A failed load — a partially-written rotation, a removed mount — is
/// logged and the previous value stays live, which is the fail-safe direction: the alternative is
/// dropping the fleet's only authenticated channel over a transient read.
async fn reload_materials(
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
    client_ca: std::path::PathBuf,
    issuing_ca: IssuingCaPaths,
    server_config: Arc<Reloadable<rustls::ServerConfig>>,
    ca: Arc<Reloadable<crate::join::IssuingCa>>,
) {
    loop {
        tokio::time::sleep(MATERIAL_RELOAD_INTERVAL).await;
        match updated::tls::server_config(&cert, &key, &client_ca) {
            Ok(config) => server_config.set(config),
            Err(error) => {
                tracing::warn!(%error, "reloading gateway TLS material failed; keeping the loaded one")
            }
        }
        match load_issuing_ca(&issuing_ca) {
            Ok(loaded) => ca.set(loaded),
            Err(error) => {
                tracing::warn!(%error, "reloading the issuing CA failed; keeping the loaded one")
            }
        }
    }
}

/// The pause after a failed `accept` before trying again.
///
/// The failures that matter are the PERSISTENT ones — EMFILE/ENFILE/ENOBUFS — where the process has
/// no descriptor to accept onto and retrying cannot clear the condition. Without a pause the loop
/// is a tight spin that saturates a core and emits one log line per iteration, turning recoverable
/// fd pressure into a gateway outage. Never tear the listener down instead: that crash-loops the
/// process precisely when it is resource-starved.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// Accept one connection, pausing after each failure. The single accept chokepoint — both listeners
/// go through it, so neither can be written without the backoff.
async fn accept_next(
    listener: &TcpListener,
    label: &'static str,
) -> (tokio::net::TcpStream, std::net::SocketAddr) {
    loop {
        match listener.accept().await {
            Ok(accepted) => return accepted,
            Err(error) => {
                tracing::warn!(%error, listener = label, "gateway accept failed; pausing before retry");
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
            }
        }
    }
}

/// Accept TLS connections and serve `app` on each. A client that fails the handshake never reaches
/// a handler.
async fn serve_tls(
    listener: TcpListener,
    server_config: Arc<Reloadable<rustls::ServerConfig>>,
    app: Router,
    budget: Arc<Semaphore>,
    label: &'static str,
) {
    loop {
        let (tcp, peer) = accept_next(&listener, label).await;
        let Ok(permit) = budget.clone().acquire_owned().await else {
            return;
        };
        // Take the current identity per connection, so a rotated certificate applies to the next
        // handshake rather than to the next process.
        let acceptor = TlsAcceptor::from(server_config.get());
        let app = app.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let tls = match timeout(IO_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    tracing::debug!(%peer, %error, listener = label, "rejected client at the TLS handshake");
                    return;
                }
                Err(_) => {
                    tracing::debug!(%peer, listener = label, "TLS handshake timed out");
                    return;
                }
            };
            // Bind the CA-verified client identity to every request on this connection, so a
            // per-node authorization check reads the trusted cert CN rather than the node's
            // self-claimed path. `None` is used only by the plaintext health listener.
            let identity = peer_identity(tls.get_ref().1);
            let app = app.layer(Extension(identity));
            serve_http(TokioIo::new(tls), app).await;
        });
    }
}

/// The plaintext accept loop (health only), bounded by its own connection budget.
async fn serve_plain(listener: TcpListener, app: Router, budget: Arc<Semaphore>) {
    loop {
        let (tcp, _) = accept_next(&listener, "health").await;
        let Ok(permit) = budget.clone().acquire_owned().await else {
            return;
        };
        let app = app.clone();
        tokio::spawn(async move {
            let _permit = permit;
            serve_http(TokioIo::new(tcp), app).await;
        });
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

async fn enroll(
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
    if !is_permitted_node_name(&request.name, &state.enrollment_client_cn) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let name = request.name.as_str();
    // A stable per-node identifier for idempotent re-enrollment, derived from the self-asserted name:
    // the same node coming back on the same name is the same UpdateAgent.
    let registration_sha256 = updated::hash::sha256_bytes(name.as_bytes());
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
        hex::encode(public_key),
        &request.csr,
    )
    .await
    {
        Ok((bundle, leaf)) => Json(updated_contracts::enrollment::EnrollResponse {
            leaf,
            chain: String::new(),
            bundle,
        })
        .into_response(),
        Err(response) => response,
    }
}

fn is_enrollment_identity(identity: &ClientIdentity, enrollment_client_cn: &str) -> bool {
    !enrollment_client_cn.is_empty()
        && identity.common_name.as_deref() == Some(enrollment_client_cn)
        && identity.node.is_none()
}

fn is_permitted_node_name(name: &str, enrollment_client_cn: &str) -> bool {
    !enrollment_client_cn.is_empty() && name != enrollment_client_cn
}

async fn renew(
    State(state): State<DataState>,
    Extension(identity): Extension<ClientIdentity>,
    body: Bytes,
) -> Response {
    // Renewal is a steady-state operation: only an already-minted per-node leaf scoped to THIS
    // repository may re-sign its own identity. The shared fleet bootstrap certificate mints leaves
    // at `/enroll` and nothing else.
    let Some(name) = identity
        .node_in(state.content.repository())
        .map(str::to_owned)
    else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let Ok(request) =
        serde_json::from_slice::<updated_contracts::enrollment::RenewalRequest>(&body)
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let Ok(public_key) = crate::join::csr_public_key(&request.csr) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    let agents: Api<crate::UpdateAgent> =
        Api::namespaced(state.enrollment.client.clone(), &state.enrollment.namespace);
    let Ok(agent) = agents.get(&name).await else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if !is_pinned_identity(
        &agent,
        &state.enrollment.repository,
        &hex::encode(public_key),
    ) {
        return StatusCode::FORBIDDEN.into_response();
    }
    match state
        .ca
        .get()
        .sign_client_csr(&state.enrollment.repository, &name, &request.csr)
    {
        Ok(leaf) => {
            tracing::info!(
                node = %name,
                repository = %state.enrollment.repository,
                "renewed node certificate"
            );
            Json(updated_contracts::enrollment::RenewalResponse {
                leaf,
                chain: String::new(),
            })
            .into_response()
        }
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

/// The single check that an existing `UpdateAgent` is the same enrolled identity, in the same
/// repository, presenting the same pinned public key. Both enrollment idempotency and renewal
/// authorization gate on this, so "is this really that node?" has ONE definition the two paths
/// cannot drift apart on — a gap on either would let a shared-fleet-cert holder mint a valid
/// `CN=<name>` leaf for another node's name with an attacker key.
fn is_pinned_identity(agent: &crate::UpdateAgent, repository: &str, public_key: &str) -> bool {
    agent.spec.identity.kind == crate::AgentIdentityKind::Enrolled
        && agent.spec.repository_ref.name == repository
        && agent.spec.identity.public_key.as_deref() == Some(public_key)
}

/// The single enrollment transaction: create the exact enrolled identity idempotently, then mint
/// its leaf and resolve its signed bundle. A conflicting name is rejected before certificate
/// issuance, and there is no alternate registration mode.
async fn register_enrollment(
    state: &DataState,
    name: &str,
    registration_sha256: String,
    public_key: String,
    csr: &str,
) -> Result<(crate::EnrollmentBundle, String), Response> {
    let context = &state.enrollment;
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
                registration_sha256: Some(registration_sha256.clone()),
                public_key: Some(public_key),
            },
            labels: repository.spec.enrollment.labels.clone(),
        },
    );
    // Idempotent re-enrollment must be the SAME pinned identity (via the one shared predicate, so it
    // can never drift from renewal) AND the same registration digest. Binding to the pinned key is
    // what stops a shared-fleet-cert holder from re-enrolling an existing name with an attacker key:
    // a different key fails this match, falls through to CONFLICT, and no `CN=<name>` leaf is minted
    // (which would otherwise read another node's secrets via the CN-authenticated endpoint). A
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
    if let Err(status) = create_agent_idempotent(&agents, name, &desired, matches).await {
        return Err(status.into_response());
    }
    let leaf = state
        .ca
        .get()
        .sign_client_csr(&context.repository, name, csr)
        .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
    let assignment = agent_assignment(&repository.spec.assignment_prefix, name);
    // The consistent-snapshot metadata walk is shared with the operator's enrollment-Secret
    // publisher so this security-sensitive resolution lives in exactly one place. A newly
    // registered agent can legitimately race publication: an object that is not there yet is
    // `Unavailable` (503, retry), while a present-but-malformed document is `Malformed` (502).
    let trust_anchor = published_root_sha256(&repository)
        .ok_or_else(|| StatusCode::SERVICE_UNAVAILABLE.into_response())?;
    let signed = match resolve_signed_enrollment(
        state.content.store(),
        state.content.prefix(),
        &assignment,
        &trust_anchor,
    )
    .await
    {
        Ok(signed) => signed,
        Err(error) => return Err(error.status_code().into_response()),
    };
    let bundle = signed.into_bundle(name.to_string(), &context.public_url, assignment);
    Ok((bundle, leaf))
}

/// Create `desired` (named `name`), treating a 409 as success iff the existing agent `matches`
/// (an idempotent re-registration); a 409 whose existing agent does not match is a real `CONFLICT`,
/// and any other API error is `500`.
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
                // The operator reserved this exact name for dynamic enrollment — an intentional
                // admission gate — but deferred identity to the node. The node has now presented its
                // CSR over the shared fleet cert, so complete the reservation in place: stamp ONLY
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
/// `runtime::publish_enrollment_secrets`, never through a CSR here — and is never completed here.
/// Any other state — a different repository, or an already-`Enrolled` agent whose registration
/// differs — is a real conflict and is never overwritten, so a node can never seize another node's
/// established identity.
///
/// A `manual` agent therefore never has a pinned key, so nothing it reports can be verified. That
/// is a deliberate fail-closed property, not a wedge: the rollout planner classifies such a node as
/// [`crate::rollout::NodeEvidence::Blind`] and stages it on what was published to it, so its group
/// stays throttled, settles on the agents that CAN be observed, and remains updatable.
fn adopts_preapproval(existing: &crate::UpdateAgent, desired: &crate::UpdateAgent) -> bool {
    existing.spec.identity.kind == crate::AgentIdentityKind::Reserved
        && existing.spec.identity.registration_sha256.is_none()
        && existing.spec.identity.public_key.is_none()
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
/// per-node client certificate (its `CN` is the agent name; see
/// `updated_contracts::enrollment`), so the
/// mTLS leaf identity rustls verified is bound against the `node` in the path below: a node may
/// write ONLY its own report. Without that check any fleet member could forge another node's
/// settled/healthy report and drive its rollout past unhealthy peers, defeating the throttle.
async fn telemetry_put(
    State(state): State<ContentState>,
    Extension(identity): Extension<ClientIdentity>,
    OriginalUri(uri): OriginalUri,
    body: Bytes,
) -> Response {
    let Some(node) = updated_contracts::telemetry::node_from_path(uri.path()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // Per-node authorization: the mTLS leaf rustls verified is the trusted identity; the path node
    // is the caller's claim. A node may write ONLY its own report, and only with a leaf minted for
    // THIS repository — otherwise any fleet member (or any node of a sibling repository sharing the
    // fleet CA) could forge another node's healthy/settled report and drive its rollout past
    // unhealthy peers. `node_in` also excludes the shared bootstrap certificate, which is
    // enroll-only.
    if identity.node_in(state.repository()) != Some(node) {
        return StatusCode::FORBIDDEN.into_response();
    }
    // A report travels as a DSSE envelope. The gateway does NOT verify its signature — it authorizes by
    // the mTLS leaf above, and the signature is end-to-end evidence for the consumers that read the
    // stored bytes back. What it does check is that the envelope is well formed and that its payload
    // names the node whose key it is being stored under, so a malformed or misfiled record is refused
    // at the door rather than stored for a reader to trip over.
    let Ok(envelope) = serde_json::from_slice::<updated_contracts::telemetry::Envelope>(&body)
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    // Same shape bounds the consumer gate applies, refused at the door: a node signs with one key,
    // so a stuffed signature list is only ever an attempt to make every later read pay for a pile
    // of ECDSA verifications.
    if envelope.payload_type != updated_contracts::telemetry::REPORT_PAYLOAD_TYPE
        || envelope.signatures.len() > updated_contracts::telemetry::Envelope::MAX_SIGNATURES
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Some(report) = updated_contracts::telemetry::report_payload_unverified(&envelope) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if report.node != node {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let key = crate::object_key(
        state.prefix(),
        &updated_contracts::telemetry::report_object_key(node),
    );
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
/// The routing root digest this repository has published, from its status in etcd. `None` before
/// the first publish — there is no anchor yet, so nothing may be enrolled against it.
pub(crate) fn published_root_sha256(repository: &crate::UpdateRepository) -> Option<String> {
    repository
        .status
        .as_ref()?
        .routing_root_sha256
        .clone()
        .filter(|digest| updated_contracts::is_sha256_hex(digest))
}

#[derive(Clone)]
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
    /// defined, so the gateway's live `/enroll` response and the operator's published
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
    /// The HTTP status a failed enrollment resolution maps to: `Unavailable`
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
    if !updated::hash::sha256_bytes(root.as_bytes()).eq_ignore_ascii_case(expected_root_sha256) {
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
    let parsed: updated_contracts::artifact::AgentDocument = serde_json::from_str(&agent_document)
        .map_err(|_| Malformed(format!("assignment document {assignment}")))?;
    let config_path = parsed.config.path;
    let config_object = consistent_target_object(&targets_value, &config_path)
        .ok_or_else(|| Malformed(format!("managed configuration target {config_path}")))?;
    let managed_configuration = object_text(store, prefix, &config_object)
        .await
        .map_err(|_| Unavailable(format!("managed configuration {config_path}")))?;

    let resolved = SignedEnrollment {
        root,
        timestamp,
        snapshot,
        targets,
        agent_document,
        managed_configuration,
    };
    // Then the full TUF chain, through the same verifier a node runs on the bundle it receives:
    // every role signature and threshold, every expiry, each metafile digest, each target digest.
    // Following JSON pointers from document to document — as this walk did — authenticates
    // nothing; it only reads what the store happens to contain.
    updated_tuf::verify_embedded_assignment(&resolved.clone().into_bundle(
        "verification".into(),
        "https://verification.invalid",
        assignment.to_string(),
    ))
    .map_err(|error| Malformed(format!("published enrollment chain ({error})")))?;
    // Cacheable only for as long as the chain that was just verified stays valid. If any role's
    // expiry cannot be read, nothing is memoized and every request re-verifies — slower, never
    // wrong.
    if let Some(expires) = chain_expiry(&resolved) {
        VERIFIED_ENROLLMENTS.insert(&generation, assignment, &resolved, expires);
    }
    Ok(resolved)
}

/// The earliest `signed.expires` across the four TUF role documents of one generation — the instant
/// at which `verify_embedded_assignment` would start rejecting this chain.
///
/// The metadata chain is identical for every agent in a generation, so this is a property of the
/// generation and is stored once alongside its key. `None` when any role's expiry is missing or
/// unparseable, which makes the chain uncacheable rather than cacheable forever.
fn chain_expiry(resolved: &SignedEnrollment) -> Option<chrono::DateTime<chrono::Utc>> {
    [
        &resolved.root,
        &resolved.timestamp,
        &resolved.snapshot,
        &resolved.targets,
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
fn generation_key(prefix: &str, expected_root_sha256: &str, timestamp: &str) -> String {
    let mut digest = updated::hash::Sha256Hasher::new();
    for part in [prefix, expected_root_sha256, timestamp] {
        digest.update(part.as_bytes());
        digest.update(&[0]);
    }
    digest.finish_hex()
}

/// Verified enrollment chains, memoized for as long as the published generation they came from is
/// current.
///
/// `resolve_signed_enrollment` performs a full TUF verification, and `/v1/node/secrets` calls it on
/// EVERY request — per-node work whose rate the fleet's polling interval multiplies, which a large
/// fleet's steady-state polling can turn into a saturated gateway. This is the same reason the
/// rollout planner memoizes report verification.
///
/// A hit is bounded by BOTH: the key (a publish re-signs `timestamp`, which changes the generation
/// key and drops every entry in one step) and the generation's own earliest role expiry. The expiry
/// half is not an optimization — a hit skips `verify_embedded_assignment`, whose expiry check is the
/// only thing standing between a publisher that has stopped re-signing and a gateway serving an
/// expired chain forever. It is a property of the generation, not of an entry: every agent's bundle
/// carries the same four role documents, so it is stored once beside the key and compared with one
/// integer comparison per request. Only successful verifications are stored, and only for assignment
/// paths derived from an already authenticated caller, so the map is bounded by the fleet's own
/// agent count.
#[derive(Default)]
struct Generation {
    key: String,
    expires: Option<chrono::DateTime<chrono::Utc>>,
    entries: std::collections::HashMap<String, SignedEnrollment>,
}

struct VerifiedEnrollments {
    inner: std::sync::Mutex<Generation>,
}

static VERIFIED_ENROLLMENTS: std::sync::LazyLock<VerifiedEnrollments> =
    std::sync::LazyLock::new(|| VerifiedEnrollments {
        inner: std::sync::Mutex::new(Generation::default()),
    });

impl VerifiedEnrollments {
    fn get(
        &self,
        generation: &str,
        assignment: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Option<SignedEnrollment> {
        let guard = self.lock();
        if guard.key != generation || guard.expires.is_none_or(|expires| now >= expires) {
            return None;
        }
        guard.entries.get(assignment).cloned()
    }

    fn insert(
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
                entries: std::collections::HashMap::new(),
            };
        }
        guard
            .entries
            .insert(assignment.to_string(), resolved.clone());
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Generation> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn consistent_target_object(targets: &serde_json::Value, logical_path: &str) -> Option<String> {
    let digest = targets
        .get("signed")?
        .get("targets")?
        .get(logical_path)?
        .get("hashes")?
        .get("sha256")?
        .as_str()?;
    if !updated_contracts::is_sha256_hex(digest) {
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
    let bytes = crate::read_object_bounded(store, &key).await?;
    String::from_utf8(bytes).map_err(|error| object_store::Error::Generic {
        store: "enrollment",
        source: Box::new(error),
    })
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
    // Confined path safety is the one shared guard; a served object key additionally rejects any
    // dot-leading segment (no `.`/`..` climb and no hidden keys).
    if tail.is_empty()
        || !tail
            .iter()
            .all(|part| updated_contracts::path::is_safe_component(part) && !part.starts_with('.'))
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

    /// A well-formed running digest for report fixtures. Nothing in this module reads it; a report
    /// simply needs one to be well formed.
    const DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    use axum::http::Request;
    use object_store::memory::InMemory;
    use tower::ServiceExt;

    fn renewal_agent(
        kind: crate::AgentIdentityKind,
        repository: &str,
        public_key: Option<&str>,
    ) -> crate::UpdateAgent {
        crate::UpdateAgent::new(
            "node-a",
            crate::UpdateAgentSpec {
                repository_ref: crate::LocalObjectReference {
                    name: repository.into(),
                },
                identity: crate::AgentIdentity {
                    kind,
                    registration_sha256: Some("registration".into()),
                    public_key: public_key.map(str::to_owned),
                },
                labels: Default::default(),
            },
        )
    }

    fn node_leaf(repository: &str, node: &str) -> ClientIdentity {
        ClientIdentity {
            common_name: Some(node.into()),
            node: Some(crate::join::NodeSpiffeId {
                repository: repository.into(),
                node: node.into(),
            }),
        }
    }

    #[test]
    fn a_node_leaf_authorizes_only_within_the_repository_it_was_minted_for() {
        // The fleet CA is shared across the repositories in a namespace, so `staging`'s leaf is a
        // perfectly valid, CA-verified certificate on `prod`'s listener. Only the SAN's scope
        // distinguishes them; dropping it let staging's `web-01` read production `web-01`'s secrets
        // and overwrite its telemetry.
        let staging = node_leaf("staging", "web-01");
        assert_eq!(staging.node_in("staging"), Some("web-01"));
        assert_eq!(staging.node_in("prod"), None);
    }

    #[test]
    fn the_bootstrap_certificate_is_a_node_in_no_repository() {
        let bootstrap = ClientIdentity {
            common_name: Some("updated-enrollment".into()),
            node: None,
        };
        assert_eq!(bootstrap.node_in("prod"), None);
        assert!(is_enrollment_identity(&bootstrap, "updated-enrollment"));
        // A minted node leaf never regains enrollment authority by taking the bootstrap CN.
        assert!(!is_enrollment_identity(
            &node_leaf("prod", "updated-enrollment"),
            "updated-enrollment"
        ));
    }

    #[test]
    fn a_spiffe_uri_round_trips_and_rejects_a_prefix_only_uri() {
        let identity = crate::join::NodeSpiffeId {
            repository: "prod".into(),
            node: "web-01".into(),
        };
        assert_eq!(
            crate::join::NodeSpiffeId::parse(&identity.uri()),
            Some(identity)
        );
        // The old gate accepted any URI carrying the trust-domain prefix, which names neither a
        // repository nor a node.
        for uri in [
            "spiffe://updated.fleet/scope/",
            "spiffe://updated.fleet/scope/prod",
            "spiffe://updated.fleet/scope//node/web-01",
            "spiffe://updated.fleet/scope/prod/node/",
            "spiffe://elsewhere/scope/prod/node/web-01",
        ] {
            assert_eq!(
                crate::join::NodeSpiffeId::parse(uri),
                None,
                "{uri} must not parse as a node identity"
            );
        }
    }

    #[test]
    fn renewal_requires_the_enrolled_agent_repository_and_pinned_key() {
        let enrolled = renewal_agent(crate::AgentIdentityKind::Enrolled, "repo", Some("key"));
        assert!(is_pinned_identity(&enrolled, "repo", "key"));
        assert!(!is_pinned_identity(&enrolled, "other", "key"));
        assert!(!is_pinned_identity(&enrolled, "repo", "other-key"));
        assert!(!is_pinned_identity(
            &renewal_agent(crate::AgentIdentityKind::Manual, "repo", Some("key")),
            "repo",
            "key"
        ));
        assert!(!is_pinned_identity(
            &renewal_agent(crate::AgentIdentityKind::Enrolled, "repo", None),
            "repo",
            "key"
        ));
    }

    #[test]
    fn only_an_explicitly_reserved_name_may_be_completed_by_enrollment() {
        // `/enroll` authenticates with the fleet-wide bootstrap certificate, so any agent this
        // predicate accepts is claimable by whichever fleet member asks first — along with its
        // labels, and hence its group and deployment. Only an explicit reservation qualifies.
        let desired = renewal_agent(crate::AgentIdentityKind::Enrolled, "repo", Some("key"));
        let deferred = |kind| {
            let mut agent = renewal_agent(kind, "repo", None);
            agent.spec.identity.registration_sha256 = None;
            agent
        };
        assert!(adopts_preapproval(
            &deferred(crate::AgentIdentityKind::Reserved),
            &desired
        ));
        assert!(
            !adopts_preapproval(&deferred(crate::AgentIdentityKind::Manual), &desired),
            "a declared manual agent is the offline path, not a hijackable reservation: adopting \
             it would let any holder of the shared fleet certificate claim an operator-declared \
             name before that machine is ever built, and read its secrets"
        );
        let mut already_identified = deferred(crate::AgentIdentityKind::Reserved);
        already_identified.spec.identity.public_key = Some("key".into());
        assert!(
            !adopts_preapproval(&already_identified, &desired),
            "an agent that already has a pinned key is never re-adopted"
        );
        let mut other_repository = deferred(crate::AgentIdentityKind::Reserved);
        other_repository.spec.repository_ref.name = "other".into();
        assert!(!adopts_preapproval(&other_repository, &desired));
        let mut established = deferred(crate::AgentIdentityKind::Reserved);
        established.spec.identity.registration_sha256 = Some("registration".into());
        assert!(!adopts_preapproval(&established, &desired));
    }

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

    fn secret_assignment() -> updated_contracts::assignment::RepositoryAssignment {
        let runtime = crate::tests::managed_runtime();
        updated_contracts::assignment::RepositoryAssignment {
            schema: updated_contracts::assignment::RepositoryAssignment::SCHEMA,
            deployment: "deployment".into(),
            metadata_url: "https://control/metadata/".into(),
            targets_url: "https://control/targets/".into(),
            report_url: Some("https://control/telemetry/node.json".into()),
            application: updated_contracts::artifact::TargetReference {
                path: "releases/app/1/app.bundle".into(),
                sha256: "a".repeat(64),
            },
            ordered_install_fallback: false,
            provider_set: updated_contracts::artifact::TargetReference {
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
            updated_contracts::assignment::SecretReference {
                environment: "DATABASE_PASSWORD".into(),
                secret: "database".into(),
                key: "password".into(),
            },
            updated_contracts::assignment::SecretReference {
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
        assignment.runtime.secrets = vec![updated_contracts::assignment::SecretReference {
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
                repository: Arc::from(TEST_REPOSITORY),
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

    /// A full TUF verification is per-request asymmetric-crypto work at a rate the fleet's polling
    /// interval multiplies, so it is memoized — but only for exactly as long as the generation it
    /// verified is the published one AND that generation's chain is unexpired. A publish re-signs
    /// `timestamp`, which is part of the key, so a new generation can neither hit an old entry nor
    /// leave one behind; and once the chain expires the memo stops answering, so the serving path
    /// goes back through the verifier that refuses it.
    #[test]
    fn a_verified_enrollment_is_memoized_only_within_one_unexpired_generation() {
        let cache = VerifiedEnrollments {
            inner: std::sync::Mutex::new(Generation::default()),
        };
        let chain = SignedEnrollment {
            root: "root".into(),
            timestamp: "timestamp-1".into(),
            snapshot: "snapshot".into(),
            targets: "targets".into(),
            agent_document: "agent".into(),
            managed_configuration: "config".into(),
        };
        let path = "assignments/agents/node.json";
        let now = chrono::Utc::now();
        let expires = now + chrono::Duration::hours(1);
        let first = generation_key("routing", "anchor", "timestamp-1");
        assert!(cache.get(&first, path, now).is_none());
        cache.insert(&first, path, &chain, expires);
        assert_eq!(
            cache.get(&first, path, now).unwrap().agent_document,
            "agent"
        );
        assert!(
            cache.get(&first, path, expires).is_none(),
            "a publisher that stops re-signing must not keep an expired chain servable: at the \
             expiry the memo stops answering and the full verifier refuses it again"
        );

        let republished = generation_key("routing", "anchor", "timestamp-2");
        assert!(
            cache.get(&republished, path, now).is_none(),
            "a new generation must never be served an older verification"
        );
        cache.insert(
            &republished,
            "assignments/agents/other.json",
            &chain,
            expires,
        );
        assert!(
            cache.get(&republished, path, now).is_none(),
            "and the previous generation's entries are dropped, not left to accumulate"
        );
        // The trust anchor and the repository prefix are part of the identity of a generation: a
        // chain verified for one must never satisfy a lookup for another.
        assert_ne!(generation_key("other", "anchor", "timestamp-1"), first);
        assert_ne!(generation_key("routing", "other", "timestamp-1"), first);
    }

    /// The cached generation expires at the EARLIEST of its four role expiries — the instant the
    /// verifier itself would start rejecting the chain — and a chain whose expiries cannot be read
    /// is not cacheable at all.
    #[test]
    fn a_generations_cache_lifetime_is_its_earliest_role_expiry() {
        let role = |expires: &str| {
            serde_json::json!({"signed": {"expires": expires}, "signatures": []}).to_string()
        };
        let chain = SignedEnrollment {
            root: role("2030-01-01T00:00:00Z"),
            timestamp: role("2027-03-04T05:06:07Z"),
            snapshot: role("2029-01-01T00:00:00Z"),
            targets: role("2028-01-01T00:00:00Z"),
            agent_document: "agent".into(),
            managed_configuration: "config".into(),
        };
        assert_eq!(
            chain_expiry(&chain).unwrap().to_rfc3339(),
            "2027-03-04T05:06:07+00:00"
        );
        let unreadable = SignedEnrollment {
            snapshot: "not json".into(),
            ..chain
        };
        assert!(
            chain_expiry(&unreadable).is_none(),
            "an unreadable expiry makes the chain uncacheable, never cacheable forever"
        );
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

    /// The repository the test gateway serves; a node leaf must be scoped to it to authorize.
    const TEST_REPOSITORY: &str = "prod";

    /// A verified per-node client identity — a minted leaf, so it carries the SPIFFE node SAN
    /// naming this gateway's repository.
    fn node_identity(cn: &str) -> ClientIdentity {
        node_leaf(TEST_REPOSITORY, cn)
    }

    /// A telemetry PUT carrying a verified client identity (what `serve_tls` would inject).
    /// `identity == None` models a connection with no client cert.
    fn telemetry_request(node_path: &str, identity: Option<&str>, body: Vec<u8>) -> Request<Body> {
        telemetry_request_as(
            node_path,
            identity.map(node_identity).unwrap_or(ClientIdentity {
                common_name: None,
                node: None,
            }),
            body,
        )
    }

    fn telemetry_request_as(
        node_path: &str,
        identity: ClientIdentity,
        body: Vec<u8>,
    ) -> Request<Body> {
        let mut request = Request::builder()
            .method("PUT")
            .uri(format!("/telemetry/{node_path}"))
            .body(Body::from(body))
            .unwrap();
        request.extensions_mut().insert(identity);
        request
    }

    /// The body an agent actually PUTs: a signed DSSE envelope. Tests must send this shape, or they
    /// would pass against a record no node ever writes.
    fn envelope_body(node: &str, deployment: &str, version: &str) -> Vec<u8> {
        use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let report = updated_contracts::telemetry::NodeReport::new(
            node, deployment, DIGEST, version, DIGEST, true,
        );
        let envelope = updated_contracts::telemetry::sign_report(&report, pkcs8.as_ref()).unwrap();
        serde_json::to_vec(&envelope).unwrap()
    }

    #[tokio::test]
    async fn stores_a_well_formed_node_report() {
        let store = Arc::new(InMemory::new());
        let body = envelope_body("agent-9", "deploy-2", "2.0.0");
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
        let mismatched = envelope_body("other", "d", "1.0.0");
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
        let forged = envelope_body("agent-9", "deploy-2", "2.0.0");
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
        let report = envelope_body("agent-9", "d", "1.0.0");
        let request = telemetry_request("agent-9.json", None, report);
        let (status, _, _) = send(Arc::new(InMemory::new()), request).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    /// The shared fleet bootstrap certificate (no SPIFFE node SAN) authenticates `/enroll` and
    /// nothing else: it must not be able to write ANY node's telemetry, not even one whose name
    /// happens to equal its own CN. Steady-state authority belongs solely to minted per-node leaves.
    #[tokio::test]
    async fn the_bootstrap_certificate_cannot_write_telemetry() {
        let store = Arc::new(InMemory::new());
        let report = envelope_body("updated-agent", "deploy-2", "2.0.0");
        let bootstrap = ClientIdentity {
            common_name: Some("updated-agent".into()),
            node: None,
        };
        let request = telemetry_request_as("updated-agent.json", bootstrap, report);
        let (status, _, _) = send(store.clone(), request).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(store
            .get(&ObjectPath::from("routing/telemetry/updated-agent.json"))
            .await
            .is_err());
    }

    #[test]
    fn only_the_configured_bootstrap_identity_can_enroll() {
        let bootstrap = |cn: &str| ClientIdentity {
            common_name: Some(cn.to_owned()),
            node: None,
        };
        assert!(is_enrollment_identity(
            &bootstrap("updated-agent"),
            "updated-agent"
        ));
        assert!(!is_enrollment_identity(
            &bootstrap("ordinary-node"),
            "updated-agent"
        ));
        assert!(!is_enrollment_identity(
            &ClientIdentity {
                common_name: None,
                node: None
            },
            "updated-agent"
        ));
        assert!(!is_enrollment_identity(&bootstrap(""), ""));
        // A minted per-node leaf can never regain enrollment authority by taking the bootstrap CN.
        assert!(!is_enrollment_identity(
            &node_identity("updated-agent"),
            "updated-agent"
        ));
        assert!(is_permitted_node_name("agent-7", "updated-agent"));
        assert!(!is_permitted_node_name("updated-agent", "updated-agent"));
    }

    /// The mirror image of the enrollment gate: only a minted per-node leaf resolves to a node.
    #[test]
    fn only_a_minted_node_leaf_carries_steady_state_authority() {
        assert_eq!(
            node_identity("agent-7").node_in(TEST_REPOSITORY),
            Some("agent-7")
        );
        assert_eq!(
            ClientIdentity {
                common_name: Some("updated-agent".into()),
                node: None
            }
            .node_in(TEST_REPOSITORY),
            None
        );
    }
}
