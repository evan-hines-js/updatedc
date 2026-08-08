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

/// Upper bound on a request body. The largest legitimate body is a node's signed report envelope,
/// so this IS that bound — the shared [`updated_contracts::telemetry::MAX_REPORT_ENVELOPE_BYTES`],
/// which the writer's output-manifest allowance is derived from. Written as a derivation rather
/// than a second literal: two 64 KiB limits stated in different units (raw manifest here, base64
/// envelope there) is exactly how a healthy node ends up unable to publish at all.
const BODY_LIMIT: usize = updated_contracts::telemetry::MAX_REPORT_ENVELOPE_BYTES;

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
    /// Hex of the leaf's certified public key (its `SubjectPublicKeyInfo` bit string), in exactly
    /// the encoding `/enroll` pins onto the `UpdateAgent` — the leaf certifies the CSR's own key,
    /// so the two are byte-identical for the holder the pin was minted for. `None` on a connection
    /// with no client certificate. This is what makes a node's identity a KEY and not merely a
    /// name: the handshake proved possession of it, so comparing it to the pin distinguishes the
    /// machine that holds the name now from a previous holder of a re-enrolled name.
    public_key: Option<String>,
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

/// Extract the leaf certificate's identity — Common Name, SPIFFE node SAN and certified public
/// key — from a completed server-side TLS connection.
fn peer_identity(conn: &tokio_rustls::rustls::ServerConnection) -> ClientIdentity {
    use x509_parser::extensions::GeneralName;

    let anonymous = ClientIdentity {
        common_name: None,
        node: None,
        public_key: None,
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
        // The key the handshake proved possession of, encoded exactly as `/enroll` pinned it.
        public_key: Some(hex::encode(&*cert.public_key().subject_public_key.data)),
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

/// How often the gateway rebuilds the configuration it was started with: its mounted certificate
/// material and its object store.
///
/// Every one of these files is a cert-manager Secret that is rotated IN PLACE, on the issuer's
/// schedule, with no restart of this process. Loading them once means the gateway keeps presenting
/// a certificate that eventually expires — at which point every agent's handshake fails and the
/// whole fleet loses metadata, telemetry, and enrollment at the same moment. Object-store
/// credentials rotate the same way and expire far faster when they are temporary.
const MATERIAL_RELOAD_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// A value rebuilt from its source while the gateway runs. Readers take the current value; a
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

/// Where this gateway reads and writes: the configured object store and the key prefix below which
/// this repository's objects live. The two travel together because they are one configuration —
/// serving objects from a rebuilt store under the previous prefix would read another repository's
/// key space — so a handler snapshots the pair once and uses that snapshot for the whole request.
struct Destination {
    store: Arc<dyn ObjectStore>,
    prefix: Arc<str>,
}

/// Store + prefix — everything the repository handler needs. The data router derives it (via
/// [`FromRef`]), so that handler requires no Kubernetes context and stays trivially testable. The
/// repository NAME is not here: it is an authorization input every handler that needs it already
/// holds on its `EnrollmentContext`, and one copy of it is the only way it cannot drift.
#[derive(Clone)]
struct ContentState {
    /// Rebuilt on a timer from the `UpdateRepository` and its credentials Secret, exactly as the
    /// controller rebuilds it every reconcile. The credentials are baked into the `ObjectStore` at
    /// construction, so a store built once at start-up serves a rotated key — or an STS session
    /// token — until it expires and then answers every request with a 502 while the repository
    /// still reports Ready.
    destination: Arc<Reloadable<Destination>>,
}

impl ContentState {
    fn destination(&self) -> Arc<Destination> {
        self.destination.get()
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

/// The label a Secret must carry, set to exactly `"true"`, before this gateway will hand any of it
/// to a node.
///
/// Deny by default, and deliberately an opt-in on the SECRET rather than a naming convention on the
/// reference: an assignment names its Secrets from `deployment.runtime.secrets`, which anyone with
/// `create`/`update` on `updategroups.updated.dev` writes — a verb that does not imply `get` on
/// Secrets. A rule those callers can satisfy on their own is not a gate. Labelling the Secret
/// requires Secret access, so marking one distributable is a decision only someone who could
/// already read it can make.
const DISTRIBUTABLE_LABEL: &str = "updated.dev/fleet-distributable";

/// The annotation cert-manager stamps on every Secret it issues. The fleet CA (whose key mints
/// every node leaf) and this gateway's own serving key are cert-manager Secrets in this very
/// namespace, so they are refused whatever labels they carry — a label is copyable from a
/// `Certificate` template, and no key that authenticates the fleet may ever be fleet-distributable.
const CERT_MANAGER_ANNOTATION: &str = "cert-manager.io/certificate-name";

/// This API group. Secrets the control plane publishes for its own use — the per-agent enrollment
/// bundles — are owned by an `updated.dev` object, so ownership is the marker that refuses them.
const CONTROL_PLANE_API_GROUP: &str = "updated.dev/";

#[derive(Debug, PartialEq, Eq)]
enum SecretError {
    /// The Secret (or the key within it) could not be read. Transient from the node's point of
    /// view: the operator may not have created it yet.
    Unavailable,
    /// The Secret was found but this control plane must not distribute it. A misconfiguration, not
    /// a race — retrying changes nothing until an operator marks the Secret distributable.
    Forbidden,
}

#[async_trait::async_trait]
trait SecretStore: Send + Sync {
    async fn value(&self, name: &str, key: &str) -> Result<Vec<u8>, SecretError>;
}

#[derive(Clone)]
struct KubernetesSecretStore {
    client: Client,
    namespace: String,
    /// The Secrets this repository's own trust depends on: its TUF signing keys and its object-store
    /// credentials. Named from the `UpdateRepository` rather than guessed, and refused before the
    /// read, so the control plane's own key material can never satisfy the predicate even if
    /// someone labels it.
    reserved: Vec<String>,
}

impl KubernetesSecretStore {
    /// The store a node's secret bundle is resolved through. The only constructor, so the reserved
    /// list can never be omitted at a call site: an empty one would make the repository's own
    /// signing keys and object-store credentials readable by any node whose assignment names them.
    fn for_repository(
        client: Client,
        namespace: String,
        repository: &crate::UpdateRepository,
    ) -> Self {
        Self {
            client,
            namespace,
            reserved: reserved_secrets(repository),
        }
    }
}

#[async_trait::async_trait]
impl SecretStore for KubernetesSecretStore {
    async fn value(&self, name: &str, key: &str) -> Result<Vec<u8>, SecretError> {
        if self.reserved.iter().any(|reserved| reserved == name) {
            return Err(SecretError::Forbidden);
        }
        let secret = Api::<Secret>::namespaced(self.client.clone(), &self.namespace)
            .get(name)
            .await
            .map_err(|_| SecretError::Unavailable)?;
        if !is_fleet_distributable(&secret) {
            return Err(SecretError::Forbidden);
        }
        secret
            .data
            .and_then(|data| data.get(key).cloned())
            .map(|value| value.0)
            .ok_or(SecretError::Unavailable)
    }
}

/// Whether this Secret has been explicitly published to the fleet.
///
/// Every clause is a refusal; there is no path that serves a Secret nobody opted in. The opt-in
/// label is the gate, and the two exclusions below cover the material the control plane's own
/// identity rests on — key material that must not become distributable by mislabelling.
fn is_fleet_distributable(secret: &Secret) -> bool {
    let labelled = secret
        .metadata
        .labels
        .as_ref()
        .and_then(|labels| labels.get(DISTRIBUTABLE_LABEL))
        .is_some_and(|value| value == "true");
    let cert_manager_issued = secret
        .metadata
        .annotations
        .as_ref()
        .is_some_and(|annotations| annotations.contains_key(CERT_MANAGER_ANNOTATION));
    let control_plane_owned = secret
        .metadata
        .owner_references
        .as_ref()
        .is_some_and(|owners| {
            owners
                .iter()
                .any(|owner| owner.api_version.starts_with(CONTROL_PLANE_API_GROUP))
        });
    labelled && !cert_manager_issued && !control_plane_owned
}

/// The Secrets that hold this repository's own signing keys and object-store credentials, refused
/// by name before any read.
fn reserved_secrets(repository: &crate::UpdateRepository) -> Vec<String> {
    let mut names = vec![repository.spec.signing_secret_ref.name.clone()];
    names.extend(
        repository
            .spec
            .s3
            .credentials_secret_ref
            .iter()
            .map(|reference| reference.name.clone()),
    );
    names
}

impl FromRef<DataState> for ContentState {
    fn from_ref(state: &DataState) -> Self {
        state.content.clone()
    }
}

/// What a telemetry write needs: the destination to store the report in, plus the Kubernetes context
/// to re-check that the writing node is still an enrolled member of this repository. A minted leaf
/// outlives the object that justified it, so the certificate alone is not authorization — the same
/// reason `/bundle`, `/renew` and `/v1/node/secrets` all resolve the `UpdateAgent` first.
#[derive(Clone)]
struct TelemetryState {
    content: ContentState,
    enrollment: EnrollmentContext,
}

impl FromRef<DataState> for TelemetryState {
    fn from_ref(state: &DataState) -> Self {
        Self {
            content: state.content.clone(),
            enrollment: state.enrollment.clone(),
        }
    }
}

fn data_router(state: DataState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/enroll", post(enroll))
        .route("/renew", post(renew))
        .route("/bundle", post(bundle))
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
    /// The assignment names a Secret this control plane will not distribute. Answered separately
    /// from `Unavailable` so the refusal is not read as "not created yet" and retried forever.
    Forbidden,
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
        // The whole bundle fails on a refused reference rather than dropping that entry: a node
        // handed a bundle silently missing one value starts its application with the environment
        // half-configured, and the operator sees a healthy rollout.
        let bytes = store
            .value(&reference.secret, &reference.key)
            .await
            .map_err(|error| match error {
                SecretError::Unavailable => SecretBundleError::Unavailable,
                SecretError::Forbidden => {
                    tracing::warn!(
                        deployment = %assignment.deployment,
                        secret = %reference.secret,
                        environment = %reference.environment,
                        "refusing to distribute a Secret this deployment references: it is not \
                         labelled {DISTRIBUTABLE_LABEL}=true, or it is control-plane key material. \
                         Label the Secret to publish it to the fleet."
                    );
                    SecretBundleError::Forbidden
                }
            })?;
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
    let Some(node) = identity.node_in(&state.enrollment.repository) else {
        return StatusCode::FORBIDDEN.into_response();
    };
    // The certificate says who the caller is; the `UpdateAgent` object says whether it is still one
    // of ours, and whether the key this connection proved possession of is the one that name is
    // pinned to. A leaf outlives the object that justified it (up to `LEAF_CERT_TTL_DAYS`), so a
    // decommissioned, re-homed or superseded node kept reading its deployment's database passwords
    // and API tokens from here for as long as no new generation was published — while `/renew`,
    // which gates on the same pin, answered 403. The endpoint that returns actual secrets applies
    // the same check as the one that mints certificates.
    let agents: Api<crate::UpdateAgent> =
        Api::namespaced(state.enrollment.client.clone(), &state.enrollment.namespace);
    let Ok(agent) = agents.get(node).await else {
        return StatusCode::FORBIDDEN.into_response();
    };
    if !is_pinned_leaf(&identity, &agent, &state.enrollment.repository) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let repositories: Api<crate::UpdateRepository> =
        Api::namespaced(state.enrollment.client.clone(), &state.enrollment.namespace);
    let Ok(repository) = repositories.get(&state.enrollment.repository).await else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let assignment = updated_contracts::telemetry::assignment_object_key(
        &repository.spec.assignment_prefix,
        node,
    );
    let Some(trust_anchor) = published_root_sha256(&repository) else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
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
    let store = KubernetesSecretStore::for_repository(
        state.enrollment.client.clone(),
        state.enrollment.namespace.clone(),
        &repository,
    );
    let bundle = match resolve_secret_bundle(&assignment, &store).await {
        Ok(bundle) => bundle,
        Err(SecretBundleError::Unavailable) => {
            return StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
        Err(SecretBundleError::Invalid) => return StatusCode::BAD_GATEWAY.into_response(),
        Err(SecretBundleError::Forbidden) => return StatusCode::FORBIDDEN.into_response(),
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

    let destination = Arc::new(Reloadable::new(Destination {
        store,
        prefix: Arc::from(prefix),
    }));
    tokio::spawn(reload_destination(
        enrollment.client.clone(),
        enrollment.namespace.clone(),
        enrollment.repository.clone(),
        destination.clone(),
    ));
    let content = ContentState { destination };
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

/// Rebuild the object store forever, on the same timer and with the same fail-safe rule as the
/// certificate material: a build that fails leaves the working store live.
///
/// Object-store credentials are baked in at construction — deliberately, since
/// `runtime::repository_store` is also the credential-resolution path the controller uses — so
/// nothing about a live store follows a rotated key or a renewed STS session token. The controller
/// rebuilt per reconcile and the gateway never did, which is the whole asymmetry: with one-hour
/// temporary credentials the entire data plane began answering 502 after an hour while the
/// `UpdateRepository` still reported Ready. Rebuilding unconditionally (rather than diffing the
/// spec) keeps this to one code path, and it picks up a changed `destination.prefix` with it. The
/// hot path is untouched: handlers read one `Arc` clone per request.
async fn reload_destination(
    client: Client,
    namespace: String,
    repository: String,
    destination: Arc<Reloadable<Destination>>,
) {
    loop {
        tokio::time::sleep(MATERIAL_RELOAD_INTERVAL).await;
        rebuild_destination(&client, &namespace, &repository, &destination).await;
    }
}

/// One rebuild, with the fail-safe: a store that cannot be built leaves the live one serving.
/// Separate from the timer above so the rule is testable — a rebuild that swapped in nothing on
/// failure would take the data plane down for a transient apiserver blip.
async fn rebuild_destination(
    client: &Client,
    namespace: &str,
    repository: &str,
    destination: &Reloadable<Destination>,
) {
    match crate::runtime::repository_store(client.clone(), namespace, repository).await {
        Ok((configured, store)) => destination.set(Destination {
            store,
            prefix: Arc::from(configured.prefix),
        }),
        Err(error) => {
            tracing::warn!(%error, "rebuilding the repository object store failed; keeping the loaded one")
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
        Ok((bundle, leaf)) => {
            Json(updated_contracts::enrollment::EnrollResponse { leaf, bundle }).into_response()
        }
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
        .node_in(&state.enrollment.repository)
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
            Json(updated_contracts::enrollment::RenewalResponse { leaf }).into_response()
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
fn is_pinned_leaf(identity: &ClientIdentity, agent: &crate::UpdateAgent, repository: &str) -> bool {
    identity
        .public_key
        .as_deref()
        .is_some_and(|public_key| is_pinned_identity(agent, repository, public_key))
}

/// Whether this repository already holds as many agents as it will enrol, read from the count the
/// controller publishes on its status every successful reconcile.
///
/// A repository whose status has not been written yet has published nothing, so it holds no agents
/// and enrollment proceeds. While reconciles succeed the count is at most one of them (a second)
/// stale, which bounds the overshoot at whatever a second of enrollments can add — orders of
/// magnitude below the headroom the ceiling leaves. While they FAIL it freezes at the last
/// successful count rather than disappearing: a failed pass omits what it cannot know instead of
/// nulling it (see [`crate::UpdateRepositoryStatus`]), because an S3 outage or a lost lease is
/// exactly when an uncapped `/enroll` does the most damage.
fn at_enrollment_capacity(repository: &crate::UpdateRepository) -> bool {
    repository
        .status
        .as_ref()
        .and_then(|status| status.agent_count)
        .is_some_and(|count| count >= crate::runtime::MAX_ENROLLED_AGENTS)
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
            hold: false,
            cordon: false,
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
    // Growth is bounded here because this is the only place a caller can create agents, and the
    // fleet-wide bootstrap certificate is all it takes to reach it. The count comes from the
    // repository status the controller already publishes each reconcile, so the check costs
    // nothing on the ordinary path; the extra read happens only at the ceiling, and only to let an
    // ALREADY-enrolled node through — a full fleet must still be able to re-enrol and renew.
    if at_enrollment_capacity(&repository) {
        let existing = agents.get_opt(name).await;
        match existing {
            Ok(Some(_)) => {}
            Ok(None) => {
                tracing::warn!(
                    node = %name,
                    repository = %context.repository,
                    limit = crate::runtime::MAX_ENROLLED_AGENTS,
                    "refusing enrollment: this repository is at its agent ceiling. Split the fleet \
                     across UpdateRepositories, or remove decommissioned UpdateAgents."
                );
                return Err(StatusCode::TOO_MANY_REQUESTS.into_response());
            }
            Err(_) => return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response()),
        }
    }
    if let Err(status) = create_agent_idempotent(&agents, name, &desired, matches).await {
        return Err(status.into_response());
    }
    let leaf = state
        .ca
        .get()
        .sign_client_csr(&context.repository, name, csr)
        .map_err(|_| StatusCode::BAD_REQUEST.into_response())?;
    let bundle = current_bundle(state, &repository, name).await?;
    Ok((bundle, leaf))
}

/// Resolve the enrollment bundle for `name` as of NOW: the repository's currently published signed
/// metadata chain, the agent's routing assignment, and the managed configuration it signs.
///
/// Enrollment and [`bundle`] share it, so a node that re-fetches its bundle receives exactly what a
/// node enrolling this instant would — there is no second, drifting notion of "the initial signed
/// configuration", and no way for the refresh path to hand out material the enrollment path would
/// refuse to.
async fn current_bundle(
    state: &DataState,
    repository: &crate::UpdateRepository,
    name: &str,
) -> Result<crate::EnrollmentBundle, Response> {
    let assignment = updated_contracts::telemetry::assignment_object_key(
        &repository.spec.assignment_prefix,
        name,
    );
    // The consistent-snapshot metadata walk is shared with the operator's enrollment-Secret
    // publisher so this security-sensitive resolution lives in exactly one place. A newly
    // registered agent can legitimately race publication: an object that is not there yet is
    // `Unavailable` (503, retry), while a present-but-malformed document is `Malformed` (502).
    let trust_anchor = published_root_sha256(repository)
        .ok_or_else(|| StatusCode::SERVICE_UNAVAILABLE.into_response())?;
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
        Err(error) => return Err(error.status_code().into_response()),
    };
    Ok(signed.into_bundle(name.to_string(), &state.enrollment.public_url, assignment))
}

/// Re-issue an already-enrolled node's enrollment bundle.
///
/// Authorization is the same steady-state rule `/renew` applies: the connection must present a
/// per-node leaf scoped to THIS repository, and the `UpdateAgent` it names must still be an enrolled
/// member of it. The shared fleet bootstrap certificate carries no node identity, so it cannot reach
/// here — it mints leaves at `/enroll` and nothing else.
///
/// Nothing is minted, created or mutated: this is a read of the material the node is already
/// entitled to, under the name its own certificate proves. It needs no CSR — the key comes from the
/// leaf the handshake already proved possession of — but it does need that key to still be the one
/// the name is pinned to, or a superseded holder of a re-enrolled name would be re-issued the
/// replacement's bundle.
async fn bundle(
    State(state): State<DataState>,
    Extension(identity): Extension<ClientIdentity>,
) -> Response {
    let Some(name) = identity
        .node_in(&state.enrollment.repository)
        .map(str::to_owned)
    else {
        return StatusCode::FORBIDDEN.into_response();
    };
    let context = &state.enrollment;
    let agents: Api<crate::UpdateAgent> =
        Api::namespaced(context.client.clone(), &context.namespace);
    let Ok(agent) = agents.get(&name).await else {
        return StatusCode::FORBIDDEN.into_response();
    };
    // A decommissioned (deleted), re-homed or superseded agent stops receiving bundles the moment
    // the object says so, even while its unexpired leaf still authenticates.
    if !is_pinned_leaf(&identity, &agent, &context.repository) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let repositories: Api<crate::UpdateRepository> =
        Api::namespaced(context.client.clone(), &context.namespace);
    let Ok(repository) = repositories.get(&context.repository).await else {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    };
    match current_bundle(&state, &repository, &name).await {
        Ok(bundle) => Json(bundle).into_response(),
        Err(response) => response,
    }
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
/// The `UpdateAgent` that leaf names must ALSO still be an enrolled member of this repository, the
/// same rule `/bundle`, `/renew` and `/v1/node/secrets` apply: a leaf outlives the object that
/// justified it, so a decommissioned or re-homed node keeps a usable certificate for the rest of its
/// 90-day life, and one object per node is all there is — its stale write would overwrite the report
/// the node that holds the name now is signing.
async fn telemetry_put(
    State(state): State<TelemetryState>,
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
    if identity.node_in(&state.enrollment.repository) != Some(node) {
        return StatusCode::FORBIDDEN.into_response();
    }
    // A report travels as a DSSE envelope. The gateway does NOT verify its signature — it authorizes by
    // the mTLS leaf above, and the signature is end-to-end evidence for the consumers that read the
    // stored bytes back. `accept_report_envelope` is the one shared write-side gate: well-formed
    // envelope, bounded signature count, and a payload that names the node it is being stored under.
    // Storing a record that fails it strands the node — every consumer discards the report, the
    // planner reads the node as silent, and it holds a `maxUnavailable` slot until someone notices —
    // so it is refused at the door, where the writer still learns about it.
    if updated_contracts::telemetry::accept_report_envelope(&body, node).is_none() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    // The object half of the authorization, resolved through the same `UpdateAgent` read every
    // other node-authenticated route uses. It runs after the local checks above so a malformed body
    // costs no apiserver request, and before anything is written, so a decommissioned, re-homed or
    // superseded agent stops being able to store a report the moment the object says so rather than
    // when its certificate finally expires.
    //
    // Only a definitive answer refuses. The hole this closes is a stale leaf outliving its object,
    // and the apiserver names that case exactly: a 404, or an object that is not this leaf's pinned
    // identity in this repository. Every other failure — connection refused, 5xx, throttling — says
    // nothing about membership, and refusing on it would couple the telemetry path to apiserver
    // availability: reports are best-effort and never retried, and `updated-healthproxy` drains a
    // backend whose report is older than `REPORT_FRESHNESS`, so an apiserver blip outlasting that
    // window would stop every node's report at once and drain the whole fleet of healthy backends.
    // So on an indefinite failure we fail open and accept on the strength of the verified mTLS leaf
    // alone, which was the sole authority here before the membership check existed.
    let context = &state.enrollment;
    let agents: Api<crate::UpdateAgent> =
        Api::namespaced(context.client.clone(), &context.namespace);
    match agents.get(node).await {
        Ok(agent) => {
            if !is_pinned_leaf(&identity, &agent, &context.repository) {
                return StatusCode::FORBIDDEN.into_response();
            }
        }
        Err(kube::Error::Api(error)) if error.code == 404 => {
            return StatusCode::FORBIDDEN.into_response()
        }
        Err(error) => {
            tracing::warn!(
                %error,
                %node,
                "reading the agent for a telemetry write failed; accepting on the client certificate alone"
            );
        }
    }
    let destination = state.content.destination();
    let key = crate::object_key(
        &destination.prefix,
        &updated_contracts::telemetry::report_object_key(node),
    );
    match timeout(
        IO_TIMEOUT,
        destination
            .store
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
    let destination = state.destination();
    let Some(key) = repository_key(&destination.prefix, uri.path()) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let range = match parse_range(&headers) {
        Ok(range) => range,
        Err(()) => return StatusCode::BAD_REQUEST.into_response(),
    };
    if let Some(range) = &range {
        let metadata = match timeout(IO_TIMEOUT, destination.store.head(&key)).await {
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
    let result = match timeout(IO_TIMEOUT, destination.store.get_opts(&key, options)).await {
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

/// The four TUF role documents of one published generation.
///
/// Every agent in a generation pins the SAME four, and `targets.json` alone carries an entry per
/// published agent — so it is O(fleet) on its own. Owning a copy of it per agent made the verified
/// enrollment cache O(fleet²) resident, tens of gigabytes at the documented `MAX_ENROLLED_AGENTS`
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
            routing_root: self.metadata.root.clone(),
            initial: crate::InitialSignedConfiguration {
                timestamp: self.metadata.timestamp.clone(),
                snapshot: self.metadata.snapshot.clone(),
                targets: self.metadata.targets.clone(),
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
    if !updated::hash::digests_match(
        &updated::hash::sha256_bytes(root.as_bytes()),
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
    let parsed: updated_contracts::artifact::AgentDocument = serde_json::from_str(&agent_document)
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
    updated_tuf::verify_embedded_assignment(&resolved.clone().into_bundle(
        "verification".into(),
        "https://verification.invalid",
        assignment.to_string(),
    ))
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
/// at which `verify_embedded_assignment` would start rejecting this chain.
///
/// The metadata chain is identical for every agent in a generation, so this is a property of the
/// generation and is stored once alongside its key. `None` when any role's expiry is missing or
/// unparseable, which makes the chain uncacheable rather than cacheable forever.
fn chain_expiry(metadata: &SignedMetadata) -> Option<chrono::DateTime<chrono::Utc>> {
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
///
/// The generation's four ROLE DOCUMENTS are stored the same way, once beside the key, for the same
/// reason and one harder one: `targets.json` carries an entry per published agent, so a per-agent
/// copy of it makes this map O(fleet²) BYTES — the gateway is OOM-killed at its own supported fleet
/// size, precisely in the steady state (nothing publishing, so nothing evicting) the cache exists to
/// serve. An entry holds only what is genuinely per-agent.
#[derive(Default)]
struct Generation {
    key: String,
    expires: Option<chrono::DateTime<chrono::Utc>>,
    /// This generation's role documents, shared by every entry below. `None` only before the first
    /// insert into a fresh generation.
    metadata: Option<std::sync::Arc<SignedMetadata>>,
    entries: std::collections::HashMap<String, AgentDocuments>,
}

/// The part of a verified enrollment that is genuinely per-agent: its signed assignment document
/// and the managed configuration that document names.
#[derive(Clone)]
struct AgentDocuments {
    agent_document: String,
    managed_configuration: String,
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
        let metadata = guard.metadata.as_ref()?;
        let entry = guard.entries.get(assignment)?;
        Some(SignedEnrollment {
            metadata: std::sync::Arc::clone(metadata),
            agent_document: entry.agent_document.clone(),
            managed_configuration: entry.managed_configuration.clone(),
        })
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
    // The grammar — which paths name a repository object — is `crate::served`'s, shared with the
    // dev CDN so the two servers an agent cannot tell apart accept exactly the same requests.
    let object = crate::served::repository_object(request_path)?;
    // The endpoint projection (`endpoints/`) is deliberately NOT served here: this is the mTLS
    // data listener, and the healthproxy — the projection's one reader — holds no fleet client
    // certificate. It reads the projection from the CDN/object store base, where the dev CDN
    // serves it beside the telemetry namespace.
    if !matches!(object.namespace, "metadata" | "targets") {
        return None;
    }
    Some(crate::object_key(prefix, &object.key()))
}

/// The object store's spelling of a parsed [`crate::served::ByteRange`]: it takes the bounded
/// shape as a half-open range, so the inclusive end becomes `end + 1`.
fn range_of(range: crate::served::ByteRange) -> GetRange {
    match range {
        crate::served::ByteRange::Offset(start) => GetRange::Offset(start),
        crate::served::ByteRange::Bounded { start, end } => {
            GetRange::Bounded(start..end.saturating_add(1))
        }
        crate::served::ByteRange::Suffix(n) => GetRange::Suffix(n),
    }
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
    let range = crate::served::parse_range_value(value).ok_or(())?;
    Ok(Some(range_of(range)))
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
                hold: false,
                cordon: false,
            },
        )
    }

    /// The key a test node's leaf certifies, hex as `peer_identity` encodes it.
    const TEST_LEAF_KEY: &str = "04a1b2c3";

    fn node_leaf(repository: &str, node: &str) -> ClientIdentity {
        node_leaf_keyed(repository, node, TEST_LEAF_KEY)
    }

    /// A minted node leaf certifying `public_key` — the previous holder of a re-enrolled name holds
    /// a leaf identical to the replacement's but for this.
    fn node_leaf_keyed(repository: &str, node: &str, public_key: &str) -> ClientIdentity {
        ClientIdentity {
            common_name: Some(node.into()),
            node: Some(crate::join::NodeSpiffeId {
                repository: repository.into(),
                node: node.into(),
            }),
            public_key: Some(public_key.into()),
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
            public_key: Some(TEST_LEAF_KEY.into()),
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

    /// The certificate-authenticated routes present no key in their body, so the gate reads it off
    /// the connection's leaf: it must refuse exactly what renewal refuses, and never merely trust
    /// that the connection authenticated.
    #[test]
    fn a_certificate_authenticated_route_requires_the_leaf_s_own_pinned_identity() {
        let enrolled = renewal_agent(crate::AgentIdentityKind::Enrolled, "repo", Some("key"));
        assert!(is_pinned_leaf(
            &node_leaf_keyed("repo", "n", "key"),
            &enrolled,
            "repo"
        ));
        // Re-provisioning a machine under its existing hostname deletes the `UpdateAgent` and lets
        // the replacement enroll fresh, pinning a NEW key to the SAME name. The previous holder's
        // leaf still authenticates for the rest of its 90-day life and there is no revocation path,
        // so the pin is the only thing that stops it reading the replacement's secrets, bundle and
        // telemetry slot.
        assert!(!is_pinned_leaf(
            &node_leaf_keyed("repo", "n", "superseded-key"),
            &enrolled,
            "repo"
        ));
        // The fleet CA is shared across repositories, so a leaf minted by another repository's
        // `/enroll` authenticates here and must still be refused this repository's material.
        assert!(!is_pinned_leaf(
            &node_leaf_keyed("repo", "n", "key"),
            &renewal_agent(crate::AgentIdentityKind::Enrolled, "other", Some("key")),
            "repo"
        ));
        // An operator-declared node never enrolled, so nothing here was ever issued to it.
        assert!(!is_pinned_leaf(
            &node_leaf_keyed("repo", "n", "key"),
            &renewal_agent(crate::AgentIdentityKind::Manual, "repo", Some("key")),
            "repo"
        ));
        assert!(!is_pinned_leaf(
            &node_leaf_keyed("repo", "n", "key"),
            &renewal_agent(crate::AgentIdentityKind::Reserved, "repo", None),
            "repo"
        ));
        // A connection with no client certificate carries no key and authorizes nothing.
        assert!(!is_pinned_leaf(
            &ClientIdentity {
                common_name: None,
                node: None,
                public_key: None,
            },
            &enrolled,
            "repo"
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

    /// The distribution gate stands in front of this store, so what it holds is by definition
    /// already fleet-distributable; `forbidden` names the Secrets that gate refused.
    struct MemorySecrets {
        values: std::collections::BTreeMap<(String, String), Vec<u8>>,
        forbidden: std::collections::BTreeSet<String>,
        calls: std::sync::Mutex<Vec<(String, String)>>,
    }

    #[async_trait::async_trait]
    impl SecretStore for MemorySecrets {
        async fn value(&self, name: &str, key: &str) -> Result<Vec<u8>, SecretError> {
            self.calls
                .lock()
                .unwrap()
                .push((name.to_owned(), key.to_owned()));
            if self.forbidden.contains(name) {
                return Err(SecretError::Forbidden);
            }
            self.values
                .get(&(name.to_owned(), key.to_owned()))
                .cloned()
                .ok_or(SecretError::Unavailable)
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
            forbidden: Default::default(),
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
                forbidden: Default::default(),
                calls: std::sync::Mutex::new(Vec::new()),
            };
            assert!(resolve_secret_bundle(&assignment, &store).await.is_err());
        }
    }

    fn labelled_secret(name: &str) -> Secret {
        Secret {
            metadata: kube::api::ObjectMeta {
                name: Some(name.into()),
                labels: Some(std::collections::BTreeMap::from([(
                    DISTRIBUTABLE_LABEL.to_string(),
                    "true".to_string(),
                )])),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn only_a_secret_explicitly_published_to_the_fleet_is_distributable() {
        // The threat this closes: `deployment.runtime.secrets` is written by anyone with
        // create/update on updategroups.updated.dev, which does NOT imply get on Secrets. Without
        // an opt-in only a Secret holder can set, such a caller could point an assignment at the
        // fleet CA key, the TUF signing keys, or the object-store credentials — all of which live
        // in this same namespace — and read them out with an ordinary node certificate.
        assert!(is_fleet_distributable(&labelled_secret("app-config")));

        let mut unlabelled = labelled_secret("fleet-ca");
        unlabelled.metadata.labels = None;
        assert!(
            !is_fleet_distributable(&unlabelled),
            "deny by default: an unlabelled Secret is never served"
        );

        let mut other_value = labelled_secret("app-config");
        other_value.metadata.labels = Some(std::collections::BTreeMap::from([(
            DISTRIBUTABLE_LABEL.to_string(),
            "yes".to_string(),
        )]));
        assert!(
            !is_fleet_distributable(&other_value),
            "the opt-in is the exact value \"true\", not merely the label's presence"
        );

        // The fleet CA whose key mints every node leaf is a cert-manager Secret in this namespace.
        // A label is copyable from a Certificate's secretTemplate, so issuance is disqualifying on
        // its own.
        let mut issued = labelled_secret("fleet-ca");
        issued.metadata.annotations = Some(std::collections::BTreeMap::from([(
            CERT_MANAGER_ANNOTATION.to_string(),
            "fleet-ca".to_string(),
        )]));
        assert!(!is_fleet_distributable(&issued));

        // The per-agent enrollment Secrets the control plane publishes are owned by an updated.dev
        // object; one node must not be able to read another's bundle through its own assignment.
        let mut owned = labelled_secret("node-a-enrollment");
        owned.metadata.owner_references = Some(vec![
            k8s_openapi::apimachinery::pkg::apis::meta::v1::OwnerReference {
                api_version: "updated.dev/v1alpha1".into(),
                kind: "UpdateRepository".into(),
                name: "fleet".into(),
                ..Default::default()
            },
        ]);
        assert!(!is_fleet_distributable(&owned));
    }

    #[test]
    fn the_repositorys_own_signing_and_storage_secrets_are_reserved() {
        let mut spec = crate::tests::repository();
        spec.s3.credentials_secret_ref = Some(crate::LocalSecretReference {
            name: "s3-credentials".into(),
        });
        let repository = crate::UpdateRepository::new("fleet", spec);
        assert_eq!(
            reserved_secrets(&repository),
            vec!["tuf-signing-keys".to_string(), "s3-credentials".to_string()],
            "the keys that sign the fleet's metadata and the credentials that write its objects \
             are refused before they are even read, whatever they are labelled"
        );
    }

    #[tokio::test]
    async fn the_store_a_node_reads_through_applies_both_refusals() {
        // The predicates are unit-tested above; this is the wiring that applies them — the only
        // place a node's read of a Secret actually happens. Without it, deleting either refusal
        // from `value` left every other test in this file green while reopening an arbitrary
        // Secret read to anyone holding a node certificate.
        let read: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
        let client = crate::tests::apiserver({
            let read = read.clone();
            move |_method: &axum::http::Method, path: &str, _body: Vec<u8>| {
                let name = path.rsplit('/').next().expect("a named Secret").to_string();
                read.lock().unwrap().push(name.clone());
                let mut secret = labelled_secret(&name);
                secret.data = Some(std::collections::BTreeMap::from([(
                    "token".to_string(),
                    k8s_openapi::ByteString(b"value".to_vec()),
                )]));
                match name.as_str() {
                    "plain" => secret.metadata.labels = None,
                    "fleet-ca" => {
                        secret.metadata.annotations = Some(std::collections::BTreeMap::from([(
                            CERT_MANAGER_ANNOTATION.to_string(),
                            "fleet-ca".to_string(),
                        )]))
                    }
                    "missing" => {
                        return (
                            StatusCode::NOT_FOUND,
                            serde_json::json!({"kind": "Status", "code": 404}),
                        )
                    }
                    _ => {}
                }
                (StatusCode::OK, serde_json::to_value(secret).unwrap())
            }
        });
        let mut spec = crate::tests::repository();
        spec.s3.credentials_secret_ref = Some(crate::LocalSecretReference {
            name: "s3-credentials".into(),
        });
        let store = KubernetesSecretStore::for_repository(
            client,
            "fleet-system".into(),
            &crate::UpdateRepository::new("fleet", spec),
        );

        assert_eq!(
            store.value("app-config", "token").await,
            Ok(b"value".into())
        );
        assert_eq!(
            store.value("app-config", "absent").await,
            Err(SecretError::Unavailable)
        );
        assert_eq!(
            store.value("plain", "token").await,
            Err(SecretError::Forbidden),
            "deny by default: the opt-in label is the gate"
        );
        assert_eq!(
            store.value("fleet-ca", "token").await,
            Err(SecretError::Forbidden),
            "a cert-manager Secret is refused however it is labelled"
        );
        assert_eq!(
            store.value("missing", "token").await,
            Err(SecretError::Unavailable)
        );

        // Reserved names are refused BEFORE the read — the control plane's own key material is
        // never even fetched, so no code path exists on which it could be returned.
        for reserved in ["tuf-signing-keys", "s3-credentials"] {
            assert_eq!(
                store.value(reserved, "token").await,
                Err(SecretError::Forbidden)
            );
        }
        assert_eq!(
            *read.lock().unwrap(),
            vec!["app-config", "app-config", "plain", "fleet-ca", "missing"],
        );
    }

    #[test]
    fn enrollment_stops_at_the_repositorys_agent_ceiling() {
        // `/enroll` is authorized by the fleet-wide bootstrap certificate and the node names
        // itself, so unbounded creation let one caller grow the durable rollout state past the
        // apiserver's object limit — after which NO generation publishes again, for any node.
        let with_agents = |count: Option<u32>| {
            let mut repository = crate::UpdateRepository::new("fleet", crate::tests::repository());
            repository.status = Some(crate::UpdateRepositoryStatus {
                agent_count: count,
                ..Default::default()
            });
            repository
        };
        assert!(!at_enrollment_capacity(&with_agents(Some(
            crate::runtime::MAX_ENROLLED_AGENTS - 1
        ))));
        assert!(at_enrollment_capacity(&with_agents(Some(
            crate::runtime::MAX_ENROLLED_AGENTS
        ))));
        assert!(at_enrollment_capacity(&with_agents(Some(
            crate::runtime::MAX_ENROLLED_AGENTS + 1
        ))));
        assert!(
            !at_enrollment_capacity(&with_agents(None)),
            "a repository that has never published holds no agents"
        );
        let mut unpublished = crate::UpdateRepository::new("fleet", crate::tests::repository());
        unpublished.status = None;
        assert!(!at_enrollment_capacity(&unpublished));
    }

    #[tokio::test]
    async fn a_refused_secret_fails_the_whole_bundle_rather_than_arriving_empty() {
        let mut assignment = secret_assignment();
        assignment.runtime.secrets = vec![
            updated_contracts::assignment::SecretReference {
                environment: "TOKEN".into(),
                secret: "app-config".into(),
                key: "token".into(),
            },
            updated_contracts::assignment::SecretReference {
                environment: "CA_KEY".into(),
                secret: "fleet-ca".into(),
                key: "tls.key".into(),
            },
        ];
        let store = MemorySecrets {
            values: std::collections::BTreeMap::from([
                (("app-config".into(), "token".into()), b"value".to_vec()),
                (("fleet-ca".into(), "tls.key".into()), b"private".to_vec()),
            ]),
            forbidden: std::collections::BTreeSet::from(["fleet-ca".to_string()]),
            calls: std::sync::Mutex::new(Vec::new()),
        };
        assert!(matches!(
            resolve_secret_bundle(&assignment, &store).await,
            Err(SecretBundleError::Forbidden)
        ));
    }

    fn content_state(store: Arc<InMemory>) -> ContentState {
        ContentState {
            destination: Arc::new(Reloadable::new(Destination {
                store,
                prefix: Arc::from("routing"),
            })),
        }
    }

    /// An `UpdateAgent` object as the apiserver would return it: an enrolled member of the
    /// repository this test gateway serves.
    fn enrolled_agent(name: &str) -> crate::UpdateAgent {
        crate::UpdateAgent::new(
            name,
            crate::UpdateAgentSpec {
                repository_ref: crate::LocalObjectReference {
                    name: TEST_REPOSITORY.into(),
                },
                identity: crate::AgentIdentity {
                    kind: crate::AgentIdentityKind::Enrolled,
                    registration_sha256: None,
                    // The key `node_leaf`'s certificate certifies: this is the machine that holds
                    // the name now.
                    public_key: Some(TEST_LEAF_KEY.into()),
                },
                labels: Default::default(),
                hold: false,
                cordon: false,
            },
        )
    }

    /// A client answering every `UpdateAgent` read with whatever `answer` makes of the requested
    /// name — the object telemetry's membership check reads.
    fn agent_apiserver<A>(answer: A) -> Client
    where
        A: Fn(&str) -> (StatusCode, serde_json::Value) + Send + Sync + 'static,
    {
        crate::tests::apiserver(move |_, path, _| {
            answer(path.rsplit('/').next().unwrap_or_default())
        })
    }

    /// The repository + telemetry router over an in-memory store at prefix `routing`, with the
    /// apiserver telemetry's membership check reads. The repository handlers need no Kubernetes
    /// context, so they keep their own state and the two halves are merged.
    fn router_with_agents(store: Arc<InMemory>, client: Client) -> Router {
        // `axum::routing::get` is fully qualified here because this test module also defines a
        // request-building helper named `get`.
        let telemetry = Router::new()
            .route("/telemetry/{file}", axum::routing::put(telemetry_put))
            .with_state(TelemetryState {
                content: content_state(store.clone()),
                enrollment: EnrollmentContext {
                    client,
                    namespace: "fleet-system".into(),
                    repository: TEST_REPOSITORY.into(),
                    public_url: "https://control".into(),
                },
            });
        Router::new()
            .route(
                "/metadata/{*rest}",
                axum::routing::get(repo_get).head(repo_get),
            )
            .route(
                "/targets/{*rest}",
                axum::routing::get(repo_get).head(repo_get),
            )
            .with_state(content_state(store))
            .merge(telemetry)
            .layer(DefaultBodyLimit::max(BODY_LIMIT))
    }

    /// The steady state: every node the path names is a live enrolled member.
    fn router(store: Arc<InMemory>) -> Router {
        router_with_agents(
            store,
            agent_apiserver(|name| {
                (
                    StatusCode::OK,
                    serde_json::to_value(enrolled_agent(name)).unwrap(),
                )
            }),
        )
    }

    #[tokio::test]
    async fn a_rebuilt_object_store_takes_effect_without_a_restart() {
        // Credentials are baked into an `ObjectStore` at construction, so a handler that captured
        // one at start-up serves a rotated key — or a one-hour STS session token — until it
        // expires and then answers 502 for the life of the process. The live router must read
        // through the reloadable, prefix included.
        let destination = Arc::new(Reloadable::new(Destination {
            store: seeded().await,
            prefix: Arc::from("routing"),
        }));
        let app = Router::new()
            .route("/targets/{*rest}", axum::routing::get(repo_get))
            .with_state(ContentState {
                destination: destination.clone(),
            });
        let read = |app: Router| async move {
            let response = app.oneshot(get("/targets/nested/app", None)).await.unwrap();
            let status = response.status();
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec();
            (status, body)
        };
        assert_eq!(read(app.clone()).await, (StatusCode::OK, b"hello".to_vec()));

        let rotated = Arc::new(InMemory::new());
        rotated
            .put(
                &ObjectPath::from("rotated/targets/nested/app"),
                PutPayload::from_static(b"rotated"),
            )
            .await
            .unwrap();
        destination.set(Destination {
            store: rotated,
            prefix: Arc::from("rotated"),
        });
        assert_eq!(
            read(app).await,
            (StatusCode::OK, b"rotated".to_vec()),
            "the same running router serves from the rebuilt store, under the rebuilt prefix"
        );
    }

    #[tokio::test]
    async fn a_failed_store_rebuild_keeps_the_working_store_serving() {
        let destination = Reloadable::new(Destination {
            store: seeded().await,
            prefix: Arc::from("routing"),
        });

        // The apiserver cannot answer: a rebuild is best-effort, so the store built from the last
        // good answer keeps serving. Swapping in nothing (or a store built from a partial read)
        // would turn a transient blip into a data-plane outage — the very failure this timer is
        // here to prevent.
        let unavailable = crate::tests::apiserver(|_, _, _| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                serde_json::json!({"kind": "Status", "code": 500}),
            )
        });
        rebuild_destination(&unavailable, "fleet-system", TEST_REPOSITORY, &destination).await;
        let live = destination.get();
        assert_eq!(&*live.prefix, "routing");
        assert_eq!(
            live.store
                .get(&ObjectPath::from("routing/targets/nested/app"))
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap()
                .to_vec(),
            b"hello".to_vec(),
        );

        // And a rebuild that succeeds replaces both halves of the destination, so a repository
        // whose prefix moved is not served out of the previous key space.
        let mut spec = crate::tests::repository();
        spec.s3.prefix = "rotated".into();
        let repository = crate::UpdateRepository::new(TEST_REPOSITORY, spec);
        let available = crate::tests::apiserver(move |_, _, _| {
            (StatusCode::OK, serde_json::to_value(&repository).unwrap())
        });
        rebuild_destination(&available, "fleet-system", TEST_REPOSITORY, &destination).await;
        assert_eq!(&*destination.get().prefix, "rotated");
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

    /// A resolved chain for one agent of the generation `timestamp` names. Each call builds its own
    /// `SignedMetadata`, exactly as a per-request resolve does.
    fn enrollment(timestamp: &str, agent: &str) -> SignedEnrollment {
        SignedEnrollment {
            metadata: std::sync::Arc::new(SignedMetadata {
                root: "root".into(),
                timestamp: timestamp.into(),
                snapshot: "snapshot".into(),
                // Stands in for the real thing, which carries one signed entry per published agent.
                targets: "targets".into(),
            }),
            agent_document: agent.into(),
            managed_configuration: "config".into(),
        }
    }

    /// The generation's role documents are held ONCE, however many agents are cached against it.
    /// `targets.json` has an entry per published agent, so a per-agent copy made the cache
    /// O(fleet²) bytes — ~15 GB at `MAX_ENROLLED_AGENTS`, and the gateway was OOM-killed at the
    /// fleet size it documents, in exactly the steady state (no publishes, so no eviction) the cache
    /// is for.
    #[test]
    fn one_generations_metadata_is_stored_once_however_many_agents_are_cached() {
        let cache = VerifiedEnrollments {
            inner: std::sync::Mutex::new(Generation::default()),
        };
        let now = chrono::Utc::now();
        let expires = now + chrono::Duration::hours(1);
        let generation = generation_key("routing", "anchor", "timestamp-1");
        for index in 0..64 {
            let path = format!("assignments/agents/node-{index}.json");
            // Each agent resolves its own copy of the chain, as a real request does.
            cache.insert(
                &generation,
                &path,
                &enrollment("timestamp-1", "agent"),
                expires,
            );
        }
        let guard = cache.lock();
        assert_eq!(guard.entries.len(), 64);
        assert_eq!(
            std::sync::Arc::strong_count(guard.metadata.as_ref().unwrap()),
            1,
            "the cache holds exactly one copy of the generation's role documents"
        );
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
        let chain = enrollment("timestamp-1", "agent");
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
        let chain = SignedMetadata {
            root: role("2030-01-01T00:00:00Z"),
            timestamp: role("2027-03-04T05:06:07Z"),
            snapshot: role("2029-01-01T00:00:00Z"),
            targets: role("2028-01-01T00:00:00Z"),
        };
        assert_eq!(
            chain_expiry(&chain).unwrap().to_rfc3339(),
            "2027-03-04T05:06:07+00:00"
        );
        let unreadable = SignedMetadata {
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
    fn every_parsed_range_shape_reaches_the_object_store_intact() {
        // The grammar itself is `crate::served`'s and tested there; what this owns is the
        // translation into the store's half-open bounded range.
        for (value, expected) in [
            ("bytes=100-", GetRange::Offset(100)),
            ("bytes=0-99", GetRange::Bounded(0..100)),
            ("bytes=-500", GetRange::Suffix(500)),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(header::RANGE, value.parse().unwrap());
            assert_eq!(parse_range(&headers), Ok(Some(expected)), "{value}");
        }
    }

    #[test]
    fn a_duplicate_or_malformed_range_header_is_refused() {
        let mut headers = HeaderMap::new();
        headers.append(header::RANGE, "bytes=0-1".parse().unwrap());
        headers.append(header::RANGE, "bytes=2-3".parse().unwrap());
        assert_eq!(parse_range(&headers), Err(()));
        let mut headers = HeaderMap::new();
        headers.insert(header::RANGE, "bytes=5-2".parse().unwrap());
        assert_eq!(parse_range(&headers), Err(()));
        assert_eq!(parse_range(&HeaderMap::new()), Ok(None));
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
                public_key: None,
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
            public_key: Some(TEST_LEAF_KEY.into()),
        };
        let request = telemetry_request_as("updated-agent.json", bootstrap, report);
        let (status, _, _) = send(store.clone(), request).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(store
            .get(&ObjectPath::from("routing/telemetry/updated-agent.json"))
            .await
            .is_err());
    }

    /// A minted leaf lives 90 days and outlives the object that justified it. A node that was
    /// decommissioned (its `UpdateAgent` deleted) or re-homed to another repository must stop being
    /// able to write the name's report the moment the object says so — there is exactly ONE
    /// telemetry object per node, so a stale holder of the name's leaf would otherwise overwrite the
    /// report the machine that holds the name NOW signs, and the planner, verifying against the new
    /// pinned key, would count the name as unreported and spend its group's `maxUnavailable` on it.
    #[tokio::test]
    async fn a_node_no_longer_enrolled_here_cannot_write_telemetry() {
        let deleted = agent_apiserver(|_| {
            (
                StatusCode::NOT_FOUND,
                serde_json::json!({"kind": "Status", "code": 404}),
            )
        });
        let rehomed = agent_apiserver(|name| {
            let mut agent = enrolled_agent(name);
            agent.spec.repository_ref.name = "staging".into();
            (StatusCode::OK, serde_json::to_value(agent).unwrap())
        });
        // Never enrolled here at all: a manual (offline) identity has no pinned key, so nothing it
        // writes could ever be verified.
        let manual = agent_apiserver(|name| {
            let mut agent = enrolled_agent(name);
            agent.spec.identity.kind = crate::AgentIdentityKind::Manual;
            (StatusCode::OK, serde_json::to_value(agent).unwrap())
        });
        for client in [deleted, rehomed, manual] {
            let store = Arc::new(InMemory::new());
            let request = telemetry_request(
                "agent-9.json",
                Some("agent-9"),
                envelope_body("agent-9", "deploy-2", "2.0.0"),
            );
            let response = router_with_agents(store.clone(), client)
                .oneshot(request)
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
            assert!(
                store
                    .get(&ObjectPath::from("routing/telemetry/agent-9.json"))
                    .await
                    .is_err(),
                "nothing was written"
            );
        }
    }

    /// Re-provisioning a machine under its existing hostname is delete-the-`UpdateAgent`-and-enroll:
    /// the replacement pins a NEW key to the SAME name, while the previous holder's leaf stays
    /// CA-valid for the rest of its 90 days with no revocation path. Name plus membership authorized
    /// it — the object read returns the REPLACEMENT, which is enrolled here — so the superseded
    /// holder could overwrite the one telemetry object the real machine signs, and the planner,
    /// verifying against the new pinned key, would count the name as unreported and spend its
    /// group's `maxUnavailable` on it. The leaf's own key must match the pin.
    #[tokio::test]
    async fn a_superseded_holder_of_a_re_enrolled_name_cannot_write_telemetry() {
        let store = Arc::new(InMemory::new());
        // The apiserver answers with the replacement: enrolled here, pinned to `TEST_LEAF_KEY`.
        let replacement = agent_apiserver(|name| {
            (
                StatusCode::OK,
                serde_json::to_value(enrolled_agent(name)).unwrap(),
            )
        });
        let request = telemetry_request_as(
            "agent-9.json",
            node_leaf_keyed(TEST_REPOSITORY, "agent-9", "04deadbeef"),
            envelope_body("agent-9", "deploy-2", "2.0.0"),
        );
        let response = router_with_agents(store.clone(), replacement)
            .oneshot(request)
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(
            store
                .get(&ObjectPath::from("routing/telemetry/agent-9.json"))
                .await
                .is_err(),
            "nothing was written"
        );
    }

    /// The other half of that gate: only a DEFINITIVE answer refuses. Reports are best-effort and
    /// never retried, and `updated-healthproxy` drains a backend whose report went stale, so an
    /// apiserver that is merely unreachable — or throttling, or 5xx-ing — must not stop the fleet's
    /// reports and drain every healthy backend. The verified leaf was the sole authority on this
    /// path before the membership check, and it remains sufficient when the apiserver says nothing.
    #[tokio::test]
    async fn telemetry_is_accepted_when_the_apiserver_cannot_answer() {
        // Unreachable at the transport, and answering but unable to serve the read.
        let unreachable = Client::new(
            tower::service_fn(|_: axum::http::Request<kube::client::Body>| async {
                Err::<axum::http::Response<kube::client::Body>, std::io::Error>(
                    std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "no apiserver"),
                )
            }),
            "default",
        );
        let unavailable = agent_apiserver(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({"kind": "Status", "code": 503}),
            )
        });
        let throttled = agent_apiserver(|_| {
            (
                StatusCode::TOO_MANY_REQUESTS,
                serde_json::json!({"kind": "Status", "code": 429}),
            )
        });
        for client in [unreachable, unavailable, throttled] {
            let store = Arc::new(InMemory::new());
            let body = envelope_body("agent-9", "deploy-2", "2.0.0");
            let request = telemetry_request("agent-9.json", Some("agent-9"), body.clone());
            let response = router_with_agents(store.clone(), client)
                .oneshot(request)
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let stored = store
                .get(&ObjectPath::from("routing/telemetry/agent-9.json"))
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap();
            assert_eq!(stored.as_ref(), body.as_slice(), "the report was written");
        }
    }

    #[test]
    fn only_the_configured_bootstrap_identity_can_enroll() {
        let bootstrap = |cn: &str| ClientIdentity {
            common_name: Some(cn.to_owned()),
            node: None,
            public_key: Some(TEST_LEAF_KEY.into()),
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
                node: None,
                public_key: None,
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
                node: None,
                public_key: Some(TEST_LEAF_KEY.into()),
            }
            .node_in(TEST_REPOSITORY),
            None
        );
    }
}
