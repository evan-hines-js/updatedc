//! The state every gateway handler is given, and the short-lived memo that keeps a node's
//! authorization from being re-derived on each request of a burst.

use super::*;

#[derive(Clone)]
pub struct EnrollmentContext {
    pub client: Client,
    pub namespace: String,
    pub repository: String,
    pub public_url: String,
    /// Pre-created, exact-RBAC Kubernetes Lease serializing enrollment across gateway replicas.
    pub lock_name: String,
}

/// The gateway presents `cert`/`key` and admits a connection only if the client presents a
/// certificate trusted by the separately mounted fleet `client_ca` bundle — that mutual TLS *is*
/// the enrollment authentication.
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

/// One coherent gateway identity generation. The listener verifier and the CA used by requests on
/// that connection are loaded and validated together, then replaced through one [`Reloadable`].
/// Keeping them in one snapshot prevents Secret update skew from installing a signer whose leaves
/// the listener rejects.
pub(crate) struct GatewayMaterials {
    pub(crate) server_config: Arc<rustls::ServerConfig>,
    pub(crate) issuing_ca: crate::join::IssuingCa,
}

/// How often the gateway rebuilds the configuration it was started with: its mounted certificate
/// material and its object store.
///
/// Every one of these files is a cert-manager Secret that is rotated IN PLACE, on the issuer's
/// schedule, with no restart of this process. Loading them once means the gateway keeps presenting
/// a certificate that eventually expires — at which point every agent's handshake fails and the
/// whole fleet loses metadata, telemetry, and enrollment at the same moment. Object-store
/// credentials rotate the same way and expire far faster when they are temporary.
pub(crate) const MATERIAL_RELOAD_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// A value rebuilt from its source while the gateway runs. Readers take the current value; a
/// reload that fails to parse leaves the last good one in place, so a half-written rotation is a
/// logged warning rather than an outage.
pub(crate) struct Reloadable<T> {
    pub(crate) current: std::sync::RwLock<Arc<T>>,
}

impl<T> Reloadable<T> {
    pub(crate) fn new(initial: T) -> Self {
        Self {
            current: std::sync::RwLock::new(Arc::new(initial)),
        }
    }

    pub(crate) fn get(&self) -> Arc<T> {
        self.current
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub(crate) fn set(&self, value: T) {
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
pub(crate) struct Destination {
    pub(crate) store: Arc<dyn ObjectStore>,
    pub(crate) signer: Arc<dyn Signer>,
    pub(crate) upload_signer: Arc<dyn crate::runtime::UploadSigner>,
    pub(crate) prefix: Arc<str>,
}

/// Reloadable store + prefix. Authorization state composes this with the repository identity
/// authority; keeping storage unaware of identity makes it reusable without creating a second
/// HTTP authorization path.
#[derive(Clone)]
pub(crate) struct ContentState {
    /// Rebuilt on a timer from the `UpdateRepository` and its credentials Secret, exactly as the
    /// controller rebuilds it every reconcile. The credentials are baked into the `ObjectStore` at
    /// construction, so a store built once at start-up serves a rotated key — or an STS session
    /// token — until it expires and then answers every request with a 502 while the repository
    /// still reports Ready.
    pub(crate) destination: Arc<Reloadable<Destination>>,
}

impl ContentState {
    pub(crate) fn destination(&self) -> Arc<Destination> {
        self.destination.get()
    }
}

#[derive(Clone)]
pub(crate) struct DataState {
    pub(crate) content: ContentState,
    pub(crate) authorization: Arc<AuthorizationMemo>,
    pub(crate) enrollment: EnrollmentContext,
    pub(crate) enrollment_client_cn: Arc<str>,
}

/// The inputs to the gateway's one live node-identity decision. This is projected from
/// [`EnrollmentContext`] instead of configured independently, so every route is necessarily scoped
/// to the same namespace and repository as enrollment.
#[derive(Clone)]
pub(crate) struct IdentityAuthority {
    pub(crate) client: Client,
    pub(crate) namespace: Arc<str>,
    pub(crate) repository: Arc<str>,
}

impl From<&EnrollmentContext> for IdentityAuthority {
    fn from(context: &EnrollmentContext) -> Self {
        Self {
            client: context.client.clone(),
            namespace: Arc::from(context.namespace.as_str()),
            repository: Arc::from(context.repository.as_str()),
        }
    }
}

/// State shared by every steady-state node route. Keeping content, identity authority, and the
/// assignment memo together makes it impossible to mount a repository or dataflow handler without
/// the same authorization path.
#[derive(Clone)]
pub(crate) struct AuthorizationState {
    pub(crate) content: ContentState,
    pub(crate) memo: Arc<AuthorizationMemo>,
    pub(crate) identity: IdentityAuthority,
}

impl FromRef<DataState> for AuthorizationState {
    fn from_ref(state: &DataState) -> Self {
        Self {
            content: state.content.clone(),
            memo: state.authorization.clone(),
            identity: IdentityAuthority::from(&state.enrollment),
        }
    }
}

/// Successful live-node authorization answers, briefly memoized by node and certified public key.
///
/// Report cadence and repository downloads scale with fleet size, and `Api::get` is a direct
/// apiserver read. Every steady-state capability endpoint uses this one memo and the one full check
/// below. The bound is deliberately shorter than both report freshness and the capability
/// lifetime: a removed/re-homed identity can mint for at most this window, and its stale
/// report/output bytes still fail the controller's current-key and assignment checks.
pub(crate) const AUTHORIZATION_MEMO_TTL: Duration =
    updated_contracts::dataflow::GATEWAY_AUTHORIZATION_MEMO_TTL;

#[derive(Default)]
pub(crate) struct AuthorizationMemo {
    pub(crate) entries: std::sync::Mutex<
        std::collections::HashMap<String, (tokio::time::Instant, AuthorizedAssignment)>,
    >,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuthorizedAssignment {
    pub(crate) assignment_sha256: String,
    pub(crate) input_object_sha256: Option<String>,
}

impl AuthorizationMemo {
    pub(crate) fn get(
        &self,
        node: &str,
        identity: &ClientIdentity,
        expected_assignment_sha256: Option<&str>,
        now: tokio::time::Instant,
    ) -> Option<AuthorizedAssignment> {
        let key = Self::key(node, identity)?;
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match entries.get(&key) {
            Some((expires, assignment))
                if now < *expires
                    && expected_assignment_sha256
                        .is_none_or(|expected| expected == assignment.assignment_sha256) =>
            {
                Some(assignment.clone())
            }
            Some(_) => {
                entries.remove(&key);
                None
            }
            None => None,
        }
    }

    pub(crate) fn insert(
        &self,
        node: &str,
        identity: &ClientIdentity,
        assignment: AuthorizedAssignment,
        now: tokio::time::Instant,
    ) {
        let Some(key) = Self::key(node, identity) else {
            return;
        };
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.retain(|_, (expires, _)| now < *expires);
        entries.insert(key, (now + AUTHORIZATION_MEMO_TTL, assignment));
    }

    pub(crate) fn key(node: &str, identity: &ClientIdentity) -> Option<String> {
        Some(format!("{node}/{}", identity.node_public_key()?))
    }
}
