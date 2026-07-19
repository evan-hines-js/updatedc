//! One-way enrollment bundle persistence shared by every agent frontend.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapConfig {
    pub enrollment: EnrollmentBootstrap,
}

/// The agent's sole node-local input. It always carries the gateway `url` and the fleet `ca` it
/// trusts for the gateway's server certificate, plus exactly one credential set:
///
/// * **Mount mode** (Kubernetes / cert-manager): `client_cert` + `client_key` are pre-provisioned
///   PEM paths — no secret in the file. The agent presents them as mTLS to `/enroll`.
/// * **Join mode** (immutable infra / Rancher userdata): `group_id` + a shared secret `nonce`
///   join token. The agent generates a keypair, gets a CSR signed at `/join`, and uses the minted
///   certificate thereafter. Here the file *does* hold a secret (the nonce), so it must be mounted
///   from a Secret.
///
/// If the cert paths are present they win (mount mode); otherwise the join token is used. Exactly
/// one complete set must be present.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentBootstrap {
    pub url: String,
    pub ca: PathBuf,
    #[serde(default)]
    pub client_cert: Option<PathBuf>,
    #[serde(default)]
    pub client_key: Option<PathBuf>,
    #[serde(default)]
    pub group_id: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
}

/// The resolved bootstrap credential — which enrollment path this node takes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BootstrapMode {
    /// Pre-provisioned client identity, presented as mTLS to `/enroll`.
    Mount {
        client_cert: PathBuf,
        client_key: PathBuf,
    },
    /// Group join token; the node mints its own identity via a CSR at `/join`.
    Join { group_id: String, nonce: String },
}

impl EnrollmentBootstrap {
    /// Resolve the credential set. Cert paths take precedence over a join token; a partially
    /// specified set (only one of a pair, or an empty path/value) is an error, as is neither.
    pub fn mode(&self) -> io::Result<BootstrapMode> {
        let cert = self.client_cert.as_ref().filter(|p| !p.as_os_str().is_empty());
        let key = self.client_key.as_ref().filter(|p| !p.as_os_str().is_empty());
        if self.client_cert.is_some() || self.client_key.is_some() {
            return match (cert, key) {
                (Some(cert), Some(key)) => Ok(BootstrapMode::Mount {
                    client_cert: cert.clone(),
                    client_key: key.clone(),
                }),
                _ => Err(invalid(
                    "mount-mode bootstrap needs both client_cert and client_key",
                )),
            };
        }
        let group = self.group_id.as_ref().filter(|s| !s.is_empty());
        let nonce = self.nonce.as_ref().filter(|s| !s.is_empty());
        if self.group_id.is_some() || self.nonce.is_some() {
            return match (group, nonce) {
                (Some(group), Some(nonce)) => Ok(BootstrapMode::Join {
                    group_id: group.clone(),
                    nonce: nonce.clone(),
                }),
                _ => Err(invalid("join-mode bootstrap needs both group_id and nonce")),
            };
        }
        Err(invalid(
            "bootstrap needs client_cert+client_key (mount) or group_id+nonce (join)",
        ))
    }

    /// The mTLS identity the agent presents on every steady-state request to the gateway. In
    /// mount mode it is the bootstrap-provided cert/key; in join mode it is the certificate the
    /// node minted at `/join`, persisted under `state_dir`.
    pub fn steady_identity(&self, state_dir: &Path) -> io::Result<crate::tls::Identity> {
        match self.mode()? {
            BootstrapMode::Mount {
                client_cert,
                client_key,
            } => Ok(crate::tls::Identity::new(
                client_cert,
                client_key,
                self.ca.clone(),
            )),
            BootstrapMode::Join { .. } => Ok(crate::tls::Identity::new(
                joined_cert_path(state_dir),
                joined_key_path(state_dir),
                self.ca.clone(),
            )),
        }
    }
}

/// Where a join-mode node persists the certificate and key it minted at `/join`.
pub(crate) fn joined_cert_path(state_dir: &Path) -> PathBuf {
    state_dir.join("agent.crt")
}
pub(crate) fn joined_key_path(state_dir: &Path) -> PathBuf {
    state_dir.join("agent.key")
}

impl BootstrapConfig {
    pub fn load(path: &Path) -> io::Result<Self> {
        let bytes = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&bytes).map_err(|error| invalid(&error.to_string()))?;
        let url = url::Url::parse(&config.enrollment.url)
            .map_err(|error| invalid(&format!("invalid enrollment URL: {error}")))?;
        // The gateway is externally exposed and always TLS, so enrollment is always HTTPS —
        // in mount mode the node verifies the gateway (and presents its client cert); in join
        // mode it verifies the gateway before it has any cert of its own.
        if url.scheme() != "https" {
            return Err(invalid("enrollment URL must use HTTPS"));
        }
        if config.enrollment.ca.as_os_str().is_empty() {
            return Err(invalid("enrollment ca path must not be empty"));
        }
        // Resolve the credential set eagerly so a misconfigured bootstrap fails at load, not at
        // first network use.
        config.enrollment.mode()?;
        Ok(config)
    }
}

/// Parse the supervisor's sole local input: `--config <bootstrap.toml>`.
pub fn bootstrap_path(prog: &str) -> Result<PathBuf, String> {
    bootstrap_path_from(prog, std::env::args_os().skip(1))
}

fn bootstrap_path_from(
    prog: &str,
    args: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<PathBuf, String> {
    let usage = || format!("usage: {prog} --config <bootstrap.toml>");
    let mut args = args.into_iter();
    match args.next().as_deref() {
        Some(value) if value == "--config" => {
            let path = args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| "--config needs a bootstrap path".to_string())?;
            if args.next().is_some() {
                return Err(format!("unexpected trailing argument; {}", usage()));
            }
            Ok(path)
        }
        Some(value) if value == "-h" || value == "--help" => {
            println!("{}", usage());
            std::process::exit(0);
        }
        _ => Err(usage()),
    }
}

/// The control-plane-agnostic enrollment endpoint: an agent `POST`s [`EnrollmentRequest`]
/// here over mutual TLS, and any control plane implementing the contract returns an
/// [`EnrollmentBundle`]. Nothing node-identifying rides in the URL.
pub const ENROLL_PATH: &str = "/enroll";

/// The join endpoint: a join-mode agent `POST`s a [`JoinRequest`] here over a server-authenticated
/// (not mutual) TLS connection — it has no client certificate yet. The control plane authenticates
/// the *join* with the group token, signs the node's CSR, and returns a [`JoinResponse`].
pub const JOIN_PATH: &str = "/join";

/// The enrollment request body. The request is authenticated by the agent's mTLS client
/// certificate (fleet membership); the registration nonce is a non-secret, per-node identifier
/// carried in the body (not the URL) that names the node. No secret rides in the request.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollmentRequest {
    pub registration: String,
}

impl EnrollmentRequest {
    /// A registration nonce is exactly 64 hex characters (a sha256 digest).
    pub fn registration_is_wellformed(&self) -> bool {
        crate::hash::is_sha256_hex(&self.registration)
    }
}

/// A join-mode agent's request. `nonce` is the shared group join token (a secret, authenticating
/// the join); `instance` is a durable, locally-generated, per-node value (64 lowercase hex) that
/// names the agent and makes the join idempotent on retry — it is *not* secret, and it is what
/// keeps two nodes sharing one group `nonce` from colliding onto one identity. `csr` is a PEM
/// certificate-signing request; only its public key is certified — the control plane sets the
/// subject and SAN itself and ignores whatever the CSR asks for.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JoinRequest {
    pub group_id: String,
    pub nonce: String,
    pub instance: String,
    pub csr: String,
}

impl JoinRequest {
    /// The durable per-node `instance` is exactly 64 hex characters (a sha256 digest), like the
    /// mount-mode registration nonce it is derived from.
    pub fn instance_is_wellformed(&self) -> bool {
        crate::hash::is_sha256_hex(&self.instance)
    }
}

/// The control plane's response to a successful join: the minted client certificate (`leaf`), any
/// issuer chain below the trusted CA (`chain`, empty when the fleet CA signs leaves directly), and
/// the same [`EnrollmentBundle`] the mount-mode `/enroll` returns — so join-mode and mount-mode
/// nodes converge on an identical steady state.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JoinResponse {
    pub leaf: String,
    #[serde(default)]
    pub chain: String,
    pub bundle: EnrollmentBundle,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollmentBundle {
    pub schema: u32,
    pub agent_id: String,
    pub routing_base_url: String,
    pub assignment: String,
    /// Exact UTF-8 bytes of the signed metadata. Strings are intentional: TUF
    /// length and digest checks cover the serialized bytes, not an equivalent JSON value.
    pub routing_root: String,
    pub initial: InitialSignedConfiguration,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct InitialSignedConfiguration {
    pub timestamp: String,
    pub snapshot: String,
    pub targets: String,
    pub agent_document: String,
    pub managed_configuration: String,
}

impl EnrollmentBundle {
    pub fn validate_shape(&self) -> io::Result<()> {
        if self.schema != 1 || self.agent_id.is_empty() {
            return Err(invalid(
                "unsupported enrollment bundle or empty agent identity",
            ));
        }
        if !self.routing_base_url.ends_with('/') || self.assignment.starts_with('/') {
            return Err(invalid("invalid enrollment routing location"));
        }
        if self
            .assignment
            .split('/')
            .any(|part| part.is_empty() || matches!(part, "." | ".."))
        {
            return Err(invalid("invalid enrollment assignment path"));
        }
        for (name, value) in [
            ("routingRoot", &self.routing_root),
            ("timestamp", &self.initial.timestamp),
            ("snapshot", &self.initial.snapshot),
            ("targets", &self.initial.targets),
            ("agentDocument", &self.initial.agent_document),
            ("managedConfiguration", &self.initial.managed_configuration),
        ] {
            let value: serde_json::Value = serde_json::from_str(value)
                .map_err(|error| invalid(&format!("enrollment {name} is invalid JSON: {error}")))?;
            if !value.is_object() {
                return Err(invalid(&format!(
                    "enrollment {name} must encode a JSON object"
                )));
            }
        }
        Ok(())
    }
}

/// Load a preplaced bundle or enroll exactly once. Missing and corrupt are deliberately
/// distinct; once the consumed marker exists, absence can never re-enable enrollment.
pub fn load_or_enroll(
    bundle_path: &Path,
    enroll: impl FnOnce() -> io::Result<Vec<u8>>,
) -> io::Result<EnrollmentBundle> {
    let consumed = consumed_path(bundle_path);
    match std::fs::read(bundle_path) {
        Ok(bytes) => {
            let bundle = decode(&bytes)?;
            consume_if_needed(&consumed)?;
            Ok(bundle)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if consumed.exists() {
                return Err(invalid(
                    "enrollment bundle is missing after bootstrap eligibility was consumed",
                ));
            }
            let bytes = enroll()?;
            let bundle = decode(&bytes)?;
            // Persist the bundle BEFORE the consumed marker. If we crash in between, the bundle is
            // present, so the next boot loads it and then writes the marker — no brick. The reverse
            // order (marker first) would, on an ill-timed crash, leave the marker set with no bundle,
            // which is permanently fatal ("missing after bootstrap eligibility was consumed"). The
            // marker's guarantee still holds: once both exist, deleting the bundle can never
            // re-enable enrollment.
            foundation::durable::atomic_write(bundle_path, ".enrollment-", &bytes)?;
            consume_if_needed(&consumed)?;
            Ok(bundle)
        }
        Err(error) => Err(error),
    }
}

/// Obtain the enrollment bundle over the network, dispatching by bootstrap mode. Mount-mode nodes
/// present their pre-provisioned client cert to `/enroll`; join-mode nodes mint an identity via a
/// CSR at `/join`. Both converge on the same persisted bundle and consumed-once semantics.
pub async fn load_or_enroll_http(
    bootstrap: &BootstrapConfig,
    state_dir: &Path,
) -> io::Result<EnrollmentBundle> {
    match bootstrap.enrollment.mode()? {
        BootstrapMode::Mount { .. } => enroll_mount(bootstrap, state_dir).await,
        BootstrapMode::Join { group_id, nonce } => {
            join_http(bootstrap, state_dir, &group_id, &nonce).await
        }
    }
}

/// If enrollment has already run (the bundle is present, or the consumed marker is set), return the
/// loaded bundle (or the consumed-but-missing error) without touching the network; return `None`
/// when a fresh network enrollment is due. `what` names the mode in the "must not run for existing
/// local state" error. Shared by both bootstrap modes so the one-way, consumed-once contract is
/// enforced identically.
fn load_existing_or_fresh(
    bundle_path: &Path,
    what: &'static str,
) -> Option<io::Result<EnrollmentBundle>> {
    (bundle_path.exists() || consumed_path(bundle_path).exists()).then(|| {
        load_or_enroll(bundle_path, || {
            Err(invalid(&format!(
                "{what} must not run for existing local state"
            )))
        })
    })
}

/// Read a successful response body, mapping a non-2xx status to an error naming the `what`
/// operation. Shared by the mount `/enroll` and join `/join` fetches.
async fn success_body(response: reqwest::Response, what: &str) -> io::Result<Vec<u8>> {
    if !response.status().is_success() {
        return Err(io::Error::other(format!(
            "{what} returned HTTP {}",
            response.status()
        )));
    }
    Ok(response.bytes().await.map_err(io::Error::other)?.to_vec())
}

/// Mount mode: the node already holds a client certificate, so the mTLS handshake at `/enroll`
/// authenticates it and nothing secret rides in the request.
async fn enroll_mount(
    bootstrap: &BootstrapConfig,
    state_dir: &Path,
) -> io::Result<EnrollmentBundle> {
    let bundle_path = state_dir.join("enrollment.json");
    if let Some(loaded) = load_existing_or_fresh(&bundle_path, "enrollment HTTP") {
        return loaded;
    }
    std::fs::create_dir_all(state_dir)?;
    let endpoint = format!(
        "{}{ENROLL_PATH}",
        bootstrap.enrollment.url.trim_end_matches('/')
    );
    let request = EnrollmentRequest {
        registration: durable_instance(state_dir)?,
    };
    let body = serde_json::to_vec(&request).map_err(io::Error::other)?;
    let response = bootstrap
        .enrollment
        .steady_identity(state_dir)?
        .reqwest_client()?
        .post(endpoint)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(io::Error::other)?;
    let bytes = success_body(response, "enrollment").await?;
    load_or_enroll(&bundle_path, move || Ok(bytes))
}

/// Join mode: the node has no certificate yet. It generates a keypair and CSR, authenticates the
/// join with the group token over server-authenticated TLS, persists the minted identity, and
/// returns the embedded bundle. The persisted identity is what every steady-state request uses.
async fn join_http(
    bootstrap: &BootstrapConfig,
    state_dir: &Path,
    group_id: &str,
    nonce: &str,
) -> io::Result<EnrollmentBundle> {
    let bundle_path = state_dir.join("enrollment.json");
    if let Some(loaded) = load_existing_or_fresh(&bundle_path, "join") {
        return loaded;
    }
    std::fs::create_dir_all(state_dir)?;
    let instance = durable_instance(state_dir)?;
    let (key_pem, csr_pem) = crate::csr::generate(&format!("updated join {group_id}"))
        .map_err(|error| invalid(&format!("generating join CSR: {error}")))?;
    let endpoint = format!("{}{JOIN_PATH}", bootstrap.enrollment.url.trim_end_matches('/'));
    let request = JoinRequest {
        group_id: group_id.to_string(),
        nonce: nonce.to_string(),
        instance,
        csr: csr_pem,
    };
    let body = serde_json::to_vec(&request).map_err(io::Error::other)?;
    // The node has no client certificate yet, so the listener is server-authenticated only: the
    // node verifies the gateway against the pinned CA and proves itself with the join token.
    let response = crate::tls::server_auth_client(&bootstrap.enrollment.ca)?
        .post(endpoint)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(io::Error::other)?;
    let bytes = success_body(response, "join").await?;
    let joined: JoinResponse = serde_json::from_slice(&bytes).map_err(invalid_error)?;
    joined.bundle.validate_shape()?;
    let bundle_bytes = serde_json::to_vec(&joined.bundle).map_err(io::Error::other)?;
    // Persist the minted identity BEFORE the bundle/consumed marker. Steady state cannot run
    // without the cert, and once the consumed marker exists join can never re-run; a crash after
    // the identity but before the bundle simply re-joins (same durable `instance` ⇒ same agent).
    persist_identity(state_dir, &key_pem, &joined.leaf, &joined.chain)?;
    load_or_enroll(&bundle_path, || Ok(bundle_bytes.clone()))
}

/// The durable, per-node registration value: 64 lowercase hex, generated once and reused on every
/// retry. It names the agent (both modes) and, in join mode, keeps nodes sharing one group token
/// from colliding onto a single identity.
fn durable_instance(state_dir: &Path) -> io::Result<String> {
    let path = state_dir.join("registration-nonce");
    match std::fs::read_to_string(&path) {
        Ok(value) if crate::hash::is_sha256_hex(&value) => Ok(value),
        Ok(_) => Err(invalid("registration nonce is corrupt")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let value = crate::rand::token()?;
            foundation::durable::atomic_write(&path, ".registration-", value.as_bytes())?;
            Ok(value)
        }
        Err(error) => Err(error),
    }
}

/// Durably write the minted key (owner-only) and certificate. The cert file is the leaf followed
/// by any issuer chain below the trusted CA; the root/CA itself stays the bootstrap-pinned `ca`.
fn persist_identity(
    state_dir: &Path,
    key_pem: &str,
    leaf_pem: &str,
    chain_pem: &str,
) -> io::Result<()> {
    let key_path = joined_key_path(state_dir);
    foundation::durable::atomic_write(&key_path, ".agent-key-", key_pem.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))?;
    }
    let mut cert = leaf_pem.to_string();
    if !chain_pem.trim().is_empty() {
        if !cert.ends_with('\n') {
            cert.push('\n');
        }
        cert.push_str(chain_pem);
    }
    foundation::durable::atomic_write(&joined_cert_path(state_dir), ".agent-crt-", cert.as_bytes())
}

fn decode(bytes: &[u8]) -> io::Result<EnrollmentBundle> {
    let bundle: EnrollmentBundle = serde_json::from_slice(bytes).map_err(invalid_error)?;
    bundle.validate_shape()?;
    Ok(bundle)
}

fn consume_if_needed(path: &Path) -> io::Result<()> {
    if path.exists() {
        return Ok(());
    }
    let parent = path
        .parent()
        .ok_or_else(|| invalid("enrollment marker has no parent"))?;
    std::fs::create_dir_all(parent)?;
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.sync_all()?;
    foundation::durable::sync_dir(parent)
}

fn consumed_path(bundle: &Path) -> PathBuf {
    bundle.with_extension("consumed")
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn invalid_error(error: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::ffi::OsString;

    fn bundle() -> Vec<u8> {
        serde_json::to_vec(&EnrollmentBundle {
            schema: 1,
            agent_id: "agent-a".into(),
            routing_base_url: "https://updates.example/".into(),
            assignment: "assignments/agents/agent-a.json".into(),
            routing_root: "{}".into(),
            initial: InitialSignedConfiguration {
                timestamp: "{}".into(),
                snapshot: "{}".into(),
                targets: "{}".into(),
                agent_document: "{}".into(),
                managed_configuration: "{}".into(),
            },
        })
        .unwrap()
    }

    #[test]
    fn preplaced_bundle_never_calls_enrollment() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.enrollment.json");
        std::fs::write(&path, bundle()).unwrap();
        let called = Cell::new(false);
        let loaded = load_or_enroll(&path, || {
            called.set(true);
            Ok(bundle())
        })
        .unwrap();
        assert_eq!(loaded.agent_id, "agent-a");
        assert!(!called.get());
    }

    #[test]
    fn consumed_bootstrap_can_never_fall_back_to_enrollment() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.enrollment.json");
        load_or_enroll(&path, || Ok(bundle())).unwrap();
        std::fs::remove_file(&path).unwrap();
        let called = Cell::new(false);
        let error = load_or_enroll(&path, || {
            called.set(true);
            Ok(bundle())
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!called.get());
    }

    #[test]
    fn corrupt_preplaced_bundle_fails_without_enrolling() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.enrollment.json");
        std::fs::write(&path, b"not-json").unwrap();
        let called = Cell::new(false);
        assert!(load_or_enroll(&path, || {
            called.set(true);
            Ok(bundle())
        })
        .is_err());
        assert!(!called.get());
    }

    fn write_bootstrap(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("bootstrap.toml");
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn mount_mode_bootstrap_uses_the_provisioned_cert() {
        let dir = tempfile::tempdir().unwrap();
        let base = "[enrollment]\nurl='https://updates.example/'\nca='/id/ca.crt'\nclient_cert='/id/tls.crt'\nclient_key='/id/tls.key'\n";
        let config = BootstrapConfig::load(&write_bootstrap(dir.path(), base)).unwrap();
        assert_eq!(
            config.enrollment.mode().unwrap(),
            BootstrapMode::Mount {
                client_cert: "/id/tls.crt".into(),
                client_key: "/id/tls.key".into(),
            }
        );
        // Steady-state identity in mount mode is the mounted cert, verbatim.
        let identity = config
            .enrollment
            .steady_identity(Path::new("/var/lib/updated/state"))
            .unwrap();
        assert_eq!(identity.client_cert.to_str(), Some("/id/tls.crt"));

        // An unknown field is still rejected, and a half-specified pair is an error.
        assert!(BootstrapConfig::load(&write_bootstrap(dir.path(), &format!("{base}key='x'\n")))
            .is_err());
        assert!(BootstrapConfig::load(&write_bootstrap(
            dir.path(),
            "[enrollment]\nurl='https://updates.example/'\nca='/id/ca.crt'\nclient_key='/id/tls.key'\n",
        ))
        .is_err());
    }

    #[test]
    fn join_mode_bootstrap_uses_the_group_token_and_mints_its_own_identity() {
        let dir = tempfile::tempdir().unwrap();
        let base = "[enrollment]\nurl='https://updates.example/'\nca='/id/ca.crt'\ngroup_id='canary'\nnonce='s3cret-join-token'\n";
        let config = BootstrapConfig::load(&write_bootstrap(dir.path(), base)).unwrap();
        assert_eq!(
            config.enrollment.mode().unwrap(),
            BootstrapMode::Join {
                group_id: "canary".into(),
                nonce: "s3cret-join-token".into(),
            }
        );
        // In join mode the steady-state identity resolves to the certificate the node will mint
        // into its state directory, not anything from the bootstrap file.
        let identity = config
            .enrollment
            .steady_identity(Path::new("/var/lib/updated/state"))
            .unwrap();
        assert_eq!(
            identity.client_cert,
            Path::new("/var/lib/updated/state/agent.crt")
        );

        // A join token without a group (or vice versa) is a misconfiguration.
        assert!(BootstrapConfig::load(&write_bootstrap(
            dir.path(),
            "[enrollment]\nurl='https://updates.example/'\nca='/id/ca.crt'\ngroup_id='canary'\n",
        ))
        .is_err());
    }

    #[test]
    fn cert_paths_take_precedence_over_a_join_token() {
        let dir = tempfile::tempdir().unwrap();
        // Both sets present (e.g. a shared template with stale cert paths): mount wins.
        let both = "[enrollment]\nurl='https://updates.example/'\nca='/id/ca.crt'\nclient_cert='/id/tls.crt'\nclient_key='/id/tls.key'\ngroup_id='canary'\nnonce='tok'\n";
        let config = BootstrapConfig::load(&write_bootstrap(dir.path(), both)).unwrap();
        assert!(matches!(
            config.enrollment.mode().unwrap(),
            BootstrapMode::Mount { .. }
        ));
    }

    #[test]
    fn bootstrap_without_any_credential_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        assert!(BootstrapConfig::load(&write_bootstrap(
            dir.path(),
            "[enrollment]\nurl='https://updates.example/'\nca='/id/ca.crt'\n",
        ))
        .is_err());
    }

    #[test]
    fn bootstrap_path_rejects_every_trailing_argument() {
        let args = ["--config", "bootstrap.toml", "--typo"]
            .into_iter()
            .map(OsString::from);
        assert!(bootstrap_path_from("supervisor", args)
            .unwrap_err()
            .contains("unexpected trailing argument"));
    }
}
