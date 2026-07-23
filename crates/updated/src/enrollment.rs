//! One-way enrollment bundle persistence shared by every agent frontend.

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapConfig {
    pub enrollment: EnrollmentBootstrap,
}

/// The agent's sole node-local input, and deliberately minimal — a name, the shared fleet
/// enrollment certificate, a CA, and where to reach the gateway. Nothing else, and never an implicit
/// environment variable:
///
/// * `url` — the gateway to enroll against.
/// * `ca` — a PEM path for the CA that signs the gateway's (self-signed) server certificate, so the
///   node can verify the server it talks to without trusting the public web PKI.
/// * `name` — this node's name. Self-asserted; it becomes the minted certificate's `CN`, the
///   `UpdateAgent` the enrollment creates, and the node key the control plane pins.
/// * `client_cert` / `client_key` — the shared, fleet-wide enrollment certificate (two PEM files,
///   issued by cert-manager into a Secret). It authenticates the `/enroll` handshake by mutual TLS
///   and nothing else; a party that holds it may enroll a node under any name. This is the single
///   credential — there is no plaintext token and no per-group join secret. Individual attribution
///   and revocation come from the per-node certificate minted at enrollment, not from this.
///
/// The node generates a keypair and CSR, presents `name` + its CSR at `/enroll` over that mutual
/// TLS, and receives a per-node certificate it uses for every steady-state request thereafter.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentBootstrap {
    pub url: String,
    pub ca: PathBuf,
    pub name: String,
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
}

impl EnrollmentBootstrap {
    /// Reject an empty `name` (the one free-form field). `serde(deny_unknown_fields)` already rejects
    /// a leftover mount/join/token field and a missing cert path, so a stale config fails loudly
    /// rather than silently enrolling wrong.
    pub fn validate(&self) -> io::Result<()> {
        if self.name.trim().is_empty() {
            return Err(invalid("bootstrap enrollment name must not be empty"));
        }
        Ok(())
    }

    /// The mTLS identity the agent presents on every steady-state request to the gateway: the
    /// per-node certificate it minted at enrollment, persisted under `state_dir`. The shared fleet
    /// enrollment cert authenticates only the one enrollment handshake and never steady-state
    /// traffic, so every node is individually attributable and revocable by its own cert.
    pub fn steady_identity(&self, state_dir: &Path) -> io::Result<crate::tls::Identity> {
        Ok(crate::tls::Identity::new(
            joined_cert_path(state_dir),
            joined_key_path(state_dir),
            self.ca.clone(),
        ))
    }

    /// The identity the node presents to authenticate its one enrollment handshake: the shared,
    /// fleet-wide enrollment certificate. That mutual TLS *is* the enrollment authentication; it is
    /// used for nothing else, and steady-state traffic uses the per-node cert from
    /// [`Self::steady_identity`].
    pub fn enroll_identity(&self) -> io::Result<crate::tls::Identity> {
        Ok(crate::tls::Identity::new(
            self.client_cert.clone(),
            self.client_key.clone(),
            self.ca.clone(),
        ))
    }
}

/// Where a node persists the per-node certificate it minted at enrollment.
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
        // The gateway is externally exposed and always TLS, so enrollment is always HTTPS: the node
        // verifies the gateway against the pinned `ca` and presents the shared fleet enrollment cert.
        if url.scheme() != "https" {
            return Err(invalid("enrollment URL must use HTTPS"));
        }
        if config.enrollment.ca.as_os_str().is_empty() {
            return Err(invalid("enrollment ca path must not be empty"));
        }
        // Validate eagerly so a misconfigured bootstrap fails at load, not at first network use.
        config.enrollment.validate()?;
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

/// The one enrollment endpoint: a node `POST`s an [`EnrollmentRequest`] here over mutual TLS
/// (the shared fleet enrollment cert), and the control plane signs its CSR and returns an
/// [`EnrollResponse`]. Nothing node-identifying rides in the URL.
pub const ENROLL_PATH: &str = "/enroll";

/// The enrollment request body. The request is authenticated by the mutual-TLS handshake with the
/// shared fleet enrollment certificate; `name` is a non-secret, self-asserted node name carried in
/// the body (never the URL). Any holder of the fleet cert may assert any name — individual
/// attribution comes from the per-node cert minted in response, and an approval gate on the
/// `UpdateAgent` can require a human to authorize the requested name.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollmentRequest {
    pub name: String,
    /// A PEM certificate-signing request. Only the CSR's public key is certified — the control plane
    /// sets the subject (`CN=<name>`) and SAN itself. Steady-state traffic uses the minted per-node
    /// cert, never the shared fleet cert.
    pub csr: String,
}

impl EnrollmentRequest {
    /// A node name must be a non-empty DNS-safe label (lowercase alphanumeric plus `-`), so it is a
    /// valid `CN`, `UpdateAgent` name, and SPIFFE path segment.
    pub fn name_is_wellformed(&self) -> bool {
        !self.name.is_empty()
            && self.name.len() <= 253
            && self
                .name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !self.name.starts_with('-')
            && !self.name.ends_with('-')
    }
}

/// The control plane's response to a successful enrollment: the minted client certificate (`leaf`),
/// any issuer chain below the trusted CA (`chain`, empty when the fleet CA signs leaves directly),
/// and the [`EnrollmentBundle`] the node runs on.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrollResponse {
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

/// Obtain the enrollment bundle over the network: the single enrollment path. The node presents the
/// shared fleet enrollment cert as mutual TLS to `/enroll`, self-asserting its configured `name`,
/// and receives a per-node leaf it persists and uses thereafter. Idempotent on retry (the durable
/// per-node key plus the stable config name yield the same agent and the same pinned key) and
/// one-way: once the bundle is consumed, enrollment can never re-run.
pub async fn load_or_enroll_http(
    bootstrap: &BootstrapConfig,
    state_dir: &Path,
) -> io::Result<EnrollmentBundle> {
    let bundle_path = state_dir.join("enrollment.json");
    if let Some(loaded) = load_existing_or_fresh(&bundle_path, "enrollment") {
        return loaded;
    }
    std::fs::create_dir_all(state_dir)?;
    let key_pem = durable_key_pem(state_dir)?;
    let csr_pem = crate::csr::csr_for(&key_pem, "updated enroll")
        .map_err(|error| invalid(&format!("generating enrollment CSR: {error}")))?;
    let endpoint = format!(
        "{}{ENROLL_PATH}",
        bootstrap.enrollment.url.trim_end_matches('/')
    );
    let request = EnrollmentRequest {
        name: bootstrap.enrollment.name.clone(),
        csr: csr_pem,
    };
    let body = serde_json::to_vec(&request).map_err(io::Error::other)?;
    // The shared fleet enrollment cert authenticates ONLY this mutual-TLS handshake; the minted
    // per-node cert below is what every steady-state request uses.
    let response = bootstrap
        .enrollment
        .enroll_identity()?
        .reqwest_client()?
        .post(endpoint)
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(io::Error::other)?;
    let bytes = success_body(response, "enrollment").await?;
    let enrolled: EnrollResponse = serde_json::from_slice(&bytes).map_err(invalid_error)?;
    enrolled.bundle.validate_shape()?;
    let bundle_bytes = serde_json::to_vec(&enrolled.bundle).map_err(io::Error::other)?;
    // Persist the minted leaf BEFORE the bundle/consumed marker (the key is already persisted):
    // steady state cannot run without the cert, and a crash after the leaf but before the bundle
    // simply re-enrolls (same durable key + name ⇒ same agent, same pinned key ⇒ idempotent).
    persist_leaf(state_dir, &enrolled.leaf, &enrolled.chain)?;
    load_or_enroll(&bundle_path, || Ok(bundle_bytes.clone()))
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

/// The node's durable per-node key (PKCS#8 PEM): generated once, persisted owner-only, and reused
/// on every enrollment retry — written BEFORE the CSR is sent so the certificate the control plane
/// pins and the key the node later signs telemetry with are always the same, even if a first
/// attempt reaches the control plane but its response is lost. A leaked key is time-bounded by the
/// leaf TTL, not the key's lifetime, since the leaf is re-minted on re-enrollment.
fn durable_key_pem(state_dir: &Path) -> io::Result<String> {
    let path = joined_key_path(state_dir);
    if let Ok(existing) = std::fs::read_to_string(&path) {
        if !existing.trim().is_empty() {
            return Ok(existing);
        }
    }
    let key_pem = crate::csr::generate_key()?;
    foundation::durable::atomic_write(&path, ".agent-key-", key_pem.as_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(key_pem)
}

/// Durably write the minted leaf (+ any issuer chain below the trusted CA). The key was persisted
/// earlier by [`durable_key_pem`]; the root/CA itself stays the bootstrap-pinned `ca`.
fn persist_leaf(state_dir: &Path, leaf_pem: &str, chain_pem: &str) -> io::Result<()> {
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
    fn bootstrap_is_name_plus_shared_cert_and_mints_a_per_node_identity() {
        let dir = tempfile::tempdir().unwrap();
        let base = "[enrollment]\nurl='https://updates.example/'\nca='/id/ca.crt'\nname='agent-7'\nclient_cert='/id/tls.crt'\nclient_key='/id/tls.key'\n";
        let config = BootstrapConfig::load(&write_bootstrap(dir.path(), base)).unwrap();
        assert_eq!(config.enrollment.name, "agent-7");
        // The shared fleet cert authenticates ONLY the enrollment handshake.
        let enroll = config.enrollment.enroll_identity().unwrap();
        assert_eq!(enroll.client_cert.to_str(), Some("/id/tls.crt"));
        // Steady-state identity is the PER-NODE cert minted at enrollment (state_dir/agent.crt),
        // never the shared fleet cert.
        let steady = config
            .enrollment
            .steady_identity(Path::new("/var/lib/updated/state"))
            .unwrap();
        assert_eq!(
            steady.client_cert,
            Path::new("/var/lib/updated/state/agent.crt")
        );
    }

    #[test]
    fn bootstrap_rejects_incomplete_or_stale_config() {
        let dir = tempfile::tempdir().unwrap();
        let ok = "[enrollment]\nurl='https://updates.example/'\nca='/id/ca.crt'\nname='agent-7'\nclient_cert='/id/tls.crt'\nclient_key='/id/tls.key'\n";
        assert!(BootstrapConfig::load(&write_bootstrap(dir.path(), ok)).is_ok());
        // A missing required field (name / cert / key) is rejected.
        for missing in [
            "[enrollment]\nurl='https://updates.example/'\nca='/id/ca.crt'\nclient_cert='/id/tls.crt'\nclient_key='/id/tls.key'\n",
            "[enrollment]\nurl='https://updates.example/'\nca='/id/ca.crt'\nname='agent-7'\nclient_key='/id/tls.key'\n",
        ] {
            assert!(BootstrapConfig::load(&write_bootstrap(dir.path(), missing)).is_err());
        }
        // An empty name is rejected by `validate()`.
        let empty = "[enrollment]\nurl='https://updates.example/'\nca='/id/ca.crt'\nname=''\nclient_cert='/id/tls.crt'\nclient_key='/id/tls.key'\n";
        assert!(BootstrapConfig::load(&write_bootstrap(dir.path(), empty)).is_err());
        // A stale mount/join/token field is rejected by `deny_unknown_fields`, so a half-migrated
        // config fails loudly instead of silently ignoring a credential.
        let stale = format!("{ok}group_id='canary'\n");
        assert!(BootstrapConfig::load(&write_bootstrap(dir.path(), &stale)).is_err());
    }

    #[test]
    fn a_node_name_must_be_a_dns_safe_label() {
        let name = |value: &str| EnrollmentRequest {
            name: value.into(),
            csr: String::new(),
        };
        assert!(name("agent-7").name_is_wellformed());
        assert!(name("magnolia-author-0").name_is_wellformed());
        for bad in ["", "-agent", "agent-", "Agent", "a_b", "a/b", "a.b"] {
            assert!(
                !name(bad).name_is_wellformed(),
                "{bad:?} should be rejected"
            );
        }
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
