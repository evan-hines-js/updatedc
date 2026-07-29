//! One-way enrollment bundle persistence shared by every agent frontend.

use std::io;
use std::path::{Path, PathBuf};

use rustls::pki_types::pem::PemObject;
use serde::Deserialize;

#[cfg(test)]
use updated_contracts::enrollment::InitialSignedConfiguration;
use updated_contracts::enrollment::{
    EnrollResponse, EnrollmentBundle, EnrollmentRequest, RenewalRequest, RenewalResponse,
    ENROLL_PATH, RENEW_PATH,
};

const ENROLLMENT_RESPONSE_LIMIT: usize = 1024 * 1024;

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
    /// removed enrollment fields and a missing cert path, so a stale config fails loudly
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

/// Resolve the enrollment bundle and ensure the node holds its steady-state identity. The bundle
/// (routing, assignment, and the initial signed configuration) may be **preplaced** for a
/// network-free first start, or fetched over the network — but identity is a separate, node-owned
/// concern. The per-node leaf (`agent.crt`) is ALWAYS minted through the `/enroll` mutual-TLS
/// handshake the first time the gateway is reachable: the node presents the shared fleet enrollment
/// cert, self-asserts its configured `name`, and receives a leaf it persists and uses for every
/// steady-state request thereafter. Idempotent on retry (the durable per-node key plus the stable
/// name yield the same agent and the same pinned leaf); the bundle remains one-way (once consumed,
/// enrollment can never re-run).
pub async fn load_or_enroll_http(
    bootstrap: &BootstrapConfig,
    state_dir: &Path,
) -> io::Result<EnrollmentBundle> {
    let bundle_path = state_dir.join("enrollment.json");
    match load_existing_or_fresh(&bundle_path, "enrollment") {
        // A preplaced (or already-loaded) bundle supplies routing/assignment/config, but carries no
        // identity. Mint the steady-state leaf now unless a prior boot already did — decoupling the
        // one-way bundle from the per-node cert is what lets an offline-seeded node still obtain a
        // real identity the first time it reaches the gateway.
        Some(loaded) => {
            let bundle = loaded?;
            // Mint the per-node steady-state leaf only when the node will actually present it: a
            // REMOTE gateway routing. A local/offline deployment (a `file:` or absolute-path
            // repository) reads routing and secrets straight from disk and never makes an mTLS
            // request, so it needs no per-node identity — and forcing an `/enroll` handshake it
            // cannot reach would wedge its boot. This mirrors the split the secrets client uses.
            if routing_is_remote(&bundle.routing_base_url) && !joined_cert_path(state_dir).exists()
            {
                // The leaf's identity (`CN`) comes from the configured enrollment name, so it must
                // name the same agent the preplaced bundle was issued for. Otherwise the node would
                // run on one agent's routing/assignment while holding another agent's steady-state
                // certificate — a split identity. Fail closed on that misconfiguration.
                if bundle.agent_id != bootstrap.enrollment.name {
                    return Err(invalid(&format!(
                        "preplaced enrollment bundle is for agent {:?}, but this node is configured \
                         to enroll as {:?}",
                        bundle.agent_id, bootstrap.enrollment.name
                    )));
                }
                mint_leaf(bootstrap, state_dir).await?;
            }
            Ok(bundle)
        }
        // No bundle yet: the `/enroll` handshake yields BOTH the minted leaf and the signed bundle.
        None => {
            let enrolled = mint_leaf(bootstrap, state_dir).await?;
            // The same split-identity check the preplaced path makes. The gateway names the agent
            // it registered; if that is not the name this node minted its leaf under, the node
            // would run on one agent's routing while presenting another's certificate. A gateway
            // that adopts a differently-named pre-existing agent is exactly how that happens.
            if enrolled.agent_id != bootstrap.enrollment.name {
                return Err(invalid(&format!(
                    "the control plane enrolled this node as agent {:?}, but it is configured to \
                     enroll as {:?}",
                    enrolled.agent_id, bootstrap.enrollment.name
                )));
            }
            let bundle_bytes = serde_json::to_vec(&enrolled).map_err(io::Error::other)?;
            load_or_enroll(&bundle_path, || Ok(bundle_bytes.clone()))
        }
    }
}

/// Whether a routing base URL is a remote gateway (reached over mTLS) rather than a local `file:`
/// or absolute-path repository read straight from disk. Mirrors the split the secrets client uses
/// (`SecretManager::initialize`): only a remote deployment ever presents the per-node leaf, so only
/// it needs one minted.
fn routing_is_remote(base_url: &str) -> bool {
    !(base_url.starts_with("file:") || Path::new(base_url).is_absolute())
}

/// Mint the node's per-node steady-state certificate through the `/enroll` mutual-TLS handshake and
/// return the signed enrollment bundle the gateway issued alongside it. The node generates a durable
/// per-node key and a CSR, presents its configured `name` over the shared fleet enrollment cert
/// (which authenticates ONLY this handshake), and persists the minted leaf before returning — the
/// key is already durable and steady state cannot run without the cert. Idempotent: the durable key
/// and stable name mean a retry re-mints the same agent's leaf, so a crash after the leaf is written
/// but before its caller finishes simply re-enrolls to the same identity.
async fn mint_leaf(bootstrap: &BootstrapConfig, state_dir: &Path) -> io::Result<EnrollmentBundle> {
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
    validate_leaf(
        &enrolled.leaf,
        &enrolled.chain,
        &request.csr,
        &request.name,
        &bootstrap.enrollment.ca,
    )?;
    persist_leaf(state_dir, &enrolled.leaf, &enrolled.chain)?;
    Ok(enrolled.bundle)
}

/// Renew the current per-node certificate when it enters its renewal window. The durable key is
/// never replaced and the request is authenticated with the still-valid current certificate.
/// Returns `true` only after a new leaf has been durably installed.
pub async fn renew_identity_if_due(
    bootstrap: &BootstrapConfig,
    state_dir: &Path,
) -> io::Result<bool> {
    const RENEW_BEFORE_SECS: i64 = 30 * 24 * 60 * 60;

    let cert_path = joined_cert_path(state_dir);
    let pem = match std::fs::read(&cert_path) {
        Ok(pem) => pem,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    let (_, pem) = x509_parser::pem::parse_x509_pem(&pem)
        .map_err(|error| invalid(&format!("parsing node certificate PEM: {error}")))?;
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents)
        .map_err(|error| invalid(&format!("parsing node certificate: {error}")))?;
    let remaining = cert.validity().not_after.timestamp() - chrono_now_unix();
    if remaining > RENEW_BEFORE_SECS {
        return Ok(false);
    }
    if remaining <= 0 {
        return Err(invalid(
            "node certificate expired before renewal; operator re-enrollment is required",
        ));
    }

    let key_pem = std::fs::read_to_string(joined_key_path(state_dir))?;
    let csr = crate::csr::csr_for(&key_pem, "updated renew")
        .map_err(|error| invalid(&format!("generating renewal CSR: {error}")))?;
    let endpoint = format!(
        "{}{RENEW_PATH}",
        bootstrap.enrollment.url.trim_end_matches('/')
    );
    let request = RenewalRequest { csr };
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
    let bytes = success_body(response, "certificate renewal").await?;
    let renewed: RenewalResponse = serde_json::from_slice(&bytes).map_err(invalid_error)?;
    validate_leaf(
        &renewed.leaf,
        &renewed.chain,
        &request.csr,
        &bootstrap.enrollment.name,
        &bootstrap.enrollment.ca,
    )?;
    persist_leaf(state_dir, &renewed.leaf, &renewed.chain)?;
    Ok(true)
}

fn validate_leaf(
    leaf_pem: &str,
    chain_pem: &str,
    csr_pem: &str,
    expected_name: &str,
    ca: &Path,
) -> io::Result<()> {
    use x509_parser::prelude::FromDer;

    let (_, leaf_pem) = x509_parser::pem::parse_x509_pem(leaf_pem.as_bytes())
        .map_err(|error| invalid(&format!("parsing issued certificate PEM: {error}")))?;
    let (_, leaf) = x509_parser::parse_x509_certificate(&leaf_pem.contents)
        .map_err(|error| invalid(&format!("parsing issued certificate: {error}")))?;
    let common_names = leaf
        .subject()
        .iter_common_name()
        .map(|name| name.as_str().ok())
        .collect::<Vec<_>>();
    if common_names.as_slice() != [Some(expected_name)] {
        return Err(invalid("issued certificate has the wrong node identity"));
    }
    if leaf.is_ca() {
        return Err(invalid("issued node certificate must not be a CA"));
    }

    let (_, csr_pem) = x509_parser::pem::parse_x509_pem(csr_pem.as_bytes())
        .map_err(|error| invalid(&format!("parsing requested CSR PEM: {error}")))?;
    let (_, csr) =
        x509_parser::certification_request::X509CertificationRequest::from_der(&csr_pem.contents)
            .map_err(|error| invalid(&format!("parsing requested CSR: {error}")))?;
    if leaf.public_key().raw != csr.certification_request_info.subject_pki.raw {
        return Err(invalid(
            "issued certificate does not contain the requested durable key",
        ));
    }
    let leaf_der = rustls::pki_types::CertificateDer::from(leaf_pem.contents);
    let intermediates = rustls::pki_types::CertificateDer::pem_slice_iter(chain_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| invalid(&format!("parsing issued certificate chain: {error}")))?;
    crate::tls::verify_client_chain(leaf_der, &intermediates, ca)?;
    Ok(())
}

fn chrono_now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
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

/// Read a successful response body, bounded by [`ENROLLMENT_RESPONSE_LIMIT`]. Shared by enrollment
/// and certificate renewal, through the one bounded-read helper every control-plane response uses.
async fn success_body(response: reqwest::Response, what: &str) -> io::Result<Vec<u8>> {
    crate::http::read_bounded(response, what, ENROLLMENT_RESPONSE_LIMIT).await
}

/// The node's durable per-node key (PKCS#8 PEM): generated once, persisted owner-only, and reused
/// on every enrollment retry — written BEFORE the CSR is sent so the certificate the control plane
/// pins and the key the node later signs telemetry with are always the same, even if a first
/// attempt reaches the control plane but its response is lost. A leaked key is time-bounded by the
/// leaf TTL, not the key's lifetime, since the leaf is re-minted on re-enrollment.
fn durable_key_pem(state_dir: &Path) -> io::Result<String> {
    let path = joined_key_path(state_dir);
    // Only a genuinely ABSENT key may be replaced. Every other failure — EACCES because the mode
    // or owner changed, EIO on a failing disk, invalid UTF-8 from a single flipped byte — means a
    // key file is there, and generating over it destroys the durable identity the control plane
    // pinned: the node's telemetry stops verifying and it can never prove it is itself again.
    match std::fs::read_to_string(&path) {
        Ok(existing) if !existing.trim().is_empty() => return Ok(existing),
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "reading the durable node key at {} failed ({error}); refusing to overwrite it",
                    path.display()
                ),
            ))
        }
    }
    let key_pem = crate::csr::generate_key()?;
    // `atomic_write` commits owner-only, so no chmod follows.
    foundation::durable::atomic_write(&path, ".agent-key-", key_pem.as_bytes())?;
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
    use rcgen::{
        CertificateParams, CertificateSigningRequestParams, DnType, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose,
    };
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
        // A removed enrollment field is rejected by `deny_unknown_fields`, so a half-migrated
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

    fn test_ca() -> (String, KeyPair) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "test enrollment CA");
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key)
    }

    fn issue_test_leaf(ca_pem: &str, ca_key: &KeyPair, csr_pem: &str, name: &str) -> String {
        let ca_params = CertificateParams::from_ca_cert_pem(ca_pem).unwrap();
        let ca = ca_params.self_signed(ca_key).unwrap();
        let mut csr = CertificateSigningRequestParams::from_pem(csr_pem).unwrap();
        csr.params.is_ca = IsCa::NoCa;
        csr.params.distinguished_name = rcgen::DistinguishedName::new();
        csr.params.distinguished_name.push(DnType::CommonName, name);
        csr.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        csr.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        csr.signed_by(&ca, ca_key).unwrap().pem()
    }

    #[test]
    fn issued_leaf_must_validate_as_client_auth_under_the_pinned_ca() {
        crate::tls::install_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let (ca_pem, ca_key) = test_ca();
        let ca_path = dir.path().join("ca.crt");
        std::fs::write(&ca_path, &ca_pem).unwrap();
        let csr = crate::csr::csr_for(&crate::csr::generate_key().unwrap(), "test").unwrap();
        let leaf = issue_test_leaf(&ca_pem, &ca_key, &csr, "agent-7");
        validate_leaf(&leaf, "", &csr, "agent-7", &ca_path).unwrap();

        let (wrong_ca, _) = test_ca();
        std::fs::write(&ca_path, wrong_ca).unwrap();
        assert!(validate_leaf(&leaf, "", &csr, "agent-7", &ca_path).is_err());
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
