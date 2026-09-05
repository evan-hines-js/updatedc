//! One-way enrollment bundle persistence shared by every agent frontend.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use updated_contracts::dataflow::DownloadCapability;
use updated_contracts::enrollment::{
    EnrollResponse, EnrollmentBundle, EnrollmentRequest, RenewalRequest, RenewalResponse,
    ENROLL_PATH, MAX_CONTROL_DOCUMENT_BYTES as CONTROL_RESPONSE_LIMIT,
    MAX_DOCUMENT_BYTES as ENROLLMENT_BUNDLE_LIMIT, RENEW_PATH,
};

const NODE_CONFIG_MAX_BYTES: usize = 64 * 1024;

/// The total wall-clock one control-plane exchange may take: the request, the response, and every
/// byte of its bounded body.
///
/// [`crate::tls::Identity::reqwest_client`] bounds *progress* only — a connect timeout and the gap
/// between two reads — because it is also the client that streams release artifacts, where a total
/// deadline is a cap on artifact size × link speed. These two exchanges are the opposite case:
/// their bodies are at most [`CONTROL_RESPONSE_LIMIT`], and a peer trickling one byte before
/// every read timeout would hold them forever — enrollment on the boot path, renewal inline in the
/// agent's single control loop, the loop that also drives update checks and the health probes,
/// so a hung gateway silently stops the node reporting health while it still looks alive. This is
/// the deadline that client's own documentation directs such a caller to impose: generous against
/// its 10s connect and 30s read, and far below any interval either caller retries on.
const CONTROL_PLANE_DEADLINE: Duration = Duration::from_secs(60);

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub enrollment: EnrollmentBootstrap,
}

/// The agent's sole node-local input, and deliberately minimal — a name, a CA, where to reach the
/// gateway, and an enrollment-only identity when this node still needs a leaf. Nothing else, and
/// never an implicit environment variable:
///
/// * `url` — the gateway to enroll against.
/// * `ca` — a PEM path for the CA that signs the gateway's (self-signed) server certificate, so the
///   node can verify the server it talks to without trusting the public web PKI.
/// * `name` — this node's name. Self-asserted; it becomes the minted certificate's `CN`, the
///   `UpdateAgent` the enrollment creates, and the node key the control plane pins.
/// * `bootstrap` — the enrollment certificate and key. It authenticates the `/enroll` handshake by
///   mutual TLS and nothing else; a party that holds it may enroll a reserved node name. It is
///   optional because an operator-provisioned node that already has `agent.crt` / `agent.key` must
///   not receive fleet-wide enrollment authority it will never use.
///
/// The node generates a keypair and CSR, presents `name` + its CSR at `/enroll` over that mutual
/// TLS, and receives a per-node certificate it uses for every steady-state request thereafter.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentBootstrap {
    pub url: String,
    pub ca: PathBuf,
    pub name: updated_contracts::identity::ResourceName,
    pub bootstrap: Option<EnrollmentClientIdentity>,
}

/// The credential for the one enrollment handshake. Keeping the pair in one optional block makes
/// the invalid half-configured states unrepresentable after TOML decoding.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentClientIdentity {
    pub client_cert: PathBuf,
    pub client_key: PathBuf,
}

impl EnrollmentBootstrap {
    /// Reject a name the gateway would refuse, and an empty path. `serde(deny_unknown_fields)`
    /// already rejects removed enrollment fields and a missing one, but a present-but-empty or
    /// otherwise ill-formed value passes it and would only fail at the first network use — the one
    /// thing eager validation exists to prevent. The name rule is asked of the wire contract that
    /// `/enroll` itself enforces ([`EnrollmentRequest::name_is_wellformed`]) rather than restated
    /// here, so a config that loads is a config the gateway will admit. The single validation site
    /// for it.
    pub fn validate(&self) -> io::Result<()> {
        let mut paths = vec![("ca", &self.ca)];
        if let Some(bootstrap) = &self.bootstrap {
            paths.extend([
                ("bootstrap.client_cert", &bootstrap.client_cert),
                ("bootstrap.client_key", &bootstrap.client_key),
            ]);
        }
        for (field, path) in paths {
            if path.as_os_str().is_empty() {
                return Err(invalid(&format!(
                    "enrollment {field} path must not be empty"
                )));
            }
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
        let bootstrap = self.bootstrap.as_ref().ok_or_else(|| {
            invalid(
                "this node has no enrollment bootstrap identity; preplace its per-node leaf or configure [enrollment.bootstrap]",
            )
        })?;
        Ok(crate::tls::Identity::new(
            bootstrap.client_cert.clone(),
            bootstrap.client_key.clone(),
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

impl NodeConfig {
    pub fn load(path: &Path) -> io::Result<Self> {
        // A host installer normally writes a regular file, while a container may mount a ConfigMap
        // key as a symlink. Both use one bounded opened-handle read; only the final symlink policy
        // differs from node-owned durable state below.
        let bytes = foundation::file::read_bounded_regular_string(
            path,
            NODE_CONFIG_MAX_BYTES,
            foundation::file::FinalSymlink::Follow,
        )?;
        let config: Self = toml::from_str(&bytes).map_err(|error| invalid(&error.to_string()))?;
        // The gateway is externally exposed and always TLS, so enrollment is always HTTPS: the node
        // verifies the gateway against the pinned `ca` and presents the shared fleet enrollment cert.
        crate::http::network_endpoint(
            &config.enrollment.url,
            crate::http::EndpointTransport::HttpsOnly,
            "enrollment URL",
        )?;
        // Validate eagerly so a misconfigured config fails at load, not at first network use.
        config.enrollment.validate()?;
        Ok(config)
    }
}

/// Parse the agent's sole local input: `--config <config.toml>`.
pub fn config_path(prog: &str) -> Result<PathBuf, String> {
    config_path_from(prog, std::env::args_os().skip(1))
}

fn config_path_from(
    prog: &str,
    args: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<PathBuf, String> {
    let usage = || format!("usage: {prog} --config <config.toml>");
    let mut args = args.into_iter();
    match args.next().as_deref() {
        Some(value) if value == "--config" => {
            let path = args
                .next()
                .map(PathBuf::from)
                .ok_or_else(|| "--config needs a path".to_string())?;
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
    match foundation::file::read_bounded_regular(
        bundle_path,
        ENROLLMENT_BUNDLE_LIMIT,
        foundation::file::FinalSymlink::Refuse,
    ) {
        Ok(bytes) => {
            let bundle = decode(&bytes)?;
            consume_if_needed(&consumed)?;
            Ok(bundle)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if foundation::file::path_entry_exists(&consumed)? {
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
            //
            // The bundle is public bootstrap metadata (routing anchor, assignment name, and the
            // immutable install-root pin), not a secret, so it commits through the managed door
            // and keeps the state directory's grant rather than an owner-only DACL no `icacls`
            // could repair.
            foundation::durable::atomic_write_managed(bundle_path, ".enrollment-", &bytes)?;
            consume_if_needed(&consumed)?;
            Ok(bundle)
        }
        Err(error) => Err(error),
    }
}

/// Resolve the enrollment bundle and ensure the node holds its steady-state identity. The small
/// routing bootstrap may be **preplaced** for an operator-assisted start, or fetched from S3 through
/// a capability minted by the enrollment endpoint — but identity is a separate, node-owned concern.
/// The per-node leaf (`agent.crt`) is either provisioned beside the bundle by an operator or minted
/// through the `/enroll` mutual-TLS handshake the first time the gateway is reachable. Online
/// enrollment presents the shared fleet enrollment cert, self-asserts the configured `name`, and
/// receives a leaf it persists and uses for every steady-state request thereafter. Idempotent on
/// retry (the durable per-node key plus the stable name yield the same agent and the same pinned
/// leaf); the bundle remains one-way (once consumed, enrollment can never re-run).
pub async fn load_or_enroll_http(
    config: &NodeConfig,
    state_dir: &Path,
) -> io::Result<EnrollmentBundle> {
    let bundle_path = bundle_path(state_dir);
    match load_existing_or_fresh(&bundle_path)? {
        // A preplaced (or already-loaded) bundle supplies the routing bootstrap, but carries no
        // identity. Mint the steady-state leaf now unless a prior boot already did — decoupling the
        // one-way bundle from the per-node cert is what lets an offline-seeded node still obtain a
        // real identity the first time it reaches the gateway.
        Some(bundle) => {
            // The leaf's identity (`CN`) comes from the configured enrollment name, so whatever
            // bundle this node runs on must name the same agent. Otherwise the node would run on one
            // agent's routing/assignment while holding another agent's steady-state certificate — a
            // split identity. Checked on EVERY boot, not only the one that mints the leaf: the
            // bundle on disk can be replaced under an already-enrolled node (a config-management
            // step, an image refresh), so fail closed on that misconfiguration every boot.
            if bundle.agent_id != config.enrollment.name {
                return Err(invalid(&format!(
                    "enrollment bundle is for agent {:?}, but this node is configured to enroll as \
                     {:?}",
                    bundle.agent_id, config.enrollment.name
                )));
            }
            // Mint the per-node steady-state leaf only when the node will actually present it: a
            // REMOTE gateway routing. A local/offline deployment (a `file:` or absolute-path
            // repository) reads routing and secrets straight from disk and never makes an mTLS
            // request, so it needs no per-node identity — and forcing an `/enroll` handshake it
            // cannot reach would wedge its boot. This mirrors the split the secrets client uses.
            let routing_is_local = crate::config::base_url_is_local(&bundle.routing_base_url)
                .map_err(|error| invalid(&format!("invalid routing base URL: {error}")))?;
            if !routing_is_local {
                let identity_complete =
                    foundation::file::path_entry_exists(&joined_cert_path(state_dir))?
                        && foundation::file::path_entry_exists(&joined_key_path(state_dir))?;
                if !identity_complete {
                    // The current object must agree on every immutable routing boundary the operator
                    // preplaced. Its root may be newer: the standard live TUF refresh walks that
                    // rotation from the preplaced root, so there is no second bundle-adoption path.
                    let minted = mint_leaf(config, state_dir).await?;
                    if minted.agent_id != bundle.agent_id
                        || minted.routing_base_url != bundle.routing_base_url
                        || minted.assignment != bundle.assignment
                        || minted.install_root != bundle.install_root
                    {
                        return Err(invalid(
                            "the live enrollment object disagrees with the preplaced node identity, routing path, or install root",
                        ));
                    }
                }
                validate_stored_leaf(config, state_dir)?;
            }
            Ok(bundle)
        }
        // No bundle yet: the `/enroll` handshake yields BOTH the minted leaf and the signed bundle.
        None => {
            let enrolled = mint_leaf(config, state_dir).await?;
            // The same split-identity check the preplaced path makes. The gateway names the agent
            // it registered; if that is not the name this node minted its leaf under, the node
            // would run on one agent's routing while presenting another's certificate. A gateway
            // that adopts a differently-named pre-existing agent is exactly how that happens.
            if enrolled.agent_id != config.enrollment.name {
                return Err(invalid(&format!(
                    "the control plane enrolled this node as agent {:?}, but it is configured to \
                     enroll as {:?}",
                    enrolled.agent_id, config.enrollment.name
                )));
            }
            let bundle_bytes = serde_json::to_vec(&enrolled).map_err(io::Error::other)?;
            load_or_enroll(&bundle_path, || Ok(bundle_bytes.clone()))
        }
    }
}

/// Where the node persists its enrollment bundle.
fn bundle_path(state_dir: &Path) -> PathBuf {
    state_dir.join("enrollment.json")
}

/// Mint the node's per-node steady-state certificate through the `/enroll` mutual-TLS handshake and
/// spend the exact S3 bundle capability issued beside it. The node generates a durable per-node key
/// and a CSR, presents its configured `name` over the shared fleet enrollment cert (which
/// authenticates ONLY this handshake), validates both results, then persists the leaf. Bundle bytes
/// never transit the gateway and the object request carries no client certificate. Idempotent: the
/// durable key and stable name mean a retry re-mints the same agent's leaf.
async fn mint_leaf(config: &NodeConfig, state_dir: &Path) -> io::Result<EnrollmentBundle> {
    std::fs::create_dir_all(state_dir)?;
    let key_pem = durable_key_pem(state_dir)?;
    let csr_pem = crate::csr::csr_for(&key_pem, "updated enroll")
        .map_err(|error| invalid(&format!("generating enrollment CSR: {error}")))?;
    let endpoint = format!(
        "{}{ENROLL_PATH}",
        config.enrollment.url.trim_end_matches('/')
    );
    let request = EnrollmentRequest {
        name: config.enrollment.name.clone(),
        csr: csr_pem,
    };
    let body = serde_json::to_vec(&request).map_err(io::Error::other)?;
    let bytes = control_plane_exchange(
        &config.enrollment.enroll_identity()?,
        &endpoint,
        body,
        "enrollment",
    )
    .await?;
    let enrolled = EnrollResponse::from_bounded_json(&bytes)?;
    validate_leaf(
        &enrolled.leaf,
        &request.csr,
        request.name.as_str(),
        &config.enrollment.ca,
    )?;
    let bundle = download_bundle(config, &enrolled.bundle_download).await?;
    persist_leaf(state_dir, &enrolled.leaf)?;
    Ok(bundle)
}

/// Spend one exact-object bearer capability without ever offering the node's certificate to the
/// object-store host. Redirects are refused so the bearer itself cannot escape to another origin;
/// the shared bundle ceiling is enforced over the streamed bytes before parsing.
async fn download_bundle(
    config: &NodeConfig,
    capability: &DownloadCapability,
) -> io::Result<EnrollmentBundle> {
    capability.validate().map_err(|error| invalid(&error))?;
    let response = crate::tls::anonymous_object_client_with_ca(&config.enrollment.ca)?
        .get(&capability.url)
        .timeout(CONTROL_PLANE_DEADLINE);
    let bytes = bounded_exchange(
        response,
        "enrollment bundle object",
        ENROLLMENT_BUNDLE_LIMIT,
    )
    .await?;
    decode_capability_bundle(capability, &bytes)
}

fn decode_capability_bundle(
    capability: &DownloadCapability,
    bytes: &[u8],
) -> io::Result<EnrollmentBundle> {
    crate::http::authenticate_download_bytes(capability, bytes, "enrollment bundle object")?;
    decode(bytes)
}

/// Renew the current per-node certificate when it enters its renewal window.
///
/// Enrollment itself is one-way; live TUF refresh owns metadata and TUF-root rotation. Certificate
/// renewal is therefore the only periodic enrollment control action this module performs. Fleet
/// CA distribution remains operator-owned configuration and is staged as an old+new PEM bundle.
pub async fn renew_node_certificate_if_due(
    config: &NodeConfig,
    state_dir: &Path,
) -> io::Result<bool> {
    renew_leaf_if_due(config, state_dir).await
}

/// Renew the current per-node certificate when it enters its renewal window. The durable key is
/// never replaced and the request is authenticated with the still-valid current certificate.
/// Returns `true` only after a new leaf has been durably installed.
async fn renew_leaf_if_due(config: &NodeConfig, state_dir: &Path) -> io::Result<bool> {
    const RENEW_BEFORE_SECS: i64 = 30 * 24 * 60 * 60;

    let cert_path = joined_cert_path(state_dir);
    let pem = match foundation::file::read_bounded_regular(
        &cert_path,
        crate::tls::TLS_MATERIAL_MAX_BYTES,
        foundation::file::FinalSymlink::Refuse,
    ) {
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

    let key_pem = crate::tls::read_private_key_pem(
        &joined_key_path(state_dir),
        foundation::file::FinalSymlink::Refuse,
    )?;
    let csr = crate::csr::csr_for(&key_pem, "updated renew")
        .map_err(|error| invalid(&format!("generating renewal CSR: {error}")))?;
    let endpoint = format!(
        "{}{RENEW_PATH}",
        config.enrollment.url.trim_end_matches('/')
    );
    let request = RenewalRequest { csr };
    let body = serde_json::to_vec(&request).map_err(io::Error::other)?;
    let bytes = control_plane_exchange(
        &config.enrollment.steady_identity(state_dir)?,
        &endpoint,
        body,
        "certificate renewal",
    )
    .await?;
    let renewed = RenewalResponse::from_bounded_json(&bytes)?;
    validate_leaf(
        &renewed.leaf,
        &request.csr,
        config.enrollment.name.as_str(),
        &config.enrollment.ca,
    )?;
    persist_leaf(state_dir, &renewed.leaf)?;
    Ok(true)
}

fn validate_leaf(leaf_pem: &str, csr_pem: &str, expected_name: &str, ca: &Path) -> io::Result<()> {
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
    crate::tls::verify_client_chain(leaf_der, ca)?;
    Ok(())
}

/// Validate an operator-provisioned or previously minted steady-state identity under exactly the
/// same name, key, CA, lifetime, and client-auth policy as a fresh `/enroll` response. This runs on
/// every remote boot, so placing files in the state directory is not a bypass around enrollment's
/// identity checks.
fn validate_stored_leaf(config: &NodeConfig, state_dir: &Path) -> io::Result<()> {
    let key_pem = crate::tls::read_private_key_pem(
        &joined_key_path(state_dir),
        foundation::file::FinalSymlink::Refuse,
    )?;
    let csr_pem = crate::csr::csr_for(&key_pem, "updated stored identity")
        .map_err(|error| invalid(&format!("validating stored node key: {error}")))?;
    let leaf = foundation::file::read_bounded_regular_string(
        &joined_cert_path(state_dir),
        crate::tls::TLS_MATERIAL_MAX_BYTES,
        foundation::file::FinalSymlink::Refuse,
    )?;
    validate_leaf(
        &leaf,
        &csr_pem,
        config.enrollment.name.as_str(),
        &config.enrollment.ca,
    )
}

fn chrono_now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}

/// If enrollment has already run (the bundle is present, or the consumed marker is set), return the
/// loaded bundle (or the consumed-but-missing error) without touching the network; return `None`
/// when a fresh network enrollment is due. Called only by [`load_or_enroll_http`], the sole
/// bootstrap entry point, so the one-way, consumed-once contract lives on that one path.
fn load_existing_or_fresh(bundle_path: &Path) -> io::Result<Option<EnrollmentBundle>> {
    if foundation::file::path_entry_exists(bundle_path)?
        || foundation::file::path_entry_exists(&consumed_path(bundle_path))?
    {
        load_or_enroll(bundle_path, || {
            Err(invalid("enrollment must not run for existing local state"))
        })
        .map(Some)
    } else {
        Ok(None)
    }
}

/// The one control-plane request shape: a JSON POST presenting `identity`, carrying
/// [`CONTROL_PLANE_DEADLINE`]. Enrollment and renewal both build their request here, so neither can
/// send one that is bounded only by the client's per-read progress timeouts.
fn control_plane_request(
    identity: &crate::tls::Identity,
    endpoint: &str,
    body: Vec<u8>,
) -> io::Result<reqwest::RequestBuilder> {
    Ok(identity
        .reqwest_control_client()?
        .post(endpoint)
        .header("content-type", "application/json")
        .body(body)
        // reqwest carries this deadline into the response body too, so it bounds the streamed read
        // below and not merely the handshake and headers.
        .timeout(CONTROL_PLANE_DEADLINE))
}

/// Perform one control-plane exchange and read its successful response, bounded by
/// [`CONTROL_RESPONSE_LIMIT`] through the one bounded-read helper every control-plane response
/// uses. Shared by enrollment and certificate renewal.
async fn control_plane_exchange(
    identity: &crate::tls::Identity,
    endpoint: &str,
    body: Vec<u8>,
    what: &str,
) -> io::Result<Vec<u8>> {
    bounded_exchange(
        control_plane_request(identity, endpoint, body)?,
        what,
        CONTROL_RESPONSE_LIMIT,
    )
    .await
}

/// The one HTTP send and bounded response read used by both authenticated control documents and
/// anonymous S3 bundle objects. Callers choose the contract limit; transport errors are always
/// redacted because the request URL may be a bearer secret.
async fn bounded_exchange(
    request: reqwest::RequestBuilder,
    what: &str,
    limit: usize,
) -> io::Result<Vec<u8>> {
    let response = request
        .send()
        .await
        .map_err(|error| crate::http::redacted_reqwest_error(what, &error))?;
    crate::http::read_bounded(response, what, limit).await
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
    match crate::tls::read_private_key_pem(&path, foundation::file::FinalSymlink::Refuse) {
        Ok(existing) if !existing.trim().is_empty() => {
            // A concurrent creator may have linked the complete key but not yet synced its name.
            foundation::durable::sync_dir(state_dir)?;
            return Ok(existing);
        }
        Ok(_) => {
            return Err(invalid(
                "the durable node key is empty; refusing to replace it",
            ))
        }
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
    match foundation::durable::atomic_write_new(&path, ".agent-key-", key_pem.as_bytes()) {
        Ok(()) => Ok(key_pem),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            // Another enrollment published first. Its complete key is the only identity either
            // caller may send to the gateway; never return the losing in-memory key.
            let key =
                crate::tls::read_private_key_pem(&path, foundation::file::FinalSymlink::Refuse)?;
            if key.trim().is_empty() {
                return Err(invalid(
                    "the durable node key is empty; refusing to replace it",
                ));
            }
            foundation::durable::sync_dir(state_dir)?;
            Ok(key)
        }
        Err(error) => Err(error),
    }
}

/// Durably write the minted leaf. The gateway's CA signs node leaves directly, so the leaf is the
/// whole client certificate; the key was persisted earlier by [`durable_key_pem`], and the root/CA
/// itself stays the bootstrap-pinned `ca`.
///
/// A certificate is public — only the key beside it is a secret — so this takes the managed door
/// and keeps the state directory's own grant, leaving it replaceable by an operator step.
fn persist_leaf(state_dir: &Path, leaf_pem: &str) -> io::Result<()> {
    foundation::durable::atomic_write_managed(
        &joined_cert_path(state_dir),
        ".agent-crt-",
        leaf_pem.as_bytes(),
    )
}

fn decode(bytes: &[u8]) -> io::Result<EnrollmentBundle> {
    EnrollmentBundle::from_bounded_json(bytes)
}

fn consume_if_needed(path: &Path) -> io::Result<()> {
    if foundation::file::path_entry_exists(path)? {
        return Ok(());
    }
    let parent = foundation::durable::parent_dir(path);
    std::fs::create_dir_all(parent)?;
    let file = foundation::durable::create_private_new(path)?;
    file.sync_all()?;
    foundation::durable::sync_dir(parent)
}

fn consumed_path(bundle: &Path) -> PathBuf {
    bundle.with_extension("consumed")
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use futures::executor::block_on;
    use rcgen::{
        CertificateParams, CertificateSigningRequestParams, DnType, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose,
    };
    use std::cell::Cell;
    use std::ffi::OsString;

    #[test]
    fn concurrent_enrollment_keeps_one_complete_durable_identity() {
        let directory = tempfile::tempdir().unwrap();
        let barrier = std::sync::Barrier::new(8);
        let keys = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        durable_key_pem(directory.path()).unwrap()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().unwrap())
                .collect::<Vec<_>>()
        });
        let persisted = durable_key_pem(directory.path()).unwrap();
        assert!(keys.iter().all(|key| *key == persisted));
        crate::csr::csr_for(&persisted, "test").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(joined_key_path(directory.path()))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn empty_enrollment_key_is_never_replaced() {
        let directory = tempfile::tempdir().unwrap();
        foundation::durable::atomic_write(&joined_key_path(directory.path()), ".test-", b"")
            .unwrap();
        assert!(durable_key_pem(directory.path()).is_err());
        assert!(std::fs::read(joined_key_path(directory.path()))
            .unwrap()
            .is_empty());
    }

    fn bundle() -> Vec<u8> {
        serde_json::to_vec(&EnrollmentBundle {
            schema: 1,
            agent_id: updated_contracts::identity::ResourceName::new("agent-a").unwrap(),
            routing_base_url: "https://updates.example/".into(),
            assignment: "assignments/agents/agent-a.json".into(),
            install_root: updated_contracts::assignment::testing::runtime().install_root,
            routing_root: "{}".into(),
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
    fn object_store_bytes_must_match_the_mtls_authenticated_digest() {
        let bytes = bundle();
        let capability = DownloadCapability {
            schema: DownloadCapability::SCHEMA,
            url: "https://objects.example/enrollment?X-Amz-Signature=secret".into(),
            sha256: updated_contracts::digest::sha256_bytes(&bytes),
        };
        assert!(decode_capability_bundle(&capability, &bytes).is_ok());

        let mut substituted = bytes;
        substituted.push(b' ');
        assert_eq!(
            decode_capability_bundle(&capability, &substituted)
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidData
        );
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

    #[cfg(unix)]
    #[test]
    fn a_dangling_consumed_marker_still_blocks_enrollment() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.enrollment.json");
        let consumed = consumed_path(&path);
        std::os::unix::fs::symlink(dir.path().join("missing-target"), consumed).unwrap();
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

    #[test]
    fn oversized_preplaced_bundle_fails_without_enrolling() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.enrollment.json");
        std::fs::write(&path, vec![b' '; ENROLLMENT_BUNDLE_LIMIT + 1]).unwrap();
        let called = Cell::new(false);
        assert_eq!(
            load_or_enroll(&path, || {
                called.set(true);
                Ok(bundle())
            })
            .unwrap_err()
            .kind(),
            io::ErrorKind::InvalidData
        );
        assert!(!called.get());
    }

    /// A bundle for `agent_id` whose `routing_root` is `marker`, so a test can tell which of two
    /// bundles a path ended up holding.
    fn bundle_for(agent_id: &str, marker: &str) -> EnrollmentBundle {
        EnrollmentBundle {
            schema: 1,
            agent_id: updated_contracts::identity::ResourceName::new(agent_id).unwrap(),
            routing_base_url: "https://updates.example/".into(),
            assignment: format!("assignments/agents/{agent_id}.json"),
            install_root: updated_contracts::assignment::testing::runtime().install_root,
            routing_root: format!("{{\"marker\":\"{marker}\"}}"),
        }
    }

    fn config_for(dir: &Path, name: &str) -> NodeConfig {
        let body = format!(
            "[enrollment]\nurl='https://updates.example/'\nca='/id/ca.crt'\nname='{name}'\n[enrollment.bootstrap]\nclient_cert='/id/tls.crt'\nclient_key='/id/tls.key'\n"
        );
        NodeConfig::load(&write_config(dir, &body)).unwrap()
    }

    /// A bundle naming another agent must be refused however long this node has been enrolled. The
    /// mint path is the obvious place it appears, but the dangerous one is a bundle swapped under a
    /// node that already holds its leaf: minting is skipped there, so the persisted-path identity
    /// rule is both conditional on aging material and warned away rather than propagated. Boot must
    /// fail closed, before any of the foreign agent's assignment is resolved.
    #[test]
    fn a_bundle_naming_another_agent_fails_the_boot_even_after_the_leaf_is_minted() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_for(dir.path(), "agent-a");
        let foreign = bundle_for("agent-b", "pinned");
        std::fs::write(
            bundle_path(dir.path()),
            serde_json::to_vec(&foreign).unwrap(),
        )
        .unwrap();
        // The node has already enrolled, so nothing on this boot would mint a leaf.
        std::fs::write(joined_cert_path(dir.path()), "leaf").unwrap();

        let error = block_on(load_or_enroll_http(&config, dir.path())).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("agent-b"), "{error}");
        // Refused on identity alone: no gateway was asked anything.
    }

    fn write_config(dir: &Path, body: &str) -> PathBuf {
        let path = dir.join("config.toml");
        std::fs::write(&path, body).unwrap();
        path
    }

    #[test]
    fn config_separates_the_optional_bootstrap_from_the_per_node_identity() {
        let dir = tempfile::tempdir().unwrap();
        let base = "[enrollment]\nurl='https://updates.example/'\nca='/id/ca.crt'\nname='agent-7'\n[enrollment.bootstrap]\nclient_cert='/id/tls.crt'\nclient_key='/id/tls.key'\n";
        let config = NodeConfig::load(&write_config(dir.path(), base)).unwrap();
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

        let manual =
            "[enrollment]\nurl='https://updates.example/'\nca='/id/ca.crt'\nname='manual-7'\n";
        let manual = NodeConfig::load(&write_config(dir.path(), manual)).unwrap();
        assert!(manual.enrollment.enroll_identity().is_err());
        assert_eq!(
            manual
                .enrollment
                .steady_identity(Path::new("/var/lib/updated/manual"))
                .unwrap()
                .client_cert,
            Path::new("/var/lib/updated/manual/agent.crt")
        );
    }

    #[test]
    fn a_preprovisioned_identity_is_validated_and_never_needs_bootstrap_authority() {
        crate::tls::install_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let (ca_pem, ca_key) = test_ca();
        let ca_path = dir.path().join("ca.crt");
        std::fs::write(&ca_path, &ca_pem).unwrap();
        let key = crate::csr::generate_key().unwrap();
        let csr = crate::csr::csr_for(&key, "offline fixture").unwrap();
        let leaf = issue_test_leaf(&ca_pem, &ca_key, &csr, "manual-7");
        foundation::durable::atomic_write(&joined_key_path(dir.path()), ".key-", key.as_bytes())
            .unwrap();
        std::fs::write(joined_cert_path(dir.path()), leaf).unwrap();
        std::fs::write(
            bundle_path(dir.path()),
            serde_json::to_vec(&bundle_for("manual-7", "offline")).unwrap(),
        )
        .unwrap();
        let config = NodeConfig::load(&write_config(
            dir.path(),
            &format!(
                "[enrollment]\nurl='https://updates.example/'\nca='{}'\nname='manual-7'\n",
                ca_path.display()
            ),
        ))
        .unwrap();

        block_on(load_or_enroll_http(&config, dir.path())).unwrap();

        // A partial external install does not silently count as a usable identity. With no
        // bootstrap authority available, recovery stops before any network request.
        std::fs::remove_file(joined_cert_path(dir.path())).unwrap();
        let error = block_on(load_or_enroll_http(&config, dir.path())).unwrap_err();
        assert!(
            error.to_string().contains("no enrollment bootstrap"),
            "{error}"
        );
    }

    #[test]
    fn node_config_is_bounded_before_toml_parsing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, vec![b' '; NODE_CONFIG_MAX_BYTES + 1]).unwrap();
        assert_eq!(
            NodeConfig::load(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn config_rejects_incomplete_or_stale_input() {
        let dir = tempfile::tempdir().unwrap();
        let ok = "[enrollment]\nurl='https://updates.example/'\nca='/id/ca.crt'\nname='agent-7'\n[enrollment.bootstrap]\nclient_cert='/id/tls.crt'\nclient_key='/id/tls.key'\n";
        assert!(NodeConfig::load(&write_config(dir.path(), ok)).is_ok());
        // A missing required field (name or one half of a present bootstrap identity) is rejected.
        for missing in [
            "[enrollment]\nurl='https://updates.example/'\nca='/id/ca.crt'\n[enrollment.bootstrap]\nclient_cert='/id/tls.crt'\nclient_key='/id/tls.key'\n",
            "[enrollment]\nurl='https://updates.example/'\nca='/id/ca.crt'\nname='agent-7'\n[enrollment.bootstrap]\nclient_key='/id/tls.key'\n",
        ] {
            assert!(NodeConfig::load(&write_config(dir.path(), missing)).is_err());
        }
        // An empty name is rejected by `validate()`.
        let empty = "[enrollment]\nurl='https://updates.example/'\nca='/id/ca.crt'\nname=''\n[enrollment.bootstrap]\nclient_cert='/id/tls.crt'\nclient_key='/id/tls.key'\n";
        assert!(NodeConfig::load(&write_config(dir.path(), empty)).is_err());
        // A removed enrollment field is rejected by `deny_unknown_fields`, so a half-migrated
        // config fails loudly instead of silently ignoring a credential.
        let stale = format!("{ok}group_id='canary'\n");
        assert!(NodeConfig::load(&write_config(dir.path(), &stale)).is_err());

        // The URL is eventually concatenated with fixed enrollment and renewal paths. Reject
        // every component that could reinterpret those paths or escape into diagnostics before
        // the node creates any durable enrollment state.
        for url in [
            "http://updates.example/",
            "https://user@updates.example/",
            "https://updates.example/?token=secret",
            "https://updates.example/#fragment",
            "updates.example",
        ] {
            let body = format!(
                "[enrollment]\nurl='{url}'\nca='/id/ca.crt'\nname='agent-7'\n[enrollment.bootstrap]\nclient_cert='/id/tls.crt'\nclient_key='/id/tls.key'\n"
            );
            let error = NodeConfig::load(&write_config(dir.path(), &body)).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput, "accepted {url}");
            assert!(
                !error.to_string().contains("secret"),
                "URL material escaped into the validation error: {error}"
            );
        }
    }

    /// A name the gateway will refuse must fail at config load, not after the node has minted and
    /// persisted a durable key and built a CSR — otherwise every boot retries and the failure is
    /// attributed to the gateway rather than to the one file the operator can fix.
    #[test]
    fn a_node_name_must_be_a_dns_safe_subdomain() {
        let dir = tempfile::tempdir().unwrap();
        let load = |name: &str| {
            let body = format!(
                "[enrollment]\nurl='https://updates.example/'\nca='/id/ca.crt'\nname='{name}'\n[enrollment.bootstrap]\nclient_cert='/id/tls.crt'\nclient_key='/id/tls.key'\n"
            );
            NodeConfig::load(&write_config(dir.path(), &body))
        };
        assert!(load("agent-7").is_ok());
        assert!(load("jenkins-author-0").is_ok());
        assert!(load("rack-1.agent-7").is_ok());
        for bad in [
            "", " ", "-agent", "agent-", "Agent", "a_b", "a/b", ".agent", "agent.", "a..b",
        ] {
            assert!(load(bad).is_err(), "{bad:?} should be rejected at load");
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
        validate_leaf(&leaf, &csr, "agent-7", &ca_path).unwrap();

        let (wrong_ca, _) = test_ca();
        std::fs::write(&ca_path, wrong_ca).unwrap();
        assert!(validate_leaf(&leaf, &csr, "agent-7", &ca_path).is_err());
    }

    /// The body of the named item in this module's own source, by brace matching from its first
    /// `{`. Used by the guard below: whether the two entry points reach the one deadline-carrying
    /// request builder is a property of the call graph, and no assertion about the builder in
    /// isolation can observe it.
    fn body_of(source: &str, signature: &str) -> String {
        let start = source
            .find(signature)
            .unwrap_or_else(|| panic!("`{signature}` is not in this module"));
        let open = start + source[start..].find('{').expect("a function body");
        let mut depth = 0usize;
        for (offset, character) in source[open..].char_indices() {
            match character {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if depth == 0 {
                        return source[open..open + offset].to_string();
                    }
                }
                _ => {}
            }
        }
        panic!("`{signature}` has an unterminated body");
    }

    /// Both control-plane calls sit where a hang is invisible — enrollment on the boot path,
    /// renewal inline in the agent's single control loop — and the client they use bounds only
    /// the gap between two reads, which a peer trickling one byte per gap never trips. Every
    /// request they send must therefore carry the total deadline.
    ///
    /// So both halves are asserted: that the shared builder attaches the deadline, and that the two
    /// entry points actually send through it. A request built anywhere else would carry the client's
    /// per-read bound and nothing more — the exact hang this guards — and the first half alone stays
    /// green while that is added.
    #[test]
    fn every_control_plane_request_carries_a_total_deadline() {
        // The production half only — this test quotes the very spellings it counts.
        let source = include_str!("enrollment.rs")
            .split("\n#[cfg(test)]\n")
            .next()
            .expect("the module source splits at its test module");
        // Exactly one send in the module, and it is built by the helper that attaches the deadline.
        assert_eq!(
            source
                .lines()
                .filter(|line| line.trim() == ".send()")
                .count(),
            1,
            "this module must send one request shape, the one that carries the deadline"
        );
        let bounded = body_of(source, "async fn bounded_exchange");
        assert!(bounded.contains(".send()") && bounded.contains("read_bounded("));
        let exchange = body_of(source, "async fn control_plane_exchange");
        assert!(
            exchange.contains("control_plane_request(") && exchange.contains("bounded_exchange(")
        );
        // …and both entry points reach the control plane only through it.
        for entry in ["async fn mint_leaf", "async fn renew_leaf_if_due"] {
            assert!(
                body_of(source, entry).contains("control_plane_exchange("),
                "`{entry}` reaches the control plane outside the deadline-carrying request"
            );
        }
        let download = body_of(source, "async fn download_bundle");
        assert!(
            download.contains("anonymous_object_client_with_ca(")
                && download.contains("bounded_exchange(")
                && download.contains("ENROLLMENT_BUNDLE_LIMIT"),
            "bundle bytes must use the public-CA-only, deadline-carrying, bounded object path"
        );

        crate::tls::install_crypto_provider();
        let dir = tempfile::tempdir().unwrap();
        let (ca_pem, ca_key) = test_ca();
        let ca_path = dir.path().join("ca.crt");
        std::fs::write(&ca_path, &ca_pem).unwrap();
        let key = crate::csr::generate_key().unwrap();
        let csr = crate::csr::csr_for(&key, "test").unwrap();
        let cert_path = dir.path().join("agent.crt");
        let key_path = dir.path().join("agent.key");
        std::fs::write(
            &cert_path,
            issue_test_leaf(&ca_pem, &ca_key, &csr, "agent-7"),
        )
        .unwrap();
        std::fs::write(&key_path, &key).unwrap();

        let identity = crate::tls::Identity::new(cert_path, key_path, ca_path);
        let request =
            control_plane_request(&identity, "https://updates.example/enroll", b"{}".to_vec())
                .unwrap()
                .build()
                .unwrap();
        assert_eq!(request.timeout(), Some(&CONTROL_PLANE_DEADLINE));
    }

    #[test]
    fn config_without_a_node_name_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        assert!(NodeConfig::load(&write_config(
            dir.path(),
            "[enrollment]\nurl='https://updates.example/'\nca='/id/ca.crt'\n",
        ))
        .is_err());
    }

    #[test]
    fn config_path_rejects_every_trailing_argument() {
        let args = ["--config", "config.toml", "--typo"]
            .into_iter()
            .map(OsString::from);
        assert!(config_path_from("agent", args)
            .unwrap_err()
            .contains("unexpected trailing argument"));
    }
}
