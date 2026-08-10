//! One-way enrollment bundle persistence shared by every agent frontend.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

#[cfg(test)]
use updated_contracts::enrollment::InitialSignedConfiguration;
use updated_contracts::enrollment::{
    EnrollResponse, EnrollmentBundle, EnrollmentRequest, RenewalRequest, RenewalResponse,
    BUNDLE_PATH, ENROLL_PATH, RENEW_PATH,
};

const ENROLLMENT_RESPONSE_LIMIT: usize = 1024 * 1024;

/// The total wall-clock one control-plane exchange may take: the request, the response, and every
/// byte of its bounded body.
///
/// [`crate::tls::Identity::reqwest_client`] bounds *progress* only — a connect timeout and the gap
/// between two reads — because it is also the client that streams release artifacts, where a total
/// deadline is a cap on artifact size × link speed. These two exchanges are the opposite case:
/// their bodies are at most [`ENROLLMENT_RESPONSE_LIMIT`], and a peer trickling one byte before
/// every read timeout would hold them forever — enrollment on the boot path, renewal inline in the
/// supervisor's single control loop, the loop that also drives update checks and the health probes,
/// so a hung gateway silently stops the node reporting health while it still looks alive. This is
/// the deadline that client's own documentation directs such a caller to impose: generous against
/// its 10s connect and 30s read, and far below any interval either caller retries on.
const CONTROL_PLANE_DEADLINE: Duration = Duration::from_secs(60);

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
    /// Reject an empty `name` and an empty path. `serde(deny_unknown_fields)` already rejects
    /// removed enrollment fields and a missing one, but a present-but-empty value passes it and
    /// would only fail at the first network use — the one thing eager validation exists to
    /// prevent. The single validation site for a bootstrap.
    pub fn validate(&self) -> io::Result<()> {
        if self.name.trim().is_empty() {
            return Err(invalid("bootstrap enrollment name must not be empty"));
        }
        for (field, path) in [
            ("ca", &self.ca),
            ("client_cert", &self.client_cert),
            ("client_key", &self.client_key),
        ] {
            if path.as_os_str().is_empty() {
                return Err(invalid(&format!(
                    "bootstrap enrollment {field} path must not be empty"
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
            //
            // The bundle is signed public metadata (routing, assignment, the initial signed
            // configuration), not a secret, so it commits through the managed door and keeps the
            // state directory's grant rather than an owner-only DACL no `icacls` could repair.
            foundation::durable::atomic_write_managed(bundle_path, ".enrollment-", &bytes)?;
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
    policy: &dyn BundlePolicy,
) -> io::Result<EnrollmentBundle> {
    let bundle_path = bundle_path(state_dir);
    match load_existing_or_fresh(&bundle_path) {
        // A preplaced (or already-loaded) bundle supplies routing/assignment/config, but carries no
        // identity. Mint the steady-state leaf now unless a prior boot already did — decoupling the
        // one-way bundle from the per-node cert is what lets an offline-seeded node still obtain a
        // real identity the first time it reaches the gateway.
        Some(loaded) => {
            let mut bundle = loaded?;
            // The leaf's identity (`CN`) comes from the configured enrollment name, so whatever
            // bundle this node runs on must name the same agent. Otherwise the node would run on one
            // agent's routing/assignment while holding another agent's steady-state certificate — a
            // split identity. Checked on EVERY boot, not only the one that mints the leaf: the
            // bundle on disk can be replaced under an already-enrolled node (a config-management
            // step, an image refresh), and nothing further down re-checks it — `refresh_bundle`'s
            // own identity rule is skipped when the material is not yet aging, and warned away
            // rather than propagated when it is. Fail closed on that misconfiguration.
            if bundle.agent_id != bootstrap.enrollment.name {
                return Err(invalid(&format!(
                    "enrollment bundle is for agent {:?}, but this node is configured to enroll as \
                     {:?}",
                    bundle.agent_id, bootstrap.enrollment.name
                )));
            }
            // Mint the per-node steady-state leaf only when the node will actually present it: a
            // REMOTE gateway routing. A local/offline deployment (a `file:` or absolute-path
            // repository) reads routing and secrets straight from disk and never makes an mTLS
            // request, so it needs no per-node identity — and forcing an `/enroll` handshake it
            // cannot reach would wedge its boot. This mirrors the split the secrets client uses.
            if !crate::config::base_url_is_local(&bundle.routing_base_url)
                && !joined_cert_path(state_dir).exists()
            {
                // The `/enroll` response carries a freshly signed bundle beside the leaf. Adopting
                // it is what makes minting an identity for a preplaced node also REFRESH the
                // material it was seeded with: the preplaced copy was signed whenever the image was
                // built, and discarding this one left the node holding metadata that only ages.
                // Rejected (a substituted root, an unverifiable chain) leaves the preplaced bundle
                // exactly as it was — the leaf is still minted, and boot proceeds on it.
                let minted = mint_leaf(bootstrap, state_dir).await?;
                match adopt_bundle(&bundle_path, bootstrap, &minted, &bundle, policy).await {
                    Ok(()) => bundle = minted,
                    Err(error) => warn(&format!(
                        "keeping the preplaced enrollment bundle: the one minted with this node's \
                         certificate was refused ({error})"
                    )),
                }
            }
            Ok(refresh_bundle_or_warn(bootstrap, state_dir, bundle, policy).await)
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

/// Where the node persists its enrollment bundle.
fn bundle_path(state_dir: &Path) -> PathBuf {
    state_dir.join("enrollment.json")
}

fn warn(message: &str) {
    foundation::log::warn("updated", message);
}

/// The trust decisions about an enrollment bundle that this module cannot make, supplied by the TUF
/// layer that owns them (`updated_tuf::EmbeddedChainPolicy`).
///
/// This module owns the bundle's transport and durability — which endpoint serves it, which identity
/// fetches it, and the one-way persistence rules — and deliberately none of its meaning. Verifying a
/// signed metadata chain, and judging when that chain is close enough to expiry to be worth
/// replacing, both need the TUF implementation, which depends on this crate and so cannot be
/// depended on from here. Inverting it through this trait keeps ONE verification implementation
/// rather than a weaker second copy on the refresh path.
#[async_trait::async_trait]
pub trait BundlePolicy: Sync {
    /// Whether `current`'s embedded metadata chain has expired, or is near enough to expiry that the
    /// node should try to replace it now. Asked before any network call, so a node holding fresh
    /// material spends nothing.
    fn needs_refresh(&self, current: &EnrollmentBundle) -> bool;

    /// Whether `candidate`, freshly issued by the gateway, may replace `current`. Must verify the
    /// candidate's complete chain AND that its root is `current`'s pinned root or a rotation signed
    /// by it — otherwise a gateway an attacker controls could hand every node a root of its own and
    /// the enrollment-time pin would be worth nothing.
    ///
    /// Async because a rotation the node was offline for spans several root versions, and the only
    /// way to check one is against the version before it: the implementation fetches the
    /// intermediate versioned roots the repository publishes and walks them one verified step at a
    /// time. That fetch is the reason this is the one policy method that may touch the network.
    async fn accept(
        &self,
        candidate: &EnrollmentBundle,
        current: &EnrollmentBundle,
    ) -> io::Result<()>;
}

/// Replace the node's persisted enrollment bundle when its signed material is aging, and return
/// whichever bundle the node should now run on.
///
/// A refresh is best-effort by construction: the bundle a node already holds still pins its root of
/// trust and still names its `install_root` even after its chain expires, so failing to replace it
/// is never a reason to fail a boot or a control loop. Every failure — an unreachable gateway, a
/// refused candidate, an unwritable state directory — warns and yields the bundle unchanged.
async fn refresh_bundle_or_warn(
    bootstrap: &BootstrapConfig,
    state_dir: &Path,
    current: EnrollmentBundle,
    policy: &dyn BundlePolicy,
) -> EnrollmentBundle {
    match refresh_bundle(bootstrap, state_dir, &current, policy).await {
        Ok(Some(refreshed)) => {
            foundation::log::info(
                "updated",
                "refreshed the enrollment bundle: its embedded metadata was at or near expiry",
            );
            refreshed
        }
        Ok(None) => current,
        Err(error) => {
            warn(&format!(
                "could not refresh the aging enrollment bundle; continuing on the persisted one \
                 (its root of trust and pinned install root do not expire): {error}"
            ));
            current
        }
    }
}

/// The refresh itself: consult the policy, and only if it says the material is aging, re-fetch and
/// durably replace it. `Ok(None)` means nothing needed doing.
async fn refresh_bundle(
    bootstrap: &BootstrapConfig,
    state_dir: &Path,
    current: &EnrollmentBundle,
    policy: &dyn BundlePolicy,
) -> io::Result<Option<EnrollmentBundle>> {
    if !can_reach_gateway(state_dir, current) {
        return Ok(None);
    }
    if !policy.needs_refresh(current) {
        return Ok(None);
    }
    let candidate = fetch_bundle(bootstrap, state_dir).await?;
    adopt_bundle(
        &bundle_path(state_dir),
        bootstrap,
        &candidate,
        current,
        policy,
    )
    .await?;
    Ok(Some(candidate))
}

/// Whether this node can ask the gateway for anything at all: the same split [`mint_leaf`] makes.
/// An offline/local deployment reads routing straight from disk, so it has no gateway to ask; a node
/// that has not yet minted its per-node certificate has nothing to ask WITH, and the shared fleet
/// enrollment cert authenticates the `/enroll` handshake and nothing else.
fn can_reach_gateway(state_dir: &Path, current: &EnrollmentBundle) -> bool {
    !crate::config::base_url_is_local(&current.routing_base_url)
        && joined_cert_path(state_dir).exists()
}

/// Fetch this node's enrollment bundle as of now, authenticated by the per-node certificate it
/// minted at enrollment. Checks only shape and that the bundle names this node; whether it may
/// REPLACE what the node holds is [`BundlePolicy::accept`]'s decision, made in [`adopt_bundle`].
async fn fetch_bundle(
    bootstrap: &BootstrapConfig,
    state_dir: &Path,
) -> io::Result<EnrollmentBundle> {
    let endpoint = format!(
        "{}{BUNDLE_PATH}",
        bootstrap.enrollment.url.trim_end_matches('/')
    );
    let bytes = control_plane_exchange(
        &bootstrap.enrollment.steady_identity(state_dir)?,
        &endpoint,
        Vec::new(),
        "enrollment bundle refresh",
    )
    .await?;
    decode(&bytes)
}

/// Durably replace the persisted bundle with `candidate`, but only if it names this node and the
/// policy accepts it over `current`.
///
/// The one-way enrollment contract is untouched: the consumed marker is already set and stays set,
/// and the write is atomic, so the bundle is never absent and this can never re-enable enrollment.
/// What changes is only WHICH signed material the node keeps.
async fn adopt_bundle(
    bundle_path: &Path,
    bootstrap: &BootstrapConfig,
    candidate: &EnrollmentBundle,
    current: &EnrollmentBundle,
    policy: &dyn BundlePolicy,
) -> io::Result<()> {
    // The same split-identity rule the enrollment paths apply: material issued for another agent
    // must never become this node's, whatever else verifies.
    if candidate.agent_id != bootstrap.enrollment.name || candidate.agent_id != current.agent_id {
        return Err(invalid(&format!(
            "the control plane issued a bundle for agent {:?}, but this node is agent {:?}",
            candidate.agent_id, bootstrap.enrollment.name
        )));
    }
    policy.accept(candidate, current).await?;
    let bytes = serde_json::to_vec(candidate).map_err(io::Error::other)?;
    foundation::durable::atomic_write_managed(bundle_path, ".enrollment-", &bytes)
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
    let bytes = control_plane_exchange(
        &bootstrap.enrollment.enroll_identity()?,
        &endpoint,
        body,
        "enrollment",
    )
    .await?;
    let enrolled: EnrollResponse = serde_json::from_slice(&bytes).map_err(invalid_error)?;
    validate_bundle(&enrolled.bundle)?;
    validate_leaf(
        &enrolled.leaf,
        &request.csr,
        &request.name,
        &bootstrap.enrollment.ca,
    )?;
    persist_leaf(state_dir, &enrolled.leaf)?;
    Ok(enrolled.bundle)
}

/// Keep everything the node's steady state is built on current: the enrollment bundle whose signed
/// metadata is aging, and the per-node certificate once it enters its renewal window.
///
/// Both decay on their own clocks and neither renews the other, which is why one entry point drives
/// them together — a node that only ever renewed its certificate kept a bundle that eventually held
/// nothing it could take for the repository's current state, and no periodic path existed that would
/// have replaced it.
///
/// The bundle goes first, while the current certificate is still the one the gateway knows; a
/// refresh failure is warned and never propagates, since the persisted bundle remains usable
/// regardless. Returns `true` only after a new leaf has been durably installed — the caller restarts
/// on that to rebuild its authenticated clients.
pub async fn renew_node_material_if_due(
    bootstrap: &BootstrapConfig,
    state_dir: &Path,
    policy: &dyn BundlePolicy,
) -> io::Result<bool> {
    if let Some(current) = persisted_bundle(state_dir)? {
        refresh_bundle_or_warn(bootstrap, state_dir, current, policy).await;
    }
    renew_leaf_if_due(bootstrap, state_dir).await
}

/// The persisted enrollment bundle, or `None` when this node has none yet (or holds one it can no
/// longer parse — nothing here can fix that, and the boot path reports it).
fn persisted_bundle(state_dir: &Path) -> io::Result<Option<EnrollmentBundle>> {
    match std::fs::read(bundle_path(state_dir)) {
        Ok(bytes) => decode(&bytes).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

/// Renew the current per-node certificate when it enters its renewal window. The durable key is
/// never replaced and the request is authenticated with the still-valid current certificate.
/// Returns `true` only after a new leaf has been durably installed.
async fn renew_leaf_if_due(bootstrap: &BootstrapConfig, state_dir: &Path) -> io::Result<bool> {
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
    let bytes = control_plane_exchange(
        &bootstrap.enrollment.steady_identity(state_dir)?,
        &endpoint,
        body,
        "certificate renewal",
    )
    .await?;
    let renewed: RenewalResponse = serde_json::from_slice(&bytes).map_err(invalid_error)?;
    validate_leaf(
        &renewed.leaf,
        &request.csr,
        &bootstrap.enrollment.name,
        &bootstrap.enrollment.ca,
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
fn load_existing_or_fresh(bundle_path: &Path) -> Option<io::Result<EnrollmentBundle>> {
    (bundle_path.exists() || consumed_path(bundle_path).exists()).then(|| {
        load_or_enroll(bundle_path, || {
            Err(invalid("enrollment must not run for existing local state"))
        })
    })
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
        .reqwest_client()?
        .post(endpoint)
        .header("content-type", "application/json")
        .body(body)
        // reqwest carries this deadline into the response body too, so it bounds the streamed read
        // below and not merely the handshake and headers.
        .timeout(CONTROL_PLANE_DEADLINE))
}

/// Perform one control-plane exchange and read its successful response, bounded by
/// [`ENROLLMENT_RESPONSE_LIMIT`] through the one bounded-read helper every control-plane response
/// uses. Shared by enrollment and certificate renewal.
async fn control_plane_exchange(
    identity: &crate::tls::Identity,
    endpoint: &str,
    body: Vec<u8>,
    what: &str,
) -> io::Result<Vec<u8>> {
    let response = control_plane_request(identity, endpoint, body)?
        .send()
        .await
        .map_err(io::Error::other)?;
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
    let bundle: EnrollmentBundle = serde_json::from_slice(bytes).map_err(invalid_error)?;
    validate_bundle(&bundle)?;
    Ok(bundle)
}

/// The single gate every enrollment bundle passes before this node will look at it, wherever it
/// came from: the persisted copy, a preplaced one, the `/enroll` response, or a `/bundle` refresh.
fn validate_bundle(bundle: &EnrollmentBundle) -> io::Result<()> {
    bundle.validate_shape()?;
    assignment_names_its_own_agent(bundle)
}

/// A bundle's `assignment` must be the routing target of the agent the bundle names.
///
/// `agent_id` and `assignment` are plaintext fields the gateway chooses; TUF covers only
/// `routing_root` and `initial.*`. `verify_embedded_chain` then verifies the embedded agent
/// document against *whatever path the bundle names*, and an [`AgentDocument`] carries no node
/// identity of its own — so without this rule a gateway that had been taken over could hand node A
/// a bundle with `agent_id: "a"` (which the identity checks accept) naming
/// `assignments/agents/b.json` plus node B's genuinely published, correctly signed documents. Every
/// signature, threshold and digest verifies, the enrollment-time root pin gives nothing, and node A
/// permanently runs node B's product, args, secret mapping and install root. Binding the path to
/// the identity is what closes it: the control plane publishes each agent's assignment at exactly
/// `<prefix>/agents/<agent>.json` (`telemetry::assignment_object_key`, and the API contract), so a
/// bundle
/// naming another agent's path is refused whether or not that path is genuinely signed.
///
/// [`AgentDocument`]: updated_contracts::artifact::AgentDocument
fn assignment_names_its_own_agent(bundle: &EnrollmentBundle) -> io::Result<()> {
    if updated_contracts::telemetry::split_assignment_path(&bundle.assignment)
        .is_some_and(|(_, agent)| agent == bundle.agent_id)
    {
        return Ok(());
    }
    Err(invalid(&format!(
        "enrollment bundle for agent {:?} names the assignment {:?}, which is another agent's \
         routing target",
        bundle.agent_id, bundle.assignment
    )))
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
    use futures::executor::block_on;
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

    /// A bundle for `agent_id` whose `routing_root` is `marker`, so a test can tell which of two
    /// bundles a path ended up holding.
    fn bundle_for(agent_id: &str, marker: &str) -> EnrollmentBundle {
        EnrollmentBundle {
            schema: 1,
            agent_id: agent_id.into(),
            routing_base_url: "https://updates.example/".into(),
            assignment: format!("assignments/agents/{agent_id}.json"),
            routing_root: format!("{{\"marker\":\"{marker}\"}}"),
            initial: InitialSignedConfiguration {
                timestamp: "{}".into(),
                snapshot: "{}".into(),
                targets: "{}".into(),
                agent_document: "{}".into(),
                managed_configuration: "{}".into(),
            },
        }
    }

    /// A stand-in for `updated_tuf::EmbeddedChainPolicy`: this crate owns transport and durability,
    /// so its tests state what it does with each verdict, not how the verdict is reached.
    struct FixedPolicy {
        stale: bool,
        verdict: Result<(), &'static str>,
        /// Atomic rather than a `Cell` only because the policy is consulted through a `&dyn` that
        /// crosses an await point and so must be `Sync`.
        consulted: std::sync::atomic::AtomicBool,
    }

    impl FixedPolicy {
        fn accepting() -> Self {
            Self {
                stale: true,
                verdict: Ok(()),
                consulted: std::sync::atomic::AtomicBool::new(false),
            }
        }
        fn refusing() -> Self {
            Self {
                stale: true,
                verdict: Err("substituted root of trust"),
                consulted: std::sync::atomic::AtomicBool::new(false),
            }
        }
        fn consulted(&self) -> bool {
            self.consulted.load(std::sync::atomic::Ordering::Relaxed)
        }
    }

    #[async_trait::async_trait]
    impl BundlePolicy for FixedPolicy {
        fn needs_refresh(&self, _current: &EnrollmentBundle) -> bool {
            self.stale
        }
        async fn accept(
            &self,
            _candidate: &EnrollmentBundle,
            _current: &EnrollmentBundle,
        ) -> io::Result<()> {
            self.consulted
                .store(true, std::sync::atomic::Ordering::Relaxed);
            self.verdict.map_err(invalid)
        }
    }

    fn bootstrap_for(dir: &Path, name: &str) -> BootstrapConfig {
        let body = format!(
            "[enrollment]\nurl='https://updates.example/'\nca='/id/ca.crt'\nname='{name}'\nclient_cert='/id/tls.crt'\nclient_key='/id/tls.key'\n"
        );
        BootstrapConfig::load(&write_bootstrap(dir, &body)).unwrap()
    }

    /// The bundle is written once at enrollment and its signed metadata expires, so it MUST be
    /// replaceable — but only by material that is still this node's and that the trust policy
    /// accepts. Every refusal leaves the persisted bundle byte-for-byte intact, because it remains
    /// the node's root of trust and pinned install root however old it is.
    #[test]
    fn a_refreshed_bundle_replaces_the_persisted_one_only_when_the_policy_accepts_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = bundle_path(dir.path());
        let bootstrap = bootstrap_for(dir.path(), "agent-a");
        let current = bundle_for("agent-a", "pinned");
        let write_current = || {
            std::fs::write(&path, serde_json::to_vec(&current).unwrap()).unwrap();
        };
        let held = || decode(&std::fs::read(&path).unwrap()).unwrap().routing_root;

        // Accepted: the node now holds the newer material.
        write_current();
        let candidate = bundle_for("agent-a", "rotated");
        let policy = FixedPolicy::accepting();
        block_on(adopt_bundle(
            &path, &bootstrap, &candidate, &current, &policy,
        ))
        .unwrap();
        assert!(policy.consulted());
        assert_eq!(held(), candidate.routing_root);

        // Refused by the trust policy: nothing is written.
        write_current();
        let policy = FixedPolicy::refusing();
        let error = block_on(adopt_bundle(
            &path, &bootstrap, &candidate, &current, &policy,
        ))
        .unwrap_err();
        assert!(error.to_string().contains("substituted root of trust"));
        assert_eq!(held(), current.routing_root);

        // Issued for another agent: refused on identity, and the trust policy is never even asked —
        // a bundle naming someone else is not a question about roots.
        write_current();
        let foreign = bundle_for("agent-b", "rotated");
        let policy = FixedPolicy::accepting();
        let error =
            block_on(adopt_bundle(&path, &bootstrap, &foreign, &current, &policy)).unwrap_err();
        assert!(error.to_string().contains("agent-b"));
        assert!(!policy.consulted());
        assert_eq!(held(), current.routing_root);
    }

    /// Refreshing needs a gateway to ask and a per-node certificate to ask with. A node missing
    /// either must skip it silently rather than fail: an offline deployment has no gateway at all,
    /// and a node that has not minted its leaf yet holds only the shared fleet enrollment
    /// certificate, which authenticates `/enroll` and nothing else.
    #[test]
    fn a_node_with_no_steady_state_identity_never_asks_for_a_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let remote = bundle_for("agent-a", "pinned");
        assert!(!can_reach_gateway(dir.path(), &remote));
        std::fs::write(joined_cert_path(dir.path()), "leaf").unwrap();
        assert!(can_reach_gateway(dir.path(), &remote));

        let mut local = remote.clone();
        local.routing_base_url = "file:///var/lib/updates/".into();
        assert!(!can_reach_gateway(dir.path(), &local));
    }

    /// A bundle naming another agent must be refused however long this node has been enrolled. The
    /// mint path is the obvious place it appears, but the dangerous one is a bundle swapped under a
    /// node that already holds its leaf: minting is skipped there, and the refresh path's identity
    /// rule is both conditional on aging material and warned away rather than propagated. Boot must
    /// fail closed, before any of the foreign agent's assignment is resolved.
    #[test]
    fn a_bundle_naming_another_agent_fails_the_boot_even_after_the_leaf_is_minted() {
        let dir = tempfile::tempdir().unwrap();
        let bootstrap = bootstrap_for(dir.path(), "agent-a");
        let foreign = bundle_for("agent-b", "pinned");
        std::fs::write(
            bundle_path(dir.path()),
            serde_json::to_vec(&foreign).unwrap(),
        )
        .unwrap();
        // The node has already enrolled, so nothing on this boot would mint a leaf.
        std::fs::write(joined_cert_path(dir.path()), "leaf").unwrap();

        let policy = FixedPolicy::accepting();
        let error = block_on(load_or_enroll_http(&bootstrap, dir.path(), &policy)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("agent-b"), "{error}");
        // Refused on identity alone: no gateway was asked anything.
        assert!(!policy.consulted());
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
        assert!(name("jenkins-author-0").name_is_wellformed());
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
    /// renewal inline in the supervisor's single control loop — and the client they use bounds only
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
            .split("\n#[cfg(test)]\nmod tests {")
            .next()
            .expect("the module source splits at its test module");
        // Exactly one send in the module, and it is built by the helper that attaches the deadline.
        assert_eq!(
            source.matches(".send()").count(),
            1,
            "this module must send one request shape, the one that carries the deadline"
        );
        let exchange = body_of(source, "async fn control_plane_exchange");
        assert!(exchange.contains("control_plane_request(") && exchange.contains(".send()"));
        // …and both entry points reach the control plane only through it.
        for entry in [
            "async fn mint_leaf",
            "async fn renew_leaf_if_due",
            "async fn fetch_bundle",
        ] {
            assert!(
                body_of(source, entry).contains("control_plane_exchange("),
                "`{entry}` reaches the control plane outside the deadline-carrying request"
            );
        }

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
