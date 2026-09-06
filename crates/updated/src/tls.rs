//! The agent's mTLS identity for the externally-exposed enrollment/capability gateway.
//!
//! Only small control-plane requests present this identity. Object transfers use a distinct
//! anonymous client, so a node certificate can never be offered to the host in a bearer URL. The
//! identity is built from cert/key/CA *file paths* (the node config holds paths, never secrets)
//! into an `aws-lc-rs` rustls client config, so there is one crypto library everywhere.

use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};

/// Maximum bytes accepted from any one certificate, CA bundle, or private-key PEM.
///
/// Real material is kilobytes; one MiB leaves room for a large CA set while ensuring a corrupt
/// mount or state file cannot allocate without bound in every TLS client/server constructor.
pub const TLS_MATERIAL_MAX_BYTES: usize = 1024 * 1024;

/// The one process crypto provider — always `aws-lc-rs`, so there is a single crypto library
/// for TLS, hashing, signing, and RNG. Built with the `fips` feature it is the FIPS-validated
/// aws-lc-rs (which links the validated AWS-LC build); we assert that here so a binary that
/// *claims* FIPS but somehow linked a non-validated provider fails closed rather than running
/// unvalidated crypto. Enabling FIPS is a build flag (`--features fips`), not a runtime toggle:
/// the validated module is chosen at link time.
pub fn crypto_provider() -> rustls::crypto::CryptoProvider {
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    #[cfg(feature = "fips")]
    assert!(
        provider.fips(),
        "built with the `fips` feature but the aws-lc-rs crypto provider is not FIPS-validated"
    );
    provider
}

/// Install the process-default crypto provider. Call once at startup, before any TLS. Idempotent:
/// a redundant call (or a race) is ignored.
pub fn install_crypto_provider() {
    let _ = crypto_provider().install_default();
}

/// Where the agent's mTLS material lives on disk — three paths, no secrets. `ca` is the fleet
/// CA the agent trusts for the gateway's server certificate.
#[derive(Clone, Debug)]
pub struct Identity {
    pub client_cert: std::path::PathBuf,
    pub client_key: std::path::PathBuf,
    pub ca: std::path::PathBuf,
}

impl Identity {
    /// The three PEM paths that make up the agent's mTLS identity.
    pub fn new(
        client_cert: impl Into<std::path::PathBuf>,
        client_key: impl Into<std::path::PathBuf>,
        ca: impl Into<std::path::PathBuf>,
    ) -> Self {
        Self {
            client_cert: client_cert.into(),
            client_key: client_key.into(),
            ca: ca.into(),
        }
    }

    /// Build an aws-lc-rs rustls client config that presents the client cert/key and trusts the
    /// fleet CA plus public WebPKI roots (the gateway itself may use a public certificate).
    /// Fail-closed: any unreadable or invalid fleet-CA PEM is an error.
    pub fn client_config(&self) -> io::Result<ClientConfig> {
        let mut roots = load_roots(&self.ca, "enrollment CA")?;
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let certs = load_cert_chain(&self.client_cert, "client certificate")?;
        let key = load_key(&self.client_key, "client key")?;

        client_config_builder()?
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, key)
            .map_err(|error| invalid(&format!("loading the client identity failed: {error}")))
    }

    /// mTLS client for the small control plane. Redirects are refused so the node identity is
    /// never offered to the object-store host named by a bearer capability.
    pub fn reqwest_control_client(&self) -> io::Result<reqwest::Client> {
        tls_client(self.client_config()?)
    }

    /// HTTPS client that spends exact-object bearer capabilities. It carries no client
    /// certificate, refuses redirects (so a bearer URL cannot be forwarded), trusts normal public
    /// roots, and additionally trusts the configured fleet CA for private MinIO-style endpoints.
    pub fn reqwest_capability_client(&self) -> io::Result<reqwest::Client> {
        anonymous_object_client_with_ca(&self.ca)
    }

    /// Anonymous client for a direct release repository. A configured fleet CA augments public
    /// roots for private HTTPS object stores. Only an absent CA is optional; a present CA that is
    /// unreadable or malformed fails closed instead of silently changing the trust policy.
    pub fn reqwest_direct_object_client(&self) -> io::Result<reqwest::Client> {
        match foundation::file::path_entry_exists(&self.ca)? {
            true => self.reqwest_capability_client(),
            false => anonymous_object_client(),
        }
    }
}

/// Anonymous HTTPS client for spending an exact-object bearer capability with public trust roots.
/// Redirects are refused and the rustls config has no client certificate, so neither the bearer
/// token nor the node identity can escape to another host.
pub fn anonymous_object_client() -> io::Result<reqwest::Client> {
    let ca = std::env::var_os("SSL_CERT_FILE").map(std::path::PathBuf::from);
    anonymous_object_client_with_optional_ca(ca.as_deref())
}

/// Anonymous HTTPS client for a bearer capability whose object store may use the fleet CA. This
/// takes only the public trust anchor: spending a capability must never require or load an mTLS
/// private key.
pub fn anonymous_object_client_with_ca(ca: &Path) -> io::Result<reqwest::Client> {
    anonymous_object_client_with_optional_ca(Some(ca))
}

fn anonymous_object_client_with_optional_ca(
    additional_ca: Option<&Path>,
) -> io::Result<reqwest::Client> {
    let mut roots = match additional_ca {
        Some(path) => load_roots(path, "client CA")?,
        None => RootCertStore::empty(),
    };
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    tls_client(
        client_config_builder()?
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// The rustls client builder every outbound TLS client in this system starts from: the one crypto
/// provider, and the safe default protocol versions. Callers choose only their trust anchors and
/// whether they present a client identity.
fn client_config_builder() -> io::Result<rustls::ConfigBuilder<ClientConfig, rustls::WantsVerifier>>
{
    ClientConfig::builder_with_provider(Arc::new(crypto_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|error| invalid(&format!("rustls protocol setup failed: {error}")))
}

/// Turn a finished rustls config into an HTTP client under the one outbound policy.
///
/// The connect and read timeouts live here rather than at each call site: an mTLS control-plane
/// client and an anonymous capability client differ in what they trust and what they present, never
/// in how patient they are, and having written those two numbers twice is how they stop matching.
fn tls_client(config: ClientConfig) -> io::Result<reqwest::Client> {
    crate::http::finish_outbound_client(
        reqwest::Client::builder()
            .use_preconfigured_tls(config)
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(30)),
        crate::http::OutboundDeadline::ExternallyEnforced,
    )
}

/// Verify a newly issued client leaf against the same pinned CA and client-auth policy the
/// gateway uses before it is allowed onto durable storage. The gateway signs node leaves directly
/// off the pinned CA, so there is no intermediate to supply.
pub fn verify_client_chain(leaf: CertificateDer<'_>, ca: &Path) -> io::Result<()> {
    use rustls::pki_types::UnixTime;
    let roots = load_roots(ca, "enrollment CA")?;
    let verifier = required_client_verifier(
        roots,
        Arc::new(crypto_provider()),
        "building issued-certificate verifier",
    )?;
    verifier
        .verify_client_cert(&leaf, &[], UnixTime::now())
        .map_err(|error| {
            invalid(&format!(
                "issued client certificate is not trusted: {error}"
            ))
        })?;
    Ok(())
}

/// Build the production mTLS server config and prove that `issued_client` is admitted by its
/// verifier before returning it. The proof and the returned config share the exact verifier built
/// from one read of `client_ca`, so a Secret rotation between two file reads cannot install an
/// issuer/verifier pair that never existed coherently on disk.
pub fn server_config_accepting_issued_client(
    cert: &Path,
    key: &Path,
    client_ca: &Path,
    issued_client: &CertificateDer<'_>,
) -> io::Result<rustls::ServerConfig> {
    use rustls::pki_types::UnixTime;

    let provider = Arc::new(crypto_provider());
    let roots = load_roots(client_ca, "client CA")?;
    let verifier = required_client_verifier(
        roots,
        provider.clone(),
        "building the client-certificate verifier",
    )?;
    verifier
        .verify_client_cert(issued_client, &[], UnixTime::now())
        .map_err(|error| {
            invalid(&format!(
                "the issuing CA is not trusted by the configured client CA bundle: {error}"
            ))
        })?;
    server_config_with_verifier(cert, key, provider, verifier)
}

fn required_client_verifier(
    roots: RootCertStore,
    provider: Arc<rustls::crypto::CryptoProvider>,
    context: &'static str,
) -> io::Result<Arc<dyn rustls::server::danger::ClientCertVerifier>> {
    let verifier: Arc<dyn rustls::server::danger::ClientCertVerifier> =
        rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
            .build()
            .map_err(|error| invalid(&format!("{context}: {error}")))?;
    Ok(verifier)
}

fn server_config_with_verifier(
    cert: &Path,
    key: &Path,
    provider: Arc<rustls::crypto::CryptoProvider>,
    verifier: Arc<dyn rustls::server::danger::ClientCertVerifier>,
) -> io::Result<rustls::ServerConfig> {
    let certs = load_cert_chain(cert, "server certificate")?;
    let key = load_key(key, "server key")?;

    rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| invalid(&format!("rustls protocol setup failed: {error}")))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|error| invalid(&format!("loading the server identity failed: {error}")))
}

/// Build the TLS policy used by the development capability gateway. Fleet certificates are
/// verified when present, but an anonymous handshake is admitted so the same test origin can
/// receive the bearer URL's second hop. Application routing must still reject every anonymous
/// request that does not carry an exact, live capability.
///
/// Production gateways use [`server_config_accepting_issued_client`] and remain mTLS-only.
pub fn capability_fixture_server_config(
    cert: &Path,
    key: &Path,
    client_ca: &Path,
) -> io::Result<rustls::ServerConfig> {
    let provider = Arc::new(crypto_provider());
    let roots = load_roots(client_ca, "client CA")?;
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(roots),
        provider.clone(),
    )
    .allow_unauthenticated()
    .build()
    .map_err(|error| {
        invalid(&format!(
            "building the optional client-certificate verifier: {error}"
        ))
    })?;
    let certs = load_cert_chain(cert, "server certificate")?;
    let key = load_key(key, "server key")?;

    rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| invalid(&format!("rustls protocol setup failed: {error}")))?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|error| invalid(&format!("loading the server identity failed: {error}")))
}

/// Build the anonymous HTTPS policy for a direct object-store fixture. This listener never sees a
/// node identity; it is the local equivalent of the S3 endpoint reached after authorization.
pub fn object_fixture_server_config(cert: &Path, key: &Path) -> io::Result<rustls::ServerConfig> {
    let provider = Arc::new(crypto_provider());
    let certs = load_cert_chain(cert, "server certificate")?;
    let key = load_key(key, "server key")?;

    rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| invalid(&format!("rustls protocol setup failed: {error}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|error| invalid(&format!("loading the server identity failed: {error}")))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn pem_err<E: std::fmt::Display>(label: &'static str, path: &Path) -> impl Fn(E) -> io::Error {
    let path = path.to_path_buf();
    move |error| invalid(&format!("parsing {label} {}: {error}", path.display()))
}

/// Read mounted TLS material through the same bounded opened-handle path everywhere. Kubernetes
/// Secret keys are final symlinks by construction, so following that one component is explicit;
/// the opened target must still be a regular file and the byte limit converges to the handle.
fn read_tls_material(path: &Path, label: &'static str) -> io::Result<Vec<u8>> {
    foundation::file::read_bounded_regular(
        path,
        TLS_MATERIAL_MAX_BYTES,
        foundation::file::FinalSymlink::Follow,
    )
    .map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("reading {label} {}: {error}", path.display()),
        )
    })
}

/// Read a private-key PEM for CSR or report signing under the same byte ceiling TLS itself uses.
/// Callers must state whether the key is a mounted projection or node-owned durable state. A
/// node-owned key (`Refuse`) must also be owner-readable with no group/world access; this is the
/// one read path used by enrollment retry, renewal, and report signing, so none can accidentally
/// accept a widened durable secret.
pub fn read_private_key_pem(
    path: &Path,
    final_symlink: foundation::file::FinalSymlink,
) -> io::Result<String> {
    let result = match final_symlink {
        foundation::file::FinalSymlink::Follow => foundation::file::read_bounded_regular_string(
            path,
            TLS_MATERIAL_MAX_BYTES,
            final_symlink,
        ),
        foundation::file::FinalSymlink::Refuse => {
            foundation::file::read_bounded_private_regular_string(path, TLS_MATERIAL_MAX_BYTES)
        }
    };
    result.map_err(|error| {
        io::Error::new(
            error.kind(),
            format!("reading private key {}: {error}", path.display()),
        )
    })
}

/// Load every PEM certificate in `path` into a fresh [`RootCertStore`]. `label` names the file in
/// any error (e.g. "enrollment CA", "client CA"). Shared by every config builder so trust-anchor
/// loading and its fail-closed error surface stay identical across client and server paths.
fn load_roots(path: &Path, label: &'static str) -> io::Result<RootCertStore> {
    let pem = read_tls_material(path, label)?;
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&pem) {
        let cert = cert.map_err(pem_err(label, path))?;
        roots
            .add(cert)
            .map_err(|error| invalid(&format!("{label} {}: {error}", path.display())))?;
    }
    if roots.is_empty() {
        return Err(invalid(&format!(
            "{label} {} contains no certificates",
            path.display()
        )));
    }
    Ok(roots)
}

/// Load a certificate chain from a PEM file, failing closed if it is unreadable, malformed, or
/// holds no certificate. `label` names the file in any error.
fn load_cert_chain(path: &Path, label: &'static str) -> io::Result<Vec<CertificateDer<'static>>> {
    let pem = read_tls_material(path, label)?;
    let certs = CertificateDer::pem_slice_iter(&pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(pem_err(label, path))?;
    if certs.is_empty() {
        return Err(invalid(&format!(
            "{label} {} contains no certificates",
            path.display()
        )));
    }
    Ok(certs)
}

/// Load a private key from a PEM file through the one bounded private-key reader, failing closed on
/// unreadable/invalid PEM. TLS identities are commonly mounted Secret projections, so the final
/// symlink is explicit here just as it is for report-signing and issuing-CA keys.
fn load_key(path: &Path, label: &'static str) -> io::Result<PrivateKeyDer<'static>> {
    let pem = read_private_key_pem(path, foundation::file::FinalSymlink::Follow)?;
    PrivateKeyDer::from_pem_slice(pem.as_bytes()).map_err(pem_err(label, path))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    #[test]
    fn direct_object_trust_falls_back_only_when_the_optional_ca_is_absent() {
        let directory = tempfile::tempdir().unwrap();
        let ca = directory.path().join("fleet-ca.pem");
        let identity = Identity::new("unused.crt", "unused.key", &ca);
        identity
            .reqwest_direct_object_client()
            .expect("an absent optional CA uses public roots");

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(directory.path().join("missing-ca"), &ca).unwrap();
            assert!(
                identity.reqwest_direct_object_client().is_err(),
                "a dangling configured CA is present-but-unreadable, never absent"
            );
            std::fs::remove_file(&ca).unwrap();
        }

        std::fs::write(&ca, b"not a PEM certificate").unwrap();
        assert!(
            identity.reqwest_direct_object_client().is_err(),
            "a present malformed CA must not silently change the trust policy"
        );

        std::fs::write(&ca, vec![b'x'; TLS_MATERIAL_MAX_BYTES + 1]).unwrap();
        assert_eq!(
            identity.reqwest_direct_object_client().unwrap_err().kind(),
            io::ErrorKind::InvalidData,
            "TLS material is bounded before PEM parsing"
        );
    }
}
