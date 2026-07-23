//! The agent's mTLS identity for the externally-exposed enrollment/repository gateway.
//!
//! The gateway is the only externally-reachable listener and it requires client auth, so every
//! agent→gateway request — enrollment and TUF metadata/target fetches alike — presents this
//! identity. It is built from cert/key/CA *file paths* (the bootstrap config holds paths, never
//! secrets) into an `aws-lc-rs` rustls client config, so there is one crypto library everywhere.

use std::io;
use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};

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

/// Whether this binary was built for FIPS (the `fips` feature). Lets a front end log or assert
/// its crypto posture at startup.
pub const fn fips_enabled() -> bool {
    cfg!(feature = "fips")
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

    /// Build an aws-lc-rs rustls client config that presents the client cert/key and trusts only
    /// the fleet CA for the gateway. Fail-closed: any unreadable or invalid PEM is an error.
    pub fn client_config(&self) -> io::Result<ClientConfig> {
        let roots = load_roots(&self.ca, "enrollment CA")?;
        let certs = load_cert_chain(&self.client_cert, "client certificate")?;
        let key = load_key(&self.client_key, "client key")?;

        ClientConfig::builder_with_provider(Arc::new(crypto_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|error| invalid(&format!("rustls protocol setup failed: {error}")))?
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, key)
            .map_err(|error| invalid(&format!("loading the client identity failed: {error}")))
    }

    /// A reqwest client that presents this identity — used for enrollment and any direct HTTP
    /// to the gateway.
    pub fn reqwest_client(&self) -> io::Result<reqwest::Client> {
        reqwest::Client::builder()
            .use_preconfigured_tls(self.client_config()?)
            .build()
            .map_err(io::Error::other)
    }
}

/// Build an aws-lc-rs rustls server config for an externally-exposed listener: it presents
/// `cert`/`key` and REQUIRES every client to present a certificate the fleet `client_ca` signed.
/// This is how the gateway (and the e2e's mock CDN) enforce mTLS — no unauthenticated client is
/// ever admitted. Fail-closed on any unreadable or invalid PEM.
pub fn server_config(
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
    .build()
    .map_err(|error| {
        invalid(&format!(
            "building the client-certificate verifier: {error}"
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

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn pem_err<E: std::fmt::Display>(label: &'static str, path: &Path) -> impl Fn(E) -> io::Error {
    let path = path.to_path_buf();
    move |error| invalid(&format!("reading {label} {}: {error}", path.display()))
}

/// Load every PEM certificate in `path` into a fresh [`RootCertStore`]. `label` names the file in
/// any error (e.g. "enrollment CA", "client CA"). Shared by every config builder so trust-anchor
/// loading and its fail-closed error surface stay identical across client and server paths.
fn load_roots(path: &Path, label: &'static str) -> io::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(path).map_err(pem_err(label, path))? {
        let cert = cert.map_err(pem_err(label, path))?;
        roots
            .add(cert)
            .map_err(|error| invalid(&format!("{label} {}: {error}", path.display())))?;
    }
    Ok(roots)
}

/// Load a certificate chain from a PEM file, failing closed if it is unreadable, malformed, or
/// holds no certificate. `label` names the file in any error.
fn load_cert_chain(path: &Path, label: &'static str) -> io::Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)
        .map_err(pem_err(label, path))?
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

/// Load a private key from a PEM file, failing closed on unreadable/invalid PEM. `label` names the
/// file in any error.
fn load_key(path: &Path, label: &'static str) -> io::Result<PrivateKeyDer<'static>> {
    PrivateKeyDer::from_pem_file(path).map_err(pem_err(label, path))
}
