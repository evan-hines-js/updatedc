//! Mint the fleet mTLS material the way `repo::generate_keys` mints TUF role keys: one
//! self-signed fleet CA, a gateway server certificate (with the gateway's SANs), and an agent
//! client certificate — all on the aws-lc-rs backend so there is one crypto library.
//!
//! Written as five PEM files into `dir`:
//!   ca.crt        — the fleet CA (agents trust it for the gateway; the gateway trusts it for clients)
//!   server.crt/.key — the gateway's server identity
//!   client.crt/.key — the agent's client identity
//!
//! This is the local/e2e issuer. In the kind demo cert-manager issues the same three roles.

use std::path::Path;

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};

type R = Result<(), Box<dyn std::error::Error>>;

/// Generate the CA, server, and client certificates into `dir`. `server_sans` are the DNS/IP
/// names the gateway is reached by (e.g. `updatec-gateway`, `127.0.0.1`).
pub async fn generate(dir: &Path, server_sans: &[String]) -> R {
    tokio::fs::create_dir_all(dir).await?;

    // The fleet CA — self-signed, may sign end-entity certs.
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "updated fleet CA");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key)?;

    // The gateway's server identity, valid for every name the agents reach it by. Each SAN is an
    // IP address SAN when it parses as one (rustls matches those literally) and a DNS SAN
    // otherwise, so `https://127.0.0.1:port` and `https://updatec-gateway` both verify.
    let server_key = KeyPair::generate()?;
    let mut server_params = CertificateParams::default();
    for san in server_sans {
        let san = match san.parse::<std::net::IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(san.clone().try_into()?),
        };
        server_params.subject_alt_names.push(san);
    }
    server_params
        .distinguished_name
        .push(DnType::CommonName, "updated gateway");
    server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key)?;

    // The agent's client identity — fleet membership, verified by the gateway against the CA.
    let client_key = KeyPair::generate()?;
    let mut client_params = CertificateParams::new(Vec::<String>::new())?;
    client_params
        .distinguished_name
        .push(DnType::CommonName, "updated-agent");
    client_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    client_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    let client_cert = client_params.signed_by(&client_key, &ca_cert, &ca_key)?;

    write_public(dir, "ca.crt", &ca_cert.pem()).await?;
    write_public(dir, "server.crt", &server_cert.pem()).await?;
    write_private(dir, "server.key", &server_key.serialize_pem())?;
    write_public(dir, "client.crt", &client_cert.pem()).await?;
    write_private(dir, "client.key", &client_key.serialize_pem())?;
    Ok(())
}

/// Certificates are public material — anyone who can reach the gateway already sees them.
async fn write_public(dir: &Path, name: &str, pem: &str) -> R {
    tokio::fs::write(dir.join(name), pem).await?;
    Ok(())
}

/// A private key goes through the one durable write, which commits the file owner-only — the same
/// path the agent's enrollment key and the TUF role keys take. `tokio::fs::write` would leave it at
/// the process umask (world-readable by default), handing the gateway's server key and the shared
/// fleet client key to every local account.
fn write_private(dir: &Path, name: &str, pem: &str) -> R {
    foundation::durable::atomic_write(&dir.join(name), ".key-", pem.as_bytes())?;
    Ok(())
}
