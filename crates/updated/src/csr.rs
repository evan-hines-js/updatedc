//! Enrollment CSR generation. A fresh agent has no per-node certificate, so at first boot it
//! generates its own keypair locally (the private key never leaves the node) and a certificate-
//! signing request the control plane certifies at `/enroll`. Built on the aws-lc-rs `rcgen` backend
//! so there is one crypto library everywhere, exactly like the mock CDN's `certs` module.

use std::io;

use rcgen::{CertificateParams, DnType, KeyPair};

/// Generate a fresh keypair and return its PKCS#8 PEM. The private key never leaves the node; it is
/// generated once, persisted, and reused for both the mTLS leaf and telemetry signing.
pub fn generate_key() -> io::Result<String> {
    let key = KeyPair::generate()
        .map_err(|error| io::Error::other(format!("generating keypair: {error}")))?;
    Ok(key.serialize_pem())
}

/// Build a PEM certificate-signing request for an existing key (PKCS#8 PEM). The control plane sets
/// the subject and SAN and certifies only this key's public half, so `subject_cn` is a throwaway
/// label. Reusing a durable key (rather than a fresh one per attempt) keeps the certificate the
/// control plane pins and the key the node signs telemetry with identical across enrollment retries.
pub fn csr_for(key_pem: &str, subject_cn: &str) -> io::Result<String> {
    let key = KeyPair::from_pem(key_pem)
        .map_err(|error| io::Error::other(format!("loading keypair: {error}")))?;
    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|error| io::Error::other(error.to_string()))?;
    params
        .distinguished_name
        .push(DnType::CommonName, subject_cn);
    let csr = params
        .serialize_request(&key)
        .map_err(|error| io::Error::other(format!("serializing CSR: {error}")))?;
    csr.pem()
        .map_err(|error| io::Error::other(format!("encoding CSR: {error}")))
}

/// The PKCS#8 DER form of a PEM key, for aws-lc-rs signing (`telemetry::sign_report`).
pub fn key_pem_to_pkcs8_der(key_pem: &str) -> io::Result<Vec<u8>> {
    let key = KeyPair::from_pem(key_pem)
        .map_err(|error| io::Error::other(format!("loading keypair: {error}")))?;
    Ok(key.serialize_der())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_a_pem_csr_and_key() {
        // CSR *parsing* (proof-of-possession, public-key match) is the control plane's job and is
        // asserted there, where rcgen's x509-parser feature is enabled. The agent only needs to
        // emit a well-formed PEM keypair + request from a durable key.
        let key_pem = generate_key().unwrap();
        let csr_pem = csr_for(&key_pem, "updated join test").unwrap();
        assert!(key_pem.contains("PRIVATE KEY"));
        assert!(csr_pem.contains("BEGIN CERTIFICATE REQUEST"));
        assert!(KeyPair::from_pem(&key_pem).is_ok());
    }

    #[test]
    fn each_generation_is_a_fresh_key() {
        let a = generate_key().unwrap();
        let b = generate_key().unwrap();
        assert_ne!(
            a, b,
            "two generations must not produce the same private key"
        );
    }
}
