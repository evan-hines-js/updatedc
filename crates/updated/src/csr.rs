//! Join-mode CSR generation. A join-mode agent has no certificate, so at first boot it generates
//! its own keypair locally (the private key never leaves the node) and a certificate-signing
//! request the control plane certifies at `/join`. Built on the aws-lc-rs `rcgen` backend so there
//! is one crypto library everywhere, exactly like the mock CDN's `certs` module.

use std::io;

use rcgen::{CertificateParams, DnType, KeyPair};

/// Generate a fresh keypair and a PEM certificate-signing request for it. Returns
/// `(private_key_pem, csr_pem)`. The `subject_cn` is a throwaway label: the control plane sets the
/// certificate subject and SAN itself and certifies only the CSR's public key.
pub fn generate(subject_cn: &str) -> io::Result<(String, String)> {
    let key = KeyPair::generate().map_err(|error| other(format!("generating keypair: {error}")))?;
    let mut params =
        CertificateParams::new(Vec::<String>::new()).map_err(|error| other(error.to_string()))?;
    params
        .distinguished_name
        .push(DnType::CommonName, subject_cn);
    let csr = params
        .serialize_request(&key)
        .map_err(|error| other(format!("serializing CSR: {error}")))?;
    let csr_pem = csr
        .pem()
        .map_err(|error| other(format!("encoding CSR: {error}")))?;
    Ok((key.serialize_pem(), csr_pem))
}

fn other(message: String) -> io::Error {
    io::Error::other(message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_a_pem_csr_and_key() {
        // CSR *parsing* (proof-of-possession, public-key match) is the control plane's job and is
        // asserted there, where rcgen's x509-parser feature is enabled. The agent only needs to
        // emit a well-formed PEM keypair + request.
        let (key_pem, csr_pem) = generate("updated join test").unwrap();
        assert!(key_pem.contains("PRIVATE KEY"));
        assert!(csr_pem.contains("BEGIN CERTIFICATE REQUEST"));
        assert!(KeyPair::from_pem(&key_pem).is_ok());
    }

    #[test]
    fn each_generation_is_a_fresh_key() {
        let (a, _) = generate("x").unwrap();
        let (b, _) = generate("x").unwrap();
        assert_ne!(a, b, "two generations must not produce the same private key");
    }
}
