//! Control-plane side of join-mode enrollment: the fleet CA, node naming, and constant-time
//! nonce comparison. This module is deliberately pure — no Kubernetes, no object store — so the
//! security invariants can be pinned by fast unit tests. The `gateway` join handler wires it to
//! the group Secret (nonce), the CRD API (agent creation), and the repository (bundle).
//!
//! Two properties matter most and are tested below:
//!
//!   * The control plane certifies only the CSR's **public key** and sets the certificate's
//!     subject and SAN itself — a valid join token can never mint an arbitrary identity.
//!   * Two nodes sharing one group token but presenting different `instance` values get two
//!     distinct, individually-revocable node identities (no collision onto one agent).

use std::io;

use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use sha2::{Digest, Sha256};

/// The SPIFFE trust domain the node identity is expressed under. Encoded as a URI SAN on every
/// minted leaf so a verified client cert names both the group it joined and its unique node.
const TRUST_DOMAIN: &str = "updated.fleet";

/// Deterministically derive an agent name from its durable `instance` value: `agent-<first 24 hex
/// of sha256(instance)>`. Identical in both modes, so mount and join agents are named the same
/// way, and stable across retries (same instance ⇒ same name ⇒ idempotent create).
pub fn agent_name(instance: &str) -> String {
    let digest = hex::encode(Sha256::digest(instance.as_bytes()));
    format!("agent-{}", &digest[..24])
}

/// Constant-time equality for the group join token, so a mismatch cannot be timed. Returns false
/// on any length difference without an early return that would leak position.
pub fn nonce_matches(presented: &str, expected: &str) -> bool {
    let (a, b) = (presented.as_bytes(), expected.as_bytes());
    // Fold length into the accumulator so unequal lengths never match and never branch early.
    let mut diff = (a.len() ^ b.len()) as u8;
    let n = a.len().max(b.len());
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        diff |= x ^ y;
    }
    diff == 0
}

/// The fleet CA that signs join-mode node certificates. Loaded from the same cert-manager CA that
/// issues mount-mode client certs and that the gateway trusts as its mTLS `client_ca`, so leaves
/// from both modes are accepted on the steady-state gateway.
pub struct IssuingCa {
    cert: rcgen::Certificate,
    key: KeyPair,
}

impl IssuingCa {
    /// Load the CA from its PEM certificate and private key (the mounted `tls.crt` / `tls.key`).
    pub fn load(cert_pem: &str, key_pem: &str) -> io::Result<Self> {
        let key = KeyPair::from_pem(key_pem)
            .map_err(|error| other(format!("loading issuing CA key: {error}")))?;
        let params = CertificateParams::from_ca_cert_pem(cert_pem)
            .map_err(|error| other(format!("loading issuing CA certificate: {error}")))?;
        let cert = params
            .self_signed(&key)
            .map_err(|error| other(format!("reconstructing issuing CA: {error}")))?;
        Ok(Self { cert, key })
    }

    /// Sign a node CSR into a client certificate. The CSR's subject and SAN are **discarded**: the
    /// control plane sets the subject to `CN=<agent_name>` and a single URI SAN naming the group
    /// and node, and certifies only the CSR's public key (whose possession the CSR self-signature
    /// proves). Returns the leaf PEM.
    pub fn sign_client_csr(
        &self,
        group_id: &str,
        agent_name: &str,
        csr_pem: &str,
    ) -> io::Result<String> {
        // `from_pem` parses and verifies the CSR self-signature (proof the requester holds the
        // private key for the public key it presents).
        let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|error| other(format!("parsing join CSR: {error}")))?;
        // Overwrite everything identity-bearing; keep only `csr.public_key` (used by `signed_by`).
        csr.params.is_ca = IsCa::NoCa;
        csr.params.distinguished_name = rcgen::DistinguishedName::new();
        csr.params
            .distinguished_name
            .push(DnType::CommonName, agent_name);
        let uri = format!("spiffe://{TRUST_DOMAIN}/group/{group_id}/node/{agent_name}");
        csr.params.subject_alt_names = vec![SanType::URI(
            uri.clone()
                .try_into()
                .map_err(|error| other(format!("encoding node URI SAN {uri}: {error}")))?,
        )];
        csr.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        csr.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        // v0: a fixed, wide validity window (no clock dependence). Short TTL + renewal-over-mTLS is
        // the documented churn follow-up; see docs/group-enrollment-design.md.
        csr.params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        csr.params.not_after = rcgen::date_time_ymd(2100, 1, 1);
        let leaf = csr
            .signed_by(&self.cert, &self.key)
            .map_err(|error| other(format!("signing join CSR: {error}")))?;
        Ok(leaf.pem())
    }
}

fn other(message: String) -> io::Error {
    io::Error::other(message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::PublicKeyData;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, UnixTime};
    use rustls::server::WebPkiClientVerifier;
    use rustls::RootCertStore;
    use std::sync::Arc;
    use x509_parser::prelude::*;

    /// A throwaway fleet CA for tests, mirroring how cert-manager mints the real one.
    fn test_ca() -> (String, String) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, "test fleet CA");
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert = params.self_signed(&key).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn parse_leaf(leaf_pem: &str) -> Vec<u8> {
        CertificateDer::from_pem_slice(leaf_pem.as_bytes())
            .unwrap()
            .to_vec()
    }

    #[test]
    fn agent_name_is_deterministic_and_distinct_per_instance() {
        let a1 = "a".repeat(64);
        let a2 = "b".repeat(64);
        assert_eq!(agent_name(&a1), agent_name(&a1), "same instance ⇒ same name");
        assert_ne!(
            agent_name(&a1),
            agent_name(&a2),
            "two nodes sharing a group token but differing in instance must not collide"
        );
        assert!(agent_name(&a1).starts_with("agent-"));
    }

    #[test]
    fn nonce_comparison_is_exact() {
        assert!(nonce_matches("s3cret-token", "s3cret-token"));
        assert!(!nonce_matches("s3cret-token", "s3cret-toker"));
        assert!(!nonce_matches("s3cret", "s3cret-token"));
        assert!(!nonce_matches("", "s3cret-token"));
    }

    #[test]
    fn signs_a_csr_the_steady_state_gateway_accepts() {
        updated::tls::install_crypto_provider();
        let (ca_cert_pem, ca_key_pem) = test_ca();
        let ca = IssuingCa::load(&ca_cert_pem, &ca_key_pem).unwrap();
        let (_key, csr) = updated::csr::generate("updated join canary").unwrap();
        let leaf = ca
            .sign_client_csr("canary", &agent_name(&"7".repeat(64)), &csr)
            .unwrap();

        // The minted leaf must verify against the fleet CA exactly as the gateway's mTLS client
        // verifier (built from the same CA) will admit it.
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(ca_cert_pem.as_bytes()).unwrap())
            .unwrap();
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(updated::tls::crypto_provider()),
        )
        .build()
        .unwrap();
        let leaf_der = CertificateDer::from(parse_leaf(&leaf));
        verifier
            .verify_client_cert(&leaf_der, &[], UnixTime::now())
            .expect("gateway must accept a leaf signed by the fleet CA");
    }

    #[test]
    fn certifies_the_csr_key_but_sets_identity_itself() {
        let (ca_cert_pem, ca_key_pem) = test_ca();
        let ca = IssuingCa::load(&ca_cert_pem, &ca_key_pem).unwrap();
        // A hostile CSR that asks to be someone else entirely.
        let (_key, csr) = updated::csr::generate("CN=admin,O=evil").unwrap();
        let name = agent_name(&"9".repeat(64));
        let leaf = ca.sign_client_csr("canary", &name, &csr).unwrap();

        let der = parse_leaf(&leaf);
        let (_, cert) = X509Certificate::from_der(&der).unwrap();

        // Subject is what the control plane chose, not what the CSR asked for.
        let cn: &str = cert
            .subject()
            .iter_common_name()
            .next()
            .unwrap()
            .as_str()
            .unwrap();
        assert_eq!(cn, name);
        assert!(!leaf.is_empty());

        // The SAN names the joined group and the node — the identity the CP assigned.
        let san = cert
            .subject_alternative_name()
            .unwrap()
            .expect("leaf must carry a SAN");
        let uris: Vec<String> = san
            .value
            .general_names
            .iter()
            .filter_map(|gn| match gn {
                GeneralName::URI(uri) => Some(uri.to_string()),
                _ => None,
            })
            .collect();
        assert_eq!(
            uris,
            vec![format!("spiffe://{TRUST_DOMAIN}/group/canary/node/{name}")]
        );

        // The certified public key is the CSR's public key (proof-of-possession), not a key the CP
        // substituted: it matches the SubjectPublicKeyInfo the CSR carried.
        // `der_bytes()` is the raw public key (the EC point); x509-parser's `subject_public_key`
        // bit string holds exactly that, inside the leaf's SubjectPublicKeyInfo.
        let csr_params = CertificateSigningRequestParams::from_pem(&csr).unwrap();
        assert_eq!(
            &*cert.public_key().subject_public_key.data,
            csr_params.public_key.der_bytes(),
            "the leaf must certify the CSR's own public key"
        );
    }

    /// A tiny deterministic xorshift PRNG. Seeded from a constant so a fuzz failure reproduces
    /// exactly in CI (no wall-clock, no `rand`).
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| (self.next() & 0xff) as u8).collect()
        }
        fn ascii(&mut self, n: usize) -> String {
            (0..n)
                .map(|_| (b'a' + (self.next() % 26) as u8) as char)
                .collect()
        }
    }

    #[test]
    fn fuzz_signing_is_robust_and_identity_is_always_control_plane_set() {
        updated::tls::install_crypto_provider();
        let (ca_cert_pem, ca_key_pem) = test_ca();
        let ca = IssuingCa::load(&ca_cert_pem, &ca_key_pem).unwrap();
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_slice(ca_cert_pem.as_bytes()).unwrap())
            .unwrap();
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(updated::tls::crypto_provider()),
        )
        .build()
        .unwrap();
        let mut rng = Rng(0x9e3779b97f4a7c15);

        // Arbitrary, non-CSR input must be rejected — never a panic, never a signed certificate.
        for _ in 0..512 {
            let len = 1 + (rng.next() % 96) as usize;
            let garbage = String::from_utf8_lossy(&rng.bytes(len)).into_owned();
            assert!(
                ca.sign_client_csr("g", "agent-x", &garbage).is_err(),
                "arbitrary bytes must never yield a certificate"
            );
        }

        // For any *valid* CSR — whatever hostile subject it carries, whatever group/instance — the
        // minted leaf always verifies against the fleet CA and always bears the control-plane name.
        for _ in 0..48 {
            let (subject_len, group_len) = (1 + (rng.next() % 40) as usize, 1 + (rng.next() % 20) as usize);
            let subject = rng.ascii(subject_len);
            let group = rng.ascii(group_len);
            let instance = hex::encode(rng.bytes(32));
            let name = agent_name(&instance);
            let (_key, csr) = updated::csr::generate(&subject).unwrap();
            let leaf = ca.sign_client_csr(&group, &name, &csr).unwrap();
            let leaf_der = CertificateDer::from(parse_leaf(&leaf));
            verifier
                .verify_client_cert(&leaf_der, &[], UnixTime::now())
                .expect("every minted leaf must be accepted by the gateway CA");
            let (_, cert) = X509Certificate::from_der(&leaf_der).unwrap();
            let cn: &str = cert
                .subject()
                .iter_common_name()
                .next()
                .unwrap()
                .as_str()
                .unwrap();
            assert_eq!(cn, name, "subject is always the CP-assigned name, never the CSR's");
        }
    }

    #[test]
    fn fuzz_nonce_matches_is_exactly_equality_and_naming_is_collision_free() {
        let mut rng = Rng(0xd1b54a32d192ed03);
        // Differential: constant-time compare must agree with `==` over random pairs, including
        // the equal case (occasionally forced) and near-misses.
        for _ in 0..5000 {
            let a_len = (rng.next() % 24) as usize;
            let a = rng.ascii(a_len);
            let b = if rng.next().is_multiple_of(4) {
                a.clone()
            } else {
                let b_len = (rng.next() % 24) as usize;
                rng.ascii(b_len)
            };
            assert_eq!(nonce_matches(&a, &b), a == b);
        }
        // Distinct instances never collide onto one agent name (the shared-token safety property).
        let mut seen = std::collections::HashSet::new();
        for _ in 0..5000 {
            let instance = hex::encode(rng.bytes(32));
            let name = agent_name(&instance);
            assert_eq!(name, agent_name(&instance), "naming must be deterministic");
            assert!(seen.insert(name), "distinct instances must not collide");
        }
    }

    #[test]
    fn two_instances_one_token_yield_distinct_identities() {
        let (ca_cert_pem, ca_key_pem) = test_ca();
        let ca = IssuingCa::load(&ca_cert_pem, &ca_key_pem).unwrap();
        let (name_a, name_b) = (agent_name(&"1".repeat(64)), agent_name(&"2".repeat(64)));
        let (_ka, csr_a) = updated::csr::generate("a").unwrap();
        let (_kb, csr_b) = updated::csr::generate("b").unwrap();
        let leaf_a = ca.sign_client_csr("canary", &name_a, &csr_a).unwrap();
        let leaf_b = ca.sign_client_csr("canary", &name_b, &csr_b).unwrap();
        assert_ne!(name_a, name_b);
        assert_ne!(leaf_a, leaf_b, "each node gets its own certificate");
    }
}
