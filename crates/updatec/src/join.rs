//! Control-plane side of enrollment: the fleet CA that mints per-node client certificates. This
//! module is deliberately pure — no Kubernetes, no object store — so the security invariants can be
//! pinned by fast unit tests. The `gateway` `/enroll` handler wires it to the CRD API (agent
//! creation) and the repository (bundle).
//!
//! The property that matters most, tested below: the control plane certifies only the CSR's
//! **public key** and sets the certificate's subject and SAN itself, so a node that reaches `/enroll`
//! (authenticated by the shared fleet enrollment cert at the mTLS handshake) can never mint an
//! arbitrary identity — the leaf's `CN` is always the name the control plane assigned.

use std::io;

use chrono::Datelike;
use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
/// The SPIFFE trust domain the node identity is expressed under. Encoded as a URI SAN on every
/// minted leaf so a verified client cert names both the group it joined and its unique node.
const TRUST_DOMAIN: &str = "updated.fleet";

/// Default validity of a minted leaf certificate. Bounded so a leaked leaf is time-limited rather
/// than permanent. Kept a single clear default here rather than a per-group spec field until
/// renewal-over-mTLS (`/renew`) lands to make a shorter TTL sustainable.
const LEAF_CERT_TTL_DAYS: i64 = 90;

/// The node's public key (uncompressed EC point) extracted from its PEM CSR — the value the control
/// plane pins on the `UpdateAgent` so it can later verify the node's *signed* telemetry against the
/// same key that certifies its mTLS leaf. Only the public half; possession of the private key is
/// proven by the CSR self-signature the CA checks at signing time. This is the exact bytes
/// `aws-lc-rs` `ECDSA_P256_SHA256` verification (in `updated::telemetry::verify_report`) expects.
pub fn csr_public_key(csr_pem: &str) -> io::Result<Vec<u8>> {
    use x509_parser::prelude::FromDer;
    let (_, pem) = x509_parser::pem::parse_x509_pem(csr_pem.as_bytes())
        .map_err(|error| other(format!("parsing CSR PEM: {error}")))?;
    let (_, csr) =
        x509_parser::certification_request::X509CertificationRequest::from_der(&pem.contents)
            .map_err(|error| other(format!("parsing CSR: {error}")))?;
    Ok(csr
        .certification_request_info
        .subject_pki
        .subject_public_key
        .data
        .to_vec())
}

/// The fleet CA that signs per-node client certificates at `/enroll`. Loaded from the same
/// cert-manager CA the gateway trusts as its mTLS `client_ca`, so the leaves it mints are accepted
/// on the steady-state gateway.
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
    /// control plane sets the subject to `CN=<name>` and a single URI SAN naming the enrollment
    /// `scope` (the repository) and node, and certifies only the CSR's public key (whose possession
    /// the CSR self-signature proves). Returns the leaf PEM.
    pub fn sign_client_csr(&self, scope: &str, name: &str, csr_pem: &str) -> io::Result<String> {
        // `from_pem` parses and verifies the CSR self-signature (proof the requester holds the
        // private key for the public key it presents).
        let mut csr = CertificateSigningRequestParams::from_pem(csr_pem)
            .map_err(|error| other(format!("parsing enrollment CSR: {error}")))?;
        // Overwrite everything identity-bearing; keep only `csr.public_key` (used by `signed_by`).
        csr.params.is_ca = IsCa::NoCa;
        csr.params.distinguished_name = rcgen::DistinguishedName::new();
        csr.params.distinguished_name.push(DnType::CommonName, name);
        let uri = format!("spiffe://{TRUST_DOMAIN}/scope/{scope}/node/{name}");
        csr.params.subject_alt_names =
            vec![SanType::URI(uri.clone().try_into().map_err(|error| {
                other(format!("encoding node URI SAN {uri}: {error}"))
            })?)];
        csr.params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        csr.params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        // Bound the leaf's validity so a leaked leaf is not effectively permanent fleet-client-cert
        // access: it expires within LEAF_CERT_TTL_DAYS and access ends unless renewed. `not_before`
        // is backdated to the issuing day's midnight UTC to tolerate modest node clock skew. This
        // TTL is the single clear default; renewal-over-mTLS (a `/renew` endpoint that re-signs with
        // the current cert) is the intended follow-up that makes a short TTL sustainable.
        let issued = chrono::Utc::now().date_naive();
        let expires = issued + chrono::Duration::days(LEAF_CERT_TTL_DAYS);
        csr.params.not_before =
            rcgen::date_time_ymd(issued.year(), issued.month() as u8, issued.day() as u8);
        csr.params.not_after =
            rcgen::date_time_ymd(expires.year(), expires.month() as u8, expires.day() as u8);
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

    #[test]
    fn pinned_csr_public_key_verifies_the_node_s_signed_telemetry() {
        // The full C trust chain across the crate boundary: a node generates a durable key and CSR;
        // the control plane pins the CSR's public key; the node signs a report with the SAME key;
        // the pinned key must verify it — and reject a tamper or a different key.
        let key_pem = updated::csr::generate_key().unwrap();
        let csr_pem = updated::csr::csr_for(&key_pem, "updated enroll").unwrap();
        let pinned = csr_public_key(&csr_pem).unwrap();

        let pkcs8_der = updated::csr::key_pem_to_pkcs8_der(&key_pem).unwrap();
        let mut report = updated::telemetry::NodeReport::new("agent-9", "deploy-2", "2.0.0", true);
        report.signature = updated::telemetry::sign_report(&report, &pkcs8_der).unwrap();
        assert!(
            updated::telemetry::verify_report(&report, &pinned),
            "pinned CSR key must verify the node's own signed report"
        );

        let mut tampered = report.clone();
        tampered.healthy = false;
        assert!(!updated::telemetry::verify_report(&tampered, &pinned));

        let other_key = updated::csr::generate_key().unwrap();
        let other_csr = updated::csr::csr_for(&other_key, "x").unwrap();
        let other_pin = csr_public_key(&other_csr).unwrap();
        assert!(
            !updated::telemetry::verify_report(&report, &other_pin),
            "a different node's pinned key must not verify this report"
        );
    }
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
    fn signs_a_csr_the_steady_state_gateway_accepts() {
        updated::tls::install_crypto_provider();
        let (ca_cert_pem, ca_key_pem) = test_ca();
        let ca = IssuingCa::load(&ca_cert_pem, &ca_key_pem).unwrap();
        let (_key, csr) = updated::csr::generate("updated enroll canary").unwrap();
        let leaf = ca.sign_client_csr("canary", "agent-7", &csr).unwrap();

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
    fn minted_leaf_has_a_bounded_validity_window() {
        // A leaked token or leaf must not be permanent: the leaf expires within ~LEAF_CERT_TTL_DAYS,
        // not in the year 2100. Guards against regressing back to a fixed wide window.
        let (ca_cert_pem, ca_key_pem) = test_ca();
        let ca = IssuingCa::load(&ca_cert_pem, &ca_key_pem).unwrap();
        let (_key, csr) = updated::csr::generate("ttl canary").unwrap();
        let leaf = ca.sign_client_csr("canary", "agent-3", &csr).unwrap();
        let der = parse_leaf(&leaf);
        let (_, cert) = X509Certificate::from_der(&der).unwrap();
        let not_before = cert.validity().not_before.timestamp();
        let not_after = cert.validity().not_after.timestamp();
        let span_days = (not_after - not_before) / 86_400;
        assert_eq!(
            span_days, LEAF_CERT_TTL_DAYS,
            "leaf TTL must be the bounded default"
        );
        // And it is anchored near now, not decades away.
        let now = chrono::Utc::now().timestamp();
        assert!(
            (now - not_before) < 2 * 86_400
                && (not_after - now) < (LEAF_CERT_TTL_DAYS + 1) * 86_400,
            "leaf validity must be anchored at issuance, not a fixed 2020..2100 window"
        );
    }

    #[test]
    fn certifies_the_csr_key_but_sets_identity_itself() {
        let (ca_cert_pem, ca_key_pem) = test_ca();
        let ca = IssuingCa::load(&ca_cert_pem, &ca_key_pem).unwrap();
        // A hostile CSR that asks to be someone else entirely.
        let (_key, csr) = updated::csr::generate("CN=admin,O=evil").unwrap();
        let name = "agent-9";
        let leaf = ca.sign_client_csr("canary", name, &csr).unwrap();

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
            vec![format!("spiffe://{TRUST_DOMAIN}/scope/canary/node/{name}")]
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

        // For any *valid* CSR — whatever hostile subject it carries, whatever scope/name — the
        // minted leaf always verifies against the fleet CA and always bears the control-plane name.
        for i in 0..48 {
            let (subject_len, scope_len) = (
                1 + (rng.next() % 40) as usize,
                1 + (rng.next() % 20) as usize,
            );
            let subject = rng.ascii(subject_len);
            let scope = rng.ascii(scope_len);
            let name = format!("agent-{i}");
            let (_key, csr) = updated::csr::generate(&subject).unwrap();
            let leaf = ca.sign_client_csr(&scope, &name, &csr).unwrap();
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
            assert_eq!(
                cn, name,
                "subject is always the CP-assigned name, never the CSR's"
            );
        }
    }

    #[test]
    fn distinct_names_one_scope_yield_distinct_identities() {
        let (ca_cert_pem, ca_key_pem) = test_ca();
        let ca = IssuingCa::load(&ca_cert_pem, &ca_key_pem).unwrap();
        let (name_a, name_b) = ("agent-a", "agent-b");
        let (_ka, csr_a) = updated::csr::generate("a").unwrap();
        let (_kb, csr_b) = updated::csr::generate("b").unwrap();
        let leaf_a = ca.sign_client_csr("canary", name_a, &csr_a).unwrap();
        let leaf_b = ca.sign_client_csr("canary", name_b, &csr_b).unwrap();
        assert_ne!(name_a, name_b);
        assert_ne!(leaf_a, leaf_b, "each node gets its own certificate");
    }
}
