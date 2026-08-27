//! What a client certificate proves. A leaf is classified exactly once, at the TLS boundary, as
//! anonymous, the fleet enrollment identity, or one repository-scoped node identity. Handlers
//! cannot assemble partially parsed identities or reinterpret malformed certificate fields.

#[derive(Clone, Debug)]
pub(crate) struct ClientIdentity {
    kind: ClientIdentityKind,
}

#[derive(Clone, Debug)]
enum ClientIdentityKind {
    Anonymous,
    /// A certificate with exactly one CN and no SAN. The `/enroll` gate still compares the CN to
    /// the repository's configured enrollment name before granting authority.
    Enrollment {
        common_name: String,
    },
    /// A certificate with exactly one CN and exactly one URI SAN, where the SPIFFE node equals the
    /// CN. The certified key is what the TLS handshake proved the caller possesses.
    Node {
        identity: crate::join::NodeSpiffeId,
        public_key: String,
    },
}

impl ClientIdentity {
    pub(crate) fn anonymous() -> Self {
        Self {
            kind: ClientIdentityKind::Anonymous,
        }
    }

    /// The node this connection is authorized to act as **within `repository`**.
    ///
    /// Naming the repository is not optional, and that is the point: the fleet CA is shared across
    /// every repository in a namespace, so a leaf minted by one repository's `/enroll` is a valid,
    /// CA-verified certificate on another repository's listener. Authorizing on the node name alone
    /// let a staging node read the production node of the same name's secrets and forge its
    /// telemetry. There is no way to obtain a node name here without saying which repository the
    /// answer is for.
    pub(crate) fn node_in(&self, repository: &str) -> Option<&str> {
        let ClientIdentityKind::Node { identity, .. } = &self.kind else {
            return None;
        };
        (identity.repository() == repository).then_some(identity.node())
    }

    /// The CN of a certificate having the one exact enrollment shape. A node certificate cannot
    /// reach this accessor: malformed or ambiguous SANs classify as anonymous instead of silently
    /// degrading into enrollment authority.
    pub(crate) fn enrollment_name(&self) -> Option<&str> {
        match &self.kind {
            ClientIdentityKind::Enrollment { common_name } => Some(common_name),
            ClientIdentityKind::Anonymous | ClientIdentityKind::Node { .. } => None,
        }
    }

    /// The certified key of an unambiguous node identity. No other certificate shape can enter an
    /// authorization memo or satisfy a live `UpdateAgent` key pin.
    pub(crate) fn node_public_key(&self) -> Option<&str> {
        match &self.kind {
            ClientIdentityKind::Node { public_key, .. } => Some(public_key),
            ClientIdentityKind::Anonymous | ClientIdentityKind::Enrollment { .. } => None,
        }
    }

    #[cfg(test)]
    pub(crate) fn test_enrollment(common_name: &str) -> Self {
        Self {
            kind: ClientIdentityKind::Enrollment {
                common_name: common_name.to_owned(),
            },
        }
    }

    #[cfg(test)]
    pub(crate) fn test_node(repository: &str, node: &str, public_key: &str) -> Self {
        Self {
            kind: ClientIdentityKind::Node {
                identity: crate::join::NodeSpiffeId::new(repository, node)
                    .expect("test node identity is canonical"),
                public_key: public_key.to_owned(),
            },
        }
    }
}

/// Classify one already-verified leaf. This is deliberately an exact grammar, not a best-effort
/// extraction:
///
/// - one CN and no SAN is an enrollment-shaped certificate;
/// - one CN plus one matching node SPIFFE URI SAN is a node certificate;
/// - every absent, malformed, mismatched, extra, or ambiguous field is anonymous.
///
/// In particular, dropping only a malformed SAN while retaining the CN would turn a malformed
/// node leaf whose CN equals the configured enrollment name into enrollment authority. Returning
/// the all-or-nothing classification makes that downgrade unrepresentable to every handler.
fn certificate_identity(leaf: &[u8]) -> ClientIdentity {
    use x509_parser::extensions::GeneralName;

    let Ok((remaining, cert)) = x509_parser::parse_x509_certificate(leaf) else {
        return ClientIdentity::anonymous();
    };
    if !remaining.is_empty() {
        return ClientIdentity::anonymous();
    }

    let mut common_names = cert.subject().iter_common_name();
    let Some(common_name) = common_names
        .next()
        .and_then(|name| name.as_str().ok())
        .filter(|name| !name.is_empty())
    else {
        return ClientIdentity::anonymous();
    };
    if common_names.next().is_some() {
        return ClientIdentity::anonymous();
    }
    let common_name = common_name.to_owned();

    let san = match cert.subject_alternative_name() {
        Ok(san) => san,
        Err(_) => return ClientIdentity::anonymous(),
    };
    let Some(san) = san else {
        return ClientIdentity {
            kind: ClientIdentityKind::Enrollment { common_name },
        };
    };
    let [only_name] = san.value.general_names.as_slice() else {
        return ClientIdentity::anonymous();
    };
    let GeneralName::URI(uri) = only_name else {
        return ClientIdentity::anonymous();
    };
    let Some(identity) = crate::join::NodeSpiffeId::parse(uri) else {
        return ClientIdentity::anonymous();
    };
    if identity.node() != common_name {
        return ClientIdentity::anonymous();
    }

    ClientIdentity {
        kind: ClientIdentityKind::Node {
            identity,
            public_key: hex::encode(&*cert.public_key().subject_public_key.data),
        },
    }
}

/// Extract and classify the leaf certificate from a completed server-side TLS connection. Rustls
/// has already validated the chain against the fleet CA before this runs; this chokepoint decides
/// what, if any, application identity that authenticated certificate proves.
pub(crate) fn peer_identity(conn: &tokio_rustls::rustls::ServerConnection) -> ClientIdentity {
    conn.peer_certificates()
        .and_then(|certificates| certificates.first())
        .map_or_else(ClientIdentity::anonymous, |leaf| {
            certificate_identity(leaf.as_ref())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};

    fn certificate(common_names: &[&str], sans: Vec<SanType>) -> Vec<u8> {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.distinguished_name = DistinguishedName::new();
        for (index, common_name) in common_names.iter().enumerate() {
            params.distinguished_name.push(
                if index == 0 {
                    DnType::CommonName
                } else {
                    // `rcgen` stores one value per `DnType`. A custom type with the same OID
                    // emits a second CN so the parser's ambiguity gate is exercised directly.
                    DnType::CustomDnType(vec![2, 5, 4, 3])
                },
                *common_name,
            );
        }
        params.subject_alt_names = sans;
        params.self_signed(&key).unwrap().der().to_vec()
    }

    fn uri(value: &str) -> SanType {
        SanType::URI(value.try_into().unwrap())
    }

    #[test]
    fn certificate_shapes_have_one_fail_closed_classification() {
        let enrollment = certificate(&["updated-enrollment"], vec![]);
        let enrollment = certificate_identity(&enrollment);
        assert_eq!(enrollment.enrollment_name(), Some("updated-enrollment"));
        assert_eq!(enrollment.node_in("prod"), None);
        assert_eq!(enrollment.node_public_key(), None);

        let node = certificate(
            &["web-01"],
            vec![uri("spiffe://updated.fleet/scope/prod/node/web-01")],
        );
        let node = certificate_identity(&node);
        assert_eq!(node.enrollment_name(), None);
        assert_eq!(node.node_in("prod"), Some("web-01"));
        assert!(node.node_public_key().is_some());
    }

    #[test]
    fn malformed_or_ambiguous_node_fields_never_degrade_to_enrollment() {
        let mut trailing_der = certificate(&["updated-enrollment"], vec![]);
        trailing_der.extend_from_slice(b"trailing");
        let cases = [
            certificate(
                &["updated-enrollment"],
                vec![uri("spiffe://updated.fleet/scope/prod/node/other")],
            ),
            certificate(
                &["updated-enrollment"],
                vec![uri("spiffe://updated.fleet/scope/prod/node/")],
            ),
            certificate(
                &["updated-enrollment"],
                vec![
                    uri("spiffe://updated.fleet/scope/prod/node/updated-enrollment"),
                    uri("spiffe://updated.fleet/scope/staging/node/updated-enrollment"),
                ],
            ),
            certificate(
                &["updated-enrollment"],
                vec![SanType::DnsName("updated.example".try_into().unwrap())],
            ),
            certificate(&["updated-enrollment", "updated-enrollment"], vec![]),
            certificate(&[""], vec![]),
            certificate(&[], vec![]),
            trailing_der,
            b"not a DER certificate".to_vec(),
        ];

        for (case, leaf) in cases.into_iter().enumerate() {
            let identity = certificate_identity(&leaf);
            assert_eq!(identity.enrollment_name(), None, "case {case}");
            assert_eq!(identity.node_in("prod"), None, "case {case}");
            assert_eq!(identity.node_public_key(), None, "case {case}");
        }
    }
}
