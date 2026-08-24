//! What a client certificate proves. A leaf carries a name, and — once enrolled — a SPIFFE
//! identity and a certified public key; authorization compares the key, not merely the name, so a
//! re-enrolled name cannot be answered for by its previous holder.

/// The verified per-connection client identity, read from the mTLS leaf rustls already validated
/// against the fleet CA before any handler runs. The node cannot forge either field — both come
/// from the CA-signed certificate, not from anything the node puts in the request — so this is the
/// trusted answer to "who is this?" that every authorization check gates on.
#[derive(Clone, Debug)]
pub(crate) struct ClientIdentity {
    /// The leaf's Common Name. `None` on a connection with no client certificate (the health
    /// listener), a leaf carrying no CN, or an ambiguous leaf carrying more than one.
    pub(crate) common_name: Option<String>,
    /// The per-node SPIFFE identity the leaf's URI SAN names — repository scope *and* node —
    /// present only on a certificate minted at `/enroll`, absent on the shared fleet bootstrap
    /// certificate. Enrollment requires it to be absent; every steady-state route requires it to
    /// name this gateway's own repository.
    pub(crate) node: Option<crate::join::NodeSpiffeId>,
    /// Hex of the leaf's certified public key (its `SubjectPublicKeyInfo` bit string), in exactly
    /// the encoding `/enroll` pins onto the `UpdateAgent` — the leaf certifies the CSR's own key,
    /// so the two are byte-identical for the holder the pin was minted for. `None` on a connection
    /// with no client certificate. This is what makes a node's identity a KEY and not merely a
    /// name: the handshake proved possession of it, so comparing it to the pin distinguishes the
    /// machine that holds the name now from a previous holder of a re-enrolled name.
    pub(crate) public_key: Option<String>,
}

impl ClientIdentity {
    /// The node this connection is authorized to act as **within `repository`**.
    ///
    /// Naming the repository is not optional, and that is the point: the fleet CA is shared across
    /// every repository in a namespace, so a leaf minted by one repository's `/enroll` is a valid,
    /// CA-verified certificate on another repository's listener. Authorizing on the node name alone
    /// let a staging node read the production node of the same name's secrets and forge its
    /// telemetry. There is no way to obtain a node name here without saying which repository the
    /// answer is for.
    ///
    /// The shared fleet bootstrap certificate carries no node SAN, so it resolves to no node in any
    /// repository — it authenticates the one `/enroll` handshake and nothing else.
    pub(crate) fn node_in(&self, repository: &str) -> Option<&str> {
        let identity = self.node.as_ref()?;
        (identity.repository == repository).then_some(identity.node.as_str())
    }
}

/// Extract the leaf certificate's identity — Common Name, SPIFFE node SAN and certified public
/// key — from a completed server-side TLS connection.
pub(crate) fn peer_identity(conn: &tokio_rustls::rustls::ServerConnection) -> ClientIdentity {
    use x509_parser::extensions::GeneralName;

    let anonymous = ClientIdentity {
        common_name: None,
        node: None,
        public_key: None,
    };
    let Some(leaf) = conn.peer_certificates().and_then(|certs| certs.first()) else {
        return anonymous;
    };
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(leaf.as_ref()) else {
        return anonymous;
    };
    let mut common_names = cert.subject().iter_common_name();
    let cn = common_names
        .next()
        .and_then(|name| name.as_str().ok())
        .map(str::to_owned);
    // An ambiguous subject is not an identity. Issued node and bootstrap certificates each carry
    // exactly one CN; fail closed if an external issuer supplies more.
    if common_names.next().is_some() {
        return anonymous;
    }
    // Every node leaf minted by this control plane carries a SPIFFE URI SAN naming its repository
    // scope and node. It is a cryptographic marker that the certificate is an ordinary node
    // identity — so it can never regain bootstrap authority merely by choosing the bootstrap
    // certificate's CN — and it is the ONLY thing that says which repository the leaf belongs to.
    let node = cert
        .subject_alternative_name()
        .ok()
        .flatten()
        .and_then(|san| {
            san.value.general_names.iter().find_map(|name| match name {
                GeneralName::URI(uri) => crate::join::NodeSpiffeId::parse(uri),
                _ => None,
            })
        })
        // The subject and the SAN are minted together from one name, so a leaf whose two identity
        // fields disagree was not minted by this control plane and is not an identity at all.
        .filter(|identity| Some(identity.node.as_str()) == cn.as_deref());
    ClientIdentity {
        common_name: cn,
        node,
        // The key the handshake proved possession of, encoded exactly as `/enroll` pinned it.
        public_key: Some(hex::encode(&*cert.public_key().subject_public_key.data)),
    }
}
