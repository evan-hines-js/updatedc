//! The controller-owned backend inventory consumed by `updated-healthproxy`.
//!
//! This is the one topology/control channel for a managed load balancer. Active entries carry the
//! exact address and report-verification key needed to route them; cordoned entries deliberately
//! carry only the identity that must be drained. Keeping cordons in this revision-checked,
//! Kubernetes-projected inventory avoids turning an unsigned object-store document into a second
//! source of routing authority.

use serde::{Deserialize, Serialize};

/// The typed active/cordoned inventory contract. Version 1 encoded members as delimiter-joined
/// strings and is intentionally unsupported: accepting both representations would recreate two
/// topology paths at the routing trust boundary.
pub const BACKEND_INVENTORY_SCHEMA: u8 = 2;

/// The one production projection width. Eight shards hold the maximum 10,000 admitted agents even
/// when every identity and DNS address is at its protocol limit. Keeping the width in the protocol
/// removes a live topology migration and prevents the controller and reader from accepting
/// different projection shapes.
pub const BACKEND_INVENTORY_SHARDS: usize = 8;

/// The operator → healthproxy configuration contract: every environment variable the operator's
/// `apply_backend_deployment` sets on the Deployment it owns, and the healthproxy's `Config::build`
/// reads back. It is a contract across a crate boundary with no compiler between its two halves —
/// and every miss on the reading side falls back to a default rather than failing, so a name spelled
/// independently on each side and renamed on only one is silent: the port name reverts to `http` and
/// kube-proxy matches nothing, the namespace reverts to `default` and the EndpointSlice lands
/// somewhere no Service reads, an absent endpoint list switches the whole process from the HAProxy
/// backend to the EndpointSlice one. Naming them once here means a rename compiles on both sides or
/// on neither.
pub const HEALTHPROXY_HEALTH_BASE_ENV: &str = "HEALTHPROXY_HEALTH_BASE";
pub const HEALTHPROXY_INVENTORY_DIR_ENV: &str = "HEALTHPROXY_INVENTORY_DIR";
pub const HEALTHPROXY_INTERVAL_SECS_ENV: &str = "HEALTHPROXY_INTERVAL_SECS";
pub const HEALTHPROXY_HEALTH_TIMEOUT_SECS_ENV: &str = "HEALTHPROXY_HEALTH_TIMEOUT_SECS";
pub const HEALTHPROXY_METRICS_ADDRESS_ENV: &str = "HEALTHPROXY_METRICS_ADDRESS";
pub const HEALTHPROXY_SERVICE_ENV: &str = "HEALTHPROXY_SERVICE";
pub const HEALTHPROXY_NAMESPACE_ENV: &str = "HEALTHPROXY_NAMESPACE";
pub const HEALTHPROXY_PORT_ENV: &str = "HEALTHPROXY_PORT";
pub const HEALTHPROXY_PORT_NAME_ENV: &str = "HEALTHPROXY_PORT_NAME";
pub const HEALTHPROXY_HAPROXY_ENDPOINTS_ENV: &str = "HEALTHPROXY_HAPROXY_ENDPOINTS";
pub const HEALTHPROXY_HAPROXY_BACKEND_ENV: &str = "HEALTHPROXY_HAPROXY_BACKEND";

/// A margin below the apiserver's 1 MiB object limit for JSON metadata and serialization overhead.
pub const BACKEND_INVENTORY_SHARD_MAX_BYTES: usize = 900 * 1024;

/// An inventory cannot legitimately exceed its repository's enrollment ceiling.
pub const MAX_BACKEND_INVENTORY_MEMBERS: usize = 10_000;

/// One identity in a backend inventory.
///
/// A cordoned identity intentionally has no address or public key. HAProxy still needs its name to
/// issue an explicit `drain` for the predeclared server, while EndpointSlice can omit it entirely.
/// More importantly, a malformed address or key cannot hold a new cordon hostage: uncordoning
/// reconstructs an [`Active`](Self::Active) entry and therefore must pass the full endpoint gate.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "camelCase", deny_unknown_fields)]
pub enum BackendInventoryMember {
    Active {
        node: String,
        address: String,
        public_key: crate::key::P256PublicKey,
    },
    Cordoned {
        node: String,
    },
}

impl BackendInventoryMember {
    pub fn active(
        node: impl Into<String>,
        address: impl Into<String>,
        public_key: &str,
    ) -> Result<Self, String> {
        let node = node.into();
        let address = address.into();
        let address = routable_host(&address).ok_or_else(|| {
            format!("inventory member {node:?} has unroutable address {address:?}")
        })?;
        let public_key = crate::key::P256PublicKey::parse_hex(public_key)
            .map_err(|error| format!("inventory member {node:?} public key {error}"))?;
        Self::Active {
            node,
            address,
            public_key,
        }
        .validate()
    }

    /// The pinned key an active member's reports verify against, or `None` for a cordon.
    pub fn public_key(&self) -> Option<&crate::key::P256PublicKey> {
        match self {
            Self::Active { public_key, .. } => Some(public_key),
            Self::Cordoned { .. } => None,
        }
    }

    /// The address the load balancer routes to, or `None` for a cordon.
    pub fn address(&self) -> Option<&str> {
        match self {
            Self::Active { address, .. } => Some(address),
            Self::Cordoned { .. } => None,
        }
    }

    pub fn cordoned(node: impl Into<String>) -> Result<Self, String> {
        Self::Cordoned { node: node.into() }.validate()
    }

    pub fn node(&self) -> &str {
        match self {
            Self::Active { node, .. } | Self::Cordoned { node } => node,
        }
    }

    pub fn is_cordoned(&self) -> bool {
        matches!(self, Self::Cordoned { .. })
    }

    /// Revalidate a deserialized entry at the one shared protocol gate.
    pub fn validate(self) -> Result<Self, String> {
        let node = self.node();
        if !crate::telemetry::is_valid_node(node) || !is_balancer_safe(node) {
            return Err(format!(
                "inventory member has invalid node identity {node:?}"
            ));
        }
        // The pin needs no check here: the field is a [`crate::key::P256PublicKey`], so neither a
        // constructor nor a deserializer can have produced one that is not already on the curve.
        if let Self::Active { address, .. } = &self {
            let Some(canonical) = routable_host(address) else {
                return Err(format!(
                    "inventory member {node:?} has unroutable address {address:?}"
                ));
            };
            if canonical != *address {
                return Err(format!(
                    "inventory member {node:?} address {address:?} is not canonical; use {canonical:?}"
                ));
            }
        }
        Ok(self)
    }
}

/// One member-inventory ConfigMap. Every shard repeats the full-set revision so a projected volume
/// observed halfway through a multi-object update is rejected instead of briefly misrouting
/// traffic from a mixture of old and new membership.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendInventoryShard {
    pub version: u8,
    pub revision: String,
    pub index: u8,
    pub shards: u8,
    pub members: Vec<BackendInventoryMember>,
}

/// The full-set digest every shard repeats. Private: [`shard_backend_inventory`] stamps it and
/// [`assemble_backend_inventory`] checks it, and those two are the whole contract — a caller that
/// could compute it itself could also mint a revision no complete member set hashes to.
fn backend_inventory_revision(members: &[BackendInventoryMember]) -> String {
    let encoded = serde_json::to_vec(members).expect("serializing inventory members cannot fail");
    crate::digest::sha256_bytes(&encoded)
}

/// Split one sorted inventory across the protocol's fixed projection. The width cannot drift
/// between controller, volume, and reader because none of them accepts a local setting.
pub fn shard_backend_inventory(
    members: &[BackendInventoryMember],
) -> Result<Vec<BackendInventoryShard>, String> {
    validate_backend_inventory_members(members)?;
    let revision = backend_inventory_revision(members);
    let shard_count = BACKEND_INVENTORY_SHARDS;
    let chunk_size = members.len().div_ceil(shard_count).max(1);
    let shards = (0..shard_count)
        .map(|index| BackendInventoryShard {
            version: BACKEND_INVENTORY_SCHEMA,
            revision: revision.clone(),
            index: index as u8,
            shards: shard_count as u8,
            members: members
                .get(index * chunk_size..((index + 1) * chunk_size).min(members.len()))
                .unwrap_or_default()
                .to_vec(),
        })
        .collect::<Vec<_>>();
    for shard in &shards {
        let bytes = serde_json::to_vec(shard)
            .map_err(|error| format!("encoding inventory shard {}: {error}", shard.index))?;
        if bytes.len() > BACKEND_INVENTORY_SHARD_MAX_BYTES {
            return Err(format!(
                "the fixed {BACKEND_INVENTORY_SHARDS}-shard inventory cannot hold this fleet: shard {} is {} bytes, over the {BACKEND_INVENTORY_SHARD_MAX_BYTES}-byte safe ConfigMap ceiling",
                shard.index,
                bytes.len()
            ));
        }
    }
    Ok(shards)
}

fn validate_backend_inventory_members(members: &[BackendInventoryMember]) -> Result<(), String> {
    if members.len() > MAX_BACKEND_INVENTORY_MEMBERS {
        return Err(format!(
            "inventory has {} members, over the admitted fleet limit of {MAX_BACKEND_INVENTORY_MEMBERS}",
            members.len()
        ));
    }
    let mut previous: Option<&str> = None;
    for member in members {
        member.clone().validate()?;
        if let Some(prior) = previous {
            if prior >= member.node() {
                return Err(format!(
                    "inventory members must be strictly ordered by node identity; {:?} follows {prior:?}",
                    member.node()
                ));
            }
        }
        previous = Some(member.node());
    }
    Ok(())
}

/// Validate and join an observed projection. This is deliberately the only assembly path used by
/// healthproxy: incomplete, duplicated, reordered, mixed-generation, or altered shards all fail
/// as one inventory and leave the previous valid membership active.
pub fn assemble_backend_inventory(
    mut shards: Vec<BackendInventoryShard>,
) -> Result<Vec<BackendInventoryMember>, String> {
    let shard_count = BACKEND_INVENTORY_SHARDS;
    if shards.len() != shard_count {
        return Err(format!(
            "inventory has {} shards, expected {shard_count}",
            shards.len()
        ));
    }
    shards.sort_by_key(|shard| shard.index);
    let revision = shards[0].revision.clone();
    for (index, shard) in shards.iter().enumerate() {
        if shard.version != BACKEND_INVENTORY_SCHEMA
            || shard.index as usize != index
            || shard.shards as usize != shard_count
            || shard.revision != revision
        {
            return Err("inventory shards do not describe one complete revision".into());
        }
    }
    let members: Vec<BackendInventoryMember> =
        shards.into_iter().flat_map(|shard| shard.members).collect();
    if backend_inventory_revision(&members) != revision {
        return Err("inventory revision does not match its members".into());
    }
    validate_backend_inventory_members(&members)?;
    Ok(members)
}

/// Validate and normalize an agent backend host.
///
/// The address is deliberately host-only. EndpointSlice owns the one service port in
/// `UpdateBackend.target.port`, while HAProxy owns its predeclared servers; accepting a second port
/// here and silently discarding it made two apparent configuration paths with only one honored.
/// Keeping this parser in the contracts crate makes operator admission and healthproxy startup
/// accept exactly the same address shapes.
pub fn routable_host(address: &str) -> Option<String> {
    if let Ok(ip) = address.parse::<std::net::IpAddr>() {
        return Some(ip.to_string());
    }
    // Colons belong only to the bare IPv6 form accepted above. Brackets and ports are URL/socket
    // syntax, not a host, and would otherwise be accepted only to be discarded.
    if address.contains([':', '[', ']']) {
        return None;
    }
    let host = address.strip_suffix('.').unwrap_or(address);
    let labelled = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
        // Do not let an invalid IP literal fall through as a platform-dependent numeric hostname.
        && !host.bytes().all(|byte| byte.is_ascii_digit() || byte == b'.');
    labelled.then(|| host.to_string())
}

/// Whether an operator-supplied name can be written into one HAProxy Runtime API command verbatim,
/// without terminating the name or appending another command.
///
/// Both names the proxy interpolates go through it — the node identity that becomes the server
/// name, and the `backend` section that qualifies it — because they share one command line and one
/// consequence.
///
/// [`crate::telemetry::is_valid_node`] is a URL/path grammar — it rejects `/ \ :`, `. % ? #`, and
/// control characters — and none of that covers the syntax of the balancer the name is programmed
/// into: the HAProxy Runtime API separates commands on a line with `;` and a command's own words
/// with whitespace. A name carrying either does not name a server, it appends a second command to a
/// `level admin` socket (`agent-0; shutdown frontend public` really does take the frontend down).
/// Whitespace alone is enough to matter without any malice: `HAPROXY_BACKEND` with a copy-pasted
/// trailing space emits `set server fleet /agent-0 state ready`, which HAProxy answers with an
/// error for every member, so every reconcile fails and nothing is ever programmed.
///
/// It is applied where the value is *parsed* — [`BackendInventoryMember::validate`] for the
/// identity, the proxy's config build for the backend — because a name problem is a configuration
/// error. Refusing it where it is interpolated instead would convert one operator typo into a
/// fleet-wide outage: the backend would fail the whole reconcile, so *no* member — including every
/// correctly named one — would ever be programmed again, every cycle, behind a single log line.
/// That is exactly the "drained forever behind a log line" harm the inventory gate exists to
/// prevent.
pub fn is_balancer_safe(name: &str) -> bool {
    !name.is_empty()
        && !name.contains(|character: char| character == ';' || character.is_whitespace())
}

/// Whether an HAProxy Runtime API endpoint is a TCP `host:port`. Unix sockets are process-local and
/// cannot be reached by an operator-created pod without a second volume-mount configuration path,
/// so the CRD deliberately admits only the transport this deployment model can actually use.
pub fn is_tcp_endpoint(endpoint: &str) -> bool {
    if let Ok(socket) = endpoint.parse::<std::net::SocketAddr>() {
        return socket.port() != 0;
    }
    let Some((host, port)) = endpoint.rsplit_once(':') else {
        return false;
    };
    !host.contains(':')
        && port.parse::<u16>().is_ok_and(|port| port != 0)
        && routable_host(host).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real pinned key. Inventory validation proves the point is on the curve, so a fabricated
    /// `04`-prefixed string is exactly the operator mistake it exists to catch and cannot stand in
    /// for one here. Generated once: the same node key legitimately appears on many members.
    fn pin() -> &'static str {
        static PIN: std::sync::LazyLock<String> =
            std::sync::LazyLock::new(|| crate::key::testing::keypair().1.to_hex());
        &PIN
    }

    #[test]
    fn accepts_only_addresses_a_backend_can_route() {
        for (address, host) in [
            ("10.0.0.1", "10.0.0.1"),
            ("fd00::5", "fd00::5"),
            ("vm-db.internal", "vm-db.internal"),
            ("vm-db.internal.", "vm-db.internal"),
        ] {
            assert_eq!(routable_host(address).as_deref(), Some(host));
        }
        for address in [
            "",
            ".",
            "host:8080",
            "[fd00::5]",
            "bad_name",
            "-host.example",
            "host-.example",
            "999.999.999.999",
        ] {
            assert_eq!(routable_host(address), None, "{address:?}");
        }
        assert!(BackendInventoryMember::active("node-a", "host.example:8080", "key").is_err());
    }

    #[test]
    fn balancer_names_and_runtime_endpoints_have_one_shared_grammar() {
        assert!(is_balancer_safe("fleet-eu_west.1"));
        assert!(!is_balancer_safe("fleet; shutdown frontend public"));
        assert!(is_tcp_endpoint("haproxy-0.agents:9999"));
        assert!(is_tcp_endpoint("[fd00::5]:9999"));
        for endpoint in ["/run/haproxy.sock", "haproxy", "haproxy:0", "host:not-port"] {
            assert!(!is_tcp_endpoint(endpoint), "{endpoint:?}");
        }
    }

    #[test]
    fn inventory_shards_round_trip_and_reject_a_mixed_projection() {
        let mut members: Vec<BackendInventoryMember> = (0..10_000)
            .map(|index| {
                BackendInventoryMember::active(
                    format!("node-{index}"),
                    format!("host-{index}"),
                    pin(),
                )
                .unwrap()
            })
            .collect();
        members.sort_by(|left, right| left.node().cmp(right.node()));
        let shards = shard_backend_inventory(&members).unwrap();
        assert_eq!(shards.len(), BACKEND_INVENTORY_SHARDS);
        assert!(shards
            .iter()
            .all(|shard| shard.version == BACKEND_INVENTORY_SCHEMA));
        assert!(shards.iter().all(|shard| {
            serde_json::to_vec(shard).unwrap().len() <= BACKEND_INVENTORY_SHARD_MAX_BYTES
        }));
        assert_eq!(assemble_backend_inventory(shards.clone()).unwrap(), members);

        let mut mixed = shards;
        mixed[3].revision = "0".repeat(64);
        assert!(assemble_backend_inventory(mixed).is_err());

        let mut obsolete = shard_backend_inventory(&members).unwrap();
        obsolete[0].version = 1;
        assert!(assemble_backend_inventory(obsolete).is_err());

        let too_many = (0..=MAX_BACKEND_INVENTORY_MEMBERS)
            .map(|index| BackendInventoryMember::cordoned(format!("node-{index}")).unwrap())
            .collect::<Vec<_>>();
        assert!(shard_backend_inventory(&too_many).is_err());
    }

    #[test]
    fn cordons_need_only_an_identity_but_active_members_need_a_route_and_pin() {
        assert!(BackendInventoryMember::cordoned("agent-0").is_ok());
        assert!(BackendInventoryMember::cordoned("../agent").is_err());
        assert!(BackendInventoryMember::active("agent-0", "10.0.0.1", pin()).is_ok());
        assert!(BackendInventoryMember::active("agent-0", "not a route", pin()).is_err());
        assert!(BackendInventoryMember::active("agent-0", "10.0.0.1", "not-a-key").is_err());

        let rooted = BackendInventoryMember::active("agent-0", "rooted.internal.", pin()).unwrap();
        assert!(matches!(
            rooted,
            BackendInventoryMember::Active { ref address, .. } if address == "rooted.internal"
        ));
        assert!(BackendInventoryMember::Active {
            node: "agent-0".into(),
            address: "rooted.internal.".into(),
            public_key: crate::key::P256PublicKey::parse_hex(pin()).unwrap(),
        }
        .validate()
        .is_err());
    }
}
