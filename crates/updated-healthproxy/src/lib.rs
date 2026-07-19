//! Health-driven load-balancer membership for the fleet.
//!
//! A node's `updated` agent publishes a signed [`NodeReport`] to shared storage (the CDN);
//! the control plane can never reach the node, but anything that *can* read that storage can
//! learn which nodes are healthy. This component reads those reports for a configured set of
//! nodes and programs a load balancer's backend set so traffic reaches only the healthy,
//! settled ones — and drains a node the instant its report says it left service.
//!
//! Crucially it does **not** sit in the data path. It *programs membership*; the load
//! balancer itself forwards. The load balancer is pluggable behind [`LoadBalancer`]:
//! Kubernetes EndpointSlices today (kube-proxy does the routing, no extra hop), and DNS or
//! HAProxy tomorrow — the same health→membership core drives any of them. This replaces the
//! earlier L4 proxy and its in-cluster/out-of-cluster split with one path.
//!
//! Every judgment **fails closed**: only an authentic, settled, healthy report for the right
//! node marks it ready. A missing, stale, malformed, or error response reads as not-ready, so
//! the safe default is to pull the backend out of rotation.

pub mod endpointslice;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use updated::telemetry::{now_ms, report_object_key, NodeReport};

/// A healthy report older than this is treated as not-ready. Without a freshness bound a node
/// that dies without writing a final not-ready report would stay routable forever — the
/// fail-*open* direction that contradicts the module contract. Generous relative to the node's
/// report cadence (heartbeats every check interval, tens of seconds) so a node that is merely
/// slow to re-report is not flapped out of rotation.
pub const REPORT_FRESHNESS: Duration = Duration::from_secs(60);

/// One node the load balancer may route to: its identity, a routable address, and whether it
/// is currently in service (from health).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub node: String,
    /// Routable host or IP the load balancer sends traffic to (the VM's address, or a pod IP).
    pub address: String,
    pub ready: bool,
}

/// A load balancer whose backend membership is reconciled from health. An implementation maps
/// `members` onto its own mechanism — EndpointSlices, DNS records, HAProxy servers. Reconcile
/// is called every cycle with the *full* desired set, so it must be idempotent and converge
/// the backend to exactly `members` (adding, removing, and flipping ready as needed).
#[async_trait::async_trait]
pub trait LoadBalancer {
    async fn reconcile(&self, members: &[Member]) -> Result<(), String>;
}

/// Interpret a fetched health document. Ready only when the body is an authentic
/// [`NodeReport`] *for this node* whose node has settled healthy *and whose timestamp is within
/// [`REPORT_FRESHNESS`]*; anything else — a report for a different node, malformed JSON, an
/// empty body, or a stale report from a node that stopped heartbeating — is not-ready.
pub fn report_is_ready(node: &str, body: &[u8]) -> bool {
    serde_json::from_slice::<NodeReport>(body)
        .map(|report| {
            report.node == node
                && report.healthy
                && report.age_ms(now_ms()) <= REPORT_FRESHNESS.as_millis() as u64
        })
        .unwrap_or(false)
}

/// Fetch one node's health from the CDN and interpret it. Any transport error, non-success
/// status, or unreadable body fails closed to not-ready.
pub async fn poll_ready(client: &reqwest::Client, health_base: &str, node: &str) -> bool {
    let url = format!(
        "{}/{}",
        health_base.trim_end_matches('/'),
        report_object_key(node)
    );
    match client.get(&url).send().await {
        Ok(response) if response.status().is_success() => match response.bytes().await {
            Ok(body) => report_is_ready(node, &body),
            Err(_) => false,
        },
        _ => false,
    }
}

/// The number of nodes polled concurrently per cycle. Bounded so a large fleet neither serializes
/// (one hung node stalling the rest, risking a reconcile longer than [`REPORT_FRESHNESS`]) nor
/// fans out an unbounded burst of simultaneous CDN fetches.
const POLL_CONCURRENCY: usize = 32;

/// Resolve the desired membership: every configured node, with its readiness read from its
/// current health report. Nodes are polled with bounded concurrency — one slow or hung node's
/// per-fetch timeout must not serialize onto the others. Order is preserved so the programmed set
/// is stable across cycles.
pub async fn resolve_members(
    client: &reqwest::Client,
    health_base: &str,
    inventory: &[(String, String)],
) -> Vec<Member> {
    use futures::stream::StreamExt;
    futures::stream::iter(inventory.iter().map(|(node, address)| async move {
        Member {
            node: node.clone(),
            address: address.clone(),
            ready: poll_ready(client, health_base, node).await,
        }
    }))
    .buffered(POLL_CONCURRENCY)
    .collect()
    .await
}

/// Reconcile forever: read membership from health, push the full set to the load balancer,
/// repeat. Steady state is quiet — beyond reconcile failures, the only log lines are readiness
/// *transitions*: this component is the one thing that knows the instant an external node leaves
/// or rejoins the pool (the control plane can never reach it), so it records each edge. That
/// makes an out-of-cluster drain — the mirror of an in-cluster pod going NotReady — visible in
/// the logs instead of silent.
pub async fn run(
    client: reqwest::Client,
    config: Config,
    load_balancer: Arc<dyn LoadBalancer + Send + Sync>,
) {
    let mut previous: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
    loop {
        let members = resolve_members(&client, &config.health_base, &config.inventory).await;
        for member in &members {
            match previous.insert(member.node.clone(), member.ready) {
                // First observation of a node that is not yet ready — it starts out of the pool.
                None if !member.ready => eprintln!(
                    "healthproxy: {} starts out of {} (no ready health report yet)",
                    member.node, config.service
                ),
                // A readiness edge: the node left or rejoined the load balancer's backend set.
                Some(was) if was != member.ready => {
                    if member.ready {
                        eprintln!(
                            "healthproxy: {} rejoined {} (health report ready)",
                            member.node, config.service
                        );
                    } else {
                        eprintln!(
                            "healthproxy: {} left {} (health report not-ready) — draining it from the endpoint set",
                            member.node, config.service
                        );
                    }
                }
                _ => {}
            }
        }
        if let Err(error) = load_balancer.reconcile(&members).await {
            eprintln!("healthproxy: reconciling {} failed: {error}", config.service);
        }
        tokio::time::sleep(config.interval).await;
    }
}

/// Runtime configuration, resolved from `HEALTHPROXY_*` environment variables.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Base URL of the CDN/object store nodes write their reports to; a node's report is at
    /// `<health_base>/telemetry/<node>.json`.
    pub health_base: String,
    /// Namespace of the target Service/EndpointSlice (Kubernetes backend).
    pub namespace: String,
    /// The load balancer to program — a Service name for the EndpointSlice backend.
    pub service: String,
    /// The named port endpoints are published on.
    pub port_name: String,
    /// The port endpoints are published on.
    pub port: u16,
    /// The fleet this load balancer fronts: `(node, address)` pairs. Readiness per node comes
    /// from health; the address is where the balancer routes when the node is ready.
    pub inventory: Vec<(String, String)>,
    pub interval: Duration,
    pub health_timeout: Duration,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Self::build(|key| std::env::var(key).ok())
    }

    /// Environment-independent core of [`from_env`](Self::from_env), so parsing is testable
    /// without mutating process-global state.
    pub fn build(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let health_base = require(&get, "HEALTHPROXY_HEALTH_BASE")?;
        let service = require(&get, "HEALTHPROXY_SERVICE")?;
        let namespace = get("HEALTHPROXY_NAMESPACE").unwrap_or_else(|| "default".into());
        let port_name = get("HEALTHPROXY_PORT_NAME").unwrap_or_else(|| "http".into());
        let port = parse_port(&get, "HEALTHPROXY_PORT", 8080)?;
        let inventory = parse_inventory(&require(&get, "HEALTHPROXY_MEMBERS")?)?;
        let interval = Duration::from_secs(parse_secs(&get, "HEALTHPROXY_INTERVAL_SECS", 2)?);
        let health_timeout =
            Duration::from_secs(parse_secs(&get, "HEALTHPROXY_HEALTH_TIMEOUT_SECS", 2)?);
        Ok(Self {
            health_base,
            namespace,
            service,
            port_name,
            port,
            inventory,
            interval,
            health_timeout,
        })
    }
}

fn require(get: &impl Fn(&str) -> Option<String>, key: &str) -> Result<String, String> {
    get(key)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{key} is required"))
}

fn parse_port(
    get: &impl Fn(&str) -> Option<String>,
    key: &str,
    default: u16,
) -> Result<u16, String> {
    match get(key) {
        None => Ok(default),
        Some(raw) => raw
            .parse()
            .map_err(|_| format!("{key} must be a port number, got {raw:?}")),
    }
}

fn parse_secs(
    get: &impl Fn(&str) -> Option<String>,
    key: &str,
    default: u64,
) -> Result<u64, String> {
    match get(key) {
        None => Ok(default),
        Some(raw) => match raw.parse::<u64>() {
            Ok(0) | Err(_) => Err(format!("{key} must be a positive integer, got {raw:?}")),
            Ok(secs) => Ok(secs),
        },
    }
}

/// Parse `node=address,node=address,…` into `(node, address)` pairs. The address must parse
/// as a host — an `ip:port` or bare host — but the port is carried by the Service, so only the
/// host portion is kept.
fn parse_inventory(raw: &str) -> Result<Vec<(String, String)>, String> {
    let mut inventory = Vec::new();
    for entry in raw.split(',').map(str::trim).filter(|entry| !entry.is_empty()) {
        let (node, address) = entry
            .split_once('=')
            .ok_or_else(|| format!("HEALTHPROXY_MEMBERS entry {entry:?} must be node=address"))?;
        let (node, address) = (node.trim(), address.trim());
        if node.is_empty() || address.is_empty() {
            return Err(format!("HEALTHPROXY_MEMBERS entry {entry:?} has an empty half"));
        }
        // Keep only the host: the Service owns the port. A bare IP literal (v4 *or* v6) is kept
        // verbatim — an unbracketed IPv6 like `::1` has no port to strip and must not be split on
        // its own colons. Otherwise an `ip:port`/`[ip]:port`/`host:port` has its trailing port
        // dropped; a bare hostname is kept as-is.
        let host = if address.parse::<std::net::IpAddr>().is_ok() {
            address.to_string()
        } else if let Ok(socket) = address.parse::<SocketAddr>() {
            socket.ip().to_string()
        } else {
            address.rsplit_once(':').map(|(h, _)| h).unwrap_or(address).to_string()
        };
        inventory.push((node.to_string(), host));
    }
    if inventory.is_empty() {
        return Err("HEALTHPROXY_MEMBERS listed no members".into());
    }
    Ok(inventory)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |key: &str| map.get(key).cloned()
    }

    fn report(node: &str, healthy: bool) -> Vec<u8> {
        serde_json::to_vec(&NodeReport::new(node, "deploy-3", "3.0.0", healthy)).unwrap()
    }

    #[test]
    fn ready_only_for_a_settled_healthy_report_for_this_node() {
        assert!(report_is_ready("agent-7", &report("agent-7", true)));
        assert!(!report_is_ready("agent-7", &report("agent-7", false)));
        // A report for a different node never marks this one ready.
        assert!(!report_is_ready("agent-7", &report("agent-8", true)));
    }

    #[test]
    fn malformed_or_empty_documents_fail_closed() {
        assert!(!report_is_ready("agent-7", b""));
        assert!(!report_is_ready("agent-7", b"not json"));
        assert!(!report_is_ready("agent-7", b"{}"));
    }

    #[test]
    fn config_requires_base_service_and_members() {
        let ok = Config::build(env(&[
            ("HEALTHPROXY_HEALTH_BASE", "http://gw"),
            ("HEALTHPROXY_SERVICE", "vm-db"),
            ("HEALTHPROXY_MEMBERS", "agent-0=10.0.0.1:8080, agent-1=10.0.0.2"),
        ]))
        .unwrap();
        assert_eq!(ok.namespace, "default");
        assert_eq!(ok.port, 8080);
        assert_eq!(
            ok.inventory,
            vec![
                ("agent-0".to_string(), "10.0.0.1".to_string()),
                ("agent-1".to_string(), "10.0.0.2".to_string()),
            ]
        );

        assert!(Config::build(env(&[("HEALTHPROXY_SERVICE", "x"), ("HEALTHPROXY_MEMBERS", "a=1")])).is_err());
        assert!(Config::build(env(&[("HEALTHPROXY_HEALTH_BASE", "x"), ("HEALTHPROXY_MEMBERS", "a=1")])).is_err());
        assert!(Config::build(env(&[("HEALTHPROXY_HEALTH_BASE", "x"), ("HEALTHPROXY_SERVICE", "s")])).is_err());
    }

    #[test]
    fn inventory_rejects_malformed_entries() {
        assert!(parse_inventory("agent-0").is_err());
        assert!(parse_inventory("=10.0.0.1").is_err());
        assert!(parse_inventory("agent-0=").is_err());
        assert!(parse_inventory("").is_err());
    }

    #[test]
    fn inventory_keeps_only_the_host_across_address_forms() {
        let parsed = parse_inventory(
            "v4=10.0.0.1, v4p=10.0.0.2:8080, v6=::1, v6p=[fe80::1]:8080, h=vm-db.internal, hp=vm-db.internal:5432",
        )
        .unwrap();
        assert_eq!(
            parsed,
            vec![
                ("v4".into(), "10.0.0.1".to_string()),
                ("v4p".into(), "10.0.0.2".to_string()),
                // A bare, unbracketed IPv6 must be kept whole — not split on its own colons.
                ("v6".into(), "::1".to_string()),
                ("v6p".into(), "fe80::1".to_string()),
                ("h".into(), "vm-db.internal".to_string()),
                ("hp".into(), "vm-db.internal".to_string()),
            ]
        );
    }
}
