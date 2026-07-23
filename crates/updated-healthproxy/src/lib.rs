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
//! node marks it ready. A missing, stale, or malformed report reads as not-ready, so the safe
//! default is to pull the backend out of rotation. The one refinement is a transient *fetch*
//! error (the CDN itself blinking): rather than instantly draining every node — a checker-side
//! outage is not evidence a node is down — the last successfully fetched report is reused, still
//! bound by [`REPORT_FRESHNESS`]. So a brief CDN outage does not mass-evict a healthy fleet, yet
//! data older than the freshness window is still not-ready.

pub mod endpointslice;
pub mod haproxy;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use updated::telemetry::{now_ms, report_url, NodeReport};

/// A healthy report older than this is treated as not-ready — the one freshness bound, defined once
/// in [`updated::telemetry`] and shared with the control plane so a reader and the throttle can
/// never disagree on when a report has gone stale.
pub use updated::telemetry::REPORT_FRESHNESS;

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

/// Fetch one node's raw health document from the CDN. `Some(body)` only on a 2xx with a readable
/// body; any transport error, non-success status, or unreadable body is `None` — "could not
/// determine right now", which the caller resolves against the node's last known report rather
/// than by instantly draining it. (Whether that body actually marks the node ready is a separate
/// judgment, [`report_is_ready`], so a genuine not-ready report still drains the node.)
pub async fn fetch_report(
    client: &reqwest::Client,
    health_base: &str,
    node: &str,
) -> Option<Vec<u8>> {
    let url = report_url(health_base, node);
    let response = client.get(&url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.bytes().await.ok().map(|body| body.to_vec())
}

/// The number of nodes polled concurrently per cycle. Bounded so a large fleet neither serializes
/// (one hung node stalling the rest, risking a reconcile longer than [`REPORT_FRESHNESS`]) nor
/// fans out an unbounded burst of simultaneous CDN fetches.
const POLL_CONCURRENCY: usize = 32;

/// Resolve the desired membership: every configured node, with its readiness read from its
/// current health report. Nodes are polled with bounded concurrency — one slow or hung node's
/// per-fetch timeout must not serialize onto the others.
///
/// A node whose report cannot be *fetched* this cycle (a transient CDN/transport error) falls back
/// to its last successfully fetched report, still bound by [`REPORT_FRESHNESS`]. This is what keeps
/// a brief CDN outage from draining the whole healthy fleet at once: the checker's own dependency
/// blinking is not evidence a node is down. It remains fail-closed — a report that is genuinely
/// not-ready still drains the node, and a cached report older than the freshness window is
/// not-ready — so the only behavior this changes is refusing to mass-evict on a checker blip.
///
/// `cache` carries the last good body per node across cycles (bounded by the fixed inventory) and is
/// updated on every successful fetch. Order is preserved so the programmed set is stable.
pub async fn resolve_members(
    client: &reqwest::Client,
    health_base: &str,
    inventory: &[(String, String)],
    cache: &mut std::collections::HashMap<String, Vec<u8>>,
) -> Vec<Member> {
    use futures::stream::StreamExt;
    // Concurrent, cache-free fetch pass: gather this cycle's fresh bodies in parallel (the shared
    // cache is not touched here), each tagged with its inventory index to restore order afterward.
    let fetched: Vec<(usize, Option<Vec<u8>>)> = futures::stream::iter(
        inventory
            .iter()
            .enumerate()
            .map(|(index, (node, _))| async move {
                (index, fetch_report(client, health_base, node).await)
            }),
    )
    .buffer_unordered(POLL_CONCURRENCY)
    .collect()
    .await;
    let mut fresh: Vec<Option<Vec<u8>>> = vec![None; inventory.len()];
    for (index, body) in fetched {
        fresh[index] = body;
    }
    // Sequential resolve pass: a fresh fetch updates the cache; a failed one falls back to the
    // cached body; readiness is always judged through the freshness bound in `report_is_ready`.
    inventory
        .iter()
        .zip(fresh)
        .map(|((node, address), fresh_body)| Member {
            node: node.clone(),
            address: address.clone(),
            ready: resolve_readiness(node, fresh_body, cache),
        })
        .collect()
}

/// Resolve one node's readiness from this cycle's fetch outcome and the cross-cycle cache. A fresh
/// body (`Some`) becomes the node's last known report and is judged now; a failed fetch (`None`)
/// falls back to the last known report. Either way readiness passes through the freshness bound in
/// [`report_is_ready`], so a cached report keeps a node ready only until it ages out. The one place
/// the fail-closed / fail-operational readiness rule lives, so it can be fuzzed without any I/O.
pub fn resolve_readiness(
    node: &str,
    fresh: Option<Vec<u8>>,
    cache: &mut std::collections::HashMap<String, Vec<u8>>,
) -> bool {
    let effective = match fresh {
        Some(body) => {
            cache.insert(node.to_string(), body.clone());
            Some(body)
        }
        None => cache.get(node).cloned(),
    };
    effective
        .as_deref()
        .map(|body| report_is_ready(node, body))
        .unwrap_or(false)
}

/// A single reconcile of the load balancer is bounded by this. The health fetches already carry
/// their own per-request timeout, but the load-balancer backend (e.g. a Kubernetes apiserver
/// patch) does not — an unbounded stall there would freeze the whole reconcile loop, silently
/// stranding the last programmed membership. Bounding it means a hung backend costs one logged,
/// retried cycle instead of a wedged proxy.
const RECONCILE_TIMEOUT: Duration = Duration::from_secs(10);

/// A node's readiness edge between reconcile cycles — the only thing this component logs, because it
/// is the one observer of an out-of-cluster node leaving or rejoining the pool (the control plane
/// can never reach it). A steady state (no change, or a first sighting already ready) is no edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Transition {
    /// First sighting of a node that is not ready — it starts outside the backend set.
    FirstOutOfPool,
    /// Not-ready → ready: the node rejoined the backend set.
    Joined,
    /// Ready → not-ready: the node was drained from the backend set.
    Left,
}

/// Classify the readiness edge for a node from its previous observation (`None` = never seen) and
/// its readiness this cycle. A first sighting is an event only when it starts out of the pool; a
/// first-seen *ready* node is the unremarkable steady state and yields nothing, as does any
/// same-state re-observation. Pure, so every edge can be fuzzed exhaustively.
pub fn classify_transition(previous: Option<bool>, ready: bool) -> Option<Transition> {
    match (previous, ready) {
        (None, false) => Some(Transition::FirstOutOfPool),
        (Some(was), now) if was != now => Some(if now {
            Transition::Joined
        } else {
            Transition::Left
        }),
        _ => None,
    }
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
    // Last good health body per node, so a transient CDN outage falls back to the last known report
    // (still freshness-bounded) instead of draining every healthy node at once.
    let mut cache: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
    loop {
        let members =
            resolve_members(&client, &config.health_base, &config.inventory, &mut cache).await;
        for member in &members {
            let prior = previous.insert(member.node.clone(), member.ready);
            match classify_transition(prior, member.ready) {
                Some(Transition::FirstOutOfPool) => eprintln!(
                    "healthproxy: {} starts out of {} (no ready health report yet)",
                    member.node, config.service
                ),
                Some(Transition::Joined) => eprintln!(
                    "healthproxy: {} rejoined {} (health report ready)",
                    member.node, config.service
                ),
                Some(Transition::Left) => eprintln!(
                    "healthproxy: {} left {} (health report not-ready) — draining it from the endpoint set",
                    member.node, config.service
                ),
                None => {}
            }
        }
        match tokio::time::timeout(RECONCILE_TIMEOUT, load_balancer.reconcile(&members)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                eprintln!(
                    "healthproxy: reconciling {} failed: {error}",
                    config.service
                )
            }
            // A backend that never returns (e.g. a hung apiserver) must not freeze the loop and
            // strand the last programmed set — bound it, log, and retry next cycle.
            Err(_) => eprintln!(
                "healthproxy: reconciling {} timed out after {}s; retrying next cycle",
                config.service,
                RECONCILE_TIMEOUT.as_secs()
            ),
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
    /// When set, program a cluster of HAProxy instances via the Runtime API instead of a
    /// Kubernetes EndpointSlice. The same health→membership core drives either backend; this only
    /// selects which one. `None` ⇒ the EndpointSlice backend (the `service`/`port` fields above).
    pub haproxy: Option<HAProxyTarget>,
}

/// A cluster of HAProxy instances to program from health (see [`haproxy::HAProxyLb`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HAProxyTarget {
    /// One admin stats socket (`host:port`) per HAProxy instance.
    pub endpoints: Vec<String>,
    /// The HAProxy `backend` section whose servers are the fleet.
    pub backend: String,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Self::build(|key| std::env::var(key).ok())
    }

    /// Environment-independent core of [`from_env`](Self::from_env), so parsing is testable
    /// without mutating process-global state.
    pub fn build(get: impl Fn(&str) -> Option<String>) -> Result<Self, String> {
        let health_base = require(&get, "HEALTHPROXY_HEALTH_BASE")?;
        let namespace = get("HEALTHPROXY_NAMESPACE").unwrap_or_else(|| "default".into());
        let port_name = get("HEALTHPROXY_PORT_NAME").unwrap_or_else(|| "http".into());
        let port = parse_port(&get, "HEALTHPROXY_PORT", 8080)?;
        let inventory = parse_inventory(&require(&get, "HEALTHPROXY_MEMBERS")?)?;
        let interval = Duration::from_secs(parse_secs(&get, "HEALTHPROXY_INTERVAL_SECS", 2)?);
        let health_timeout =
            Duration::from_secs(parse_secs(&get, "HEALTHPROXY_HEALTH_TIMEOUT_SECS", 2)?);
        // Selecting the HAProxy backend: a non-empty endpoint list switches from EndpointSlices to
        // programming that cluster of HAProxy admin sockets. Absent ⇒ the EndpointSlice backend.
        let haproxy = match get("HEALTHPROXY_HAPROXY_ENDPOINTS") {
            Some(raw) if !raw.trim().is_empty() => {
                let endpoints: Vec<String> = raw
                    .split(',')
                    .map(str::trim)
                    .filter(|endpoint| !endpoint.is_empty())
                    .map(str::to_owned)
                    .collect();
                if endpoints.is_empty() {
                    return Err("HEALTHPROXY_HAPROXY_ENDPOINTS listed no endpoints".into());
                }
                Some(HAProxyTarget {
                    endpoints,
                    backend: get("HEALTHPROXY_HAPROXY_BACKEND").unwrap_or_else(|| "fleet".into()),
                })
            }
            _ => None,
        };
        // The target Kubernetes Service is required only for the EndpointSlice backend; the HAProxy
        // backend programs admin sockets and never touches a Service, so it does not need one.
        let service = if haproxy.is_some() {
            get("HEALTHPROXY_SERVICE").unwrap_or_default()
        } else {
            require(&get, "HEALTHPROXY_SERVICE")?
        };
        Ok(Self {
            health_base,
            namespace,
            service,
            port_name,
            port,
            inventory,
            interval,
            health_timeout,
            haproxy,
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
    for entry in raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let (node, address) = entry
            .split_once('=')
            .ok_or_else(|| format!("HEALTHPROXY_MEMBERS entry {entry:?} must be node=address"))?;
        let (node, address) = (node.trim(), address.trim());
        if node.is_empty() || address.is_empty() {
            return Err(format!(
                "HEALTHPROXY_MEMBERS entry {entry:?} has an empty half"
            ));
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
            address
                .rsplit_once(':')
                .map(|(h, _)| h)
                .unwrap_or(address)
                .to_string()
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

    /// The distinct outcomes a single health fetch can produce for a node in one cycle. Every one
    /// must resolve to a defined readiness, and the fuzz asserts each is actually exercised.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    enum Outcome {
        HealthyFresh,
        Unhealthy,
        WrongNode,
        Malformed,
        Stale,
        Missing,
    }
    const OUTCOMES: [Outcome; 6] = [
        Outcome::HealthyFresh,
        Outcome::Unhealthy,
        Outcome::WrongNode,
        Outcome::Malformed,
        Outcome::Stale,
        Outcome::Missing,
    ];

    /// The fetched body an outcome produces for `node` (`None` = the fetch failed this cycle).
    fn body_for(outcome: Outcome, node: &str) -> Option<Vec<u8>> {
        match outcome {
            Outcome::HealthyFresh => Some(report(node, true)),
            Outcome::Unhealthy => Some(report(node, false)),
            // A healthy report, but for a *different* node — must never mark this one ready.
            Outcome::WrongNode => Some(report("someone-else", true)),
            Outcome::Malformed => Some(b"{ not valid json".to_vec()),
            Outcome::Stale => {
                let mut old = NodeReport::new(node, "deploy-3", "3.0.0", true);
                old.reported_at_ms =
                    now_ms().saturating_sub(REPORT_FRESHNESS.as_millis() as u64 + 10_000);
                Some(serde_json::to_vec(&old).unwrap())
            }
            Outcome::Missing => None,
        }
    }

    /// The readiness the model expects, given this cycle's outcome and the outcome whose body is
    /// currently cached. A fresh fetch is judged directly (ready only when it is a healthy, fresh,
    /// right-node report); a failed fetch falls back to the cached body — which keeps the node ready
    /// *only* if what is cached is a fresh healthy report. This is the whole fail-closed /
    /// fail-operational contract, stated independently of the implementation under test.
    fn expected_ready(outcome: Outcome, cached: Option<Outcome>) -> bool {
        match outcome {
            Outcome::HealthyFresh => true,
            Outcome::Missing => cached == Some(Outcome::HealthyFresh),
            _ => false,
        }
    }

    struct Lcg(u64);
    impl Lcg {
        fn next(&mut self) -> u64 {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            self.0
        }
        fn pick(&mut self, n: usize) -> usize {
            (self.next() >> 33) as usize % n
        }
    }

    /// Deterministic seeded fuzz over the healthproxy's readiness resolution and transition
    /// classification. Across many seeds it drives every node through a random walk of fetch
    /// outcomes (healthy, unhealthy, wrong-node, malformed, stale, and CDN-failure), and at every
    /// step asserts (a) `resolve_readiness` matches an independent model of the fail-closed /
    /// fail-operational contract, and (b) `classify_transition` reports exactly the edge implied by
    /// the previous and current readiness. It then asserts *coverage*: every fetch outcome and every
    /// readiness transition — FirstOutOfPool, Joined, Left, and the no-edge steady state — was
    /// actually hit, so "all transitions" is proven, not hoped.
    #[test]
    fn all_readiness_transitions_and_fetch_outcomes_are_fuzzed() {
        use std::collections::HashSet;

        const NODES: usize = 6;
        const CYCLES: usize = 256;
        let node_names: Vec<String> = (0..NODES).map(|i| format!("agent-{i}")).collect();

        let mut outcomes_seen: HashSet<Outcome> = HashSet::new();
        let mut transitions_seen: HashSet<Option<Transition>> = HashSet::new();

        for seed in 0..64u64 {
            let mut rng = Lcg(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1));
            // Per-node cross-cycle state: the real cache under test, the model's view of what body is
            // cached, and the previous readiness the transition classifier saw.
            let mut cache: HashMap<String, Vec<u8>> = HashMap::new();
            let mut cached_kind: HashMap<String, Outcome> = HashMap::new();
            let mut previous: HashMap<String, bool> = HashMap::new();

            for _ in 0..CYCLES {
                for node in &node_names {
                    let outcome = OUTCOMES[rng.pick(OUTCOMES.len())];
                    outcomes_seen.insert(outcome);

                    let cached = cached_kind.get(node).copied();
                    let expected = expected_ready(outcome, cached);

                    // The behavior under test must agree with the independent model.
                    let ready = resolve_readiness(node, body_for(outcome, node), &mut cache);
                    assert_eq!(
                        ready, expected,
                        "seed {seed}: outcome {outcome:?} over cached {cached:?} for {node}"
                    );

                    // A successful fetch (any Some outcome) updates what is cached; a Missing does not.
                    if outcome != Outcome::Missing {
                        cached_kind.insert(node.clone(), outcome);
                    }

                    // The edge must be exactly what the previous/current readiness implies.
                    let prior = previous.insert(node.clone(), ready);
                    let transition = classify_transition(prior, ready);
                    let expected_transition = match (prior, ready) {
                        (None, false) => Some(Transition::FirstOutOfPool),
                        (None, true) => None,
                        (Some(was), now) if was != now => Some(if now {
                            Transition::Joined
                        } else {
                            Transition::Left
                        }),
                        _ => None,
                    };
                    assert_eq!(
                        transition, expected_transition,
                        "seed {seed}: edge for {node}"
                    );
                    transitions_seen.insert(transition);
                }
            }
        }

        // Coverage: every fetch outcome and every transition (including the no-edge steady state)
        // was actually exercised — otherwise the fuzz would silently not be testing "all" of them.
        for outcome in OUTCOMES {
            assert!(
                outcomes_seen.contains(&outcome),
                "fetch outcome {outcome:?} was never fuzzed"
            );
        }
        for edge in [
            Some(Transition::FirstOutOfPool),
            Some(Transition::Joined),
            Some(Transition::Left),
            None,
        ] {
            assert!(
                transitions_seen.contains(&edge),
                "readiness transition {edge:?} was never fuzzed"
            );
        }
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
            (
                "HEALTHPROXY_MEMBERS",
                "agent-0=10.0.0.1:8080, agent-1=10.0.0.2",
            ),
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

        assert!(Config::build(env(&[
            ("HEALTHPROXY_SERVICE", "x"),
            ("HEALTHPROXY_MEMBERS", "a=1")
        ]))
        .is_err());
        assert!(Config::build(env(&[
            ("HEALTHPROXY_HEALTH_BASE", "x"),
            ("HEALTHPROXY_MEMBERS", "a=1")
        ]))
        .is_err());
        assert!(Config::build(env(&[
            ("HEALTHPROXY_HEALTH_BASE", "x"),
            ("HEALTHPROXY_SERVICE", "s")
        ]))
        .is_err());
    }

    #[test]
    fn haproxy_endpoints_select_the_haproxy_backend() {
        // No HAProxy endpoints ⇒ the EndpointSlice backend.
        let slice = Config::build(env(&[
            ("HEALTHPROXY_HEALTH_BASE", "http://gw"),
            ("HEALTHPROXY_SERVICE", "vm-db"),
            ("HEALTHPROXY_MEMBERS", "agent-0=10.0.0.1"),
        ]))
        .unwrap();
        assert_eq!(slice.haproxy, None);

        // A non-empty endpoint list ⇒ the HAProxy backend, default backend name "fleet".
        let haproxy = Config::build(env(&[
            ("HEALTHPROXY_HEALTH_BASE", "http://gw"),
            ("HEALTHPROXY_SERVICE", "fleet-haproxy"),
            ("HEALTHPROXY_MEMBERS", "agent-0=10.0.0.1, agent-1=10.0.0.2"),
            (
                "HEALTHPROXY_HAPROXY_ENDPOINTS",
                "10.0.0.9:9999, 10.0.0.10:9999",
            ),
        ]))
        .unwrap();
        assert_eq!(
            haproxy.haproxy,
            Some(HAProxyTarget {
                endpoints: vec!["10.0.0.9:9999".into(), "10.0.0.10:9999".into()],
                backend: "fleet".into(),
            })
        );
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
