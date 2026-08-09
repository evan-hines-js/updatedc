//! Health-driven load-balancer membership for the fleet.
//!
//! A node's `updated` agent publishes a signed [`updated_contracts::telemetry::NodeReport`] to shared storage (the CDN);
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
//! default is to pull the backend out of rotation. The one refinement is a failure of this
//! component's *own* dependencies — the CDN blinking, or the resolver failing to answer for a
//! member's hostname. A checker-side outage is not evidence a node is down, so every such
//! observation resolves through [`LastKnownGood`]: the last value actually observed is reused,
//! bounded by [`updated_contracts::telemetry::REPORT_FRESHNESS`]. So neither a brief CDN outage
//! nor a DNS hiccup mass-evicts a healthy fleet, yet anything older than that window is still
//! not-ready.

pub mod endpointslice;
pub mod haproxy;
pub mod metrics;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use updated_contracts::telemetry::{
    is_uncompressed_p256_point, now_ms, report_is_authentic_and_fresh, report_url, Envelope,
    REPORT_FRESHNESS,
};

/// One node the load balancer may route to: its identity, a routable address, and whether it
/// is currently in service (from health).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub node: String,
    /// Routable host or IP the load balancer sends traffic to (the VM's address, or a pod IP).
    pub address: String,
    pub ready: bool,
}

/// One node in the fleet this proxy fronts: its identity, the address the load balancer routes to,
/// and the public key its health reports are pinned against. The key is the raw EC point from the
/// node's enrollment identity (the same key the control-plane throttle pins) and must reach this
/// proxy over a trusted channel — the operator's config — never the CDN it reads reports from, or
/// an attacker able to write the report could supply the key that verifies it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FleetNode {
    pub node: String,
    pub address: String,
    pub public_key: PinnedKey,
}

/// A pinned report-verification key whose shape has already been checked.
///
/// Only [`PinnedKey::parse`] constructs one, so a key of the wrong length or encoding cannot
/// reach the verifier: there it would fail every signature check and drain a perfectly healthy
/// node forever, logged identically to a genuinely unhealthy one. Pasting a certificate digest or
/// a PEM-derived blob into the inventory is therefore a startup error, which is what the operator
/// can act on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedKey(Vec<u8>);

impl PinnedKey {
    /// Parse a hex-encoded uncompressed EC point, rejecting anything the report verifier could
    /// not use.
    pub fn parse(hex_point: &str) -> Result<Self, String> {
        let point = hex::decode(hex_point).map_err(|_| "is not hex".to_string())?;
        if !is_uncompressed_p256_point(&point) {
            return Err(format!(
                "is not an uncompressed P-256 point (65 bytes starting 0x04), got {} byte(s)",
                point.len()
            ));
        }
        Ok(Self(point))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A load balancer whose backend membership is reconciled from health. An implementation maps
/// `members` onto its own mechanism — EndpointSlices, DNS records, HAProxy servers. Reconcile
/// is called every cycle with the *full* desired set, so it must be idempotent and converge
/// the backend to exactly `members` (adding, removing, and flipping ready as needed).
#[async_trait::async_trait]
pub trait LoadBalancer {
    async fn reconcile(&self, members: &[Member]) -> Result<(), String>;
}

/// Interpret a fetched health document. Ready only when the body is an *authentic* [`updated_contracts::telemetry::NodeReport`]
/// *for this node* — its signature verifies against the node's pinned `public_key` — whose node has
/// settled healthy *and whose timestamp is within
/// [`updated_contracts::telemetry::REPORT_FRESHNESS`]*. Anything else — a report
/// for a different node, an unsigned or forged report (a compromised gateway or a direct bucket
/// write cannot forge one without the node's key), malformed JSON, an empty body, or a stale report
/// from a node that stopped heartbeating — is not-ready. The pin's shape is guaranteed by
/// [`PinnedKey`], so an unverifiable report here always means the *report* is wrong, never that
/// the configuration is.
pub fn report_is_ready(node: &str, public_key: &PinnedKey, body: &[u8]) -> bool {
    // The gate hands back the report only when the envelope is authentic and usable, so `healthy` here
    // is necessarily read from bytes this node signed — there is no path that reads a report first and
    // remembers to check it second.
    serde_json::from_slice::<Envelope>(body)
        .ok()
        .and_then(|envelope| {
            report_is_authentic_and_fresh(&envelope, node, public_key.as_bytes(), now_ms())
        })
        .is_some_and(|report| report.healthy)
}

/// Upper bound on one fetched health document: the shared
/// [`updated_contracts::telemetry::MAX_REPORT_ENVELOPE_BYTES`], the same number the writer's
/// manifest allowance is derived from, so no report a node may legitimately sign is unreadable
/// here. The reports live in storage this component reads but does not control, so — exactly as on
/// the agent side — a declared length is only a claim and the running total is what actually caps
/// the read. Enforced through the one shared bounded-read helper so this path cannot drift from
/// the agent's.
const REPORT_BYTES_LIMIT: usize = updated_contracts::telemetry::MAX_REPORT_ENVELOPE_BYTES;

/// Fetch one node's raw health document from the CDN. `Some(body)` only on a 2xx with a readable,
/// bounded body; any transport error, non-success status, unreadable body, or a body exceeding
/// [`REPORT_BYTES_LIMIT`] is `None` — "could not determine right now", which the caller resolves
/// against the node's last known report rather than by instantly draining it. (Whether that body
/// actually marks the node ready is a separate judgment, [`report_is_ready`], so a genuine
/// not-ready report still drains the node.)
pub async fn fetch_report(
    client: &reqwest::Client,
    health_base: &str,
    node: &str,
) -> Option<Vec<u8>> {
    let url = report_url(health_base, node);
    let response = client.get(&url).send().await.ok()?;
    updated::http::read_bounded(response, "node health report", REPORT_BYTES_LIMIT)
        .await
        .ok()
}

/// Fetch the control plane's endpoint projection — the cordoned set — from the same base the
/// reports come from, resolving through [`LastKnownGood`] exactly as a report fetch does: a blip
/// of the checker's own dependency must not flap a deliberate cordon.
///
/// Fails OPEN in every terminal direction (see `updated_contracts::endpoints`): a store that has
/// no projection (404), a document that cannot be read or decoded, and a cache that aged out all
/// end at "nobody is cordoned" — health alone then governs, which is the safe steady state.
/// Terminal is the operative word: a document that cannot be USED is a failed observation like any
/// other, so the cordons are bridged from the last usable projection first and released only when
/// that ages out.
///
/// Returns the cordoned set and whether a USABLE projection was actually OBSERVED this cycle.
/// Failing open is deliberate; failing open SILENTLY is not — the caller stamps the observation
/// into the metrics exposition and logs the edges, so "every cordon was released because the
/// projection stopped being readable" is an alertable fact rather than something an operator infers
/// from a node quietly taking production traffic again.
pub async fn fetch_drained(
    client: &reqwest::Client,
    health_base: &str,
    health_timeout: Duration,
    cache: &mut LastKnownGood<std::collections::BTreeSet<String>>,
) -> (std::collections::BTreeSet<String>, bool) {
    let url = updated_contracts::endpoints::endpoints_url(health_base);
    let fetch = async {
        let response = client.get(&url).send().await.ok()?;
        // A 404 — no projection ever published — is simply a failed observation here, resolved
        // through the cache like any other: special-casing it as a definitive empty document
        // CACHED that emptiness, so one transient 404 both un-cordoned the fleet for the cycle
        // and destroyed the last-known-good the cordon was supposed to be bridged with. A store
        // that genuinely has no projection resolves to an empty cache, which reads as "nobody is
        // cordoned" below — the same fail-open answer, without the poisoning.
        updated::http::read_bounded(
            response,
            "endpoint projection",
            updated_contracts::endpoints::MAX_PROJECTION_BYTES,
        )
        .await
        .ok()
    };
    // A body that arrived is not an observation: it must also DECODE into a projection this build
    // knows. Deciding "observed" on readability alone made a corrupt or newer-schema document —
    // a truncated object, a 200 error page from a CDN, or a control plane one release ahead of
    // this replica — release every cordon, cache the garbage over the last known good so the
    // release outlived the bad cycle, and stamp the freshness gauge as current, with no edge
    // logged. Decoding first turns exactly that case back into a failed observation: the cordons
    // are bridged from the last usable projection, age out on the normal clock, and say so.
    let usable = tokio::time::timeout(health_timeout, fetch)
        .await
        .ok()
        .flatten()
        .as_deref()
        .and_then(updated_contracts::endpoints::EndpointProjection::parse);
    let observed = usable.is_some();
    let cordoned = cache
        .resolve("endpoints", usable, Instant::now())
        .unwrap_or_default();
    (cordoned, observed)
}

/// Whether a drained node's drain is explained by report STALENESS: nothing usable was observed
/// at all, or the last observed report's own timestamp is outside the freshness window. Metric
/// classification only — the drain itself was already decided by the one trust gate — so the
/// timestamp is read off the unverified document, which cannot make anything more trusted than
/// the gate already decided.
pub fn drain_is_stale(now_ms: u64, body: Option<&[u8]>) -> bool {
    let Some(body) = body else {
        return true;
    };
    serde_json::from_slice::<Envelope>(body)
        .ok()
        .and_then(|envelope| updated_contracts::telemetry::unverified_report(&envelope))
        .is_some_and(|report| !report.is_fresh(now_ms))
}

/// The floor on the width of every per-cycle fan-out: the node report poll here, and the
/// load-balancer backend's own fan-out across its instances. A fan-out at least this wide is what
/// keeps a cycle from serializing — one hung peer stalling the rest, risking a cycle longer than
/// [`updated_contracts::telemetry::REPORT_FRESHNESS`] — while staying a modest number of
/// simultaneous connections on the small fleets where nothing forces it wider.
///
/// It is a floor, not a cap: [`fanout_width`] raises a fan-out above it when the work needs it,
/// bounded by that fan-out's share of the blocking pool. The load-balancer fan-outs, which resolve
/// no names and have no pass deadline, use it as-is against [`RECONCILE_TIMEOUT`]. One constant
/// rather than one per fan-out so the starting width the whole component reasons about has a single
/// value — two copies that agree today would silently stop agreeing.
pub(crate) const FANOUT_CONCURRENCY: usize = 32;

/// How many blocking threads this component's runtime is built with, and therefore how many
/// `getaddrinfo` calls can be in flight at once.
///
/// `tokio::net::lookup_host` is not async: every lookup occupies one thread of the blocking pool for
/// its whole duration, so the pool size is a hard ceiling on the DNS fan-out's *real* width — a
/// wider fan-out simply queues, and queued waves are waves. Pinned here rather than left to tokio's
/// default, because both name-resolving fan-outs' widths are derived from it (see
/// [`NAME_LOOKUP_CONCURRENCY`] and [`REPORT_POLL_CONCURRENCY`]), and a derivation resting on a
/// default is one that silently stops holding when the default moves. The binary builds its runtime
/// with exactly this value.
pub const BLOCKING_POOL_THREADS: usize = 512;

/// The half of [`BLOCKING_POOL_THREADS`] the EndpointSlice backend's hostname lookups may occupy
/// (`endpointslice::NameResolver`).
///
/// `tokio::net::lookup_host` holds one blocking thread for the whole `getaddrinfo`, and abandoning
/// the future does *not* free that thread, so this is not merely a per-pass width: it is a
/// reservation held by a semaphore whose permits are released only when the blocking call really
/// returns, across cycles. Without that, a blackholed resolver (20-40s per call) against a 2s
/// reconcile interval fills the pool with lookups whose answers were already discarded.
pub(crate) const NAME_LOOKUP_CONCURRENCY: usize = BLOCKING_POOL_THREADS / 2;

/// The other half of [`BLOCKING_POOL_THREADS`]: the widest the report poll ([`poll_plan`]) may run.
///
/// The poll's requests look like pure network I/O, but each one needs `health_base` resolved
/// through hyper's `GaiResolver` — the same blocking pool the hostname lookups use. A poll width
/// past this share is width on paper only: the surplus requests queue behind the pool and run as a
/// further wave, and it eats the reservation the lookup pass was sized against.
pub(crate) const REPORT_POLL_CONCURRENCY: usize = BLOCKING_POOL_THREADS - NAME_LOOKUP_CONCURRENCY;

// Both halves must leave room for the floor, or `fanout_width`'s clamp has an empty range.
const _: () = assert!(
    FANOUT_CONCURRENCY <= NAME_LOOKUP_CONCURRENCY && FANOUT_CONCURRENCY <= REPORT_POLL_CONCURRENCY
);

/// How wide one fan-out runs: one task in flight per unit of `wanted` work, floored at
/// [`FANOUT_CONCURRENCY`] so a small fleet never serializes, and capped at `cap` — that fan-out's
/// share of [`BLOCKING_POOL_THREADS`].
///
/// One derivation for every fan-out that resolves names, because the cap is the whole point and a
/// second copy is a copy that loses it: a width past the pool is not width, it is a queue, so an
/// uncapped derivation "fits" its deadline only on paper while the pass really runs several waves
/// past it — and it silently spends the share the *other* fan-out was proven to fit inside.
pub(crate) fn fanout_width(wanted: usize, cap: usize) -> usize {
    wanted.clamp(FANOUT_CONCURRENCY, cap)
}

/// The share of [`updated_contracts::telemetry::REPORT_FRESHNESS`] one report-poll pass may spend,
/// as a divisor: a quarter, leaving the rest of the window for the node's own report cadence, the
/// reconcile that follows the pass, and the sleep between cycles.
const POLL_SHARE: u32 = 4;

/// How one report-poll pass is spread across the fleet: what each request gets, and how wide the
/// fan-out must run for the whole pass to fit its share of the freshness window.
struct PollPlan {
    /// The budget for one report fetch. Always exactly the operator's configured
    /// `HEALTHPROXY_HEALTH_TIMEOUT_SECS` — see [`poll_plan`] for why this is never scaled down.
    timeout: Duration,
    /// How many fetches are in flight at once, so `ceil(nodes / concurrency)` waves of `timeout`
    /// fit the pass's share. Never narrower than [`FANOUT_CONCURRENCY`], never wider than
    /// [`REPORT_POLL_CONCURRENCY`].
    concurrency: usize,
}

/// Plan one report-poll pass over `nodes` given the operator's per-request `health_timeout`.
///
/// The pass gates rotation on freshness, so it must finish well inside
/// [`updated_contracts::telemetry::REPORT_FRESHNESS`]: a body fetched in the first wave is judged
/// against a clock read after the last one, so a pass that outlives the window ages out reports
/// that were fresh when they were read and drains healthy nodes — the mass eviction
/// [`LastKnownGood`] exists to prevent, caused here by the checker's own cycle time.
///
/// What is derived from the window is the fan-out *width*, never the per-request budget. Deriving
/// the budget instead is the same failure wearing the other mask: dividing the share across the
/// waves a fixed width implies drives the per-request timeout under a real HTTPS round trip at
/// fleet scale, at which point *every* fetch in the pass times out, the whole fleet falls to its
/// last known report, and one freshness window later the entire fleet reads not-ready. So the
/// operator's timeout stands and the fleet gets the parallelism it needs: `floor(share /
/// health_timeout)` waves of that budget fit the share, and the width is whatever covers `nodes` in
/// that many waves.
///
/// The width is capped at [`REPORT_POLL_CONCURRENCY`] all the same, because width past the pool is
/// not width. Each fetch needs its host resolved through the same blocking pool the hostname
/// lookups reserve their half of, so claiming more only queues the surplus behind the pool *and*
/// starves the other fan-out. Past that size the arithmetic below stops fitting the share and the
/// pass may run long; [`run`] says so once at startup rather than letting a derivation assert a
/// fan-out the runtime cannot perform.
///
/// A `health_timeout` wider than the share itself cannot be both honored and bounded. The
/// operator's budget wins — one wave, and the pass may run past its share — because a timeout below
/// the round trip is worse than a slow cycle. [`run`] says so once at startup, since the operator's
/// own setting is the cause.
fn poll_plan(nodes: usize, health_timeout: Duration) -> PollPlan {
    let share = REPORT_FRESHNESS / POLL_SHARE;
    // `floor(share / health_timeout)`, at least one: a budget at or above the share still buys the
    // one wave above. `max(1)` on the divisor because a zero timeout must not divide by zero.
    let waves_allowed = usize::try_from(share.as_nanos() / health_timeout.as_nanos().max(1))
        .unwrap_or(usize::MAX)
        .max(1);
    PollPlan {
        timeout: health_timeout,
        concurrency: fanout_width(nodes.div_ceil(waves_allowed), REPORT_POLL_CONCURRENCY),
    }
}

/// Resolve the desired membership: every configured node, with its readiness read from its
/// current health report. Nodes are polled with bounded concurrency — one slow or hung node's
/// per-fetch timeout must not serialize onto the others.
///
/// A node whose report cannot be *fetched* this cycle (a transient CDN/transport error) falls back
/// to its last successfully fetched report, still bound by
/// [`updated_contracts::telemetry::REPORT_FRESHNESS`]. This is what keeps
/// a brief CDN outage from draining the whole healthy fleet at once: the checker's own dependency
/// blinking is not evidence a node is down. It remains fail-closed — a report that is genuinely
/// not-ready still drains the node, and a cached report older than the freshness window is
/// not-ready — so the only behavior this changes is refusing to mass-evict on a checker blip.
///
/// `health_timeout` is the operator's per-request budget; the fan-out widens with the fleet to keep
/// the pass inside its share of the freshness window (see [`poll_plan`]).
///
/// `cache` carries the last good body per node across cycles (bounded by the fixed inventory) and is
/// updated on every successful fetch. Order is preserved so the programmed set is stable.
pub async fn resolve_members(
    client: &reqwest::Client,
    health_base: &str,
    inventory: &[FleetNode],
    health_timeout: Duration,
    cache: &mut LastKnownGood<Vec<u8>>,
) -> Vec<Member> {
    use futures::stream::StreamExt;
    // Concurrent, cache-free fetch pass: gather this cycle's fresh bodies in parallel (the shared
    // cache is not touched here), each tagged with its inventory index to restore order afterward.
    // Each fetch gets the operator's full budget and the pass runs as wide as fitting inside its
    // share of the freshness window requires — a hung CDN costs one node's last-known-good fallback,
    // never a cycle so long that bodies read at its start have aged out by the time they are judged.
    let plan = poll_plan(inventory.len(), health_timeout);
    let budget = plan.timeout;
    let fetched: Vec<(usize, Option<Vec<u8>>)> = futures::stream::iter(
        inventory
            .iter()
            .enumerate()
            .map(|(index, member)| async move {
                let fetch = fetch_report(client, health_base, &member.node);
                (
                    index,
                    tokio::time::timeout(budget, fetch).await.ok().flatten(),
                )
            }),
    )
    .buffer_unordered(plan.concurrency)
    .collect()
    .await;
    let mut fresh: Vec<Option<Vec<u8>>> = vec![None; inventory.len()];
    for (index, body) in fetched {
        fresh[index] = body;
    }
    // Sequential resolve pass: a fresh fetch updates the cache; a failed one falls back to the
    // cached body; readiness is always judged through the freshness bound AND the pinned-key
    // signature check in `report_is_ready`.
    inventory
        .iter()
        .zip(fresh)
        .map(|(member, fresh_body)| Member {
            node: member.node.clone(),
            address: member.address.clone(),
            ready: resolve_readiness(&member.node, &member.public_key, fresh_body, cache),
        })
        .collect()
}

/// Resolve one node's readiness from this cycle's fetch outcome and the cross-cycle cache. A fresh
/// body (`Some`) becomes the node's last known report and is judged now; a failed fetch (`None`)
/// falls back to the last known report through [`LastKnownGood`]. Either way readiness passes
/// through the freshness bound in [`report_is_ready`], so a cached report keeps a node ready only
/// until it ages out. The one place the fail-closed / fail-operational readiness rule lives, so it
/// can be fuzzed without any I/O.
pub fn resolve_readiness(
    node: &str,
    public_key: &PinnedKey,
    fresh: Option<Vec<u8>>,
    cache: &mut LastKnownGood<Vec<u8>>,
) -> bool {
    cache
        .resolve(node, fresh, Instant::now())
        .is_some_and(|body| report_is_ready(node, public_key, &body))
}

/// The last value a checker successfully observed for each node, and how long a failure to
/// observe may keep using it.
///
/// The whole component rests on one rule: *a checker-side outage is not evidence a node is down*.
/// A failed report fetch and a failed DNS lookup are the same event — this checker could not
/// determine something right now — and both must fall back to what was last known rather than
/// evict a healthy node. This type is that rule, so the two paths cannot drift into separate
/// policies. It stays fail-closed: an entry older than [`STALENESS`](Self::STALENESS) is dropped
/// and resolves to `None`, so a checker that never recovers still ages every node out in bounded
/// time.
#[derive(Debug, Default)]
pub struct LastKnownGood<T> {
    entries: std::collections::HashMap<String, (T, Instant)>,
}

impl<T: Clone> LastKnownGood<T> {
    /// How long a value survives without being re-observed. The same window a report itself is
    /// judged fresh against, so a node goes out of rotation in one bounded time regardless of
    /// which observation failed.
    pub const STALENESS: Duration = REPORT_FRESHNESS;

    pub fn new() -> Self {
        Self {
            entries: std::collections::HashMap::new(),
        }
    }

    /// Fold this cycle's observation into the cache and return the value to act on: a fresh
    /// observation is stored and returned; a failed one falls back to the stored value while it
    /// is within [`STALENESS`](Self::STALENESS), and is otherwise forgotten.
    pub fn resolve(&mut self, key: &str, fresh: Option<T>, now: Instant) -> Option<T> {
        if let Some(value) = fresh {
            self.entries.insert(key.to_string(), (value.clone(), now));
            return Some(value);
        }
        let (value, observed) = self.entries.get(key)?;
        if now.duration_since(*observed) > Self::STALENESS {
            self.entries.remove(key);
            return None;
        }
        Some(value.clone())
    }
}

/// A single reconcile of the load balancer is bounded by this. The health fetches already carry
/// their own per-request timeout, but the load-balancer backend (e.g. a Kubernetes apiserver
/// patch) does not — an unbounded stall there would freeze the whole reconcile loop, silently
/// stranding the last programmed membership. Bounding it means a hung backend costs one logged,
/// retried cycle instead of a wedged proxy.
pub(crate) const RECONCILE_TIMEOUT: Duration = Duration::from_secs(10);

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
    let mut cache: LastKnownGood<Vec<u8>> = LastKnownGood::new();
    // The control plane's endpoint projection (cordoned nodes), through the same last-known-good
    // discipline as the reports it travels beside. It caches the DECODED set, so only a document
    // this build could actually act on can ever become the value a cordon is bridged with.
    let mut drained_cache: LastKnownGood<std::collections::BTreeSet<String>> = LastKnownGood::new();
    // Whether a usable projection was observed last cycle, and who it cordoned — the two things
    // the edge logs below need, so a lost cordon says so instead of reading as a health event.
    // It starts true so the FIRST failed observation is an edge and gets logged.
    let mut projection_usable = true;
    let mut prior_drained: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    // The scrape state, updated at the bottom of every cycle; the listener only reads it.
    let shared_metrics: metrics::Shared = Arc::default();
    if let Some(address) = config.metrics_address.clone() {
        let served = shared_metrics.clone();
        tokio::spawn(async move {
            if let Err(error) = metrics::serve(address, served).await {
                eprintln!("healthproxy: metrics listener failed: {error}");
            }
        });
    }
    // A per-request budget wider than the whole share a poll may spend cannot be both honored and
    // bounded; the operator's budget wins (see [`poll_plan`]), so name the setting that causes it.
    let share = REPORT_FRESHNESS / POLL_SHARE;
    if config.health_timeout > share {
        eprintln!(
            "healthproxy: HEALTHPROXY_HEALTH_TIMEOUT_SECS={}s is wider than the {}s one report poll may spend of the {}s freshness window — a single fetch wave can outlast that share",
            config.health_timeout.as_secs(),
            share.as_secs(),
            REPORT_FRESHNESS.as_secs()
        );
    }
    // The poll's width is capped by the blocking pool it resolves through, so past a certain fleet
    // size no width fits the pass into its share: the fleet is simply larger than one checker can
    // poll in that window. Say it once, at startup, rather than letting the arithmetic claim a
    // fan-out the runtime cannot perform — the answer is more checkers or a coarser cadence.
    let plan = poll_plan(config.inventory.len(), config.health_timeout);
    let waves = config.inventory.len().div_ceil(plan.concurrency).max(1) as u32;
    if waves > 1 && plan.timeout.saturating_mul(waves) > share {
        eprintln!(
            "healthproxy: polling {} nodes takes {waves} wave(s) of {}s at the widest fan-out this runtime can resolve ({}), past the {}s share one poll may spend of the {}s freshness window — reports may age out mid-pass",
            config.inventory.len(),
            plan.timeout.as_secs(),
            plan.concurrency,
            share.as_secs(),
            REPORT_FRESHNESS.as_secs()
        );
    }
    loop {
        // The projection fetch runs BESIDE the report poll, not before it: serialized, its
        // timeout added up to a full `health_timeout` of dead time outside the share `poll_plan`
        // sizes the pass to fit inside the freshness window.
        let ((drained, projection_observed), mut members) = tokio::join!(
            fetch_drained(
                &client,
                &config.health_base,
                config.health_timeout,
                &mut drained_cache,
            ),
            resolve_members(
                &client,
                &config.health_base,
                &config.inventory,
                config.health_timeout,
                &mut cache,
            )
        );
        // The projection fails OPEN, so its own failure is the one thing that must not be silent:
        // once the last-known-good ages out, every cordon is released and the benched machines
        // take production traffic again while `UpdateAgent.status.cordoned` still reads true. Both
        // edges are logged, and the metrics exposition carries when it was last observed so the
        // release is alertable rather than inferred.
        if projection_observed != projection_usable {
            projection_usable = projection_observed;
            if projection_observed {
                eprintln!(
                    "healthproxy: endpoint projection at {} is usable again",
                    updated_contracts::endpoints::endpoints_url(&config.health_base)
                );
            } else {
                eprintln!(
                    "healthproxy: endpoint projection at {} is unreadable or does not decode; cordons hold from the last observed projection for up to {}s and are then released",
                    updated_contracts::endpoints::endpoints_url(&config.health_base),
                    LastKnownGood::<std::collections::BTreeSet<String>>::STALENESS.as_secs()
                );
            }
        }
        if !prior_drained.is_empty() && drained.is_empty() && !projection_observed {
            eprintln!(
                "healthproxy: the endpoint projection aged out — {} cordon(s) released, health alone now governs {}",
                prior_drained.len(),
                config.target()
            );
        }
        // A cordoned node is programmed drained WHATEVER its report says — the same drained state
        // a stale report produces, so the backend handling is unchanged. Applied after health is
        // resolved so an uncordon restores the node's real readiness the same cycle.
        for member in &mut members {
            if drained.contains(&member.node) {
                member.ready = false;
            }
        }
        for member in &members {
            let prior = previous.insert(member.node.clone(), member.ready);
            let transition = classify_transition(prior, member.ready);
            match transition {
                Some(Transition::FirstOutOfPool) => eprintln!(
                    "healthproxy: {} starts out of {} (no ready health report yet)",
                    member.node, config.target()
                ),
                // A rejoin has TWO causes and they are not interchangeable: the node's health
                // report went ready, or its cordon was lifted — either by the operator or by the
                // projection ageing out, which puts a deliberately benched machine back into
                // production traffic. Claiming "health report ready" for the second named the
                // wrong cause for the one edge an operator most needs explained.
                Some(Transition::Joined) if prior_drained.contains(&member.node) => eprintln!(
                    "healthproxy: {} rejoined {} (no longer cordoned)",
                    member.node,
                    config.target()
                ),
                Some(Transition::Joined) => eprintln!(
                    "healthproxy: {} rejoined {} (health report ready)",
                    member.node, config.target()
                ),
                Some(Transition::Left) if drained.contains(&member.node) => eprintln!(
                    "healthproxy: {} left {} (cordoned by the control plane) — draining it from the endpoint set",
                    member.node, config.target()
                ),
                Some(Transition::Left) => eprintln!(
                    "healthproxy: {} left {} (health report not-ready) — draining it from the endpoint set",
                    member.node, config.target()
                ),
                None => {}
            }
            // The staleness counter: a drain whose cause is the report AGING OUT, told apart from
            // a genuine not-ready report and from a cordon, off the last observed document. A
            // FIRST sighting that is already stale counts too — a checker started against an
            // already-silent fleet is exactly the silent freshness failure this series exists to
            // make visible.
            if matches!(
                transition,
                Some(Transition::Left) | Some(Transition::FirstOutOfPool)
            ) && !drained.contains(&member.node)
            {
                let body = cache.resolve(&member.node, None, Instant::now());
                if drain_is_stale(now_ms(), body.as_deref()) {
                    shared_metrics
                        .lock()
                        .expect("metrics lock")
                        .reports_stale_total += 1;
                }
            }
        }
        prior_drained = drained;
        // Stamped on the OBSERVATION, not on the reconcile: this series answers "is the cordon
        // set this proxy is programming still coming from the control plane", and a scrape that
        // sees it fall more than `LastKnownGood::STALENESS` behind wall clock is watching every
        // cordon get released.
        if projection_observed {
            shared_metrics
                .lock()
                .expect("metrics lock")
                .endpoints_timestamp_seconds = now_ms() / 1000;
        }
        match tokio::time::timeout(RECONCILE_TIMEOUT, load_balancer.reconcile(&members)).await {
            // The scrape state describes what was PROGRAMMED, so it is stamped only when the
            // reconcile actually landed: a timestamp that advanced on failed cycles answered "is
            // it alive" yes while nothing had been programmed for minutes.
            Ok(Ok(())) => {
                let mut metrics = shared_metrics.lock().expect("metrics lock");
                metrics.backends_up = members.iter().filter(|member| member.ready).count();
                metrics.backends_drained = members.len() - metrics.backends_up;
                metrics.reconcile_timestamp_seconds = now_ms() / 1000;
            }
            Ok(Err(error)) => {
                eprintln!(
                    "healthproxy: reconciling {} failed: {error}",
                    config.target()
                )
            }
            // A backend that never returns (e.g. a hung apiserver) must not freeze the loop and
            // strand the last programmed set — bound it, log, and retry next cycle.
            Err(_) => eprintln!(
                "healthproxy: reconciling {} timed out after {}s; retrying next cycle",
                config.target(),
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
    /// The load balancer to program — a Service name for the EndpointSlice backend, and unused by
    /// the HAProxy backend, which names its target by backend instead (see [`Config::target`]).
    pub service: String,
    /// The named port endpoints are published on.
    pub port_name: String,
    /// The port endpoints are published on.
    pub port: u16,
    /// The fleet this load balancer fronts. Readiness per node comes from its signed health report,
    /// verified against the node's pinned public key; the address is where the balancer routes when
    /// the node is ready.
    pub inventory: Vec<FleetNode>,
    pub interval: Duration,
    pub health_timeout: Duration,
    /// When set, program a cluster of HAProxy instances via the Runtime API instead of a
    /// Kubernetes EndpointSlice. The same health→membership core drives either backend; this only
    /// selects which one. `None` ⇒ the EndpointSlice backend (the `service`/`port` fields above).
    pub haproxy: Option<HAProxyTarget>,
    /// When set (`HEALTHPROXY_METRICS_ADDRESS`), serve `GET /metrics` on this address — plain
    /// HTTP, cluster-internal, read-only, nothing else. Default off.
    pub metrics_address: Option<String>,
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
    /// What the operational log calls the thing being programmed: the HAProxy backend name on the
    /// HAProxy path (which has no Service and leaves `service` empty), the Service name otherwise.
    pub fn target(&self) -> &str {
        match &self.haproxy {
            Some(haproxy) => &haproxy.backend,
            None => &self.service,
        }
    }

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
                // The backend name is interpolated into the same `;`-joined admin batch as the node
                // identity (`set server {backend}/{node} state …`), so it faces the same gate, for
                // the same two reasons: `;` or whitespace in it appends a second command to a
                // `level admin` socket, and anything HAProxy answers with an error fails EVERY
                // reconcile forever — the whole fleet never programmed again behind one log line.
                let backend = get("HEALTHPROXY_HAPROXY_BACKEND").unwrap_or_else(|| "fleet".into());
                if backend.is_empty() || !is_balancer_safe(&backend) {
                    return Err(format!(
                        "HEALTHPROXY_HAPROXY_BACKEND={backend:?} is not a usable HAProxy backend \
                         name: it must be non-empty and contain no `;` and no whitespace, or it \
                         would end the command it is written into"
                    ));
                }
                Some(HAProxyTarget { endpoints, backend })
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
            // Validated here so a typo is a startup error, not a listener that silently never
            // came up behind a Ready process.
            metrics_address: get("HEALTHPROXY_METRICS_ADDRESS")
                .filter(|value| !value.is_empty())
                .map(|value| {
                    value
                        .parse::<SocketAddr>()
                        .map(|address| address.to_string())
                        .map_err(|error| format!("HEALTHPROXY_METRICS_ADDRESS={value:?}: {error}"))
                })
                .transpose()?,
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

/// A day: no interval or per-fetch budget this component honours is usefully longer, and an
/// unbounded value turns duration arithmetic elsewhere into an overflow.
const MAX_SECS: u64 = 24 * 60 * 60;

fn parse_secs(
    get: &impl Fn(&str) -> Option<String>,
    key: &str,
    default: u64,
) -> Result<u64, String> {
    match get(key) {
        None => Ok(default),
        Some(raw) => match raw.parse::<u64>() {
            Ok(secs) if (1..=MAX_SECS).contains(&secs) => Ok(secs),
            _ => Err(format!(
                "{key} must be a positive integer of at most {MAX_SECS} seconds, got {raw:?}"
            )),
        },
    }
}

/// Parse `node=address=pubkeyhex,node=address=pubkeyhex,…` into [`FleetNode`]s. The node identity
/// must satisfy [`updated_contracts::telemetry::is_valid_node`] — the same grammar the write path
/// enforces on `telemetry/<node>.json` — because a name only this side accepts is a node whose
/// report can never be stored where [`fetch_report`] looks for it: the URL 404s every cycle and the
/// node is drained forever behind the same log line as a genuinely unhealthy one. The same identity
/// is the server name this programs into the balancer, so the one property that grammar does not
/// cover — [`is_balancer_safe`] — is checked once, here, rather than at each use. The address must
/// parse as a host — see [`host_of`] — but the port is carried by the Service, so only the host
/// portion is kept, and an address of no recognizable shape is a startup error rather than a
/// guessed-at host that is silently left out of rotation forever. The pinned public key is the node's enrollment EC point in hex; it is
/// required, and required to be a usable [`PinnedKey`]: a key that is missing, or present but of a
/// shape no report could ever verify against, is a configuration error rather than a node that is
/// silently drained forever with the same log line as an unhealthy one.
fn parse_inventory(raw: &str) -> Result<Vec<FleetNode>, String> {
    let mut inventory = Vec::new();
    for entry in raw
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
    {
        let mut parts = entry.splitn(3, '=');
        let node = parts.next().unwrap_or_default().trim();
        let address = parts.next().unwrap_or_default().trim();
        let key_hex = parts.next().unwrap_or_default().trim();
        if node.is_empty() || address.is_empty() || key_hex.is_empty() {
            return Err(format!(
                "HEALTHPROXY_MEMBERS entry {entry:?} must be node=address=pubkeyhex"
            ));
        }
        if !updated_contracts::telemetry::is_valid_node(node) {
            return Err(format!(
                "HEALTHPROXY_MEMBERS entry {entry:?} has node identity {node:?}, which is not a \
                 valid node name: it must be a single path component (no `/`, `\\`, `:`, control \
                 character, `.` or `..`) and must contain none of `. % ? #`"
            ));
        }
        if !is_balancer_safe(node) {
            return Err(format!(
                "HEALTHPROXY_MEMBERS entry {entry:?} has node identity {node:?}, which is not a \
                 usable balancer server name: it must contain no `;` and no whitespace, or it would \
                 end the command it is written into"
            ));
        }
        let public_key = PinnedKey::parse(key_hex).map_err(|reason| {
            format!("HEALTHPROXY_MEMBERS entry {entry:?} has a pinned public key that {reason}")
        })?;
        let host = host_of(address).ok_or_else(|| {
            format!("HEALTHPROXY_MEMBERS entry {entry:?} has an address that is not an IP literal, an [IPv6] literal, a hostname, or any of those with a port")
        })?;
        inventory.push(FleetNode {
            node: node.to_string(),
            address: host,
            public_key,
        });
    }
    if inventory.is_empty() {
        return Err("HEALTHPROXY_MEMBERS listed no members".into());
    }
    Ok(inventory)
}

/// Whether an operator-supplied name can be written into a balancer command verbatim. Both names
/// `haproxy::state_batches` interpolates go through it — the node identity that becomes the server
/// name, and the `backend` section that qualifies it — because they share one command line and one
/// consequence.
///
/// [`updated_contracts::telemetry::is_valid_node`] is a URL/path grammar — it rejects `/ \ :`,
/// `. % ? #`, and control characters — and none of that covers the syntax of the balancer the name
/// is programmed into: the HAProxy Runtime API separates commands on a line with `;` and a
/// command's own words with whitespace. A name carrying either does not name a server, it appends a
/// second command to a `level admin` socket (`agent-0; shutdown frontend public` really does take
/// the frontend down). Whitespace alone is enough to matter without any malice: `HAPROXY_BACKEND`
/// with a copy-pasted trailing space emits `set server fleet /agent-0 state ready`, which HAProxy
/// answers with an error for every member, so every reconcile fails and nothing is ever programmed.
///
/// It is applied where the value is *parsed* — [`parse_inventory`] for the identity,
/// [`Config::build`] for the backend — because a name problem is a configuration error. Refusing it
/// where it is interpolated instead would convert one operator typo into a fleet-wide outage: the
/// backend would fail the whole reconcile, so *no* member — including every correctly named one —
/// would ever be programmed again, every cycle, behind a single log line. That is exactly the
/// "drained forever behind a log line" harm [`parse_inventory`] exists to prevent.
fn is_balancer_safe(name: &str) -> bool {
    !name.contains(|character: char| character == ';' || character.is_whitespace())
}

/// Extract the routable host from a configured member address, or `None` if the address is not a
/// shape this component can route to.
///
/// The Service owns the port, so only the host is kept: a bare IP literal (v4 or v6) is kept
/// verbatim — an unbracketed IPv6 like `::1` has no port to strip and must not be split on its own
/// colons — a bracketed IPv6 is unwrapped with or without a trailing port, and an `ip:port` or
/// `host:port` has its port dropped. A hostname may be root-anchored (`vm-db.internal.`): that
/// trailing dot is the root label, not an empty one, and is dropped along with any port.
///
/// Anything else is `None`, which [`parse_inventory`] turns into a startup error. That is the same
/// fail-closed policy as a mis-shaped pin, for the same reason: a host this function guessed at
/// resolves to nothing on every cycle, so the node is left out of rotation forever behind a log
/// line indistinguishable from a genuinely unreachable one. `[fd00::5]` — the natural bracketed
/// spelling without a port — is exactly that case: split on its last colon it yields the host
/// `[fd00:`, which is neither an IP literal nor a resolvable name.
fn host_of(address: &str) -> Option<String> {
    if let Ok(ip) = address.parse::<std::net::IpAddr>() {
        return Some(ip.to_string());
    }
    if let Ok(socket) = address.parse::<SocketAddr>() {
        return Some(socket.ip().to_string());
    }
    if let Some(rest) = address.strip_prefix('[') {
        // A bracketed literal `SocketAddr` could not parse: either there is no port, or the port
        // is unusable. Only the first is a routable address.
        let (literal, after) = rest.split_once(']')?;
        let ip: std::net::Ipv6Addr = literal.parse().ok()?;
        return after.is_empty().then(|| ip.to_string());
    }
    // A hostname, optionally with a port. A name carries no colons of its own, so the only colon
    // that may appear is the port separator — and it must actually introduce a port.
    let (host, port) = match address.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (address, None),
    };
    if port.is_some_and(|port| port.parse::<u16>().is_err()) {
        return None;
    }
    // A root-anchored FQDN (`vm-db.internal.`) is a legal spelling an operator may reasonably paste
    // out of a DNS zone, so the one trailing dot is the root label rather than an empty one: drop it
    // and validate what is left. Only that single dot is forgiven, so `host..example` and a bare `.`
    // are still refused. The dot is dropped from the kept host too — the balancers this programs
    // take a plain name, and the two spellings resolve identically.
    let host = host.strip_suffix('.').unwrap_or(host);
    let labelled = !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        });
    labelled.then(|| host.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
    use std::collections::HashMap;
    use updated_contracts::telemetry::NodeReport;

    static TEST_KEY: std::sync::LazyLock<(Vec<u8>, PinnedKey)> = std::sync::LazyLock::new(|| {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
        (
            pkcs8.as_ref().to_vec(),
            PinnedKey::parse(&hex::encode(key.public_key().as_ref())).unwrap(),
        )
    });

    /// A hex pin of the exact shape the report verifier requires. Config fixtures must use a
    /// usable pin: the parser refuses anything else, which is the whole point of [`PinnedKey`].
    fn pin(seed: u8) -> String {
        let mut point = vec![4u8; 65];
        point[64] = seed;
        hex::encode(point)
    }

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |key: &str| map.get(key).cloned()
    }

    /// A well-formed running digest. The proxy never reads it — membership follows health — but it
    /// must be present and well-formed for a report to pass the shared trust gate at all.
    const DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// A report the node signs *after* `mutate` runs, so a fixture can be authentically signed and
    /// still be one the trust gate must refuse.
    fn report_with(node: &str, healthy: bool, mutate: impl FnOnce(&mut NodeReport)) -> Vec<u8> {
        let mut report = NodeReport::new(node, "deploy-3", DIGEST, "3.0.0", DIGEST, healthy);
        mutate(&mut report);
        let envelope = updated_contracts::telemetry::sign_report(&report, &TEST_KEY.0).unwrap();
        serde_json::to_vec(&envelope).unwrap()
    }

    fn report(node: &str, healthy: bool) -> Vec<u8> {
        report_with(node, healthy, |_| {})
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
        /// Authentically signed and healthy, but carrying a running digest no reader can join on.
        MalformedDigest,
        /// Authentically signed and healthy, but labelled with a schema this build does not know.
        WrongSchema,
    }
    const OUTCOMES: [Outcome; 8] = [
        Outcome::HealthyFresh,
        Outcome::Unhealthy,
        Outcome::WrongNode,
        Outcome::Malformed,
        Outcome::Stale,
        Outcome::Missing,
        Outcome::MalformedDigest,
        Outcome::WrongSchema,
    ];

    /// The fetched body an outcome produces for `node` (`None` = the fetch failed this cycle).
    fn body_for(outcome: Outcome, node: &str) -> Option<Vec<u8>> {
        match outcome {
            Outcome::HealthyFresh => Some(report(node, true)),
            Outcome::Unhealthy => Some(report(node, false)),
            // A healthy report, but for a *different* node — must never mark this one ready.
            Outcome::WrongNode => Some(report("someone-else", true)),
            Outcome::Malformed => Some(b"{ not valid json".to_vec()),
            // Healthy and genuinely signed, but refused by the shared trust gate — a node whose
            // report this build cannot interpret must drain, not linger in rotation.
            Outcome::MalformedDigest => Some(report_with(node, true, |report| {
                report.archive_sha256 = "not-a-digest".into()
            })),
            Outcome::WrongSchema => Some(report_with(node, true, |report| {
                report.schema = NodeReport::SCHEMA + 1
            })),
            Outcome::Stale => Some(report_with(node, true, |report| {
                report.reported_at_ms = now_ms().saturating_sub(
                    updated_contracts::telemetry::REPORT_FRESHNESS.as_millis() as u64 + 10_000,
                );
            })),
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
    /// outcomes (healthy, unhealthy, wrong-node, malformed, stale, CDN-failure, and the two
    /// authentically-signed-but-ungated shapes: an unusable running digest and an unknown schema),
    /// and at every
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
            let mut cache: LastKnownGood<Vec<u8>> = LastKnownGood::new();
            let mut cached_kind: HashMap<String, Outcome> = HashMap::new();
            let mut previous: HashMap<String, bool> = HashMap::new();

            for _ in 0..CYCLES {
                for node in &node_names {
                    let outcome = OUTCOMES[rng.pick(OUTCOMES.len())];
                    outcomes_seen.insert(outcome);

                    let cached = cached_kind.get(node).copied();
                    let expected = expected_ready(outcome, cached);

                    // The behavior under test must agree with the independent model.
                    let ready =
                        resolve_readiness(node, &TEST_KEY.1, body_for(outcome, node), &mut cache);
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
        assert!(report_is_ready(
            "agent-7",
            &TEST_KEY.1,
            &report("agent-7", true)
        ));
        assert!(!report_is_ready(
            "agent-7",
            &TEST_KEY.1,
            &report("agent-7", false)
        ));
        // A report for a different node never marks this one ready.
        assert!(!report_is_ready(
            "agent-7",
            &TEST_KEY.1,
            &report("agent-8", true)
        ));
    }

    #[test]
    fn malformed_or_empty_documents_fail_closed() {
        assert!(!report_is_ready("agent-7", &TEST_KEY.1, b""));
        assert!(!report_is_ready("agent-7", &TEST_KEY.1, b"not json"));
        assert!(!report_is_ready("agent-7", &TEST_KEY.1, b"{}"));
    }

    #[test]
    fn config_requires_base_service_and_members() {
        let members = format!(
            "agent-0=10.0.0.1:8080={}, agent-1=10.0.0.2={}",
            pin(1),
            pin(2)
        );
        let ok = Config::build(env(&[
            ("HEALTHPROXY_HEALTH_BASE", "http://gw"),
            ("HEALTHPROXY_SERVICE", "vm-db"),
            ("HEALTHPROXY_MEMBERS", &members),
        ]))
        .unwrap();
        assert_eq!(ok.namespace, "default");
        assert_eq!(ok.port, 8080);
        assert_eq!(
            ok.inventory,
            vec![
                FleetNode {
                    node: "agent-0".into(),
                    address: "10.0.0.1".into(),
                    public_key: PinnedKey::parse(&pin(1)).unwrap(),
                },
                FleetNode {
                    node: "agent-1".into(),
                    address: "10.0.0.2".into(),
                    public_key: PinnedKey::parse(&pin(2)).unwrap(),
                },
            ]
        );

        assert!(Config::build(env(&[
            ("HEALTHPROXY_SERVICE", "x"),
            ("HEALTHPROXY_MEMBERS", &members)
        ]))
        .is_err());
        assert!(Config::build(env(&[
            ("HEALTHPROXY_HEALTH_BASE", "x"),
            ("HEALTHPROXY_MEMBERS", &members)
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
        let one = format!("agent-0=10.0.0.1={}", pin(1));
        let slice = Config::build(env(&[
            ("HEALTHPROXY_HEALTH_BASE", "http://gw"),
            ("HEALTHPROXY_SERVICE", "vm-db"),
            ("HEALTHPROXY_MEMBERS", &one),
        ]))
        .unwrap();
        assert_eq!(slice.haproxy, None);

        // A non-empty endpoint list ⇒ the HAProxy backend, default backend name "fleet".
        let haproxy = Config::build(env(&[
            ("HEALTHPROXY_HEALTH_BASE", "http://gw"),
            ("HEALTHPROXY_SERVICE", "fleet-haproxy"),
            ("HEALTHPROXY_MEMBERS", &one),
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

    /// The backend name shares a command line with the node identity — `set server
    /// {backend}/{node} state …`, `;`-joined onto a `level admin` socket — so it shares the
    /// identity's gate. Gating only one of the two names is gating neither: a `;` in the backend
    /// appends a second admin command to every batch (`shutdown frontend public` takes the frontend
    /// down for real), and the likelier copy-paste trailing space emits `set server fleet /agent-0
    /// …`, which HAProxy answers with an error for every member — so every reconcile fails and the
    /// whole fleet is never programmed again, behind one log line.
    ///
    /// Refused at startup, where it is an operator's configuration error, rather than at the
    /// interpolation, where it would be that fleet-wide outage.
    #[test]
    fn an_unsafe_haproxy_backend_name_is_a_startup_error() {
        let one = format!("agent-0=10.0.0.1={}", pin(1));
        let with_backend = |backend: &str| {
            Config::build(env(&[
                ("HEALTHPROXY_HEALTH_BASE", "http://gw"),
                ("HEALTHPROXY_SERVICE", "fleet-haproxy"),
                ("HEALTHPROXY_MEMBERS", &one),
                ("HEALTHPROXY_HAPROXY_ENDPOINTS", "10.0.0.9:9999"),
                ("HEALTHPROXY_HAPROXY_BACKEND", backend),
            ]))
        };
        for refused in [
            // Command injection on the admin socket.
            "fleet; shutdown frontend public",
            // A copy-pasted trailing space: not malice, still every reconcile failing forever.
            "fleet ",
            " fleet",
            "fl eet",
            "fleet\n",
            // Nothing at all is not a backend either.
            "",
        ] {
            let error = with_backend(refused).expect_err(
                "a backend name that ends the command it is written into must not start",
            );
            assert!(
                error.contains("HEALTHPROXY_HAPROXY_BACKEND"),
                "the error must name the setting at fault, got {error:?}"
            );
        }
        // The same predicate as the node identity, so one gate really is one gate.
        assert!(!is_balancer_safe("fleet; shutdown frontend public"));
        assert!(is_balancer_safe("fleet-eu-west"));
        // And an ordinary name still starts.
        assert_eq!(
            with_backend("fleet-eu-west")
                .unwrap()
                .haproxy
                .unwrap()
                .backend,
            "fleet-eu-west"
        );
    }

    /// The report poll gates rotation on freshness, so the pass that reads the reports must finish
    /// well inside the freshness window at EVERY fleet size. Past that point bodies read in the
    /// first wave age out before the pass ends and healthy nodes are drained — by the checker's own
    /// cycle time, not by anything the nodes did.
    ///
    /// The pass may only buy that with *width*. Buying it by shrinking the per-request budget is
    /// the same mass eviction by another route: below a real HTTPS round trip every fetch in the
    /// pass times out, the whole fleet falls to last-known-good, and one window later the whole
    /// fleet reads not-ready. So the operator's budget is a floor at every size.
    ///
    /// And the width it is bought with is a width the runtime can really deliver. Each fetch
    /// resolves `health_base` through the same blocking pool the hostname lookups reserve half of,
    /// so past [`REPORT_POLL_CONCURRENCY`] the surplus requests queue rather than run — an uncapped
    /// derivation would "fit" the share only on paper (100_000 nodes asked for 14_286 simultaneous
    /// requests against a 512-thread pool) while starving the other fan-out of the pool it was
    /// sized against. Beyond the size the cap can cover, the honest answer is that the pass does not
    /// fit and `run` says so at startup — not an arithmetic that claims otherwise.
    #[test]
    fn the_report_poll_fits_inside_its_share_of_the_freshness_window_at_every_fleet_size() {
        let share = REPORT_FRESHNESS / POLL_SHARE;
        for health_timeout in [
            Duration::from_secs(1),
            // The `HEALTHPROXY_HEALTH_TIMEOUT_SECS` default.
            Duration::from_secs(2),
            Duration::from_secs(10),
            share,
            // Wider than the whole share: one wave at the operator's budget, and it may overrun.
            share * 2,
        ] {
            // 225 / 1000 / 4000 are the sizes at which the derived-budget form fell to 1.87s,
            // 468ms and 117ms respectively — all under a real round trip, 225 already under the
            // 2s default.
            for nodes in [0, 1, FANOUT_CONCURRENCY, 96, 225, 1000, 4000, 100_000] {
                let plan = poll_plan(nodes, health_timeout);
                // (a) The operator's per-request budget is never shrunk to make the pass fit.
                assert_eq!(
                    plan.timeout, health_timeout,
                    "{nodes} nodes must not shrink the operator's {health_timeout:?} budget"
                );
                assert!(plan.concurrency >= FANOUT_CONCURRENCY);
                // (b) The width is one the runtime can actually run: never past this fan-out's
                // share of the blocking pool every request resolves through.
                assert!(
                    plan.concurrency <= REPORT_POLL_CONCURRENCY,
                    "{nodes} nodes ask for width {}, past the {REPORT_POLL_CONCURRENCY} requests the blocking pool can really resolve at once",
                    plan.concurrency
                );
                // (c) The waves that width implies fit the share — whenever a width within the cap
                // can make them fit at all. Exactly one wave is the other acceptable answer: it is
                // all a budget at or above the share can afford, and all a fleet larger than the
                // cap can cover in one.
                let waves = nodes.div_ceil(plan.concurrency).max(1) as u32;
                let fits_the_pool =
                    nodes.div_ceil(REPORT_POLL_CONCURRENCY) as u32 * plan.timeout <= share;
                assert!(
                    waves == 1 || !fits_the_pool || plan.timeout * waves <= share,
                    "{nodes} nodes take {waves} wave(s) of {:?} at width {}, past the {share:?} poll share a width within the pool could have fit",
                    plan.timeout,
                    plan.concurrency
                );
            }
        }
        // A fleet that fits the base width in the waves its budget allows is not fanned out wider
        // than it needs to be.
        assert_eq!(
            poll_plan(FANOUT_CONCURRENCY, Duration::from_secs(2)).concurrency,
            FANOUT_CONCURRENCY
        );
        // A fleet that does not gets exactly the parallelism that fits it into its allowed waves...
        let waves_allowed = (share.as_secs() / 2) as usize;
        assert_eq!(
            poll_plan(1000, Duration::from_secs(2)).concurrency,
            1000usize.div_ceil(waves_allowed)
        );
        // ...up to the pool's ceiling, which a fleet this size asks well past (4000 nodes wanted
        // 572, 100_000 wanted 14_286 — 28x the whole pool).
        assert_eq!(
            poll_plan(4000, Duration::from_secs(2)).concurrency,
            REPORT_POLL_CONCURRENCY
        );
        assert_eq!(
            poll_plan(100_000, Duration::from_secs(2)).concurrency,
            REPORT_POLL_CONCURRENCY
        );
        // The two name-resolving fan-outs partition the pool rather than each claiming all of it.
        const { assert!(REPORT_POLL_CONCURRENCY + NAME_LOOKUP_CONCURRENCY <= BLOCKING_POOL_THREADS) };
    }

    #[test]
    fn inventory_rejects_malformed_entries() {
        assert!(parse_inventory("agent-0").is_err());
        assert!(parse_inventory(&format!("=10.0.0.1={}", pin(1))).is_err());
        assert!(parse_inventory("agent-0=").is_err());
        assert!(parse_inventory("").is_err());
        // A member without a pinned key is rejected — a keyless node could never verify, so it is a
        // configuration error rather than a silently-never-ready node.
        assert!(parse_inventory("agent-0=10.0.0.1").is_err());
        // A non-hex pinned key is rejected.
        assert!(parse_inventory("agent-0=10.0.0.1=zz").is_err());
    }

    /// A pin of the wrong shape verifies nothing, so a node carrying one would be drained forever
    /// while logging exactly like an unhealthy node. It must fail at startup instead.
    #[test]
    fn a_pin_the_verifier_could_never_use_is_a_startup_error() {
        // A certificate digest (32 bytes) and a compressed point are the realistic paste errors.
        assert!(PinnedKey::parse(&"ab".repeat(32)).is_err());
        assert!(PinnedKey::parse(&format!("02{}", "ab".repeat(32))).is_err());
        // 65 bytes, but not an uncompressed point, and the all-zero encoding.
        assert!(PinnedKey::parse(&format!("03{}", "ab".repeat(64))).is_err());
        assert!(PinnedKey::parse(&format!("04{}", "00".repeat(64))).is_err());
        assert!(PinnedKey::parse(&pin(1)).is_ok());

        let error = parse_inventory(&format!("agent-3=10.0.0.1={}", "ab".repeat(32)))
            .expect_err("a malformed pin is refused at config time");
        assert!(error.contains("uncompressed P-256 point"), "{error}");
    }

    /// A node identity this side accepts but the write path's grammar rejects is a node whose
    /// report can never exist at `telemetry/<node>.json`: the fetch 404s every cycle and the node
    /// is drained forever behind the same line as an unhealthy one. So the inventory is gated on
    /// the very predicate the write path uses, and both sides are asserted to agree here.
    #[test]
    fn a_node_identity_the_write_path_could_never_store_is_a_startup_error() {
        for node in ["agent-0", "agent_7", "AGENT-7", "a"] {
            let parsed = parse_inventory(&format!("{node}=10.0.0.1={}", pin(1)))
                .expect("a name the write path accepts is configurable");
            assert_eq!(parsed[0].node, node);
            assert_eq!(
                updated_contracts::telemetry::node_from_path(&format!("/telemetry/{node}.json")),
                Some(node),
                "{node} must round-trip through the write path it was accepted for"
            );
        }
        for node in [
            "agent#1",
            "agent.7",
            "agent/7",
            "agent\\7",
            "agent:7",
            "agent%2f7",
            "agent?7",
            ".",
            "..",
            "agent\n7",
        ] {
            let error = parse_inventory(&format!("{node}=10.0.0.1={}", pin(1)))
                .expect_err("a name the write path rejects is refused at config time");
            // The offending name is named back to the operator, escaped — a name whose damage is a
            // stray `\n` must be legible in the log line that refuses it.
            assert!(error.contains(&format!("{node:?}")), "{error}");
            assert!(error.contains("valid node name"), "{error}");
            assert_eq!(
                updated_contracts::telemetry::node_from_path(&format!("/telemetry/{node}.json")),
                None,
                "{node} must be refused for exactly the reason claimed"
            );
        }
        // The empty identity is refused too, by the `node=address=pubkeyhex` shape check that
        // already ran — the grammar agrees, but the earlier message is the more useful one.
        assert!(parse_inventory(&format!("=10.0.0.1={}", pin(1))).is_err());
        // Length is not part of the grammar: a long-but-safe name is configurable.
        assert!(parse_inventory(&format!("{}=10.0.0.1={}", "a".repeat(512), pin(1))).is_ok());
    }

    /// The identity is also the server name programmed into the balancer, where `;` separates
    /// commands and whitespace separates a command's words — neither of which the write path's
    /// URL/path grammar forbids. `agent-0; shutdown frontend public` would be two commands on a
    /// `level admin` socket, so it must be refused *here*, at startup, where it is one operator's
    /// typo: refusing it at the point of interpolation instead fails the whole reconcile, so every
    /// correctly named node in the fleet stops being programmed too, every cycle, forever.
    #[test]
    fn a_node_identity_that_could_end_a_balancer_command_is_a_startup_error() {
        for node in [
            "agent-0; shutdown frontend public",
            "agent-0;",
            "agent-0 state maint",
            "agent\t0",
        ] {
            let error = parse_inventory(&format!("{node}=10.0.0.1={}", pin(1)))
                .expect_err("a name that would end the command it is written into is refused");
            assert!(error.contains(&format!("{node:?}")), "{error}");
            assert!(!is_balancer_safe(node));
        }
        // Everything the inventory grammar actually intends as an identity still passes, and it is
        // the same set the write path accepts — one gate, not two disagreeing ones.
        for node in ["agent-0", "vm_db-17", "AGENT-7"] {
            assert!(is_balancer_safe(node));
            assert!(parse_inventory(&format!("{node}=10.0.0.1={}", pin(1))).is_ok());
        }
    }

    /// The last-known-good rule both the report fetch and the DNS lookup resolve through: a
    /// failed observation reuses what was last seen, and only within the shared staleness bound.
    #[test]
    fn a_failed_observation_reuses_the_last_known_value_until_it_ages_out() {
        let mut known: LastKnownGood<String> = LastKnownGood::new();
        let start = Instant::now();
        // Nothing observed yet: a failure has nothing to fall back to (fail closed).
        assert_eq!(known.resolve("db", None, start), None);
        assert_eq!(
            known.resolve("db", Some("10.0.0.1".into()), start),
            Some("10.0.0.1".to_string())
        );
        // A failed observation inside the window keeps the last known value...
        assert_eq!(
            known.resolve("db", None, start + LastKnownGood::<String>::STALENESS),
            Some("10.0.0.1".to_string())
        );
        // ...and past it the value is forgotten, so a checker that never recovers still ages
        // every node out in bounded time.
        assert_eq!(
            known.resolve(
                "db",
                None,
                start + LastKnownGood::<String>::STALENESS + Duration::from_secs(1)
            ),
            None
        );
        assert_eq!(
            known.resolve("db", None, start + Duration::from_secs(1)),
            None,
            "the aged-out entry is dropped, not merely hidden"
        );
    }

    /// Every address spelling an operator may reasonably write, and what host it must yield.
    /// A bracketed IPv6 *without* a port is the one that used to be split on its last colon into
    /// `[fd00:` — accepted at startup, unresolvable forever after.
    #[test]
    fn every_address_form_yields_its_host() {
        for (address, expected) in [
            ("10.0.0.1", "10.0.0.1"),
            ("10.0.0.1:8443", "10.0.0.1"),
            ("fd00::5", "fd00::5"),
            ("[fd00::5]", "fd00::5"),
            ("[fd00::5]:8443", "fd00::5"),
            ("host.example", "host.example"),
            ("host.example:8443", "host.example"),
            // Root-anchored FQDNs: the trailing dot is the root label, not an empty one.
            ("vm-db.internal.", "vm-db.internal"),
            ("vm-db.internal.:5432", "vm-db.internal"),
        ] {
            assert_eq!(
                host_of(address).as_deref(),
                Some(expected),
                "address {address:?}"
            );
        }
    }

    /// An address of no recognizable shape must fail at startup. Guessing a host from it produces
    /// one that resolves to nothing on every cycle, draining a healthy node forever behind a log
    /// line identical to a genuinely unreachable one.
    #[test]
    fn an_unparseable_address_is_a_startup_error() {
        for address in [
            "[fd00::5",
            "fd00::5]",
            "[not-an-ip]",
            "[fd00::5]:notaport",
            "[fd00::5]junk",
            "host.example:notaport",
            // Only ONE trailing dot is the root label; a doubled dot is still an empty label.
            "host..example",
            "host.example..",
            ".",
            // Out of the port range: fail-closed, since the Service owns the port and a member
            // written with an impossible one is a configuration error, not a routable host.
            "host.example:65536",
            "10.0.0.1:99999",
            "",
        ] {
            assert_eq!(host_of(address), None, "address {address:?}");
        }
        let error = parse_inventory(&format!("agent-3=[fd00::5]junk={}", pin(1)))
            .expect_err("an address of no recognizable shape is refused at config time");
        assert!(error.contains("not an IP literal"), "{error}");
    }

    #[test]
    fn inventory_keeps_only_the_host_across_address_forms() {
        let key = pin(1);
        let parsed = parse_inventory(&format!(
            "v4=10.0.0.1={key}, v4p=10.0.0.2:8080={key}, v6=::1={key}, v6p=[fe80::1]:8080={key}, \
             v6b=[fd00::5]={key}, h=vm-db.internal={key}, hp=vm-db.internal:5432={key}"
        ))
        .unwrap();
        let hosts: Vec<(String, String)> = parsed
            .into_iter()
            .map(|member| (member.node, member.address))
            .collect();
        assert_eq!(
            hosts,
            vec![
                ("v4".into(), "10.0.0.1".to_string()),
                ("v4p".into(), "10.0.0.2".to_string()),
                // A bare, unbracketed IPv6 must be kept whole — not split on its own colons.
                ("v6".into(), "::1".to_string()),
                ("v6p".into(), "fe80::1".to_string()),
                // Bracketed without a port: the brackets are stripped, not split on.
                ("v6b".into(), "fd00::5".to_string()),
                ("h".into(), "vm-db.internal".to_string()),
                ("hp".into(), "vm-db.internal".to_string()),
            ]
        );
    }

    /// The staleness classifier behind `healthproxy_reports_stale_total`: a drain is attributed to
    /// staleness when nothing was observed at all, or when the last observed report's own
    /// timestamp is outside the freshness window. A genuinely not-ready or unusable report is a
    /// different cause and is not counted. Metric only — the drain itself was already decided by
    /// the one trust gate.
    #[test]
    fn a_drain_is_attributed_to_staleness_only_when_the_report_aged_out() {
        let now = now_ms();
        assert!(
            drain_is_stale(now, None),
            "nothing observed at all is stale"
        );
        assert!(
            !drain_is_stale(now, Some(&report("agent-7", false))),
            "a fresh not-ready report is a health drain, not a staleness drain"
        );
        assert!(
            !drain_is_stale(now, Some(b"not json")),
            "an unusable body is not attributed to staleness"
        );
        let stale = report_with("agent-7", true, |report| {
            report.reported_at_ms =
                now.saturating_sub(REPORT_FRESHNESS.as_millis() as u64 + 10_000);
        });
        assert!(drain_is_stale(now, Some(&stale)));
    }

    /// docs/node-controls-design.md — cordon: the endpoint projection resolves through the same
    /// last-known-good discipline as the reports, and fails OPEN: no projection, or one that aged
    /// out entirely, means nobody is cordoned and health alone governs.
    #[test]
    fn the_drained_projection_is_sticky_across_blips_and_fails_open() {
        use std::collections::BTreeSet;
        let mut cache: LastKnownGood<BTreeSet<String>> = LastKnownGood::new();
        let projection = BTreeSet::from(["agent-0".to_string()]);
        let now = Instant::now();

        // A fresh fetch programs the cordon.
        let drained = cache
            .resolve("endpoints", Some(projection.clone()), now)
            .unwrap_or_default();
        assert!(drained.contains("agent-0"));

        // A checker-side blip reuses the last known projection: a deliberate cordon must not flap
        // because the CDN blinked.
        let drained = cache
            .resolve("endpoints", None, now + Duration::from_secs(1))
            .unwrap_or_default();
        assert!(drained.contains("agent-0"));

        // Aged out entirely: fail open — nobody cordoned, health alone governs. This is also what
        // a store that never published a projection resolves to: every fetch (404 included) is a
        // failed observation, and an empty cache reads as an empty set — never a cached empty
        // document that would erase a real cordon on one transient 404.
        let drained = cache
            .resolve(
                "endpoints",
                None,
                now + LastKnownGood::<BTreeSet<String>>::STALENESS + Duration::from_secs(1),
            )
            .unwrap_or_default();
        assert!(drained.is_empty());
    }
}
