//! Health-driven load-balancer membership for the fleet.
//!
//! A node's `updated` agent publishes a signed [`updated_contracts::telemetry::NodeReport`],
//! which the control plane folds into one indexed generation of bounded shards in shared storage
//! (the CDN);
//! the control plane can never reach the node, but anything that *can* read that storage can
//! learn which nodes are healthy. This component fetches the stable index and its bounded shard
//! set each cycle, verifies each node's envelope against its
//! pinned key, and programs a load balancer's backend set so traffic reaches only the healthy,
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

use futures::{stream, StreamExt as _};
use updated_contracts::backend;
use updated_contracts::backend::BackendInventoryMember;
use updated_contracts::key::P256PublicKey;
use updated_contracts::telemetry::{
    authenticate_report, now_ms, Envelope, FleetReports, REPORT_FRESHNESS,
};

/// One node the load balancer may route to: its identity, a routable address, and whether it
/// is currently in service (from health).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub node: String,
    /// Routable host or IP the load balancer sends traffic to. Empty is the single explicit
    /// control-plane-cordon sentinel: stateful balancers still receive the identity to drain,
    /// while topology balancers omit the endpoint entirely.
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

/// Interpret one node's report envelope. Ready only when it is an *authentic*
/// [`updated_contracts::telemetry::NodeReport`] *for this node* — its signature verifies against
/// the node's pinned `public_key` — whose node has settled healthy *and whose timestamp is within
/// [`updated_contracts::telemetry::REPORT_FRESHNESS`]*. Anything else — a report
/// for a different node, an unsigned or forged report (a compromised control plane writing the
/// indexed fleet generation cannot forge one without the node's key), an unusable payload, or a stale report
/// from a node that stopped heartbeating — is not-ready. The pin's shape is guaranteed by
/// [`P256PublicKey`], so an unverifiable report here always means the *report* is wrong, never that
/// the configuration is.
pub fn report_is_ready(node: &str, public_key: &P256PublicKey, envelope: &Envelope) -> bool {
    // The gate hands back the report only when the envelope is authentic and usable, so `healthy` here
    // is necessarily read from bytes this node signed — there is no path that reads a report first and
    // remembers to check it second.
    authenticate_report(envelope, node, public_key)
        .and_then(|report| report.fresh(now_ms()))
        .is_some_and(|report| report.healthy)
}

/// Fetch the stable fleet index and the bounded shards that can contain configured inventory
/// members. The index supplies the exact active count and canonical placement, so readers have no
/// layout knob or hash implementation of their own and cannot disagree with the writer. Both the
/// index and each selected shard are bounded while streaming; missing, corrupt, or oversized
/// shards yield a partial observation whose absent nodes resolve through last-known-good state. An
/// unusable index yields `None` because there is no generation identity against which a shard can
/// be authenticated.
///
/// `health_timeout` is the operator's budget for ONE fetch — the index, and then each shard — not
/// for the pass. One budget spanning the whole fan-out discarded partial progress: a single slow
/// shard voided the entire cycle's observation and dropped EVERY node to last-known-good, which is
/// precisely what the partial-observation rule above promises it does not do.
///
/// `None` also when the index parsed but not one selected shard could be read. Readiness is read
/// from the SHARDS, so an empty `FleetReports` there is not an observation of a silent fleet: the
/// writer commits every shard of a generation before the index that names it
/// (`gateway::flush_fleet_reports`), so a readable index over unreadable shards is a broken read —
/// a negative-cached or swept per-generation prefix, an ACL on it, a partially published
/// generation. Reported as `Some` it drained the entire inventory one freshness window later while
/// the caller's edge log stayed quiet and its freshness gauge kept advancing: the exact fleet-wide
/// silent drain the observation flag exists to make alertable. An inventory selecting no shard at
/// all (an empty inventory) has nothing to read and stays an observation.
async fn fetch_fleet_reports(
    client: &reqwest::Client,
    health_base: &str,
    health_timeout: Duration,
    inventory: &[BackendInventoryMember],
) -> Option<FleetReports> {
    // An all-cordoned inventory has no report-dependent decision to make. Treat it as a complete
    // empty observation without touching S3: bucket availability and contents cannot weaken a
    // control-plane drain. With no active member, report availability is vacuously usable.
    if inventory.iter().all(BackendInventoryMember::is_cordoned) {
        return Some(FleetReports::default());
    }
    let url = updated_contracts::telemetry::fleet_index_url(health_base);
    let body = tokio::time::timeout(health_timeout, async {
        let response = client.get(&url).send().await.ok()?;
        updated::http::read_bounded(
            response,
            "fleet report index",
            updated_contracts::telemetry::MAX_FLEET_INDEX_BYTES,
        )
        .await
        .ok()
    })
    .await
    .ok()
    .flatten()?;
    let index = updated_contracts::telemetry::FleetIndex::parse(&body)?;
    let locations = index.shard_locations_for(
        inventory
            .iter()
            .filter(|node| !node.is_cordoned())
            .map(BackendInventoryMember::node),
    );
    let selected = locations.len();
    let mut fetches = stream::iter(locations.into_iter().map(|location| async move {
        let body = tokio::time::timeout(health_timeout, async {
            let response = client.get(location.url(health_base)).send().await.ok()?;
            updated::http::read_bounded(
                response,
                "fleet report shard",
                updated_contracts::telemetry::MAX_FLEET_REPORT_SHARD_BYTES,
            )
            .await
            .ok()
        })
        .await
        .ok()
        .flatten()?;
        FleetReports::parse_shard(&body, &location)
    }))
    .buffered(updated_contracts::telemetry::FLEET_SHARD_IO_CONCURRENCY);
    let mut reports = FleetReports::default();
    let mut read = 0usize;
    while let Some(shard) = fetches.next().await {
        if let Some(shard) = shard {
            read += 1;
            reports.overlay(shard);
        }
    }
    (read > 0 || selected == 0).then_some(reports)
}

/// Whether a drained node's drain is explained by report STALENESS: nothing usable was observed
/// at all, or the last observed report's own timestamp is outside the freshness window. Metric
/// classification only — the drain itself was already decided by the one trust gate — so the
/// timestamp is read off the unverified document, which cannot make anything more trusted than
/// the gate already decided.
pub fn drain_is_stale(now_ms: u64, envelope: Option<&Envelope>) -> bool {
    let Some(envelope) = envelope else {
        return true;
    };
    updated_contracts::telemetry::report_staleness_for_observability(envelope, now_ms)
        .is_some_and(std::convert::identity)
}

/// The floor on the width of every per-cycle fan-out — the load-balancer backends' fan-outs
/// across their instances, and the EndpointSlice backend's hostname lookups. A fan-out at least
/// this wide is what keeps a cycle from serializing — one hung peer stalling the rest, risking a
/// cycle longer than [`updated_contracts::telemetry::REPORT_FRESHNESS`] — while staying a modest
/// number of simultaneous connections on the small fleets where nothing forces it wider.
///
/// It is a floor, not a cap: [`fanout_width`] raises a fan-out above it when the work needs it,
/// bounded by its share of the blocking pool. The load-balancer fan-outs, which resolve
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
/// default, because the name-resolving fan-out's width is derived from it (see
/// [`NAME_LOOKUP_CONCURRENCY`]), and a derivation resting on a
/// default is one that silently stops holding when the default moves. The binary builds its runtime
/// with exactly this value.
pub const BLOCKING_POOL_THREADS: usize = 512;

/// The share of [`BLOCKING_POOL_THREADS`] the EndpointSlice backend's hostname lookups may occupy
/// (`endpointslice::NameResolver`): everything except one floor's worth, reserved for the bounded
/// fleet-shard HTTP fan-out, whose `health_base` resolves through
/// hyper's `GaiResolver` — the same blocking pool. The reservation keeps a lookup storm from
/// starving the reads the whole cycle exists to make.
///
/// `tokio::net::lookup_host` holds one blocking thread for the whole `getaddrinfo`, and abandoning
/// the future does *not* free that thread, so this is not merely a per-pass width: it is a
/// reservation held by a semaphore whose permits are released only when the blocking call really
/// returns, across cycles. Without that, a blackholed resolver (20-40s per call) against a 2s
/// reconcile interval fills the pool with lookups whose answers were already discarded.
pub(crate) const NAME_LOOKUP_CONCURRENCY: usize = BLOCKING_POOL_THREADS - FANOUT_CONCURRENCY;

// The reservation must leave room for the floor, or `fanout_width`'s clamp has an empty range.
const _: () = assert!(FANOUT_CONCURRENCY <= NAME_LOOKUP_CONCURRENCY);

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

/// Resolve the desired membership: every configured node, with its readiness read from its
/// entry in this cycle's bounded fleet generation.
///
/// A node whose entry cannot be *observed* this cycle — the document fetch failed (a transient
/// CDN/transport error), or the document was readable but simply has no entry for the node yet —
/// falls back to its last successfully observed envelope, still bound by
/// [`updated_contracts::telemetry::REPORT_FRESHNESS`]. This is what keeps
/// a brief CDN outage from draining the whole healthy fleet at once: the checker's own dependency
/// blinking is not evidence a node is down. It remains fail-closed — a report that is genuinely
/// not-ready still drains the node, and a cached report older than the freshness window is
/// not-ready — so the only behavior this changes is refusing to mass-evict on a checker blip.
///
/// `health_timeout` is the operator's per-fetch budget, applied by [`fetch_fleet_reports`] to the
/// index and to each shard separately (the setting the CRD and `HEALTHPROXY_HEALTH_TIMEOUT_SECS`
/// have always described). Order is preserved so the programmed set is stable, and `cache` carries
/// the last observed envelope per node across cycles (bounded by the fixed inventory).
///
/// Returns the membership and whether a USABLE fleet generation — the index AND at least one of the
/// shards it names — was actually OBSERVED this cycle. Report failure drains the entire active
/// fleet once cached reports age out. `reports_stale_total` counts those drains one node at a time
/// and cannot tell "the generation is unreadable" from "every node stopped heartbeating", so the
/// caller logs the edge and stamps the observation into metrics.
pub async fn resolve_members(
    client: &reqwest::Client,
    health_base: &str,
    inventory: &[BackendInventoryMember],
    health_timeout: Duration,
    cache: &mut LastKnownGood<Envelope>,
) -> (Vec<Member>, bool) {
    let mut fetched = fetch_fleet_reports(client, health_base, health_timeout, inventory).await;
    let observed = fetched.is_some();
    let members = inventory
        .iter()
        .map(|member| match member {
            BackendInventoryMember::Active {
                node,
                address,
                public_key,
            } => Member {
                node: node.clone(),
                address: address.clone(),
                ready: resolve_readiness(
                    node,
                    public_key,
                    fetched.as_mut().and_then(|reports| reports.remove(node)),
                    cache,
                ),
            },
            BackendInventoryMember::Cordoned { node } => Member {
                node: node.clone(),
                address: String::new(),
                ready: false,
            },
        })
        .collect();
    (members, observed)
}

/// Resolve one node's readiness from this cycle's observation and the cross-cycle cache. A fresh
/// envelope (`Some`) becomes the node's last known report and is judged now; a failed observation
/// (`None` — the indexed generation was unreadable, or carried no entry for this node) falls back to
/// the last known envelope through [`LastKnownGood`]. Either way readiness passes
/// through the freshness bound in [`report_is_ready`], so a cached report keeps a node ready only
/// until it ages out. The one place the fail-closed / fail-operational readiness rule lives, so it
/// can be fuzzed without any I/O.
pub fn resolve_readiness(
    node: &str,
    public_key: &P256PublicKey,
    fresh: Option<Envelope>,
    cache: &mut LastKnownGood<Envelope>,
) -> bool {
    cache
        .resolve(node, fresh, Instant::now())
        .is_some_and(|envelope| report_is_ready(node, public_key, &envelope))
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

    /// Drop identities that no longer belong to this backend. Without this, a bounded live fleet
    /// could still grow the process forever by cycling through distinct historical members.
    pub fn retain(&mut self, mut keep: impl FnMut(&str) -> bool) {
        self.entries.retain(|key, _| keep(key));
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
pub async fn run<S>(
    client: reqwest::Client,
    mut config: Config,
    load_balancer: Arc<dyn LoadBalancer + Send + Sync>,
    shutdown: S,
) where
    S: std::future::Future<Output = ()>,
{
    tokio::pin!(shutdown);
    let mut previous: std::collections::HashMap<String, bool> = std::collections::HashMap::new();
    // Last observed envelope per node, so a transient CDN outage falls back to the last known
    // report (still freshness-bounded) instead of draining every healthy node at once.
    let mut cache: LastKnownGood<Envelope> = LastKnownGood::new();
    // Whether the fleet report generation was usable last cycle. An unreadable
    // generation is the one failure that drains everything, and it must say so rather than arriving
    // as N per-node staleness drains. Starts true so the first failed read is an edge.
    let mut reports_usable = true;
    let mut inventory_error: Option<String> = None;
    let mut prior_drained: std::collections::BTreeSet<String> = config
        .inventory
        .iter()
        .filter(|member| member.is_cordoned())
        .map(|member| member.node().to_string())
        .collect();
    // The scrape state, updated at the bottom of every cycle; the listener only reads it.
    let shared_metrics: metrics::Shared = Arc::default();
    if let Some(address) = config.metrics_address {
        let served = shared_metrics.clone();
        tokio::spawn(async move {
            if let Err(error) = metrics::serve(address, served).await {
                eprintln!("healthproxy: metrics listener failed: {error}");
            }
        });
    }
    // A budget wider than the freshness window cannot be honored: a fetch that slow returns a
    // document whose fresh entries have already aged out by the time they are judged. The
    // operator's budget still wins — a timeout below the round trip is worse — so name the setting.
    if config.health_timeout > REPORT_FRESHNESS {
        eprintln!(
            "healthproxy: HEALTHPROXY_HEALTH_TIMEOUT_SECS={}s is wider than the {}s report freshness window — a fetch that slow returns already-stale reports",
            config.health_timeout.as_secs(),
            REPORT_FRESHNESS.as_secs()
        );
    }
    loop {
        match load_inventory(&config.inventory_dir).await {
            Ok(inventory) => {
                if inventory_error.take().is_some() {
                    eprintln!("healthproxy: projected inventory is usable again");
                }
                {
                    let present: std::collections::HashSet<&str> =
                        inventory.iter().map(BackendInventoryMember::node).collect();
                    let active: std::collections::HashSet<&str> = inventory
                        .iter()
                        .filter(|member| !member.is_cordoned())
                        .map(BackendInventoryMember::node)
                        .collect();
                    previous.retain(|node, _| present.contains(node.as_str()));
                    cache.retain(|node| active.contains(node));
                }
                config.inventory = inventory;
            }
            Err(error) if inventory_error.as_deref() != Some(&error) => {
                eprintln!(
                    "healthproxy: projected inventory is unusable; retaining the last valid membership: {error}"
                );
                inventory_error = Some(error);
            }
            Err(_) => {}
        }
        let drained: std::collections::BTreeSet<String> = config
            .inventory
            .iter()
            .filter(|member| member.is_cordoned())
            .map(|member| member.node().to_string())
            .collect();
        let (members, reports_observed) = resolve_members(
            &client,
            &config.health_base,
            &config.inventory,
            config.health_timeout,
            &mut cache,
        )
        .await;
        // While the generation is unreadable every active node resolves through
        // its cached report, and once those age out the WHOLE inventory is programmed out of the
        // backend set. The per-node `reports_stale_total` drains that follow look identical to a
        // fleet that genuinely went silent, so the cause is logged here — and only here. The
        // generation is the index AND the shards it names, so losing every shard under a readable
        // index logs the same edge: the drain it causes is identical.
        if reports_observed != reports_usable {
            reports_usable = reports_observed;
            if reports_observed {
                eprintln!(
                    "healthproxy: the fleet report generation at {} is readable again",
                    updated_contracts::telemetry::fleet_index_url(&config.health_base)
                );
            } else {
                eprintln!(
                    "healthproxy: the fleet report generation at {} is unreadable — its index, or every shard the index names, failed to read or parse; readiness holds from the last observed reports for up to {}s, after which every node drains",
                    updated_contracts::telemetry::fleet_index_url(&config.health_base),
                    LastKnownGood::<Envelope>::STALENESS.as_secs()
                );
            }
        }
        for member in &members {
            let prior = previous.insert(member.node.clone(), member.ready);
            let transition = classify_transition(prior, member.ready);
            match transition {
                Some(Transition::FirstOutOfPool) if drained.contains(&member.node) => eprintln!(
                    "healthproxy: {} starts out of {} (cordoned by the control plane)",
                    member.node, config.target()
                ),
                Some(Transition::FirstOutOfPool) => eprintln!(
                    "healthproxy: {} starts out of {} (no ready health report yet)",
                    member.node, config.target()
                ),
                // A rejoin has TWO causes and they are not interchangeable: the node's health
                // report went ready, or its cordon was lifted. Claiming "health report ready" for
                // the second names the wrong cause for the one edge an operator most needs
                // explained.
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
                if drain_is_stale(now_ms(), body.as_ref()) {
                    shared_metrics
                        .lock()
                        .expect("metrics lock")
                        .reports_stale_total += 1;
                }
            }
        }
        prior_drained = drained;
        // Stamped on the report OBSERVATION: a scrape that watches this stop advancing while the
        // fleet is still reporting is watching the fleet generation go unreadable, which is the one
        // thing the per-node staleness counter cannot say.
        if reports_observed {
            let mut metrics = shared_metrics.lock().expect("metrics lock");
            metrics.reports_timestamp_seconds = now_ms() / 1000;
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
        tokio::select! {
            _ = &mut shutdown => break,
            _ = tokio::time::sleep(config.interval) => {}
        }
    }

    // Kubernetes terminates the workload before the operator removes its permission. Program an
    // empty set while that authority is still valid so deleting a backend cannot strand stale
    // traffic. This is also what makes HAProxy membership replacement safe: the old process knows
    // which runtime servers it owned, whereas its replacement only knows the new inventory.
    match tokio::time::timeout(RECONCILE_TIMEOUT, load_balancer.reconcile(&[])).await {
        Ok(Ok(())) => eprintln!("healthproxy: drained {} before shutdown", config.target()),
        Ok(Err(error)) => eprintln!(
            "healthproxy: failed to drain {} before shutdown: {error}",
            config.target()
        ),
        Err(_) => eprintln!(
            "healthproxy: draining {} timed out after {}s during shutdown",
            config.target(),
            RECONCILE_TIMEOUT.as_secs()
        ),
    }
}

/// Runtime configuration, resolved from `HEALTHPROXY_*` environment variables.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Base URL of the CDN/object store the control plane folds node reports into; the stable fleet
    /// index is at `<health_base>/telemetry/fleet.json` and names its bounded shards.
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
    pub inventory: Vec<BackendInventoryMember>,
    /// Operator-owned projected inventory. Its fixed shard set is re-read every reconcile so
    /// membership changes do not restart this process or expose a partial ConfigMap update.
    pub inventory_dir: std::path::PathBuf,
    pub interval: Duration,
    pub health_timeout: Duration,
    /// When set, program a cluster of HAProxy instances via the Runtime API instead of a
    /// Kubernetes EndpointSlice. The same health→membership core drives either backend; this only
    /// selects which one. `None` ⇒ the EndpointSlice backend (the `service`/`port` fields above).
    pub haproxy: Option<HAProxyTarget>,
    /// When set (`HEALTHPROXY_METRICS_ADDRESS`), serve `GET /metrics` on this address — plain
    /// HTTP, cluster-internal, read-only, nothing else. Default off. Parsed here, once, so a typo
    /// is a startup error and the bind uses exactly what validation accepted.
    pub metrics_address: Option<std::net::SocketAddr>,
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

    pub async fn from_env() -> Result<Self, String> {
        // The parameter type is spelled out so the closure stays general over the borrow's
        // lifetime: inferred from its first use, it would be pinned to that one call and refuse
        // the higher-ranked `impl Fn(&str)` bound `build` requires.
        let get = |key: &str| std::env::var(key).ok();
        let inventory_dir =
            std::path::PathBuf::from(require(&get, backend::HEALTHPROXY_INVENTORY_DIR_ENV)?);
        let inventory = load_inventory(&inventory_dir).await?;
        Self::build(get, inventory_dir, inventory)
    }

    /// Environment-independent core of [`from_env`](Self::from_env), so parsing is testable
    /// without mutating process-global state.
    pub fn build(
        get: impl Fn(&str) -> Option<String>,
        inventory_dir: std::path::PathBuf,
        inventory: Vec<BackendInventoryMember>,
    ) -> Result<Self, String> {
        let health_base = require(&get, backend::HEALTHPROXY_HEALTH_BASE_ENV)?;
        // Validate at the process boundary even though updatec also validates the CR before it
        // projects this environment variable. The binary is independently runnable, and this is
        // the one parser used by both paths rather than security inherited from a particular
        // launcher.
        let health_base = updated::http::network_endpoint(
            &health_base,
            updated::http::EndpointTransport::HttpOrHttps,
            backend::HEALTHPROXY_HEALTH_BASE_ENV,
        )
        .map_err(|error| error.to_string())?
        .to_string();
        let namespace = get(backend::HEALTHPROXY_NAMESPACE_ENV).unwrap_or_else(|| "default".into());
        let port_name = get(backend::HEALTHPROXY_PORT_NAME_ENV).unwrap_or_else(|| "http".into());
        let port = parse_port(&get, backend::HEALTHPROXY_PORT_ENV, 8080)?;
        let interval =
            Duration::from_secs(parse_secs(&get, backend::HEALTHPROXY_INTERVAL_SECS_ENV, 2)?);
        let health_timeout = Duration::from_secs(parse_secs(
            &get,
            backend::HEALTHPROXY_HEALTH_TIMEOUT_SECS_ENV,
            2,
        )?);
        // Selecting the HAProxy backend: a non-empty endpoint list switches from EndpointSlices to
        // programming that cluster of HAProxy admin sockets. Absent ⇒ the EndpointSlice backend.
        let haproxy = match get(backend::HEALTHPROXY_HAPROXY_ENDPOINTS_ENV) {
            Some(raw) if !raw.trim().is_empty() => {
                let endpoints: Vec<String> = raw
                    .split(',')
                    .map(str::trim)
                    .filter(|endpoint| !endpoint.is_empty())
                    .map(str::to_owned)
                    .collect();
                if endpoints.is_empty()
                    || endpoints
                        .iter()
                        .any(|endpoint| !updated_contracts::backend::is_tcp_endpoint(endpoint))
                {
                    return Err(format!(
                        "{} must list TCP host:port endpoints",
                        backend::HEALTHPROXY_HAPROXY_ENDPOINTS_ENV
                    ));
                }
                // The backend name is interpolated into the same `;`-joined admin batch as the node
                // identity (`set server {backend}/{node} state …`), so it faces the same gate, for
                // the same two reasons: `;` or whitespace in it appends a second command to a
                // `level admin` socket, and anything HAProxy answers with an error fails EVERY
                // reconcile forever — the whole fleet never programmed again behind one log line.
                let name =
                    get(backend::HEALTHPROXY_HAPROXY_BACKEND_ENV).unwrap_or_else(|| "fleet".into());
                if !backend::is_balancer_safe(&name) {
                    return Err(format!(
                        "{}={name:?} is not a usable HAProxy backend name: it must be non-empty \
                         and contain no `;` and no whitespace, or it would end the command it is \
                         written into",
                        backend::HEALTHPROXY_HAPROXY_BACKEND_ENV
                    ));
                }
                Some(HAProxyTarget {
                    endpoints,
                    backend: name,
                })
            }
            _ => None,
        };
        // The target Kubernetes Service is required only for the EndpointSlice backend; the HAProxy
        // backend programs admin sockets and never touches a Service, so it does not need one.
        let service = if haproxy.is_some() {
            get(backend::HEALTHPROXY_SERVICE_ENV).unwrap_or_default()
        } else {
            require(&get, backend::HEALTHPROXY_SERVICE_ENV)?
        };
        Ok(Self {
            health_base,
            namespace,
            service,
            port_name,
            port,
            inventory,
            inventory_dir,
            interval,
            health_timeout,
            haproxy,
            // Validated here so a typo is a startup error, not a listener that silently never
            // came up behind a Ready process.
            metrics_address: get(backend::HEALTHPROXY_METRICS_ADDRESS_ENV)
                .filter(|value| !value.is_empty())
                .map(|value| {
                    value.parse::<SocketAddr>().map_err(|error| {
                        format!(
                            "{}={value:?}: {error}",
                            backend::HEALTHPROXY_METRICS_ADDRESS_ENV
                        )
                    })
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

fn decode_inventory_shard(
    bytes: Vec<u8>,
    path: &std::path::Path,
) -> Result<updated_contracts::backend::BackendInventoryShard, String> {
    if bytes.len() > updated_contracts::backend::BACKEND_INVENTORY_SHARD_MAX_BYTES {
        return Err(format!(
            "{} exceeds the {}-byte inventory shard limit",
            path.display(),
            updated_contracts::backend::BACKEND_INVENTORY_SHARD_MAX_BYTES
        ));
    }
    serde_json::from_slice(&bytes).map_err(|error| format!("decoding {}: {error}", path.display()))
}

async fn load_inventory(
    directory: &std::path::Path,
) -> Result<Vec<BackendInventoryMember>, String> {
    let mut shards = Vec::with_capacity(updated_contracts::backend::BACKEND_INVENTORY_SHARDS);
    for index in 0..updated_contracts::backend::BACKEND_INVENTORY_SHARDS {
        let path = directory.join(format!("inventory-{index:02}.json"));
        let read_path = path.clone();
        let bytes = tokio::task::spawn_blocking(move || {
            foundation::file::read_bounded_regular(
                &read_path,
                updated_contracts::backend::BACKEND_INVENTORY_SHARD_MAX_BYTES,
                foundation::file::FinalSymlink::Follow,
            )
        })
        .await
        .map_err(|error| format!("reading {}: task failed: {error}", path.display()))?
        .map_err(|error| format!("reading {}: {error}", path.display()))?;
        shards.push(decode_inventory_shard(bytes, &path)?);
    }
    let members = updated_contracts::backend::assemble_backend_inventory(shards)?;
    parse_inventory(members)
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

/// Revalidate the projected member list at the shared protocol gate.
///
/// There is no second, runtime representation to build: an entry that survives
/// [`updated_contracts::backend::BackendInventoryMember::validate`] already carries its canonical
/// routable address and its pinned key as a [`P256PublicKey`]. Reconstructing those into a
/// proxy-local type is how the proxy's idea of a member and the control plane's drifted apart.
fn parse_inventory(
    entries: Vec<BackendInventoryMember>,
) -> Result<Vec<BackendInventoryMember>, String> {
    entries
        .into_iter()
        .map(BackendInventoryMember::validate)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
    use std::collections::HashMap;
    use updated_contracts::telemetry::NodeReport;

    static TEST_KEY: std::sync::LazyLock<(Vec<u8>, P256PublicKey)> =
        std::sync::LazyLock::new(|| {
            let rng = aws_lc_rs::rand::SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
            let key =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
            (
                pkcs8.as_ref().to_vec(),
                P256PublicKey::parse_hex(&hex::encode(key.public_key().as_ref())).unwrap(),
            )
        });

    /// A real, distinct pin per `seed`. Config fixtures must use a key the verifier could actually
    /// use — the parser proves the point is on the curve, which is the whole point of
    /// [`P256PublicKey`] — so a fabricated `04`-prefixed string cannot stand in for one.
    fn pin(seed: u8) -> String {
        static PINS: std::sync::LazyLock<std::sync::Mutex<HashMap<u8, String>>> =
            std::sync::LazyLock::new(Default::default);
        PINS.lock()
            .unwrap()
            .entry(seed)
            .or_insert_with(|| {
                let rng = aws_lc_rs::rand::SystemRandom::new();
                let pkcs8 =
                    EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
                let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref())
                    .unwrap();
                hex::encode(key.public_key().as_ref())
            })
            .clone()
    }

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        move |key: &str| map.get(key).cloned()
    }

    fn active(node: &str, address: &str, key: &str) -> backend::BackendInventoryMember {
        backend::BackendInventoryMember::active(node, address, key).unwrap()
    }

    fn config(
        pairs: &[(&str, &str)],
        inventory: &[backend::BackendInventoryMember],
    ) -> Result<Config, String> {
        Config::build(
            env(pairs),
            "/inventory".into(),
            parse_inventory(inventory.to_vec())?,
        )
    }

    /// A well-formed running digest. The proxy never reads it — membership follows health — but it
    /// must be present and well-formed for a report to pass the shared trust gate at all.
    const DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// A report produced through the same single validation/signing/encoding boundary as a node.
    fn report_with(node: &str, healthy: bool, mutate: impl FnOnce(&mut NodeReport)) -> Envelope {
        let mut report =
            NodeReport::new(node, "deploy-3", DIGEST, "3.0.0", DIGEST, DIGEST, healthy);
        bind_reconciliation(&mut report);
        mutate(&mut report);
        let body =
            updated_contracts::telemetry::encode_signed_report(&report, &TEST_KEY.0).unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    fn bind_reconciliation(report: &mut NodeReport) {
        use updated_contracts::reconciler::{
            HostAction, LastReconciliation, MutationOperation, Reason, ReconciledRelease,
            ReconcilerIdentity, ReconciliationTransition, SuccessfulMutation,
        };
        let running = ReconciledRelease::new(
            report.version.clone(),
            DIGEST.into(),
            report.archive_sha256.clone(),
        )
        .unwrap();
        let transition = ReconciliationTransition::new(running.clone(), running);
        let reconciler_release =
            ReconciledRelease::new("1.0.0".into(), DIGEST.into(), DIGEST.into()).unwrap();
        report.reconciliation = Some(
            LastReconciliation::new(
                MutationOperation::Apply,
                Reason::Restart,
                updated_contracts::reconciler::attempt::CONVERGE.into(),
                transition,
                ReconcilerIdentity::new(
                    report.provider_set_sha256.clone(),
                    "system".into(),
                    reconciler_release,
                )
                .unwrap(),
                SuccessfulMutation::new(false, HostAction::None, None).unwrap(),
                1,
            )
            .unwrap(),
        );
    }

    fn report(node: &str, healthy: bool) -> Envelope {
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
    }
    const OUTCOMES: [Outcome; 6] = [
        Outcome::HealthyFresh,
        Outcome::Unhealthy,
        Outcome::WrongNode,
        Outcome::Malformed,
        Outcome::Stale,
        Outcome::Missing,
    ];

    /// The observed envelope an outcome produces for `node` (`None` = the node was not observed
    /// this cycle: the indexed generation fetch failed, or it carried no entry for the node).
    fn body_for(outcome: Outcome, node: &str) -> Option<Envelope> {
        match outcome {
            Outcome::HealthyFresh => Some(report(node, true)),
            Outcome::Unhealthy => Some(report(node, false)),
            // A healthy report, but for a *different* node — must never mark this one ready.
            Outcome::WrongNode => Some(report("someone-else", true)),
            // An envelope whose payload is not a report at all — a corrupt fleet-document entry.
            Outcome::Malformed => Some(Envelope {
                payload: "eyBub3QgdmFsaWQganNvbg==".into(),
                payload_type: updated_contracts::telemetry::REPORT_PAYLOAD_TYPE.into(),
                signatures: Vec::new(),
            }),
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
            let mut cache: LastKnownGood<Envelope> = LastKnownGood::new();
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
    fn unusable_envelopes_fail_closed() {
        // Not a report payload type, no signatures, garbage payload: each fails closed alone.
        for envelope in [
            Envelope {
                payload: String::new(),
                payload_type: "application/other".into(),
                signatures: Vec::new(),
            },
            Envelope {
                payload: "!!!not base64!!!".into(),
                payload_type: updated_contracts::telemetry::REPORT_PAYLOAD_TYPE.into(),
                signatures: Vec::new(),
            },
        ] {
            assert!(!report_is_ready("agent-7", &TEST_KEY.1, &envelope));
        }
    }

    #[test]
    fn config_requires_base_service_and_members() {
        let members = vec![
            active("agent-0", "10.0.0.1", &pin(1)),
            active("agent-1", "10.0.0.2", &pin(2)),
        ];
        let ok = config(
            &[
                ("HEALTHPROXY_HEALTH_BASE", "http://gw"),
                ("HEALTHPROXY_SERVICE", "vm-db"),
            ],
            &members,
        )
        .unwrap();
        assert_eq!(ok.namespace, "default");
        assert_eq!(ok.port, 8080);
        assert_eq!(
            ok.inventory,
            vec![
                BackendInventoryMember::Active {
                    node: "agent-0".into(),
                    address: "10.0.0.1".into(),
                    public_key: P256PublicKey::parse_hex(&pin(1)).unwrap(),
                },
                BackendInventoryMember::Active {
                    node: "agent-1".into(),
                    address: "10.0.0.2".into(),
                    public_key: P256PublicKey::parse_hex(&pin(2)).unwrap(),
                },
            ]
        );

        assert!(config(&[("HEALTHPROXY_SERVICE", "x")], &members).is_err());
        assert!(config(&[("HEALTHPROXY_HEALTH_BASE", "x")], &members).is_err());
        for invalid in [
            "file:///health",
            "http://user@health.example/",
            "https://health.example/?token=secret",
            "https://health.example/#fragment",
        ] {
            let error = config(
                &[
                    ("HEALTHPROXY_HEALTH_BASE", invalid),
                    ("HEALTHPROXY_SERVICE", "vm-db"),
                ],
                &members,
            )
            .unwrap_err();
            assert!(!error.contains("secret"), "URL leaked in {error}");
        }
        // A membership of nobody never reaches `Config::build`: `parse_inventory` is the one place a
        // `Vec<BackendInventoryMember>` comes into existence, so it is the one place that refuses an empty one —
        // the same order `from_env` runs them in.
        assert!(config(
            &[
                ("HEALTHPROXY_HEALTH_BASE", "x"),
                ("HEALTHPROXY_SERVICE", "s")
            ],
            &[]
        )
        .is_err());
    }

    #[test]
    fn haproxy_endpoints_select_the_haproxy_backend() {
        // No HAProxy endpoints ⇒ the EndpointSlice backend.
        let one = vec![active("agent-0", "10.0.0.1", &pin(1))];
        let slice = config(
            &[
                ("HEALTHPROXY_HEALTH_BASE", "http://gw"),
                ("HEALTHPROXY_SERVICE", "vm-db"),
            ],
            &one,
        )
        .unwrap();
        assert_eq!(slice.haproxy, None);

        // A non-empty endpoint list ⇒ the HAProxy backend, default backend name "fleet".
        let haproxy = config(
            &[
                ("HEALTHPROXY_HEALTH_BASE", "http://gw"),
                ("HEALTHPROXY_SERVICE", "fleet-haproxy"),
                (
                    "HEALTHPROXY_HAPROXY_ENDPOINTS",
                    "10.0.0.9:9999, 10.0.0.10:9999",
                ),
            ],
            &one,
        )
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
        let one = vec![active("agent-0", "10.0.0.1", &pin(1))];
        let with_backend = |backend: &str| {
            config(
                &[
                    ("HEALTHPROXY_HEALTH_BASE", "http://gw"),
                    ("HEALTHPROXY_SERVICE", "fleet-haproxy"),
                    ("HEALTHPROXY_HAPROXY_ENDPOINTS", "10.0.0.9:9999"),
                    ("HEALTHPROXY_HAPROXY_BACKEND", backend),
                ],
                &one,
            )
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
        assert!(!updated_contracts::backend::is_balancer_safe(
            "fleet; shutdown frontend public"
        ));
        assert!(updated_contracts::backend::is_balancer_safe(
            "fleet-eu-west"
        ));
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

    #[test]
    fn inventory_rejects_malformed_entries() {
        assert!(backend::BackendInventoryMember::active("", "10.0.0.1", &pin(1)).is_err());
        assert!(backend::BackendInventoryMember::active("agent-0", "", &pin(1)).is_err());
        assert!(backend::BackendInventoryMember::active("agent-0", "10.0.0.1", "zz").is_err());
        // A complete signed-revision inventory of nobody is an explicit drain, distinct from a
        // missing/corrupt projection, which `load_inventory` rejects before this parser.
        assert_eq!(parse_inventory(Vec::new()).unwrap(), Vec::new());
        let duplicate = vec![
            active("agent-0", "10.0.0.1", &pin(1)),
            active("agent-0", "10.0.0.2", &pin(2)),
        ];
        assert!(backend::shard_backend_inventory(&duplicate).is_err());
    }

    #[tokio::test]
    async fn projected_inventory_is_complete_and_one_revision_or_not_adopted() {
        let directory = tempfile::tempdir().unwrap();
        let members = vec![
            active("agent-0", "10.0.0.1", &pin(1)),
            active("agent-1", "10.0.0.2", &pin(2)),
        ];
        let shards = updated_contracts::backend::shard_backend_inventory(&members).unwrap();
        for shard in &shards {
            std::fs::write(
                directory
                    .path()
                    .join(format!("inventory-{:02}.json", shard.index)),
                serde_json::to_vec(shard).unwrap(),
            )
            .unwrap();
        }
        let loaded = load_inventory(directory.path()).await.unwrap();
        assert_eq!(loaded.len(), members.len());

        let mut mixed = shards[1].clone();
        mixed.revision = "0".repeat(64);
        std::fs::write(
            directory.path().join("inventory-01.json"),
            serde_json::to_vec(&mixed).unwrap(),
        )
        .unwrap();
        assert!(load_inventory(directory.path()).await.is_err());

        std::fs::write(
            directory.path().join("inventory-00.json"),
            vec![b'x'; updated_contracts::backend::BACKEND_INVENTORY_SHARD_MAX_BYTES + 1],
        )
        .unwrap();
        let error = load_inventory(directory.path()).await.unwrap_err();
        assert!(error.contains("size limit"), "{error}");
    }

    /// A pin of the wrong shape verifies nothing, so a node carrying one would be drained forever
    /// while logging exactly like an unhealthy node. It must fail at startup instead.
    #[test]
    fn a_pin_the_verifier_could_never_use_is_a_startup_error() {
        // A certificate digest (32 bytes) and a compressed point are the realistic paste errors.
        assert!(P256PublicKey::parse_hex(&"ab".repeat(32)).is_err());
        assert!(P256PublicKey::parse_hex(&format!("02{}", "ab".repeat(32))).is_err());
        // 65 bytes, but not an uncompressed point; the all-zero encoding; and — the paste error
        // shape alone never caught — a correctly tagged 65-byte point that is not on the curve.
        assert!(P256PublicKey::parse_hex(&format!("03{}", "ab".repeat(64))).is_err());
        assert!(P256PublicKey::parse_hex(&format!("04{}", "00".repeat(64))).is_err());
        assert!(P256PublicKey::parse_hex(&format!("04{}", "ab".repeat(64))).is_err());
        assert!(P256PublicKey::parse_hex(&pin(1)).is_ok());

        let error =
            backend::BackendInventoryMember::active("agent-3", "10.0.0.1", &"ab".repeat(32))
                .expect_err("a malformed pin is refused at config time");
        assert!(error.contains("uncompressed P-256 point"), "{error}");
    }

    /// Inventory and report maps use the same Kubernetes DNS-subdomain identity grammar.
    #[test]
    fn a_node_identity_outside_the_shared_grammar_is_a_startup_error() {
        for node in ["agent-0", "rack-1.agent-7", "a"] {
            let parsed = backend::BackendInventoryMember::active(node, "10.0.0.1", &pin(1))
                .expect("a valid node name is configurable");
            assert_eq!(parsed.node(), node);
            assert!(updated_contracts::identity::is_dns_subdomain(node));
        }
        for node in [
            "agent#1",
            "agent_7",
            "AGENT-7",
            "agent/7",
            "agent\\7",
            "agent:7",
            "agent%2f7",
            "agent?7",
            ".",
            "..",
            "agent\n7",
        ] {
            let error = backend::BackendInventoryMember::active(node, "10.0.0.1", &pin(1))
                .expect_err("a name the write path rejects is refused at config time");
            // The offending name is named back to the operator, escaped — a name whose damage is a
            // stray `\n` must be legible in the log line that refuses it.
            assert!(error.contains(&format!("{node:?}")), "{error}");
            assert!(error.contains("invalid node identity"), "{error}");
            assert!(!updated_contracts::identity::is_dns_subdomain(node));
        }
        assert!(backend::BackendInventoryMember::active("", "10.0.0.1", &pin(1)).is_err());
        // The shared grammar carries Kubernetes' object-name ceiling because every production
        // node identity must be representable as an UpdateAgent.
        let maximum = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(
            maximum.len(),
            updated_contracts::identity::MAX_DNS_SUBDOMAIN_BYTES
        );
        assert!(backend::BackendInventoryMember::active(&maximum, "10.0.0.1", &pin(1)).is_ok());
        assert!(backend::BackendInventoryMember::active(
            "a".repeat(updated_contracts::identity::MAX_DNS_SUBDOMAIN_BYTES + 1),
            "10.0.0.1",
            &pin(1)
        )
        .is_err());
    }

    /// The identity is also the server name programmed into the balancer, where `;` separates
    /// commands and whitespace separates words. The shared DNS-subdomain identity grammar already
    /// refuses those bytes; the sink-specific guard remains defense in depth if that grammar is
    /// ever widened.
    #[test]
    fn a_node_identity_that_could_end_a_balancer_command_is_a_startup_error() {
        for node in [
            "agent-0; shutdown frontend public",
            "agent-0;",
            "agent-0 state maint",
            "agent\t0",
        ] {
            let error = backend::BackendInventoryMember::active(node, "10.0.0.1", &pin(1))
                .expect_err("a name that would end the command it is written into is refused");
            assert!(error.contains(&format!("{node:?}")), "{error}");
            assert!(!updated_contracts::backend::is_balancer_safe(node));
        }
        // Everything the shared identity grammar accepts is safe for the balancer too, including
        // dotted cluster-scoped names.
        for node in ["agent-0", "vm-db-17", "agent-7.prod"] {
            assert!(updated_contracts::identity::is_dns_subdomain(node));
            assert!(updated_contracts::backend::is_balancer_safe(node));
            assert!(backend::BackendInventoryMember::active(node, "10.0.0.1", &pin(1)).is_ok());
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

    #[test]
    fn removing_members_prunes_their_last_known_reports() {
        let mut known: LastKnownGood<String> = LastKnownGood::new();
        let now = Instant::now();
        known.resolve("departed", Some("old".into()), now);
        known.resolve("active", Some("current".into()), now);
        known.retain(|node| node == "active");
        assert_eq!(known.resolve("departed", None, now), None);
        assert_eq!(known.resolve("active", None, now), Some("current".into()));
    }

    /// The backend address has one meaning and one grammar: a host. A port belongs to the
    /// `UpdateBackend` target; accepting one here and discarding it made a typo look configured
    /// while traffic went somewhere else.
    #[test]
    fn backend_addresses_have_one_host_only_form() {
        for (address, expected) in [
            ("10.0.0.1", "10.0.0.1"),
            ("fd00::5", "fd00::5"),
            ("host.example", "host.example"),
            // Root-anchored FQDNs: the trailing dot is the root label, not an empty one.
            ("vm-db.internal.", "vm-db.internal"),
        ] {
            assert_eq!(
                updated_contracts::backend::routable_host(address).as_deref(),
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
            "host.example:8443",
            "10.0.0.1:8443",
            "[fd00::5]",
            // Only ONE trailing dot is the root label; a doubled dot is still an empty label.
            "host..example",
            "host.example..",
            "bad_name.example",
            "-host.example",
            "host-.example",
            // An invalid IP must not fall through into platform-dependent numeric-host parsing.
            "999.999.999.999",
            ".",
            "host.example:65536",
            "10.0.0.1:99999",
            "",
        ] {
            assert_eq!(
                updated_contracts::backend::routable_host(address),
                None,
                "address {address:?}"
            );
        }
        let error = backend::BackendInventoryMember::active("agent-3", "[fd00::5]junk", &pin(1))
            .expect_err("an address of no recognizable shape is refused at config time");
        assert!(error.contains("unroutable address"), "{error}");
    }

    #[test]
    fn inventory_keeps_canonical_host_spellings() {
        let key = pin(1);
        let parsed = parse_inventory(vec![
            active("v4", "10.0.0.1", &key),
            active("v6", "::1", &key),
            active("h", "vm-db.internal", &key),
            active("rooted", "rooted.internal.", &key),
        ])
        .unwrap();
        let hosts: Vec<(String, String)> = parsed
            .into_iter()
            .map(|member| match member {
                BackendInventoryMember::Active { node, address, .. } => (node, address),
                BackendInventoryMember::Cordoned { node } => panic!("unexpected cordon {node}"),
            })
            .collect();
        assert_eq!(
            hosts,
            vec![
                ("v4".into(), "10.0.0.1".to_string()),
                // A bare, unbracketed IPv6 must be kept whole — not split on its own colons.
                ("v6".into(), "::1".to_string()),
                ("h".into(), "vm-db.internal".to_string()),
                ("rooted".into(), "rooted.internal".to_string()),
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
        let garbage = Envelope {
            payload: "!!!not base64!!!".into(),
            payload_type: updated_contracts::telemetry::REPORT_PAYLOAD_TYPE.into(),
            signatures: Vec::new(),
        };
        assert!(
            !drain_is_stale(now, Some(&garbage)),
            "an unusable envelope is not attributed to staleness"
        );
        let stale = report_with("agent-7", true, |report| {
            report.reported_at_ms =
                now.saturating_sub(REPORT_FRESHNESS.as_millis() as u64 + 10_000);
        });
        assert!(drain_is_stale(now, Some(&stale)));
    }
}
