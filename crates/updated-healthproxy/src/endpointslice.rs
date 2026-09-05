//! The Kubernetes [`LoadBalancer`] backend: program a selectorless Service's EndpointSlice
//! from health, and let kube-proxy do the forwarding. A node's report going unhealthy flips
//! its endpoint to not-ready, which drains it from the Service with no data-path hop of ours.
//!
//! This is the first backend; DNS and HAProxy are future implementations of the same
//! [`LoadBalancer`] trait, driven by the identical health→membership core.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use k8s_openapi::api::discovery::v1::{Endpoint, EndpointConditions, EndpointPort, EndpointSlice};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{Api, Patch, PatchParams};
use kube::Client;

use crate::{LastKnownGood, LoadBalancer, Member};

/// Value we stamp as the EndpointSlice manager, and the field-manager for server-side apply.
pub const MANAGED_BY: &str = "updated-healthproxy";

/// The EndpointSlice backend for one Service. The Service must be selectorless (no pod
/// selector) so that we, not the Endpoints controller, own its membership.
pub struct EndpointSliceLb {
    api: Api<EndpointSlice>,
    service: String,
    port_name: String,
    port: u16,
    /// Everything the hostname resolve pass carries across cycles (see [`NameResolver`]).
    resolved: tokio::sync::Mutex<NameResolver>,
}

impl EndpointSliceLb {
    pub fn new(
        client: Client,
        namespace: &str,
        service: String,
        port_name: String,
        port: u16,
    ) -> Self {
        Self {
            api: Api::namespaced(client, namespace),
            service,
            port_name,
            port,
            resolved: tokio::sync::Mutex::new(NameResolver::new()),
        }
    }

    /// One immutable name per IP family. Kubernetes does not allow an EndpointSlice's
    /// `addressType` to change, so a stable family-specific name removes the destructive
    /// delete-and-recreate path entirely.
    fn slice_name(&self, family: AddressType) -> String {
        format!("{}-updated-{}", self.service, family.suffix())
    }
}

#[async_trait::async_trait]
impl LoadBalancer for EndpointSliceLb {
    async fn reconcile(&self, members: &[Member]) -> Result<(), String> {
        // A cordoned inventory entry carries no route: HAProxy needs its identity to issue an
        // explicit drain for a predeclared server, but an EndpointSlice expresses the same state by
        // omitting the endpoint. Filter that one shared sentinel before address-family reasoning so
        // it can never become a DNS lookup or a placeholder address.
        let routable: Vec<Member> = members
            .iter()
            .filter(|member| !member.address.is_empty())
            .cloned()
            .collect();
        let members = routable.as_slice();
        // ONE family rule for the whole reconcile: the majority of the members that HAVE a family.
        //
        // Configured literals answer it, and they answer it for both halves — names are resolved
        // into that family and the slice is typed as it — because the literals are the operator's
        // stated intent and are immune to the resolver's own RFC 6724 ordering. A single name that
        // answers only in the minority family therefore cannot flip the slice and evict every
        // member that was configured correctly.
        //
        // An inventory of nothing but hostnames — the documented member form for out-of-cluster
        // VMs — has no literal to ask, so the resolved addresses answer instead. Defaulting that
        // case to IPv4 typed an IPv6-only fleet's slice against every address in it and programmed
        // zero endpoints, every cycle, with nothing misconfigured anywhere: for a load balancer an
        // empty backend set is a total outage, not a fail-closed default.
        let configured = family_majority(members);
        let members = self
            .resolved
            .lock()
            .await
            .resolve(members, configured.unwrap_or(AddressType::Ipv4))
            .await;
        let family = configured
            .or_else(|| family_majority(&members))
            .unwrap_or(AddressType::Ipv4);
        let inactive_family = match family {
            AddressType::Ipv4 => AddressType::Ipv6,
            AddressType::Ipv6 => AddressType::Ipv4,
            AddressType::Fqdn => {
                return Err("resolved EndpointSlice family cannot be FQDN".to_string());
            }
        };
        let name = self.slice_name(family);
        let slice = build_slice(
            &self.service,
            &name,
            &self.port_name,
            self.port,
            &members,
            family,
        );
        // A single slice is one address family; any member of another family was dropped from
        // it (fail closed). Surface that misconfiguration rather than silently under-routing.
        let kept = slice.endpoints.len();
        if kept < members.len() {
            eprintln!(
                "healthproxy: {} inventory mixes address families; slice typed {}, dropped {} member(s) of another family",
                self.service,
                slice.address_type,
                members.len() - kept
            );
        }
        // Keep both immutable family slices present. Empty the inactive family first so a family
        // transition never leaves old-family nodes in rotation; then apply the desired family.
        // Server-side apply uses PATCH for both first creation and every later update, which lets
        // RBAC restrict this controller to exactly these two named resources and this one verb.
        let inactive_name = self.slice_name(inactive_family);
        let inactive = build_slice(
            &self.service,
            &inactive_name,
            &self.port_name,
            self.port,
            &[],
            inactive_family,
        );
        let params = PatchParams::apply(MANAGED_BY).force();
        for (slice_name, desired) in [(&inactive_name, &inactive), (&name, &slice)] {
            self.api
                .patch(slice_name, &params, &Patch::Apply(desired))
                .await
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }
}

/// Everything the hostname resolve pass carries across cycles: the last address each name resolved
/// to, where the next pass starts, and the reservation of blocking threads its lookups run on.
///
/// One type because the three are one policy. The pass cannot look up more names than the reserved
/// half of the blocking pool can hold, so on a large or slow inventory it necessarily stops short —
/// and stopping short in a *fixed* order is how the tail of the inventory never gets looked up at
/// all, ages out of [`LastKnownGood`], and is drained while resolving in milliseconds. The cursor is
/// what makes "stops short" mean *later*, not *never*.
pub(crate) struct NameResolver {
    /// The address each hostname member last resolved to, so a DNS blip on this side does not
    /// evict a healthy node (see [`NameResolver::resolve`]).
    known: LastKnownGood<String>,
    /// Index into the hostname members at which the next pass starts. Advanced to the first name a
    /// pass did not attempt, so every name is eventually attempted however little of the pass's
    /// share or of the pool the leading names leave behind.
    cursor: usize,
    /// The reserved share of the blocking pool ([`crate::NAME_LOOKUP_CONCURRENCY`]), one permit per
    /// thread a `getaddrinfo` may occupy.
    ///
    /// A permit is released by the lookup task itself, when the blocking call really returns — not
    /// when this pass loses interest in the answer. That is the whole point: dropping a
    /// `lookup_host` future does not cancel `getaddrinfo`, which against a blackholed resolver runs
    /// 20-40s while the pass abandons it after [`NAME_LOOKUP_TIMEOUT`]. With the reservation held
    /// only within a pass, a 2s interval abandons a poolful every few seconds until the pool is
    /// entirely occupied by work whose answers were discarded, the HTTP client can no longer resolve
    /// `health_base` either, and one [`LastKnownGood::STALENESS`] later the ENTIRE fleet reads
    /// not-ready — the mass eviction this module exists to prevent. Held across cycles, a saturated
    /// pool instead makes this pass skip names, which the cursor turns into "next cycle".
    permits: Arc<tokio::sync::Semaphore>,
}

impl NameResolver {
    pub(crate) fn new() -> Self {
        Self {
            known: LastKnownGood::new(),
            cursor: 0,
            permits: Arc::new(tokio::sync::Semaphore::new(crate::NAME_LOOKUP_CONCURRENCY)),
        }
    }

    /// Replace every hostname member with a resolved IP literal, dropping any for which no address
    /// is known.
    ///
    /// Kubernetes accepts an `FQDN` EndpointSlice but **kube-proxy does not implement that address
    /// type**, so a hostname slice programs zero working endpoints while every apply succeeds and
    /// every log line looks healthy — the worst failure shape there is. Members are documented as
    /// bare hostnames for out-of-cluster VMs, so the names are resolved here, each cycle, and the
    /// slice only ever carries addresses kube-proxy can actually route.
    ///
    /// A lookup that fails falls back to the address the name last resolved to, through the same
    /// [`LastKnownGood`] policy the report fetch uses: a resolver hiccup on this side is not
    /// evidence the node moved or went down, and without the fallback one SERVFAIL cycle empties
    /// the Service's backend set entirely. It stays fail-closed — a name that has not resolved
    /// within [`LastKnownGood::STALENESS`] leaves its member out of rotation.
    ///
    /// The lookups run concurrently and each is bounded by [`NAME_LOOKUP_TIMEOUT`], because a
    /// resolver that *hangs* rather than answering is not the same event as one that SERVFAILs: the
    /// last-known-good fallback only sees lookups that return. Serialized, unbounded lookups let one
    /// blackholed name spend the whole reconcile deadline this runs inside, so `build_slice`/apply
    /// never runs at all and membership freezes at whatever was last programmed — identically every
    /// cycle, since the walk restarts at the same name. Bounding each lookup ([`lookup_budget`],
    /// which also bounds the pass as a whole) and fanning them out turns that into the ordinary
    /// fail-closed path: the name falls back to its last known address and ages out on schedule.
    ///
    /// A pass that runs out of share, or of pool, skips the rest — but never the same rest twice:
    /// it starts where the last one stopped ([`NameResolver::cursor`]), so a blackholed leading
    /// name costs its own members' fallback and not the permanent disappearance of every name
    /// behind it.
    async fn resolve(&mut self, members: &[Member], preferred: AddressType) -> Vec<Member> {
        use futures::stream::StreamExt;
        let hostnames: Vec<usize> = members
            .iter()
            .enumerate()
            .filter(|(_, member)| AddressType::of(&member.address) == AddressType::Fqdn)
            .map(|(index, _)| index)
            .collect();
        // The whole pass is bounded by its share of the reconcile deadline, so the apply that
        // programs the slice always gets the rest — at any inventory size, and without the width
        // having to grow past what the runtime can run at once.
        let deadline = Instant::now() + crate::RECONCILE_TIMEOUT / RESOLVE_SHARE;
        // This cycle's walk order: the configured order, rotated to where the last pass stopped.
        let start = walk_start(self.cursor, hostnames.len());
        let order: Vec<usize> = hostnames[start..]
            .iter()
            .chain(&hostnames[..start])
            .copied()
            .collect();
        // Concurrent, cache-free lookup pass. Each result is tagged with its member index, to
        // restore the configured order afterward (the programmed set must be stable), and with its
        // rank in the walk, to find where this pass stopped.
        let width = crate::fanout_width(order.len(), crate::NAME_LOOKUP_CONCURRENCY);
        let permits = &self.permits;
        let looked_up: Vec<(usize, usize, Lookup)> =
            futures::stream::iter(order.iter().copied().enumerate().map(
                |(rank, index)| async move {
                    (
                        rank,
                        index,
                        lookup_one(
                            &members[index],
                            lookup_budget(deadline, Instant::now()),
                            preferred,
                            permits,
                        )
                        .await,
                    )
                },
            ))
            .buffer_unordered(width)
            .collect()
            .await;
        let mut fresh: Vec<Option<String>> = vec![None; members.len()];
        // Where this pass stopped: the earliest name in the walk that was never attempted. The next
        // pass starts there, so the inventory is covered even when no single pass can cover it.
        let mut stopped: Option<(usize, &'static str)> = None;
        let mut skipped = 0usize;
        for (rank, index, lookup) in looked_up {
            match lookup {
                Lookup::Answered(address) => fresh[index] = Some(address),
                Lookup::Unanswered => {}
                Lookup::NotAttempted(reason) => {
                    skipped += 1;
                    if stopped.is_none_or(|(first, _)| rank < first) {
                        stopped = Some((rank, reason));
                    }
                }
            }
        }
        if let Some((rank, reason)) = stopped {
            eprintln!(
                "healthproxy: {skipped} of {} hostname(s) were not looked up this cycle ({reason}); they keep their last known address, and the next pass resumes at {}",
                order.len(),
                members[order[rank]].address
            );
        }
        self.cursor = next_start(start, order.len(), stopped.map(|(rank, _)| rank));
        // Sequential resolve pass: a fresh lookup updates the cache, a failed, timed-out or skipped
        // one falls back to the last known address, and a name with neither leaves its member out
        // of rotation.
        let now = Instant::now();
        let mut resolved = Vec::with_capacity(members.len());
        for (member, fresh) in members.iter().zip(fresh) {
            if AddressType::of(&member.address) != AddressType::Fqdn {
                resolved.push(member.clone());
                continue;
            }
            match self.known.resolve(&member.address, fresh, now) {
                Some(address) => resolved.push(Member {
                    address,
                    ..member.clone()
                }),
                None => eprintln!(
                    "healthproxy: {} ({}) has no known address; leaving it out of rotation",
                    member.node, member.address
                ),
            }
        }
        // Drop names that left the inventory, the same discipline `run` converges to the caches it
        // owns. [`LastKnownGood`] ages a key out only when that key is looked up again — and a
        // hostname removed from the projected inventory is never passed to `resolve` again, so
        // without this its entry outlives the member forever and ordinary VM recycling grows this
        // map for the life of the process (see [`LastKnownGood::retain`]).
        let present: std::collections::HashSet<&str> = members
            .iter()
            .filter(|member| AddressType::of(&member.address) == AddressType::Fqdn)
            .map(|member| member.address.as_str())
            .collect();
        self.known.retain(|address| present.contains(address));
        resolved
    }
}

/// Where a pass's walk over `total` hostnames begins, given the cursor the last pass left.
fn walk_start(cursor: usize, total: usize) -> usize {
    if total == 0 {
        0
    } else {
        cursor % total
    }
}

/// Where the *next* pass begins: at the earliest name this one did not attempt (`stopped`, a rank in
/// this pass's walk, which began at `start`), or back at the configured order when it attempted them
/// all.
///
/// This is the whole of the coverage guarantee, and it is exact rather than a heuristic rotation: a
/// pass that can only reach `k` of `n` names hands the next pass the first name it did not reach, so
/// `ceil(n / k)` passes attempt every name — however small `k` is, and whichever names are the slow
/// ones. Rotating by a fixed stride instead would skip names whenever the stride and the reachable
/// count disagree; returning to the start would be the fixed order whose tail is never attempted at
/// all, which is what ages healthy nodes out of rotation while their own names resolve instantly.
///
/// Returning to zero once nothing was skipped matters too: rotation exists to cover a shortfall, and
/// a walk that kept drifting without one would reorder the lookups every cycle for no reason.
fn next_start(start: usize, total: usize, stopped: Option<usize>) -> usize {
    match stopped {
        Some(rank) if total > 0 => (start + rank) % total,
        _ => 0,
    }
}

/// What one name's lookup produced this cycle.
enum Lookup {
    /// The name answered, and an address of the preferred family was picked from the answer.
    Answered(String),
    /// The lookup ran and produced nothing usable — an error, a timeout, or an empty answer. All
    /// the same event: this checker could not determine the address right now, so the caller falls
    /// back to the last known one.
    Unanswered,
    /// The lookup was never started. Distinct from [`Lookup::Unanswered`] because it is the only
    /// outcome that says nothing about the *name* — it says the pass ran out of something — and so
    /// it is the outcome that must move the cursor.
    NotAttempted(&'static str),
}

/// Resolve one hostname member to an address literal of the `preferred` family within `budget`,
/// holding one of `permits` for as long as the lookup really occupies a blocking thread.
async fn lookup_one(
    member: &Member,
    budget: Duration,
    preferred: AddressType,
    permits: &Arc<tokio::sync::Semaphore>,
) -> Lookup {
    // No budget left means the pass spent its share (see [`lookup_budget`]). Return without
    // starting the lookup at all rather than starting one that can only be abandoned: `getaddrinfo`
    // runs on the blocking pool and cannot be cancelled, so submitting it would leave the pool
    // occupied by work whose answer is already discarded — and the next cycle's pass starts behind
    // it. The cursor is what keeps this name from being the one skipped every cycle.
    if budget.is_zero() {
        return Lookup::NotAttempted("the pass spent its share of the reconcile deadline");
    }
    // No permit means the reserved share of the pool is still occupied by lookups earlier cycles
    // abandoned. Starting anyway would queue behind them — a "lookup" that spends its whole budget
    // waiting for a thread and never runs — and push the pool past the reserve the per-cycle
    // document fetches resolve through.
    let Ok(permit) = Arc::clone(permits).try_acquire_owned() else {
        return Lookup::NotAttempted(
            "every reserved blocking thread is still held by a lookup an earlier cycle abandoned",
        );
    };
    let name = member.address.clone();
    // Spawned rather than awaited in place, so the permit outlives this pass's interest in the
    // answer: the task holds it until `getaddrinfo` actually returns, which is when the thread is
    // actually free. Dropping the `JoinHandle` on timeout below abandons the answer, not the task.
    // The port is irrelevant to the lookup; the Service owns it.
    let lookup = tokio::spawn(async move {
        // Collected inside the task: the iterator borrows the name, and the answer has to outlive
        // both it and the task.
        let answer = tokio::net::lookup_host((name.as_str(), 0))
            .await
            .map(|addresses| addresses.collect::<Vec<_>>());
        drop(permit);
        answer
    });
    match tokio::time::timeout(budget, lookup).await {
        Ok(Ok(Ok(addresses))) => {
            match pick_address(addresses.into_iter().map(|address| address.ip()), preferred) {
                Some(address) => Lookup::Answered(address),
                None => {
                    eprintln!(
                        "healthproxy: resolving {} ({}) answered with no address; using its last known address",
                        member.node, member.address
                    );
                    Lookup::Unanswered
                }
            }
        }
        Ok(Ok(Err(error))) => {
            eprintln!(
                "healthproxy: resolving {} ({}) failed ({error}); using its last known address",
                member.node, member.address
            );
            Lookup::Unanswered
        }
        Ok(Err(join)) => {
            eprintln!(
                "healthproxy: resolving {} ({}) did not complete ({join}); using its last known address",
                member.node, member.address
            );
            Lookup::Unanswered
        }
        Err(_) => {
            eprintln!(
                "healthproxy: resolving {} ({}) timed out after {}ms; using its last known address",
                member.node,
                member.address,
                budget.as_millis()
            );
            Lookup::Unanswered
        }
    }
}

/// Choose one address out of a name's answers: the `preferred` family first, and within a family the
/// lowest address, so the choice is a function of the answer *set* and not of the order it arrived
/// in.
///
/// Both halves matter. Family, because the resolver's order is a routing preference, not ours: on a
/// host with global IPv6 connectivity glibc's RFC 6724 sorting puts a dual-stack name's AAAA first,
/// so taking the first answer types that member IPv6 while the IPv4 literals beside it in the
/// inventory type the slice IPv4 — and `build_slice` then drops the member from an otherwise
/// perfectly healthy rotation, behind a "mixes address families" line pointing at a mix the operator
/// never wrote. Order, because a name with several A records is commonly returned round-robin: the
/// slice would then churn its endpoint every cycle for no reason.
///
/// A name that answers *only* in the other family still resolves to what it has — its member is then
/// dropped by `build_slice` with the mixed-family warning, which is the honest report of a genuinely
/// mixed inventory rather than a silent disappearance.
fn pick_address(
    addresses: impl Iterator<Item = std::net::IpAddr>,
    preferred: AddressType,
) -> Option<String> {
    addresses
        .min_by_key(|address| (AddressType::of_ip(address) != preferred, *address))
        .map(|address| address.to_string())
}

/// The address family a set of members is, by majority of the members that have one, ties going
/// IPv4. `None` when not one member is an IP literal — the set has nothing to say about family.
///
/// The ONE family rule. The reconcile asks it of the configured inventory first, and only of the
/// resolved addresses when the inventory had no literal to answer with; both halves of the decision
/// (which family names resolve into, and how the slice is typed) come from that single answer, so
/// they cannot drift apart.
///
/// Hostnames are never counted — a name has no family until it answers, and counting the answer is
/// what would let the resolver's ordering, rather than the operator, choose the slice's family.
/// Only the two IP families are candidates: [`NameResolver::resolve`] turns every hostname into a
/// literal or drops it, and kube-proxy does not route `FQDN` slices.
fn family_majority(members: &[Member]) -> Option<AddressType> {
    let (mut ipv4, mut ipv6) = (0usize, 0usize);
    for member in members {
        match AddressType::of(&member.address) {
            AddressType::Ipv4 => ipv4 += 1,
            AddressType::Ipv6 => ipv6 += 1,
            AddressType::Fqdn => {}
        }
    }
    match (ipv4, ipv6) {
        (0, 0) => None,
        (_, ipv6) if ipv6 > ipv4 => Some(AddressType::Ipv6),
        _ => Some(AddressType::Ipv4),
    }
}

/// The budget for one hostname lookup, whatever the inventory size. `getaddrinfo` against a
/// blackholed resolver commonly blocks for tens of seconds, so a single hung name must not stall the
/// rest; three seconds still covers a resolver that walks a multi-entry `search` path.
///
/// Fixed, never divided down by the inventory size: what bounds the pass is [`lookup_budget`]'s
/// real deadline plus the cursor that carries an unfinished walk into the next cycle, not a
/// per-lookup budget shrunk until every lookup in the pass times out.
const NAME_LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);

/// The share of [`crate::RECONCILE_TIMEOUT`] the whole resolve pass may spend, as a divisor: half,
/// leaving the other half for the apply that actually programs the slice. Resolution is only the
/// prelude — a resolve pass that consumes the whole deadline reconciles nothing at all.
const RESOLVE_SHARE: u32 = 2;

/// What one lookup starting at `now` may spend: the full [`NAME_LOOKUP_TIMEOUT`], until the pass's
/// `deadline` leaves less than that, and zero once it has passed.
///
/// This is what bounds the pass, at any inventory size and whatever the pool can run at once. The
/// budget is never pre-divided by a wave count:
/// a per-lookup timeout under a real `getaddrinfo` round trip (1000 names at width 32 would be
/// 156ms, less than a resolver walking a multi-entry `search` path takes) times out *every* lookup
/// in the pass, drops every hostname member to its last known address, and one
/// [`LastKnownGood::STALENESS`] later programs the slice empty. Here every lookup gets the full
/// budget for as long as the share lasts; only lookups starting after the share is genuinely spent
/// are cut short, and a resolver still answering at that point has already answered them — the pass
/// only reaches its deadline when lookups are hanging, which is precisely the case whose answer is
/// the last-known-good fallback anyway.
fn lookup_budget(deadline: Instant, now: Instant) -> Duration {
    NAME_LOOKUP_TIMEOUT.min(deadline.saturating_duration_since(now))
}

/// Build the desired EndpointSlice for a set of members. Pure, so the mapping from health to
/// endpoints (addresses, ready conditions, the service-name label kube-proxy keys on) is
/// tested without a cluster.
///
/// An EndpointSlice is single-address-typed, so a mixed inventory (IPv4 plus IPv6 members) cannot
/// go in one slice: it is partitioned to `address_type` — the reconcile's one [`family_majority`]
/// decision, passed in rather than re-derived here — and any member of another family is dropped,
/// i.e. left out of rotation (fail closed). Such a mix is a misconfiguration; the reconcile loop
/// logs the drop.
///
/// Members reach here as IP literals — [`NameResolver::resolve`] has already turned any hostname into
/// one — because kube-proxy does not route `FQDN` slices.
fn build_slice(
    service: &str,
    slice_name: &str,
    port_name: &str,
    port: u16,
    members: &[Member],
    address_type: AddressType,
) -> EndpointSlice {
    let endpoints = members
        .iter()
        .filter(|member| AddressType::of(&member.address) == address_type)
        .map(|member| Endpoint {
            addresses: vec![member.address.clone()],
            conditions: Some(EndpointConditions {
                // `ready` gates routing; `serving` mirrors it; nothing we manage is
                // "terminating" — a drained node is simply not ready.
                ready: Some(member.ready),
                serving: Some(member.ready),
                terminating: Some(false),
            }),
            ..Default::default()
        })
        .collect();
    let mut labels = BTreeMap::new();
    // The label kube-proxy/the EndpointSlice mirroring uses to attach this slice to its
    // Service, plus a manager marker so ownership is legible.
    labels.insert(
        "kubernetes.io/service-name".to_string(),
        service.to_string(),
    );
    labels.insert(
        "endpointslice.kubernetes.io/managed-by".to_string(),
        MANAGED_BY.to_string(),
    );
    EndpointSlice {
        metadata: ObjectMeta {
            name: Some(slice_name.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        address_type: address_type.label().to_string(),
        endpoints,
        ports: Some(vec![EndpointPort {
            name: Some(port_name.to_string()),
            port: Some(i32::from(port)),
            protocol: Some("TCP".to_string()),
            app_protocol: None,
        }]),
    }
}

/// The address family of one member address: a parseable IPv4 or IPv6 literal, else a hostname
/// (`FQDN`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AddressType {
    Ipv4,
    Ipv6,
    Fqdn,
}

impl AddressType {
    fn of(address: &str) -> Self {
        if address.parse::<Ipv4Addr>().is_ok() {
            Self::Ipv4
        } else if address.parse::<Ipv6Addr>().is_ok() {
            Self::Ipv6
        } else {
            Self::Fqdn
        }
    }

    /// The family of an already-parsed address, so a resolver answer is classified by the same
    /// rule as a configured literal without a round trip through its text form.
    fn of_ip(address: &std::net::IpAddr) -> Self {
        match address {
            std::net::IpAddr::V4(_) => Self::Ipv4,
            std::net::IpAddr::V6(_) => Self::Ipv6,
        }
    }

    /// The Kubernetes `addressType` string for this family.
    fn label(self) -> &'static str {
        match self {
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
            Self::Fqdn => "FQDN",
        }
    }

    fn suffix(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
            Self::Fqdn => "fqdn",
        }
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn member(node: &str, address: &str, ready: bool) -> Member {
        Member {
            node: node.to_string(),
            address: address.to_string(),
            ready,
        }
    }

    #[test]
    fn slice_reflects_member_readiness_and_attaches_to_its_service() {
        let members = vec![
            member("agent-0", "10.0.0.1", true),
            member("agent-1", "10.0.0.2", false),
        ];
        let slice = build_slice(
            "vm-db",
            "vm-db-updated",
            "http",
            5432,
            &members,
            family_majority(&members).unwrap_or(AddressType::Ipv4),
        );

        assert_eq!(slice.address_type, "IPv4");
        let labels = slice.metadata.labels.unwrap();
        assert_eq!(labels.get("kubernetes.io/service-name").unwrap(), "vm-db");
        assert_eq!(
            labels
                .get("endpointslice.kubernetes.io/managed-by")
                .unwrap(),
            MANAGED_BY
        );

        assert_eq!(slice.endpoints.len(), 2);
        assert_eq!(slice.endpoints[0].addresses, vec!["10.0.0.1".to_string()]);
        assert_eq!(
            slice.endpoints[0].conditions.as_ref().unwrap().ready,
            Some(true)
        );
        assert_eq!(
            slice.endpoints[1].conditions.as_ref().unwrap().ready,
            Some(false)
        );

        let ports = slice.ports.unwrap();
        assert_eq!(ports[0].port, Some(5432));
        assert_eq!(ports[0].name.as_deref(), Some("http"));
    }

    #[test]
    fn address_families_have_stable_distinct_suffixes() {
        assert_eq!(AddressType::Ipv4.suffix(), "ipv4");
        assert_eq!(AddressType::Ipv6.suffix(), "ipv6");
    }

    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    #[test]
    fn a_hostname_never_reaches_a_slice_as_an_fqdn_endpoint() {
        // kube-proxy does not route `FQDN` slices, so a hostname with no known address must leave
        // the member OUT of rotation rather than produce a slice that is accepted and routes
        // nothing.
        let mut resolver = NameResolver::new();
        let inventory = [member("db", "vm-db.invalid.example", true)];
        let members = block_on(resolver.resolve(
            &inventory,
            family_majority(&inventory).unwrap_or(AddressType::Ipv4),
        ));
        assert!(members.is_empty(), "a never-resolved member is dropped");

        let slice = build_slice("s", "s-updated", "http", 80, &members, AddressType::Ipv4);
        assert_eq!(slice.address_type, "IPv4");
        assert!(slice.endpoints.is_empty());
    }

    /// A resolver hiccup on this side is not evidence a node moved or went down. Without the
    /// last-known-good fallback, one SERVFAIL cycle empties the Service's backend set entirely
    /// while every node is still publishing fresh, healthy, signed reports.
    #[test]
    fn a_dns_failure_keeps_the_last_known_address_in_rotation() {
        let members = [member("db", "vm-db.invalid.example", true)];
        let mut resolver = NameResolver::new();
        // Seed what a successful cycle would have recorded for this name.
        assert_eq!(
            resolver.known.resolve(
                "vm-db.invalid.example",
                Some("10.0.0.7".into()),
                Instant::now()
            ),
            Some("10.0.0.7".to_string())
        );

        // This lookup genuinely fails (`.invalid` never resolves) — the member must survive it.
        let resolved = block_on(resolver.resolve(
            &members,
            family_majority(&members).unwrap_or(AddressType::Ipv4),
        ));
        assert_eq!(
            resolved,
            vec![member("db", "10.0.0.7", true)],
            "a checker-side DNS failure must not drain a healthy node"
        );
        let slice = build_slice("s", "s-updated", "http", 80, &resolved, AddressType::Ipv4);
        assert_eq!(slice.endpoints.len(), 1);
    }

    /// The fallback above is what makes this cache necessary, and what makes it a leak if it is
    /// never pruned: an entry ages out only when its own name is looked up again, and a name the
    /// projected inventory dropped is never looked up again. Left alone, the map keeps every
    /// address the fleet ever had for the life of the process — a bounded live fleet growing it
    /// forever through ordinary VM recycling, in the one process that writes balancer membership.
    #[test]
    fn a_name_that_leaves_the_inventory_is_forgotten_rather_than_kept_forever() {
        let mut resolver = NameResolver::new();
        assert_eq!(
            resolver.known.resolve(
                "vm-db.invalid.example",
                Some("10.0.0.7".into()),
                Instant::now()
            ),
            Some("10.0.0.7".to_string())
        );

        // A cycle whose inventory no longer lists that name. Nothing looks it up, so only the
        // prune can forget it.
        let current = [member("web", "10.0.0.1", true)];
        assert_eq!(
            block_on(resolver.resolve(&current, AddressType::Ipv4)),
            current.to_vec()
        );

        // Should the name come back, it is a name with no known address — not one still carrying an
        // address remembered from before it left.
        let returned = [member("db", "vm-db.invalid.example", true)];
        assert!(
            block_on(resolver.resolve(&returned, AddressType::Ipv4)).is_empty(),
            "a departed name must not keep its last known address in the cache"
        );
    }

    /// A resolver that hangs instead of answering must cost one member's fallback, not the whole
    /// reconcile: the resolve pass has to leave the apply that programs the slice enough of the
    /// deadline to run, at EVERY inventory size, or membership freezes at the last programmed set
    /// identically every cycle behind a single "timed out" line.
    ///
    /// The pass's bound is a real deadline, not arithmetic over a fan-out width the runtime cannot
    /// deliver: `getaddrinfo` occupies one blocking thread per lookup, so a width past the pool
    /// merely queues, and a derivation that widens without limit "fits" the share only on paper
    /// while the pass really runs several waves past it — burning the reconcile deadline that
    /// `build_slice`/apply must fit inside.
    ///
    /// And the deadline is never bought with the per-lookup budget while there is share left. A
    /// budget divided by the wave count a fixed width implies falls under a real `getaddrinfo`
    /// round trip at fleet scale (1000 names at width 32 would be 156ms), at which point every
    /// lookup in the pass times out, every hostname member falls back, and one staleness window
    /// later the slice is programmed empty — draining a completely healthy fleet.
    #[test]
    fn the_resolve_pass_leaves_the_apply_room_inside_the_reconcile_deadline_at_every_size() {
        let share = crate::RECONCILE_TIMEOUT / RESOLVE_SHARE;
        for names in [0, 1, crate::FANOUT_CONCURRENCY, 96, 1000, 100_000] {
            let width = crate::fanout_width(names, crate::NAME_LOOKUP_CONCURRENCY);
            assert!(width >= crate::FANOUT_CONCURRENCY);
            assert!(
                width <= crate::NAME_LOOKUP_CONCURRENCY,
                "{names} names ask for width {width}, past the {} lookups the blocking pool can really run at once",
                crate::NAME_LOOKUP_CONCURRENCY
            );
        }
        // And the ceiling is a width the pool can really run, with room left for the HTTP
        // client's own resolutions on the same pool — the two per-cycle document fetches — so the
        // reservation and that reserve are a partition, not two claims on the whole of it.
        const {
            assert!(
                crate::NAME_LOOKUP_CONCURRENCY + crate::FANOUT_CONCURRENCY
                    <= crate::BLOCKING_POOL_THREADS
            )
        };
        // Small inventories still start at the floor rather than one lookup per name.
        assert_eq!(
            crate::fanout_width(1, crate::NAME_LOOKUP_CONCURRENCY),
            crate::FANOUT_CONCURRENCY
        );
        // A fleet-sized one gets one lookup per name, up to the pool's ceiling.
        assert_eq!(crate::fanout_width(96, crate::NAME_LOOKUP_CONCURRENCY), 96);
        assert_eq!(
            crate::fanout_width(100_000, crate::NAME_LOOKUP_CONCURRENCY),
            crate::NAME_LOOKUP_CONCURRENCY
        );

        // The budget is never shrunk to buy the deadline while the share lasts: a lookup starting at
        // the top of the pass gets the full three seconds, which is what keeps a `search`-path
        // resolver from timing out fleet-wide.
        assert_eq!(NAME_LOOKUP_TIMEOUT, Duration::from_secs(3));
        let start = Instant::now();
        let deadline = start + share;
        assert_eq!(lookup_budget(deadline, start), NAME_LOOKUP_TIMEOUT);
        // It is trimmed only to the deadline itself, and a lookup that would start after the share
        // is spent does not start at all — that is what caps the pass at the share no matter how
        // many waves the pool forces.
        assert_eq!(
            lookup_budget(deadline, start + share - Duration::from_millis(500)),
            Duration::from_millis(500)
        );
        assert!(lookup_budget(deadline, start + share).is_zero());
        assert!(lookup_budget(deadline, start + share + Duration::from_secs(60)).is_zero());
    }

    /// A pass that cannot reach every name must reach the rest NEXT time. Before the cursor, a
    /// pass walked the inventory in configured order and stopped when its share or its share of the
    /// blocking pool ran out — so under a resolver that hangs on the LEADING names, the tail was
    /// never attempted, on any cycle, even though those names resolve in milliseconds. One
    /// `LastKnownGood::STALENESS` later every one of them is dropped out of rotation: healthy nodes
    /// drained because of where they sit in the operator's member list.
    #[test]
    fn every_hostname_is_eventually_attempted_however_little_one_pass_can_reach() {
        // Whatever the inventory size and however few names a pass reaches, walking from the
        // cursor covers the whole inventory in `ceil(names / reachable)` passes and never re-walks
        // a name before every other one has been attempted.
        for names in [1usize, 2, 7, 800] {
            for reachable in [1usize, 3, 512] {
                let reachable = reachable.min(names);
                let mut cursor = 0;
                let mut attempted = std::collections::BTreeSet::new();
                let passes = names.div_ceil(reachable);
                for _ in 0..passes {
                    let start = walk_start(cursor, names);
                    // The pass attempts `reachable` names from `start` and skips the rest; the
                    // earliest rank it did not attempt is exactly `reachable`.
                    for rank in 0..reachable {
                        attempted.insert((start + rank) % names);
                    }
                    let stopped = (reachable < names).then_some(reachable);
                    cursor = next_start(start, names, stopped);
                }
                assert_eq!(
                    attempted.len(),
                    names,
                    "{names} names at {reachable} per pass left {} name(s) never attempted after {passes} pass(es)",
                    names - attempted.len()
                );
            }
        }
        // A pass that attempted everything does not drift: the next walk is the configured order.
        assert_eq!(next_start(7, 800, None), 0);
        // An empty inventory has no walk to resume.
        assert_eq!(walk_start(9, 0), 0);
        assert_eq!(next_start(0, 0, Some(0)), 0);
    }

    /// `getaddrinfo` cannot be cancelled: abandoning a hung lookup leaves the blocking thread
    /// occupied for the 20-40s the resolver takes, while the loop starts another pass every
    /// interval. The reservation therefore has to hold ACROSS cycles — a pass with no free
    /// reserved thread must skip, not submit. Otherwise the pool fills with lookups whose answers
    /// were already discarded, the HTTP client can no longer resolve `health_base` either, and one
    /// staleness window later the ENTIRE fleet reads not-ready.
    #[test]
    fn a_pool_still_held_by_abandoned_lookups_makes_the_pass_skip_rather_than_pile_on() {
        let mut resolver = NameResolver::new();
        let members = [member("db", "localhost", true)];
        assert_eq!(
            resolver
                .known
                .resolve("localhost", Some("10.0.0.7".into()), Instant::now()),
            Some("10.0.0.7".to_string())
        );
        // Stand in for a poolful of lookups earlier cycles abandoned: every reserved permit is
        // held by work that has not returned.
        let held = Arc::clone(&resolver.permits)
            .try_acquire_many_owned(u32::try_from(crate::NAME_LOOKUP_CONCURRENCY).unwrap())
            .expect("a fresh resolver reserves the whole half-pool");
        let resolved = block_on(resolver.resolve(
            &members,
            family_majority(&members).unwrap_or(AddressType::Ipv4),
        ));
        assert_eq!(
            resolved,
            vec![member("db", "10.0.0.7", true)],
            "with no reserved thread free, the name must fall back rather than queue a lookup"
        );
        // And the member is NOT dropped: a checker-side shortfall is not evidence a node is down.

        // The reservation is a gate, not a latch — once the abandoned lookups return, the very next
        // pass resolves normally again.
        drop(held);
        // Only meaningful where `localhost` really resolves; where it does not, the fallback path
        // above is all this environment can show.
        if block_on(tokio::net::lookup_host(("localhost", 0))).is_ok() {
            let resolved = block_on(resolver.resolve(
                &members,
                family_majority(&members).unwrap_or(AddressType::Ipv4),
            ));
            assert_eq!(resolved.len(), 1);
            assert_ne!(
                resolved[0].address, "10.0.0.7",
                "with the pool free again the name must actually be looked up"
            );
        }
    }

    /// The concurrent lookup pass must hand `build_slice` the members in configured order, with the
    /// literals untouched — completion order is not membership order.
    #[test]
    fn resolution_preserves_configured_order_and_leaves_literals_alone() {
        let members = [
            member("a", "10.0.0.1", true),
            member("b", "vm-b.invalid.example", true),
            member("c", "fd00::1", false),
        ];
        let mut resolver = NameResolver::new();
        assert_eq!(
            resolver.known.resolve(
                "vm-b.invalid.example",
                Some("10.0.0.2".into()),
                Instant::now()
            ),
            Some("10.0.0.2".to_string())
        );

        let resolved = block_on(resolver.resolve(
            &members,
            family_majority(&members).unwrap_or(AddressType::Ipv4),
        ));
        assert_eq!(
            resolved,
            vec![
                member("a", "10.0.0.1", true),
                member("b", "10.0.0.2", true),
                member("c", "fd00::1", false),
            ]
        );
    }

    /// The exact inventory from the report: two IPv4 literals and one dual-stack hostname whose AAAA
    /// the resolver hands back first (RFC 6724 sorting on a host with global IPv6). Taking the first
    /// answer types that member IPv6, the inventory's family is IPv4 by majority, and `build_slice`
    /// drops the member — a node that publishes fresh, healthy, correctly-signed
    /// reports and receives zero traffic forever, with no transition ever logged for it.
    #[test]
    fn a_dual_stack_hostname_resolves_into_the_inventorys_family_and_stays_in_rotation() {
        let members = [
            member("db-a", "10.0.0.1", true),
            member("db-b", "10.0.0.2", true),
            member("db-c", "vm-dbc.internal", true),
        ];
        let preferred = family_majority(&members).unwrap_or(AddressType::Ipv4);
        assert_eq!(preferred, AddressType::Ipv4);

        // The resolver's answer for vm-dbc.internal, AAAA first.
        let answers = ["fd00::3".parse().unwrap(), "10.0.0.3".parse().unwrap()];
        assert_eq!(
            pick_address(answers.into_iter(), preferred),
            Some("10.0.0.3".to_string())
        );

        let resolved: Vec<Member> = vec![
            members[0].clone(),
            members[1].clone(),
            member("db-c", "10.0.0.3", true),
        ];
        let slice = build_slice("vm-db", "vm-db-updated", "http", 5432, &resolved, preferred);
        assert_eq!(slice.address_type, "IPv4");
        assert_eq!(
            slice.endpoints.len(),
            3,
            "every healthy member must be in the slice"
        );
    }

    /// The choice must be a function of the answer *set*, not of the order it arrived in: a name
    /// with several A records is commonly returned round-robin, and a slice that churns its
    /// endpoint every cycle is endpoint flapping for no reason. Family preference likewise decides
    /// an IPv6-majority inventory the other way, so both slice types are stable.
    #[test]
    fn address_selection_is_independent_of_resolver_order() {
        let answers: Vec<std::net::IpAddr> = ["10.0.0.9", "fd00::3", "10.0.0.3", "fd00::1"]
            .iter()
            .map(|address| address.parse().unwrap())
            .collect();
        for rotation in 0..answers.len() {
            let mut rotated = answers.clone();
            rotated.rotate_left(rotation);
            assert_eq!(
                pick_address(rotated.iter().copied(), AddressType::Ipv4),
                Some("10.0.0.3".to_string())
            );
            assert_eq!(
                pick_address(rotated.iter().copied(), AddressType::Ipv6),
                Some("fd00::1".to_string())
            );
        }
        // A name that answers only in the other family still resolves to what it has — the member
        // is then dropped by `build_slice` with the mixed-family warning, not silently lost here.
        let only_v6: Vec<std::net::IpAddr> = vec!["fd00::7".parse().unwrap()];
        assert_eq!(
            pick_address(only_v6.into_iter(), AddressType::Ipv4),
            Some("fd00::7".to_string())
        );
        // And that ONE off-family member is all that is lost: the family is decided from the
        // literals before resolution, so it cannot enter the count and flip the slice onto the
        // minority — which would evict the three correctly-configured IPv6 members instead.
        let inventory = [
            member("a", "fd00::1", true),
            member("b", "fd00::2", true),
            member("c", "fd00::3", true),
            member("d", "10.0.0.1", true),
            member("e", "10.0.0.2", true),
            member("f", "vm-f.internal", true),
        ];
        let family = family_majority(&inventory).unwrap_or(AddressType::Ipv4);
        assert_eq!(family, AddressType::Ipv6);
        let resolved: Vec<Member> = inventory[..5]
            .iter()
            .cloned()
            .chain([member("f", "10.0.0.3", true)])
            .collect();
        let slice = build_slice("s", "s-updated", "http", 80, &resolved, family);
        assert_eq!(slice.address_type, "IPv6");
        assert_eq!(
            slice.endpoints.len(),
            3,
            "the off-family hostname is the member dropped, never the IPv6 majority"
        );
        assert_eq!(pick_address(std::iter::empty(), AddressType::Ipv4), None);

        // An IPv6-majority inventory resolves its hostnames IPv6, matching how the slice is typed.
        assert_eq!(
            family_majority(&[
                member("a", "fd00::1", true),
                member("b", "fd00::2", true),
                member("c", "10.0.0.1", true),
                member("d", "vm-d.internal", true),
            ]),
            Some(AddressType::Ipv6)
        );
        // A tie goes IPv4.
        assert_eq!(
            family_majority(&[member("a", "fd00::1", true), member("b", "10.0.0.1", true)]),
            Some(AddressType::Ipv4)
        );
    }

    /// An all-hostname inventory — the documented member form for out-of-cluster VMs — on an
    /// IPv6-only fleet. Nothing is misconfigured: every name answers AAAA and only AAAA. Typing the
    /// slice from the pre-resolution inventory reads that as a tie, types it IPv4, and `build_slice`
    /// then drops every single member: the Service is programmed with an empty endpoint set on
    /// every cycle, which for a load balancer is a total outage, not a fail-closed default.
    #[test]
    fn an_all_hostname_inventory_is_typed_by_what_its_names_actually_answer() {
        let inventory = [
            member("a", "vm-a.internal", true),
            member("b", "vm-b.internal", true),
            member("c", "vm-c.internal", true),
        ];
        // Nothing in the inventory has a family, so it cannot answer; resolution falls back to the
        // IPv4 preference, which only decides which answer to take from a name that has both.
        assert_eq!(family_majority(&inventory), None);
        let preferred = family_majority(&inventory).unwrap_or(AddressType::Ipv4);
        assert_eq!(
            pick_address(["fd00::1".parse().unwrap()].into_iter(), preferred),
            Some("fd00::1".to_string()),
            "a name that answers only AAAA still resolves to what it has"
        );

        let resolved = [
            member("a", "fd00::1", true),
            member("b", "fd00::2", true),
            member("c", "fd00::3", true),
        ];
        let family = family_majority(&inventory)
            .or_else(|| family_majority(&resolved))
            .unwrap_or(AddressType::Ipv4);
        assert_eq!(family, AddressType::Ipv6);
        let slice = build_slice("vm-db", "vm-db-updated", "http", 5432, &resolved, family);
        assert_eq!(slice.address_type, "IPv6");
        assert_eq!(
            slice.endpoints.len(),
            3,
            "every member of a correctly-configured IPv6 fleet must stay in rotation"
        );
    }
}
