//! The Kubernetes [`LoadBalancer`] backend: program a selectorless Service's EndpointSlice
//! from health, and let kube-proxy do the forwarding. A node's report going unhealthy flips
//! its endpoint to not-ready, which drains it from the Service with no data-path hop of ours.
//!
//! This is the first backend; DNS and HAProxy are future implementations of the same
//! [`LoadBalancer`] trait, driven by the identical health→membership core.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
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
    /// The address each hostname member last resolved to, so a DNS blip on this side does not
    /// evict a healthy node (see [`resolve_addresses`]).
    resolved: tokio::sync::Mutex<LastKnownGood<String>>,
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
            resolved: tokio::sync::Mutex::new(LastKnownGood::new()),
        }
    }

    /// The single slice we manage for the Service. One slice suffices well past any fleet
    /// this fronts (EndpointSlices hold up to 1000 endpoints).
    fn slice_name(&self) -> String {
        format!("{}-updated", self.service)
    }
}

#[async_trait::async_trait]
impl LoadBalancer for EndpointSliceLb {
    async fn reconcile(&self, members: &[Member]) -> Result<(), String> {
        let name = self.slice_name();
        let members = resolve_addresses(members, &mut *self.resolved.lock().await).await;
        let slice = build_slice(&self.service, &name, &self.port_name, self.port, &members);
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
        let error = match self.apply(&name, &slice).await {
            Ok(()) => return Ok(()),
            Err(error) => error,
        };
        // `addressType` is immutable, and `force()` resolves field-manager conflicts, not
        // validation: once the inventory's family flips (IPv4 → IPv6), every future apply is
        // rejected with a 422 that no retry can clear, and membership silently freezes at whatever
        // was last programmed. Replacing the slice is the only way through. It is ours (we own the
        // name and the field manager), so deleting it costs one reconcile interval of the endpoints
        // it held.
        //
        // Only for a genuine family flip, though — 422 is the apiserver's generic Invalid, and the
        // destructive recovery must not run for a rejection it cannot fix (crossing the
        // 1000-endpoint ceiling, an over-long service-name label). Those delete the slice and then
        // fail the re-apply identically, leaving the Service with ZERO endpoints where the ordinary
        // error path keeps the last good membership programmed. So the observed slice's address
        // type is what decides, not the status code alone.
        //
        // The status code is checked FIRST because reading the slice costs an apiserver round trip
        // out of the same reconcile deadline the failed apply already spent from. A 409, a 403, or a
        // transport failure cannot be a family flip whatever the read returns, so paying for that
        // read on every failure only doubles the request rate against an apiserver that is already
        // unwell.
        if !is_invalid_rejection(&error) {
            return Err(error.to_string());
        }
        let observed = match self.api.get_opt(&name).await {
            Ok(observed) => observed,
            // Without the slice as the apiserver holds it there is no positive evidence of a flip,
            // so this falls back to the ordinary error path — which for a real flip is the
            // permanently-frozen membership this recovery exists to break. Say so: silence here
            // reads exactly like an ordinary rejection while the Service quietly stops converging.
            Err(read_error) => {
                eprintln!(
                    "healthproxy: {} slice apply was refused as invalid and the slice could not be read back ({read_error}); not replacing it",
                    self.service
                );
                return Err(error.to_string());
            }
        };
        if !is_address_type_flip(observed.as_ref(), &slice.address_type) {
            return Err(error.to_string());
        }
        eprintln!(
            "healthproxy: {} slice must change address type to {}; replacing it",
            self.service, slice.address_type
        );
        if let Err(delete_error) = self.api.delete(&name, &Default::default()).await {
            return Err(format!(
                "replacing the {} slice for a new address type: {delete_error}",
                self.service
            ));
        }
        self.apply(&name, &slice)
            .await
            .map_err(|error| error.to_string())
    }
}

impl EndpointSliceLb {
    async fn apply(&self, name: &str, slice: &EndpointSlice) -> Result<(), kube::Error> {
        self.api
            .patch(
                name,
                &PatchParams::apply(MANAGED_BY).force(),
                &Patch::Apply(slice),
            )
            .await
            .map(|_| ())
    }
}

/// Whether a failed apply is the apiserver's generic Invalid. Necessary but nowhere near sufficient
/// for a family flip; it is the cheap half, and it gates the expensive half — a conflict, a
/// permission error, or a transport failure is answered without spending a second round trip on the
/// apiserver that just refused the first.
fn is_invalid_rejection(error: &kube::Error) -> bool {
    matches!(error, kube::Error::Api(response) if response.code == 422)
}

/// Whether the slice the apiserver already holds is typed for another address family — the one
/// rejection replacing the slice actually resolves, given a 422 the caller has already matched.
///
/// The status code alone is not evidence: 422 is the generic Invalid, and every other cause of one
/// survives the delete, so acting on the code alone destroys the programmed membership and re-fails.
/// `observed` is the slice as the apiserver holds it (`None` when it does not exist); without
/// positive evidence of a family flip the ordinary error path retries against the existing object
/// instead of deleting it.
fn is_address_type_flip(observed: Option<&EndpointSlice>, desired: &str) -> bool {
    observed.is_some_and(|slice| slice.address_type != desired)
}

/// Replace every hostname member with a resolved IP literal, dropping any for which no address is
/// known.
///
/// Kubernetes accepts an `FQDN` EndpointSlice but **kube-proxy does not implement that address
/// type**, so a hostname slice programs zero working endpoints while every apply succeeds and
/// every log line looks healthy — the worst failure shape there is. Members are documented as
/// bare hostnames for out-of-cluster VMs, so the names are resolved here, each cycle, and the
/// slice only ever carries addresses kube-proxy can actually route.
///
/// A lookup that fails falls back to the address the name last resolved to, through the same
/// [`LastKnownGood`] policy the report fetch uses: a resolver hiccup on this side is not evidence
/// the node moved or went down, and without the fallback one SERVFAIL cycle empties the Service's
/// backend set entirely. It stays fail-closed — a name that has not resolved within
/// [`LastKnownGood::STALENESS`] leaves its member out of rotation.
///
/// The lookups run concurrently and each is bounded by [`lookup_timeout`], because a resolver that
/// *hangs* rather than answering is not the same event as one that SERVFAILs: the last-known-good
/// fallback only sees lookups that return. Serialized, unbounded lookups let one blackholed name
/// spend the whole reconcile deadline this runs inside, so `build_slice`/apply never runs at all and
/// membership freezes at whatever was last programmed — identically every cycle, since the walk
/// restarts at the same name. Bounding each lookup and fanning them out turns that into the ordinary
/// fail-closed path: the name falls back to its last known address and ages out on schedule.
async fn resolve_addresses(members: &[Member], known: &mut LastKnownGood<String>) -> Vec<Member> {
    use futures::stream::StreamExt;
    let hostnames: Vec<usize> = members
        .iter()
        .enumerate()
        .filter(|(_, member)| AddressType::of(&member.address) == AddressType::Fqdn)
        .map(|(index, _)| index)
        .collect();
    // Concurrent, cache-free lookup pass, each result tagged with its member index to restore the
    // configured order afterward (the programmed set must be stable). Every name is resolved into
    // the same family the rest of the inventory already uses, so a dual-stack name cannot be typed
    // out of the slice it belongs in (see [`preferred_family`]).
    let budget = lookup_timeout(hostnames.len());
    let preferred = preferred_family(members);
    let looked_up: Vec<(usize, Option<String>)> =
        futures::stream::iter(hostnames.into_iter().map(|index| async move {
            (index, lookup_one(&members[index], budget, preferred).await)
        }))
        .buffer_unordered(crate::FANOUT_CONCURRENCY)
        .collect()
        .await;
    let mut fresh: Vec<Option<String>> = vec![None; members.len()];
    for (index, address) in looked_up {
        fresh[index] = address;
    }
    // Sequential resolve pass: a fresh lookup updates the cache, a failed or timed-out one falls
    // back to the last known address, and a name with neither leaves its member out of rotation.
    let now = Instant::now();
    let mut resolved = Vec::with_capacity(members.len());
    for (member, fresh) in members.iter().zip(fresh) {
        if AddressType::of(&member.address) != AddressType::Fqdn {
            resolved.push(member.clone());
            continue;
        }
        match known.resolve(&member.address, fresh, now) {
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
    resolved
}

/// Resolve one hostname member to an address literal of the `preferred` family within `budget`, or
/// `None` for the caller's last-known-good fallback. A lookup that hangs and one that errors are the
/// same event here: this checker could not determine the address right now.
async fn lookup_one(member: &Member, budget: Duration, preferred: AddressType) -> Option<String> {
    // The port is irrelevant to the lookup; the Service owns it.
    let lookup = tokio::net::lookup_host((member.address.as_str(), 0));
    match tokio::time::timeout(budget, lookup).await {
        Ok(Ok(addresses)) => pick_address(addresses.map(|address| address.ip()), preferred),
        Ok(Err(error)) => {
            eprintln!(
                "healthproxy: resolving {} ({}) failed ({error}); using its last known address",
                member.node, member.address
            );
            None
        }
        Err(_) => {
            eprintln!(
                "healthproxy: resolving {} ({}) timed out after {}ms; using its last known address",
                member.node,
                member.address,
                budget.as_millis()
            );
            None
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

/// The family hostname members are resolved into: the family the inventory's *literal* members
/// already use, by majority, ties and an all-hostname inventory going IPv4.
///
/// The same rule and the same tie-break as [`slice_address_type`], deliberately: a hostname resolved
/// into the family the slice will be typed as is a member that actually routes, and one resolved
/// into the other family is a member that is silently dropped. Deriving it from the literals only —
/// never from this cycle's resolution results — is what makes it stable: the preference cannot
/// itself depend on the resolver order it exists to neutralize.
fn preferred_family(members: &[Member]) -> AddressType {
    let (mut ipv4, mut ipv6) = (0usize, 0usize);
    for member in members {
        match AddressType::of(&member.address) {
            AddressType::Ipv4 => ipv4 += 1,
            AddressType::Ipv6 => ipv6 += 1,
            AddressType::Fqdn => {}
        }
    }
    if ipv6 > ipv4 {
        AddressType::Ipv6
    } else {
        AddressType::Ipv4
    }
}

/// The longest one hostname lookup may take, whatever the inventory size. `getaddrinfo` against a
/// blackholed resolver commonly blocks for tens of seconds, so a single hung name must not stall the
/// rest even when there is budget to spare.
const NAME_LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);

/// The share of [`crate::RECONCILE_TIMEOUT`] the whole resolve pass may spend, as a divisor: half,
/// leaving the other half for the apply that actually programs the slice. Resolution is only the
/// prelude — a resolve pass that consumes the whole deadline reconciles nothing at all.
const RESOLVE_SHARE: u32 = 2;

/// The budget for one lookup when `names` hostnames are resolved this reconcile.
///
/// Derived, not written down, for the same reason the HAProxy backend's exchange budget is: the pass
/// runs [`crate::FANOUT_CONCURRENCY`] wide, so `names` take `ceil(names / width)` waves, and a
/// per-lookup timeout picked independently of the outer deadline holds only for as many names as it
/// happens to cover — one inventory larger than that and the waves past the deadline are never
/// resolved, on every cycle, because the walk restarts at the same leading names.
fn lookup_timeout(names: usize) -> Duration {
    let waves = names.div_ceil(crate::FANOUT_CONCURRENCY).max(1) as u32;
    NAME_LOOKUP_TIMEOUT.min(crate::RECONCILE_TIMEOUT / RESOLVE_SHARE / waves)
}

/// Build the desired EndpointSlice for a set of members. Pure, so the mapping from health to
/// endpoints (addresses, ready conditions, the service-name label kube-proxy keys on) is
/// tested without a cluster.
///
/// An EndpointSlice is single-address-typed, so a mixed inventory (IPv4 plus IPv6 members) cannot
/// go in one slice: it is partitioned to one family ([`slice_address_type`]) and any member of
/// another family is dropped, i.e. left out of rotation (fail closed). Such a mix is a
/// misconfiguration; the reconcile loop logs the drop.
///
/// Members reach here as IP literals — [`resolve_addresses`] has already turned any hostname into
/// one — because kube-proxy does not route `FQDN` slices.
pub fn build_slice(
    service: &str,
    slice_name: &str,
    port_name: &str,
    port: u16,
    members: &[Member],
) -> EndpointSlice {
    let address_type = slice_address_type(members);
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
}

/// The one family the slice is typed as: the family the most members share, so a mixed inventory
/// keeps its largest partition and drops the rest rather than emitting a mismatched endpoint. Ties
/// break IPv4 → IPv6 for a deterministic slice. An empty inventory types as IPv4 (an empty slice,
/// draining everything — fail closed).
///
/// Only the two IP families are candidates: `resolve_addresses` has already turned every hostname
/// into a literal (kube-proxy does not route `FQDN` slices) or dropped it, so typing a slice FQDN
/// would produce a slice that is accepted and then silently routes nothing.
fn slice_address_type(members: &[Member]) -> AddressType {
    let ipv6 = members
        .iter()
        .filter(|member| AddressType::of(&member.address) == AddressType::Ipv6)
        .count();
    if ipv6 * 2 > members.len() {
        AddressType::Ipv6
    } else {
        AddressType::Ipv4
    }
}

#[cfg(test)]
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
        let slice = build_slice("vm-db", "vm-db-updated", "http", 5432, &members);

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

    /// Deleting the slice is only ever right for the immutable-`addressType` case. 422 is the
    /// apiserver's generic Invalid — crossing the 1000-endpoint ceiling or carrying an over-long
    /// service-name label produces one too — and for those the delete destroys the programmed
    /// membership and the re-apply fails identically, leaving the Service with zero endpoints where
    /// the ordinary error path would have kept the last good membership.
    #[test]
    fn only_a_genuine_address_family_flip_replaces_the_slice() {
        let rejection = |code: u16| {
            kube::Error::Api(kube::core::ErrorResponse {
                status: "Failure".to_string(),
                message: "EndpointSlice is invalid".to_string(),
                reason: "Invalid".to_string(),
                code,
            })
        };
        let typed = |address_type: &str| EndpointSlice {
            address_type: address_type.to_string(),
            ..Default::default()
        };

        // A conflict or a permission error is answered by the cheap half alone — no slice read, and
        // therefore no second request against an apiserver that just refused the first.
        assert!(!is_invalid_rejection(&rejection(409)));
        assert!(!is_invalid_rejection(&rejection(403)));
        assert!(is_invalid_rejection(&rejection(422)));

        // The family genuinely flipped: no retry can clear it, so the slice is replaced.
        assert!(is_address_type_flip(Some(&typed("IPv4")), "IPv6"));
        // A 422 with any other cause: the existing slice is already the desired family, so
        // destroying it fixes nothing.
        assert!(!is_address_type_flip(Some(&typed("IPv4")), "IPv4"));
        // No slice is no evidence of a flip.
        assert!(!is_address_type_flip(None, "IPv6"));
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
        let mut known = LastKnownGood::new();
        let members = block_on(resolve_addresses(
            &[member("db", "vm-db.invalid.example", true)],
            &mut known,
        ));
        assert!(members.is_empty(), "a never-resolved member is dropped");

        let slice = build_slice("s", "s-updated", "http", 80, &members);
        assert_eq!(slice.address_type, "IPv4");
        assert!(slice.endpoints.is_empty());
    }

    /// A resolver hiccup on this side is not evidence a node moved or went down. Without the
    /// last-known-good fallback, one SERVFAIL cycle empties the Service's backend set entirely
    /// while every node is still publishing fresh, healthy, signed reports.
    #[test]
    fn a_dns_failure_keeps_the_last_known_address_in_rotation() {
        let members = [member("db", "vm-db.invalid.example", true)];
        let mut known = LastKnownGood::new();
        // Seed what a successful cycle would have recorded for this name.
        assert_eq!(
            known.resolve(
                "vm-db.invalid.example",
                Some("10.0.0.7".into()),
                Instant::now()
            ),
            Some("10.0.0.7".to_string())
        );

        // This lookup genuinely fails (`.invalid` never resolves) — the member must survive it.
        let resolved = block_on(resolve_addresses(&members, &mut known));
        assert_eq!(
            resolved,
            vec![member("db", "10.0.0.7", true)],
            "a checker-side DNS failure must not drain a healthy node"
        );
        let slice = build_slice("s", "s-updated", "http", 80, &resolved);
        assert_eq!(slice.endpoints.len(), 1);
    }

    /// A resolver that hangs instead of answering must cost one member's fallback, not the whole
    /// reconcile: the resolve pass has to leave the apply that programs the slice enough of the
    /// deadline to run, at EVERY inventory size, or membership freezes at the last programmed set
    /// identically every cycle behind a single "timed out" line.
    #[test]
    fn the_resolve_pass_leaves_the_apply_room_inside_the_reconcile_deadline_at_every_size() {
        for names in [0, 1, crate::FANOUT_CONCURRENCY, 96, 1000, 100_000] {
            let waves = names.div_ceil(crate::FANOUT_CONCURRENCY).max(1) as u32;
            assert!(
                lookup_timeout(names) * waves <= crate::RECONCILE_TIMEOUT / RESOLVE_SHARE,
                "{names} names take {waves} wave(s) of {:?}, past the {:?} resolve share",
                lookup_timeout(names),
                crate::RECONCILE_TIMEOUT / RESOLVE_SHARE
            );
            assert!(lookup_timeout(names) > Duration::ZERO);
        }
        // Small inventories are bounded by the per-lookup ceiling, not by the share.
        assert_eq!(lookup_timeout(1), NAME_LOOKUP_TIMEOUT);
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
        let mut known = LastKnownGood::new();
        assert_eq!(
            known.resolve(
                "vm-b.invalid.example",
                Some("10.0.0.2".into()),
                Instant::now()
            ),
            Some("10.0.0.2".to_string())
        );

        let resolved = block_on(resolve_addresses(&members, &mut known));
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
    /// answer types that member IPv6, `slice_address_type` still types the slice IPv4 by majority,
    /// and `build_slice` drops the member — a node that publishes fresh, healthy, correctly-signed
    /// reports and receives zero traffic forever, with no transition ever logged for it.
    #[test]
    fn a_dual_stack_hostname_resolves_into_the_inventorys_family_and_stays_in_rotation() {
        let members = [
            member("db-a", "10.0.0.1", true),
            member("db-b", "10.0.0.2", true),
            member("db-c", "vm-dbc.internal", true),
        ];
        let preferred = preferred_family(&members);
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
        let slice = build_slice("vm-db", "vm-db-updated", "http", 5432, &resolved);
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
        assert_eq!(pick_address(std::iter::empty(), AddressType::Ipv4), None);

        // An IPv6-majority inventory resolves its hostnames IPv6, matching how the slice is typed.
        assert_eq!(
            preferred_family(&[
                member("a", "fd00::1", true),
                member("b", "fd00::2", true),
                member("c", "10.0.0.1", true),
                member("d", "vm-d.internal", true),
            ]),
            AddressType::Ipv6
        );
        // Ties and an all-hostname inventory go IPv4, the same tie-break the slice type uses.
        assert_eq!(
            preferred_family(&[member("a", "fd00::1", true), member("b", "10.0.0.1", true)]),
            AddressType::Ipv4
        );
        assert_eq!(
            preferred_family(&[member("a", "vm-a.internal", true)]),
            AddressType::Ipv4
        );
    }
}
