use std::time::Duration;

/// Each set must hold a full, healthy pool this long before its load balancer starts
/// counting: no synthetic traffic (and no availability) is recorded until the set has
/// actually reached steady-state baseline, so warm-up churn never burns error budget.
pub(crate) const LOAD_STEADY_GRACE: Duration = Duration::from_secs(10);

pub(crate) const DEMO_SET_COUNT: usize = 8;
/// Cohort groups per set. The per-set cap is `DEMO_GROUPS_PER_SET - 1` (the throttle
/// default), so with 2 the control plane rolls at most ONE group per set at a time —
/// every set always keeps its other group serving, even while one rotates.
pub(crate) const DEMO_GROUPS_PER_SET: usize = 2;
/// Managed agents (service pods) per cohort group.
pub(crate) const DEMO_COHORT_SIZE: usize = 2;
/// Groups the control plane keeps rolling at once, fleet-wide. Because the per-set cap is 1,
/// these spread across this many DISTINCT sets (one group each) — never draining a set — and
/// the next starts the instant one settles, so the pipeline stays full across set order.
pub(crate) const DEMO_FLEET_CONCURRENCY: u32 = 4;
/// How long a generation may take to fully settle. Generous, because the chaos mechanism also
/// crashes the controller (recovering only after lease expiry), which stretches rollouts.
pub(crate) const DEMO_SETTLE_TIMEOUT_SECS: usize = 900;
/// How long the convergence that closes an epoch may spend *admitting* (a frozen set's time does
/// not count) before it is called failed.
pub(crate) const DEMO_CONVERGE_TIMEOUT_SECS: usize = 240;
/// The ceiling an automated driver waits one whole epoch out under. An epoch queues every cohort
/// in a single generation (`Demo::select_generation` hands them all over, then `None`), so it is
/// that generation's settle budget plus the convergence that closes the epoch, with a minute of
/// slack for the patches and polling in between. Derived rather than written down: a driver
/// capped below the budget it drives reports "did not converge" for a run that is still healthy
/// and well inside its own documented ceiling.
pub(crate) const DEMO_EPOCH_TIMEOUT_SECS: usize =
    DEMO_SETTLE_TIMEOUT_SECS + DEMO_CONVERGE_TIMEOUT_SECS + 60;

/// Canonical fleet-chaos seed. `exercise` pass 1 (and the one-shot `e2e` verification) use it
/// verbatim; later soak passes derive a distinct, reproducible seed from it (see
/// `exercise_existing_cluster`), so a long soak spans many chaos schedules while any failure stays
/// replayable from its printed seed.
pub(crate) const CHAOS_SEED_BASE: u64 = 20260719;
/// Mixing constant (golden-ratio odd) for spreading derived seeds and per-wave choices.
pub(crate) const CHAOS_SEED_SPREAD: u64 = 0x9E37_79B9_7F4A_7C15;

/// Total cohort groups and total managed agents — derived from the layout above.
pub(crate) const DEMO_COHORT_COUNT: usize = DEMO_SET_COUNT * DEMO_GROUPS_PER_SET;
pub(crate) const DEMO_NODE_COUNT: usize = DEMO_COHORT_COUNT * DEMO_COHORT_SIZE;

/// A slice of the fleet that "pretends" to run outside Kubernetes. These are ordinary agent
/// pods, but *nothing selects them by label*; instead the real `updated-healthproxy` binary —
/// the product path that would front OpenStack/VMware VMs — programs a selectorless Service's
/// EndpointSlice from their CDN health. Their ordinals follow the in-cluster fleet, so
/// [`node_set_index`] returns `None` for them and the per-set machinery (labeler, load
/// balancers, chaos) ignores them entirely. This dogfoods the reconciler end to end.
pub(crate) const DEMO_EXTERNAL_COUNT: usize = 2;
/// The cohort label and UpdateGroup the external agents share (same app as the fleet).
pub(crate) const DEMO_EXTERNAL_COHORT: &str = "external";
/// The selectorless Service whose endpoints the reconciler programs from external health.
pub(crate) const DEMO_EXTERNAL_SERVICE: &str = "external";
/// Total agent pods in the shared StatefulSet: the in-cluster fleet plus the external slice.
pub(crate) const DEMO_TOTAL_AGENTS: usize = DEMO_NODE_COUNT + DEMO_EXTERNAL_COUNT;

/// Ordinal of the i-th external agent (`agent-<n>`), right after the in-cluster fleet.
pub(crate) fn external_ordinal(index: usize) -> usize {
    DEMO_NODE_COUNT + index
}

/// A genuinely out-of-cluster node — a real VM reached over passwordless SSH — provisioned for
/// the live demo by the shipped ansible role (`deploy/ansible`), which builds the agent on the
/// VM and runs it as a systemd service pointed, via a `socat`/`/etc/hosts` shim, at the
/// in-cluster gateway exposed on the laptop's LAN. It enrolls, installs Magnolia, and becomes
/// **the manual Magnolia node** — managed by its own UpdateGroup ([`MAGNOLIA_MANUAL_GROUP`]), with
/// no in-cluster pod standing in for it. Also appears as a real endpoint the reconciler programs. Optional and
/// guarded: skipped unless `DEMO_EXTERNAL_VM` (e.g. `root@10.0.0.206`) is set AND passwordless
/// SSH works. Its Magnolia role reaches the UI as an explicit backend field (`FleetNode::kind`),
/// not by anything reading this name.
pub(crate) const DEMO_EXTERNAL_VM_HOSTNAME: &str = "magnolia-manual-vm";
pub(crate) const DEMO_EXTERNAL_VM_COHORT: &str = "external-vm";
/// LAN port `kubectl port-forward` publishes the in-cluster gateway on for the VM to reach.
pub(crate) const DEMO_EXTERNAL_VM_GATEWAY_PORT: u16 = 18080;
/// Real Magnolia CMS runs as its two standard instance kinds — an `author` cohort (editing)
/// and a `publisher` cohort (public traffic) — each a pair the supervisor upgrades one node at
/// a time with zero downtime. A genuinely complex Java deployment, installed and upgraded by
/// the exact same mechanism as the sample app, but kept outside the convergence/chaos
/// machinery so its slow (~4-min) installs never gate the fast cohorts.
/// Fields: (display role, Magnolia instance, servlet context, replicas).
///
/// The `manual` Magnolia node is the out-of-cluster VM ([`DEMO_EXTERNAL_VM_HOSTNAME`]), not an
/// in-cluster pod, so it is not listed here.
pub(crate) const MAGNOLIA_COHORTS: [(&str, &str, &str, usize); 2] = [
    ("author", "author", "magnoliaAuthor", 2),
    ("publisher", "public", "magnoliaPublic", 2),
];
/// Total in-cluster Magnolia pods — derived from the cohort table above, like every other total
/// in this file, so changing a cohort's replicas cannot silently under-reserve cluster capacity
/// (this feeds [`DEMO_REQUIRED_POD_CAPACITY`]).
pub(crate) const DEMO_MAGNOLIA_TOTAL: usize = magnolia_total();

const fn magnolia_total() -> usize {
    let mut total = 0;
    let mut index = 0;
    while index < MAGNOLIA_COHORTS.len() {
        total += MAGNOLIA_COHORTS[index].3;
        index += 1;
    }
    total
}

/// The updated-managed HAProxy tier: a StatefulSet of this many HAProxy pods, each an ordinary
/// `updated` agent that installs HAProxy from a signed tarball bundle (never a bespoke image) and
/// upgrades it in place via the provider's SIGUSR2 master-worker re-exec. Two replicas so the
/// control plane rolls them one at a time and the front Service always keeps one serving — the
/// zero-downtime story. This is the thesis demonstrator: `updated` managing infrastructure
/// (a load balancer) that fronts real services, which plain Kubernetes rollouts cannot express.
pub(crate) const DEMO_HAPROXY_REPLICAS: usize = 2;
/// The cohort label the HAProxy pods carry and the `haproxy` UpdateGroup selects on. Outside the
/// per-set/fleet throttle and the pod-kill chaos, exactly like the Magnolia tier.
pub(crate) const DEMO_HAPROXY_COHORT: &str = "haproxy";
/// The single HAProxy UpdateGroup that rolls the tier from 1.0.0 → 2.0.0. It owns both HAProxy
/// nodes with `maxUnavailable: 1`, so the group itself caps the tier to ONE node rolling at a time
/// behind the front Service — genuinely zero-downtime, with no synthetic set/group split.
pub(crate) const DEMO_HAPROXY_GROUP: &str = "haproxy";
/// The HAProxy `backend` section whose server membership the HAProxy-mode healthproxy programs
/// from signed CDN health (`set server <backend>/<node> state ready|drain`).
pub(crate) const DEMO_HAPROXY_BACKEND: &str = "fleet";
/// TCP port each HAProxy exposes its admin runtime API (stats socket) on, reachable in-cluster at
/// `haproxy-<n>.agents:<port>` so the healthproxy can flip backend server state.
pub(crate) const DEMO_HAPROXY_ADMIN_PORT: u16 = 9999;
/// The ClusterIP Service that fans traffic across the HAProxy pods — the fleet's front door. The
/// synthetic load test drives it across the HAProxy upgrade to prove zero dropped requests.
pub(crate) const DEMO_HAPROXY_FRONT_SERVICE: &str = "haproxy-front";
/// The two release versions the HAProxy tier demonstrates an in-place upgrade between.
pub(crate) const DEMO_HAPROXY_V1: &str = "1.0.0";
pub(crate) const DEMO_HAPROXY_V2: &str = "2.0.0";
/// Annotation on the `haproxy` UpdateGroup carrying the pre-published 2.0.0 target the e2e upgrade
/// patches in — so the bytes are signed and in the store up front and the upgrade is a pure group
/// patch, never a live publish.
pub(crate) const DEMO_HAPROXY_NEXT_PATH_ANNOTATION: &str = "demo.updated.dev/next-path";
pub(crate) const DEMO_HAPROXY_NEXT_SHA_ANNOTATION: &str = "demo.updated.dev/next-sha256";
/// The group that manages the out-of-cluster VM ([`DEMO_EXTERNAL_VM_HOSTNAME`]) — a node with no
/// Kubernetes pod behind it, held at its baseline by the same mechanism as every in-cluster
/// cohort. Nothing rolls it: it is the demo's proof that management is not pod-shaped.
pub(crate) const MAGNOLIA_MANUAL_GROUP: &str = "magnolia-manual";
/// Extra pods the HAProxy tier consumes: the HAProxy replicas plus the one HAProxy-mode
/// healthproxy Deployment that programs their backend membership.
pub(crate) const DEMO_HAPROXY_TOTAL: usize = DEMO_HAPROXY_REPLICAS + 1;
pub(crate) const DEMO_REQUIRED_POD_CAPACITY: usize =
    DEMO_TOTAL_AGENTS + DEMO_MAGNOLIA_TOTAL + DEMO_HAPROXY_TOTAL + 40;

/// Serving pods a set is guaranteed to keep while it rolls: total pods minus the pods of the
/// at-most-one group the per-set cap lets roll (`gps - 1` groups). Chaos never enters this
/// floor because it disrupts exactly that one group (`Demo::inject_chaos` picks a single group
/// per set) and only deletes pods that are ALREADY draining (out of the load balancer), so it
/// cannot reduce serving capacity. Must stay `>= 1` for 100% uptime — a compile error here means
/// the layout would drain a set.
pub(crate) const DEMO_UPTIME_MARGIN: usize = (DEMO_GROUPS_PER_SET - 1) * DEMO_COHORT_SIZE;
// Written as "the groups that are NOT rolling", which is what the floor actually is. Subtracting
// the rolling groups from the total the other way around yields the *rolling* count — a value that
// is `>= 1` whenever the cohort is non-empty, so the assertion held no matter how the layout was
// configured, including a one-group-per-set layout that drains a set completely.
const _: () = assert!(
    DEMO_UPTIME_MARGIN >= 1,
    "demo layout would drain a set below its SLA: increase DEMO_COHORT_SIZE or DEMO_GROUPS_PER_SET"
);

/// Availability objective the demo publicly holds the fleet to, as a percentage. The live
/// service-level panel burns an error budget against this line as chaos kills pods and
/// rollouts churn the fleet — the whole point is that a correct drain keeps it green.
pub(crate) const DEMO_SLA_TARGET: f64 = 99.5;
/// Rolling window the golden signals are computed over.
pub(crate) const LOAD_WINDOW: Duration = Duration::from_secs(30);
/// Each set has its own readiness-respecting load balancer: this many synthetic workers
/// per set each pick a currently-ready endpoint *within that set* and pace themselves so
/// every set sees steady, independent load.
pub(crate) const LOAD_WORKERS_PER_SET: usize = 3;
pub(crate) const LOAD_REQUEST_TIMEOUT: Duration = Duration::from_millis(800);
/// How often the load balancer's view of the ready endpoint set is refreshed.
pub(crate) const LOAD_READY_REFRESH: Duration = Duration::from_millis(300);

/// A readiness watch that has gone this long without a successful event or relist is treated as
/// stalled: [`Demo::fleet`] and [`Demo::ready_endpoints`] then report every node OUT (fail
/// closed) instead of serving the frozen last-known membership as authoritative — otherwise a
/// prolonged API outage could hide a real drain or forge a premature settle on a stale IN.
/// Generous relative to the watcher's ~1s reconnect pause, so a routine reconnect never flaps
/// the fleet.
pub(crate) const READINESS_WATCH_STALE: Duration = Duration::from_secs(30);

pub(crate) fn cohort_label(index: usize) -> String {
    format!("cohort-{index:02}")
}

pub(crate) fn cohort_group(index: usize) -> String {
    format!("demo-{}", cohort_label(index))
}

/// The display set a cohort belongs to — sets are contiguous runs of
/// [`DEMO_GROUPS_PER_SET`] cohorts. A set is a UI box with its own load balancer, NOT a
/// throttle; concurrency is fleet-wide (see [`DEMO_FLEET_SET`]).
pub(crate) fn cohort_set_index(index: usize) -> usize {
    index / DEMO_GROUPS_PER_SET
}

/// The display set a fleet node (`agent-<ordinal>`) belongs to, via its cohort. `None`
/// for a name that does not parse or lands outside the demo's sets.
pub(crate) fn node_set_index(node: &str) -> Option<usize> {
    let ordinal: usize = node.strip_prefix("agent-")?.parse().ok()?;
    let set = cohort_set_index(ordinal / DEMO_COHORT_SIZE);
    (set < DEMO_SET_COUNT).then_some(set)
}

/// The cohort group a fleet node (`agent-<ordinal>`) belongs to — its global group index.
/// Chaos uses it to bound disruption to at most one group per set. `None` for a name that does
/// not parse or lands outside the demo's cohorts.
pub(crate) fn node_cohort_index(node: &str) -> Option<usize> {
    let ordinal: usize = node.strip_prefix("agent-")?.parse().ok()?;
    let cohort = ordinal / DEMO_COHORT_SIZE;
    (cohort < DEMO_COHORT_COUNT).then_some(cohort)
}

/// The display-set name a cohort group carries as its `set` label, so the UI can box its
/// groups together and give each set its own load balancer.
pub(crate) fn set_name(set: usize) -> String {
    format!("demo-set-{set:02}")
}

/// Label key marking which display set a cohort group belongs to (UI grouping only).
pub(crate) const SET_LABEL: &str = "demo.updated.dev/set";

/// The single fleet-wide throttle set: every managed group belongs to it, and the control
/// plane keeps at most [`DEMO_FLEET_CONCURRENCY`] groups rolling at once, admitting the next
/// (in set order) the instant one settles. So the rollout pipelines across set boundaries
/// instead of pausing set-by-set — as a group completes, the next queued group starts
/// immediately. This is the "cross-group merge": one cap over the fleet.
pub(crate) const DEMO_FLEET_SET: &str = "demo-fleet";
pub(crate) const DEMO_FLEET_LABEL: &str = "demo.updated.dev/fleet";
pub(crate) const DEMO_FLEET_VALUE: &str = "managed";

/// Where cohort agents write their rollout telemetry — the in-cluster routing gateway. The
/// gateway admits only fleet-CA client certs, so this is https and every node PUTs under its
/// own mTLS identity (the same one it fetches its repository with); the gateway persists each
/// report to the object store the operator reads. Signed into every group's deployment so the
/// control plane can gate rollouts on real node health.
pub(crate) const DEMO_REPORT_URL: &str = "https://updatec-gateway";

/// Where readers (the healthproxy) fetch persisted telemetry — the MinIO object store the
/// gateway writes reports into, read directly as the CDN. This is the read side of the split:
/// nodes *write* over mTLS to the gateway ([`DEMO_REPORT_URL`]); readers *read* the resulting
/// `<base>/telemetry/<node>.json` from the store. Anonymous read is enabled on the bucket.
///
/// The path is `<bucket>/<repository s3.prefix>`: the gateway persists each report under the
/// repository's own object-store prefix (`<prefix>/telemetry/<node>.json`), the same prefix the
/// controller reads them back through. Pointing this at the bucket root instead would 404 every
/// report and silently drain the whole fleet, so it must track the demo repository's spec.
pub(crate) const DEMO_HEALTH_CDN: &str = "http://minio:9000/updates/routing";

/// The demo's release repository in the in-cluster MinIO — the ONE place its location is written
/// down. Everything that publishes into it (`updatectl` inside the release-server pod, and the
/// demo's own `updatectl deploy`) and everything that resolves out of it (each group's signed
/// `releaseRepository`) is built from these, so a publish cannot land somewhere the signed
/// repository does not name.
pub(crate) const DEMO_RELEASE_ENDPOINT: &str = "http://minio:9000";
pub(crate) const DEMO_RELEASE_BUCKET: &str = "updates";
pub(crate) const DEMO_RELEASE_PREFIX: &str = "releases";
pub(crate) const DEMO_RELEASE_REGION: &str = "us-east-1";

/// The flags every `updatectl` invocation addresses that repository with.
pub(crate) fn release_repository_flags() -> String {
    format!(
        "--bucket {DEMO_RELEASE_BUCKET} --prefix {DEMO_RELEASE_PREFIX} \
         --endpoint {DEMO_RELEASE_ENDPOINT} --region {DEMO_RELEASE_REGION}"
    )
}

/// The URL a group's signed `releaseRepository` resolves `namespace` (`metadata`/`targets`) from.
pub(crate) fn release_repository_url(namespace: &str) -> String {
    format!("{DEMO_RELEASE_ENDPOINT}/{DEMO_RELEASE_BUCKET}/{DEMO_RELEASE_PREFIX}/{namespace}/")
}

/// In-cluster base URL of the ingress the synthetic load test drives. Each set's traffic
/// enters at `<base>/set-<n>/…`; the ingress routes it to that set's Service, whose selector
/// admits only that set's pods — so Kubernetes, not the demo, enforces that no other set's
/// pod can ever answer for a set. Points at the ingress-nginx controller Service.
pub(crate) const DEMO_INGRESS_URL: &str = "http://ingress-nginx-controller.ingress-nginx";

/// Name of the per-set ClusterIP Service the ingress routes a set's traffic to. Distinct
/// from the set's `UpdateGroupSet` (a throttle CR) though both concern the same set.
pub(crate) fn set_service_name(set: usize) -> String {
    format!("demo-lb-set-{set:02}")
}

/// Major component of a `MAJOR.0.0` demo version, if parseable.
pub(crate) fn version_major(version: &str) -> Option<usize> {
    version.split('.').next()?.parse().ok()
}

/// Cap the retained event log so a long-running demo does not grow unbounded.
pub(crate) fn trim_events(events: &mut Vec<String>) {
    const MAX_EVENTS: usize = 100;
    if events.len() > MAX_EVENTS {
        let remove = events.len() - MAX_EVENTS;
        events.drain(..remove);
    }
}

/// Deterministic PRNG (splitmix64). Chaos choices derive from the rollout seed so a
/// run reproduces exactly while still varying per generation; no wall-clock entropy.
pub(crate) fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The fleet-wide rollout width (`maxConcurrent`) for one wave, deterministic from its seed so a
/// run replays exactly. Ranges over `[DEMO_FLEET_CONCURRENCY, DEMO_SET_COUNT]` — from the baseline
/// concurrency up to the structural ceiling of one rolling group per set (above `DEMO_SET_COUNT`
/// the per-set cap would silently clamp it anyway). The per-set cap keeps every set's other group
/// serving at ANY width in this range, so uptime stays 100% even at the ceiling; a wider wave only
/// piles more simultaneous rollouts onto the (chaos-crashed) controller.
pub(crate) fn fleet_rollout_width(seed: u64) -> u32 {
    let span = (DEMO_SET_COUNT - DEMO_FLEET_CONCURRENCY as usize + 1) as u64;
    let offset = (seed.wrapping_mul(CHAOS_SEED_SPREAD) >> 33) % span;
    DEMO_FLEET_CONCURRENCY + offset as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn fleet_rollout_width_stays_in_the_uptime_safe_band_and_spans_it() {
        // Every wave's width must sit in [baseline concurrency, one rolling group per set]. Below
        // the floor it would not be a real rollout; above DEMO_SET_COUNT the per-set cap would
        // clamp it and the "every set keeps its other group serving" (100% uptime) reasoning breaks.
        let band: Vec<u32> = (DEMO_FLEET_CONCURRENCY..=DEMO_SET_COUNT as u32).collect();
        let mut seen = BTreeSet::new();
        for seed in 0..10_000u64 {
            let w = fleet_rollout_width(seed);
            assert!(
                band.contains(&w),
                "width {w} out of the uptime-safe band for seed {seed}"
            );
            seen.insert(w);
        }
        // ...and it actually varies across the whole band, not stuck on one value.
        assert_eq!(seen.into_iter().collect::<Vec<_>>(), band);
    }

    /// The one repository spec the demo/e2e cluster applies. The healthproxy reads the reports
    /// the gateway writes *into that repository's object-store location*, so this test is against
    /// the spec source rather than a copy of its literals.
    const REPOSITORY_SPEC: &str = include_str!("../../updatec/examples/kind_resources.rs");

    fn spec_field(field: &str) -> String {
        let block = REPOSITORY_SPEC
            .split_once("s3: S3Destination {")
            .expect("repository spec declares an S3 destination")
            .1;
        let value = block
            .split_once(&format!("{field}: "))
            .unwrap_or_else(|| panic!("S3 destination declares {field}"))
            .1;
        let quoted = value
            .split_once('"')
            .expect("field value is a string literal")
            .1;
        quoted
            .split_once('"')
            .expect("field value is a string literal")
            .0
            .to_string()
    }

    #[test]
    fn health_cdn_addresses_the_prefix_the_gateway_writes_reports_under() {
        // The gateway persists a node report at `<s3.prefix>/telemetry/<node>.json` inside the
        // repository's bucket, and the healthproxy fetches `<health base>/telemetry/<node>.json`.
        // If the base omits the prefix, every GET 404s, no report is ever cached, and every node
        // is programmed `ready: false` forever — silently draining the entire external LB path.
        let endpoint = spec_field("endpoint");
        let bucket = spec_field("bucket");
        let prefix = spec_field("prefix");
        assert_eq!(DEMO_HEALTH_CDN, format!("{endpoint}/{bucket}/{prefix}"));

        let node = "demo-node-01";
        assert_eq!(
            format!("{DEMO_HEALTH_CDN}/telemetry/{node}.json"),
            format!("{endpoint}/{bucket}/{prefix}/telemetry/{node}.json"),
        );
    }
}
