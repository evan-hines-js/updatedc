/// The namespace every resource this e2e touches lives in — the one the operator's kind
/// environment (`scripts/kind-updatec-e2e.sh`) installs into.
pub(crate) const NAMESPACE: &str = "updated-system";

pub(crate) const SET_COUNT: usize = 8;
/// Cohort groups per set. The per-set cap is `GROUPS_PER_SET - 1` (the throttle default), so
/// with 2 the control plane rolls at most ONE group per set at a time — every set always keeps
/// its other group serving, even while one rotates.
pub(crate) const GROUPS_PER_SET: usize = 2;
/// Managed agents (service pods) per cohort group.
pub(crate) const COHORT_SIZE: usize = 2;
/// Groups the control plane keeps rolling at once, fleet-wide. Because the per-set cap is 1,
/// these spread across this many DISTINCT sets (one group each) — never draining a set — and
/// the next starts the instant one settles, so the pipeline stays full across set order.
pub(crate) const FLEET_CONCURRENCY: u32 = 4;
/// How long any fleet-wide rollout of all [`COHORT_COUNT`] groups may take. One budget, because
/// every such rollout is the same work: each node runs the full enterprise lifecycle transaction
/// (two dwells, the workload stop/start, the health gate), paced [`FLEET_CONCURRENCY`] groups at a
/// time with at most one per set — and the chaos mechanism also crashes the controller, which
/// recovers only after lease expiry. Sized for the whole pipelined rollout, not one group's.
pub(crate) const FLEET_ROLLOUT_TIMEOUT_SECS: usize = 900;

/// The fleet-chaos seed. Every chaos choice — kill timing, controller-crash rounds, victim pods,
/// and per-wave rollout width — derives from it, so a failure replays exactly.
pub(crate) const CHAOS_SEED: u64 = 20260719;
/// Mixing constant (golden-ratio odd) for spreading per-wave choices.
pub(crate) const CHAOS_SEED_SPREAD: u64 = 0x9E37_79B9_7F4A_7C15;

/// Total cohort groups and total managed agents — derived from the layout above.
pub(crate) const COHORT_COUNT: usize = SET_COUNT * GROUPS_PER_SET;
pub(crate) const NODE_COUNT: usize = COHORT_COUNT * COHORT_SIZE;

/// A slice of the fleet that "pretends" to run outside Kubernetes. These are ordinary agent
/// pods, but *nothing selects them by label*; instead the real `updated-healthproxy` binary —
/// the product path that would front OpenStack/VMware VMs — programs a selectorless Service's
/// EndpointSlice from their CDN health. Their ordinals follow the in-cluster fleet, so
/// [`node_set_index`] returns `None` for them and the per-set machinery (labeler, chaos)
/// ignores them entirely. This dogfoods the reconciler end to end.
pub(crate) const EXTERNAL_COUNT: usize = 2;
/// The cohort label and UpdateGroup the external agents share (same app as the fleet).
pub(crate) const EXTERNAL_COHORT: &str = "external";
/// The selectorless Service whose endpoints the reconciler programs from external health.
pub(crate) const EXTERNAL_SERVICE: &str = "external";
/// Total agent pods in the shared StatefulSet: the in-cluster fleet plus the external slice.
pub(crate) const TOTAL_AGENTS: usize = NODE_COUNT + EXTERNAL_COUNT;

/// Ordinal of the i-th external agent (`agent-<n>`), right after the in-cluster fleet.
pub(crate) fn external_ordinal(index: usize) -> usize {
    NODE_COUNT + index
}

/// Real Jenkins runs as two independent controller cohorts — a `ci` cohort (build traffic)
/// and a `release` cohort (release pipelines) — each a pair the agent upgrades one node at
/// a time with zero downtime. A genuinely complex Java deployment, installed and upgraded by
/// the exact same mechanism as the sample app, but kept outside the convergence/chaos
/// machinery so its slow (~4-min) installs never gate the fast cohorts.
/// Fields: (display role, replicas).
pub(crate) const JENKINS_COHORTS: [(&str, usize); 2] = [("ci", 2), ("release", 2)];
/// Total in-cluster Jenkins pods — derived from the cohort table above, like every other total
/// in this file, so changing a cohort's replicas cannot silently under-reserve cluster capacity
/// (this feeds [`REQUIRED_POD_CAPACITY`]).
pub(crate) const JENKINS_TOTAL: usize = jenkins_total();

const fn jenkins_total() -> usize {
    let mut total = 0;
    let mut index = 0;
    while index < JENKINS_COHORTS.len() {
        total += JENKINS_COHORTS[index].1;
        index += 1;
    }
    total
}

/// The updated-managed HAProxy tier: a StatefulSet of this many HAProxy pods, each an ordinary
/// `updated` agent that installs HAProxy from a signed tarball bundle (never a bespoke image) and
/// upgrades it in place via the provider's SIGUSR2 master-worker re-exec. Two replicas so the
/// control plane rolls them one at a time and the front Service always keeps one serving — the
/// zero-downtime story: `updated` managing infrastructure (a load balancer) that fronts real
/// services, which plain Kubernetes rollouts cannot express.
pub(crate) const HAPROXY_REPLICAS: usize = 2;
/// The cohort label the HAProxy pods carry and the `haproxy` UpdateGroup selects on. Outside the
/// per-set/fleet throttle and the pod-kill chaos, exactly like the Jenkins tier.
pub(crate) const HAPROXY_COHORT: &str = "haproxy";
/// The single HAProxy UpdateGroup that rolls the tier from 1.0.0 → 2.0.0. It owns both HAProxy
/// nodes with `maxUnavailable: 1`, so the group itself caps the tier to ONE node rolling at a time
/// behind the front Service — genuinely zero-downtime, with no synthetic set/group split.
pub(crate) const HAPROXY_GROUP: &str = "haproxy";
/// The HAProxy `backend` section whose server membership the HAProxy-mode healthproxy programs
/// from signed CDN health (`set server <backend>/<node> state ready|drain`).
pub(crate) const HAPROXY_BACKEND: &str = "fleet";
/// TCP port each HAProxy exposes its admin runtime API (stats socket) on, reachable in-cluster at
/// `haproxy-<n>.agents:<port>` so the healthproxy can flip backend server state.
pub(crate) const HAPROXY_ADMIN_PORT: u16 = 9999;
/// The ClusterIP Service that fans traffic across the HAProxy pods — the fleet's front door. The
/// synthetic load probe drives it across the HAProxy upgrade to prove zero dropped requests.
pub(crate) const HAPROXY_FRONT_SERVICE: &str = "haproxy-front";
/// The two release versions the HAProxy tier demonstrates an in-place upgrade between.
pub(crate) const HAPROXY_V1: &str = "1.0.0";
pub(crate) const HAPROXY_V2: &str = "2.0.0";

/// The one spelling for a rollout deployment identity in this harness. It is carried through
/// signed assignments and telemetry, so construct it through the production contract rather than
/// letting scenarios invent separators the agent will reject.
pub(crate) fn versioned_deployment_name(group: &str, version: &str) -> String {
    let name = format!("{group}-{version}");
    assert!(
        updated_contracts::identity::is_segment(&name),
        "E2E deployment identity {name:?} violates the shared identity grammar"
    );
    name
}
/// Annotation on the `haproxy` UpdateGroup carrying the pre-published 2.0.0 target the upgrade
/// patches in — so the bytes are signed and in the store up front and the upgrade is a pure group
/// patch, never a live publish.
pub(crate) const HAPROXY_NEXT_PATH_ANNOTATION: &str = "e2e.updated.dev/next-path";
pub(crate) const HAPROXY_NEXT_SHA_ANNOTATION: &str = "e2e.updated.dev/next-sha256";
/// Extra pods the HAProxy tier consumes: the HAProxy replicas plus the one HAProxy-mode
/// healthproxy Deployment that programs their backend membership.
pub(crate) const HAPROXY_TOTAL: usize = HAPROXY_REPLICAS + 1;
pub(crate) const REQUIRED_POD_CAPACITY: usize = TOTAL_AGENTS + JENKINS_TOTAL + HAPROXY_TOTAL + 40;

/// Serving pods a set is guaranteed to keep while it rolls: total pods minus the pods of the
/// at-most-one group the per-set cap lets roll (`gps - 1` groups). Chaos never enters this
/// floor because it disrupts exactly that one group ([`crate::Chaos::inject_chaos`] picks a
/// single group per set) and only deletes pods that are ALREADY draining (out of the load
/// balancer), so it cannot reduce serving capacity. Must stay `>= 1` — a compile error here
/// means the layout would drain a set.
pub(crate) const UPTIME_MARGIN: usize = (GROUPS_PER_SET - 1) * COHORT_SIZE;
// Written as "the groups that are NOT rolling", which is what the floor actually is. Subtracting
// the rolling groups from the total the other way around yields the *rolling* count — a value that
// is `>= 1` whenever the cohort is non-empty, so the assertion held no matter how the layout was
// configured, including a one-group-per-set layout that drains a set completely.
const _: () = assert!(
    UPTIME_MARGIN >= 1,
    "layout would drain a set below its serving floor: increase COHORT_SIZE or GROUPS_PER_SET"
);

/// The version the whole fleet is seeded on and converges to before any rollout runs.
pub(crate) const BASELINE_VERSION: &str = "22.0.0";

pub(crate) fn cohort_label(index: usize) -> String {
    format!("cohort-{index:02}")
}

pub(crate) fn cohort_group(index: usize) -> String {
    format!("fleet-{}", cohort_label(index))
}

/// The set a cohort belongs to — sets are contiguous runs of [`GROUPS_PER_SET`] cohorts. A set
/// owns a load-balancer Service and a per-set throttle; fleet-wide concurrency is a separate
/// cap (see [`FLEET_SET`]).
pub(crate) fn cohort_set_index(index: usize) -> usize {
    index / GROUPS_PER_SET
}

/// The set a fleet node (`agent-<ordinal>`) belongs to, via its cohort. `None` for a name that
/// does not parse or lands outside the fleet's sets.
pub(crate) fn node_set_index(node: &str) -> Option<usize> {
    let ordinal: usize = node.strip_prefix("agent-")?.parse().ok()?;
    let set = cohort_set_index(ordinal / COHORT_SIZE);
    (set < SET_COUNT).then_some(set)
}

/// The set name a cohort group carries as its `set` label, and the name of that set's
/// `UpdateGroupSet`.
pub(crate) fn set_name(set: usize) -> String {
    format!("fleet-set-{set:02}")
}

/// Label key marking which set a cohort group belongs to.
pub(crate) const SET_LABEL: &str = "e2e.updated.dev/set";

/// The single fleet-wide throttle set: every managed group belongs to it, and the control
/// plane keeps at most [`FLEET_CONCURRENCY`] groups rolling at once, admitting the next
/// (in set order) the instant one settles. So the rollout pipelines across set boundaries
/// instead of pausing set-by-set — as a group completes, the next queued group starts
/// immediately. This is the "cross-group merge": one cap over the fleet.
pub(crate) const FLEET_SET: &str = "fleet-all";
pub(crate) const FLEET_LABEL: &str = "e2e.updated.dev/fleet";
pub(crate) const FLEET_VALUE: &str = "managed";

/// The freshness bound a report ages out on — the ONE staleness definition, read from the contract
/// rather than restated, so a change to it moves this wait with it.
pub(crate) const REPORT_FRESHNESS_SECS: usize =
    updated_contracts::telemetry::REPORT_FRESHNESS.as_secs() as usize;
/// How long the staleness scenario watches a wedged rollout before accepting that it is genuinely
/// held. Long enough to cover several reconciles and several agent check intervals (both are
/// ~1s here), so "it did not advance" is a property of the planner and not of the sampling.
pub(crate) const STALENESS_HOLD_SECS: usize = 30;

/// The in-cluster webhook receiver for `updatec`'s alerts, and the port/record its subcommand
/// serves on (`crate::alertsink`). The controller is pointed at it during fleet preparation, so a
/// condition TRANSITION anywhere in the run is delivered and durably recorded.
pub(crate) const ALERT_SINK: &str = "alert-sink";
pub(crate) const ALERT_PORT: u16 = crate::alertsink::ALERT_PORT;
pub(crate) const ALERT_RECORD: &str = crate::alertsink::ALERT_RECORD;

/// The URL the controller delivers alerts to — the Service above, spelled once.
pub(crate) fn alert_url() -> String {
    format!("http://{ALERT_SINK}:{ALERT_PORT}/alerts")
}

/// Where readers (the healthproxy) fetch the controller's fleet projection. Nodes obtain an exact
/// write capability from their routing gateway and POST raw signed reports directly to MinIO; the
/// controller reads those objects and publishes the stable `<base>/telemetry/fleet.json` index and
/// bounded shard keys. Anonymous read is enabled on the bucket in this disposable test cluster.
///
/// The path is `<bucket>/routing/<namespace>/<repository>`: the gateway flushes the index under the
/// controller-derived managed-repository prefix. Pointing this at the bucket root would 404 the
/// document and silently drain the whole fleet, so the test below tracks the production constructor.
pub(crate) const HEALTH_CDN: &str = "http://minio:9000/updates/routing/updated-system/default";

/// The flags every `updatectl` invocation addresses that repository with.
pub(crate) fn release_repository_flags() -> String {
    use crate::fixture::{RELEASE_BUCKET, RELEASE_ENDPOINT, RELEASE_PREFIX, RELEASE_REGION};

    format!(
        "--bucket {RELEASE_BUCKET} --prefix {RELEASE_PREFIX} \
         --endpoint {RELEASE_ENDPOINT} --region {RELEASE_REGION}"
    )
}

/// The URL a group's signed `releaseRepository` resolves `namespace` (`metadata`/`targets`) from.
pub(crate) fn release_repository_url(namespace: &str) -> String {
    use crate::fixture::{RELEASE_BUCKET, RELEASE_PREFIX, RELEASE_PUBLIC_ENDPOINT};

    format!("{RELEASE_PUBLIC_ENDPOINT}/{RELEASE_BUCKET}/{RELEASE_PREFIX}/{namespace}/")
}

/// Name of the per-set ClusterIP Service backing a set's pods. Distinct from the set's
/// `UpdateGroupSet` (a throttle CR) though both concern the same set.
pub(crate) fn set_service_name(set: usize) -> String {
    format!("fleet-lb-set-{set:02}")
}

/// Major component of a `MAJOR.0.0` fleet version, if parseable.
pub(crate) fn version_major(version: &str) -> Option<usize> {
    version.split('.').next()?.parse().ok()
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
/// run replays exactly. Ranges over `[FLEET_CONCURRENCY, SET_COUNT]` — from the baseline
/// concurrency up to the structural ceiling of one rolling group per set (above `SET_COUNT`
/// the per-set cap would silently clamp it anyway). The per-set cap keeps every set's other group
/// serving at ANY width in this range, so uptime stays 100% even at the ceiling; a wider wave only
/// piles more simultaneous rollouts onto the (chaos-crashed) controller.
pub(crate) fn fleet_rollout_width(seed: u64) -> u32 {
    let span = (SET_COUNT - FLEET_CONCURRENCY as usize + 1) as u64;
    let offset = (seed.wrapping_mul(CHAOS_SEED_SPREAD) >> 33) % span;
    FLEET_CONCURRENCY + offset as u32
}

/// An agent pod's volume mounts: the workload's own, then the two every agent gets.
///
/// TLS material is mounted READ-ONLY at `/etc/agent-tls` from the `agent-tls` secret, and every
/// agent gets a writable `/tmp`. That is one fact about how an agent runs, and the two pod specs in
/// this suite — the plain fleet and the HAProxy-fronted one — each spelled it out. The specs are
/// otherwise genuinely different workloads, so only the shared part is shared: a drift in where an
/// agent finds its identity, or in whether it can write over it, would otherwise reach one workload
/// and not the other.
pub(crate) fn agent_volume_mounts(workload: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
    let mut mounts = workload;
    mounts.push(serde_json::json!({
        "name": "agent-tls", "mountPath": "/etc/agent-tls", "readOnly": true
    }));
    mounts.push(serde_json::json!({ "name": "tmp", "mountPath": "/tmp" }));
    mounts
}

/// The volumes [`agent_volume_mounts`] resolves against, plus the workload's own.
pub(crate) fn agent_volumes(workload: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
    let mut volumes = workload;
    volumes.push(serde_json::json!({ "name": "tmp", "emptyDir": {} }));
    volumes.push(serde_json::json!({
        "name": "agent-tls", "secret": { "secretName": "agent-tls" }
    }));
    volumes
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shared fragments must render exactly the pod spec the two workloads used to spell out.
    /// Extracting them was meant to remove a copy, not to change where an agent finds its identity
    /// or whether it can write over it.
    #[test]
    fn agent_pods_mount_their_identity_read_only_under_the_workload_s_own_volumes() {
        assert_eq!(
            serde_json::Value::from(agent_volume_mounts(vec![serde_json::json!(
                { "name": "state", "mountPath": "/var/lib/updated" }
            )])),
            serde_json::json!([
                { "name": "state", "mountPath": "/var/lib/updated" },
                { "name": "agent-tls", "mountPath": "/etc/agent-tls", "readOnly": true },
                { "name": "tmp", "mountPath": "/tmp" }
            ])
        );
        assert_eq!(
            serde_json::Value::from(agent_volumes(vec![])),
            serde_json::json!([
                { "name": "tmp", "emptyDir": {} },
                { "name": "agent-tls", "secret": { "secretName": "agent-tls" } }
            ])
        );
    }
    use std::collections::BTreeSet;

    #[test]
    fn versioned_deployments_use_the_signed_identity_grammar() {
        let name = versioned_deployment_name("edge", "1.2.3-rc.1");
        assert_eq!(name, "edge-1.2.3-rc.1");
        assert!(updated_contracts::identity::is_segment(&name));
    }

    #[test]
    fn fleet_rollout_width_stays_in_the_uptime_safe_band_and_spans_it() {
        // Every wave's width must sit in [baseline concurrency, one rolling group per set]. Below
        // the floor it would not be a real rollout; above SET_COUNT the per-set cap would clamp it
        // and the "every set keeps its other group serving" (100% uptime) reasoning breaks.
        let band: Vec<u32> = (FLEET_CONCURRENCY..=SET_COUNT as u32).collect();
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

    #[test]
    fn health_cdn_addresses_the_prefix_the_gateway_flushes_the_fleet_index_under() {
        // The controller publishes the fleet index to its canonical
        // `routing/<namespace>/<name>/telemetry/fleet.json` key
        // inside the repository's bucket, and the healthproxy fetches
        // `<health base>/telemetry/fleet.json`. If the base omits the prefix, the GET 404s every
        // cycle, no report is ever cached, and every node is programmed `ready: false` forever —
        // silently draining the entire external LB path.
        let endpoint = crate::fixture::RELEASE_ENDPOINT;
        let bucket = crate::fixture::RELEASE_BUCKET;
        let prefix =
            updatec::runtime::managed_repository_prefix(NAMESPACE, crate::fixture::REPOSITORY_NAME);
        assert_eq!(HEALTH_CDN, format!("{endpoint}/{bucket}/{prefix}"));

        assert_eq!(
            updated_contracts::telemetry::fleet_index_url(HEALTH_CDN),
            format!("{endpoint}/{bucket}/{prefix}/telemetry/fleet.json"),
        );
    }
}
