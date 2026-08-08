use crate::*;
use futures::StreamExt;
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Patch, PatchParams};
use kube::runtime::watcher;
use kube::runtime::watcher::Event;
use kube::ResourceExt;
use std::sync::atomic::Ordering;
use std::time::Duration;
use std::time::Instant;

/// Start the synthetic client that emulates a readiness-respecting load balancer over the
/// fleet: one task keeps the ready-endpoint set fresh, and a pool of workers continuously
/// route real `/version` requests to those endpoints, recording every outcome. The golden
/// panel reads the resulting window. Because workers only ever target *ready* pods, a
/// correct drain (readiness withdrawn before shutdown) keeps availability pinned at the
/// SLA line even as chaos kills pods and rollouts churn the fleet — a failed drain shows up
/// immediately as burned error budget.
pub(crate) fn spawn_load_generator(demo: Demo) {
    // One refresher probes readiness fleet-wide and partitions ready endpoints into each
    // set's load balancer, so a set's workers only ever route within their own set.
    let refresher = demo.clone();
    tokio::spawn(async move {
        // Per-set instant the pool first became full; a set starts counting once it has
        // held a full pool continuously for LOAD_STEADY_GRACE (baseline reached).
        let expected_per_set = DEMO_GROUPS_PER_SET * DEMO_COHORT_SIZE;
        let mut full_since: Vec<Option<Instant>> = vec![None; DEMO_SET_COUNT];
        loop {
            if let Ok(ready) = refresher.ready_endpoints().await {
                let mut per_set: Vec<Vec<String>> =
                    (0..DEMO_SET_COUNT).map(|_| Vec::new()).collect();
                for node in ready {
                    if let Some(set) = node_set_index(&node) {
                        per_set[set].push(node);
                    }
                }
                for (set, endpoints) in per_set.into_iter().enumerate() {
                    if endpoints.len() >= expected_per_set {
                        let since = full_since[set].get_or_insert_with(Instant::now);
                        if since.elapsed() >= LOAD_STEADY_GRACE {
                            refresher.counting[set].store(true, Ordering::Relaxed);
                        }
                    } else {
                        // Lost the full pool before the grace elapsed: restart the timer,
                        // but never un-latch once a set has started counting.
                        full_since[set] = None;
                    }
                    *refresher.ready[set].lock().unwrap() = endpoints;
                }
            }
            tokio::time::sleep(LOAD_READY_REFRESH).await;
        }
    });
    for set in 0..DEMO_SET_COUNT {
        for _worker in 0..LOAD_WORKERS_PER_SET {
            let load = demo.load.clone();
            let counting = demo.counting.clone();
            // Every request for this set enters the shared ingress on the set's own path.
            // Kubernetes routes it to this set's Service, whose selector admits only this
            // set's pods — and only the *ready* ones — so we no longer pick an endpoint in
            // process: a set can never be answered by another set's pod, by construction.
            let url = format!("{DEMO_INGRESS_URL}/set-{set}/version");
            tokio::spawn(async move {
                let client = match reqwest::Client::builder()
                    .timeout(LOAD_REQUEST_TIMEOUT)
                    .build()
                {
                    Ok(client) => client,
                    Err(_) => return,
                };
                loop {
                    // No load and no availability accounting until this set has reached
                    // steady-state baseline, so warm-up never counts against the SLA.
                    if !counting[set].load(Ordering::Relaxed) {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        continue;
                    }
                    let start = Instant::now();
                    // A set-wide outage (or a drain that left no ready pod) surfaces as the
                    // ingress returning 503 — recorded as unavailable, burning that set's
                    // budget, exactly as a real load balancer would report it.
                    let ok = match client.get(&url).send().await {
                        Ok(response) if response.status().is_success() => response
                            .text()
                            .await
                            .map(|body| !body.trim().is_empty())
                            .unwrap_or(false),
                        _ => false,
                    };
                    load[set].lock().unwrap().record(LoadSample {
                        at: start,
                        ok,
                        latency_ms: start.elapsed().as_millis() as u64,
                    });
                    tokio::time::sleep(Duration::from_millis(40)).await;
                }
            });
        }
    }
}

/// Continuously watch fleet pod readiness — the single source of load-balancer membership for
/// every pod-backed node. A pod's native readinessProbe is what the per-set Service
/// EndpointSlices route on, so its `Ready` condition *is* whether it is in the pool. The watch
/// is a stream, not a sample, so unlike a periodic curl it cannot land between an OUT and the
/// following IN edge and miss it. Two derived views are maintained from the one stream:
///   * [`Demo::readiness`] — live `Ready` per node, which [`Demo::fleet`] and
///     [`Demo::ready_endpoints`] read so the UI's IN/OUT and the synthetic load balancer's pool
///     reflect exactly what Kubernetes routes on, without a per-node probe.
///   * [`Demo::left_lb`] — every node seen out of the pool since the current generation began,
///     the generation-settle's durable proof a broken cohort actually attempted the bad release
///     and drained (a brief, already-past drain still counts).
///
/// The pod name is the node key (`agent-<ordinal>`, `magnolia-<role>-<ordinal>`), the same value
/// the fleet and settle logic read from each agent's `demo.updated.dev/node` label, so the maps
/// join cleanly by node name.
pub(crate) fn spawn_readiness_watcher(demo: Demo) {
    tokio::spawn(async move {
        let pods = demo.publisher.pods();
        let config = watcher::Config::default().labels("app=updated-agent");
        loop {
            // Buffer the relist (Init → InitApply* → InitDone) into a fresh snapshot and swap it
            // in atomically at InitDone, so a pod that vanished during a watch gap drops out of
            // the map instead of lingering wrongly IN. Steady-state Apply/Delete update in place.
            let mut relist: Option<std::collections::HashMap<String, bool>> = None;
            let mut stream = watcher(pods.clone(), config.clone()).boxed();
            while let Some(event) = stream.next().await {
                let event = match event {
                    Ok(event) => event,
                    Err(error) => {
                        eprintln!("demo readiness watch reset: {error}");
                        break;
                    }
                };
                // Any successful event or relist is proof the watch is live: stamp the liveness
                // heartbeat [`Demo::fleet`]/[`Demo::ready_endpoints`] age against. A stalled or
                // erroring watch stops delivering events, so the heartbeat goes cold and those
                // reads fail closed instead of serving the frozen membership map.
                *demo.readiness_fresh_at.lock().unwrap() = Instant::now();
                match event {
                    Event::Init => relist = Some(std::collections::HashMap::new()),
                    // A relist is a snapshot re-observation, not a fresh transition: stage each
                    // pod's readiness into the new snapshot, but do NOT feed `left_lb` — a pod
                    // that merely reads not-ready across a reconnect must not be counted as having
                    // drained *this generation*, or a reconnect could forge the drain proof.
                    Event::InitApply(pod) => {
                        if let Some(snapshot) = relist.as_mut() {
                            snapshot.insert(pod.name_any(), pod_ready(&pod));
                        }
                    }
                    Event::InitDone => {
                        if let Some(snapshot) = relist.take() {
                            *demo.readiness.lock().unwrap() = snapshot;
                        }
                    }
                    // A live transition: record its readiness, and note any departure as a real
                    // drain edge for the generation-settle proof.
                    Event::Apply(pod) => {
                        record_readiness(&demo, &pod);
                    }
                    // A gone pod is out of the pool by definition (fail closed).
                    Event::Delete(pod) => {
                        demo.readiness.lock().unwrap().insert(pod.name_any(), false);
                    }
                }
            }
            // The watcher relists on desync; pause briefly before re-establishing so a transient
            // API hiccup cannot spin. Recorded state persists across the reconnect.
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
}

/// Fold one live pod transition into both readiness views: its `Ready` membership, and — when
/// out — the durable "left the load balancer this generation" set the settle loop reads.
fn record_readiness(demo: &Demo, pod: &Pod) {
    let node = pod.name_any();
    let ready = pod_ready(pod);
    demo.readiness.lock().unwrap().insert(node.clone(), ready);
    if !ready {
        demo.left_lb.lock().unwrap().insert(node);
    }
}

/// Whether a pod currently reports `Ready=True`. Anything else — unready, unknown, or no status
/// yet — reads as out of the load balancer (fail closed), matching how readiness gates traffic.
fn pod_ready(pod: &Pod) -> bool {
    pod.status
        .as_ref()
        .and_then(|status| status.conditions.as_ref())
        .is_some_and(|conditions| {
            conditions
                .iter()
                .any(|condition| condition.type_ == "Ready" && condition.status == "True")
        })
}

/// Keep each agent pod's set label current so the per-set load-balancer Services select the
/// right pods. A StatefulSet recreates a chaos-killed pod without the label, so this
/// re-applies it on a slow loop, deriving the set from the pod ordinal. Without it a
/// restarted pod would silently fall out of its set's rotation.
///
/// Patches through the kube API (not a `kubectl` subprocess — the demo image ships no
/// `kubectl`, which silently left every pod unlabelled, so the Services had no endpoints and
/// synthetic load 100%-errored). The `updatec-demo` ServiceAccount carries `pods: patch`.
pub(crate) fn spawn_pod_set_labeler(demo: Demo) {
    tokio::spawn(async move {
        let pods = demo.publisher.pods();
        loop {
            for ordinal in 0..DEMO_NODE_COUNT {
                let node = format!("agent-{ordinal}");
                let Some(set) = node_set_index(&node) else {
                    continue;
                };
                let patch = serde_json::json!({
                    "metadata": { "labels": { SET_LABEL: set_name(set) } }
                });
                let _ = pods
                    .patch(&node, &PatchParams::default(), &Patch::Merge(&patch))
                    .await;
            }
            tokio::time::sleep(Duration::from_secs(15)).await;
        }
    });
}
