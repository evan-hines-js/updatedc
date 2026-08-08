use crate::*;
use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
/// The reconciler protocol vocabulary is defined once, in the contracts crate; the demo driver
/// reads the audit log in exactly those terms rather than re-spelling operations locally.
use updated_contracts::reconciler::{attempt, Operation};

/// `kubectl` argument prefix that execs into the in-cluster release-server container. Every
/// release-repository query and mutation runs through it, so it lives in one place.
pub(crate) const RELEASE_SERVER_EXEC: [&str; 6] = [
    "-n",
    "updated-system",
    "exec",
    "deployment/release-server",
    "-c",
    "release-server",
];

const DEMO_LIFECYCLE_STATE: &str = "/var/lib/updated/providers/state/demo-enterprise-lifecycle";

/// The enterprise sub-phases the demo reconciler runs, in order, inside one `apply`. Each one
/// requires its predecessor's completion marker, so finding every marker in an attempt's effects
/// directory is proof the whole sequence ran in this order.
const LIFECYCLE_SUB_PHASES: [&str; 8] = [
    "preflight",
    "prepare",
    "pre-drain",
    "drain",
    "stop",
    "activate",
    "start",
    "verify",
];

pub(crate) async fn start_demo(
    automated: bool,
    exit_after: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    for command in ["docker", "kind", "kubectl", "cargo", "curl"] {
        command_exists(command)?;
    }
    let root = workspace_root()?;
    let cluster = demo_cluster();
    let port = demo_port();
    // Always start from a clean cluster. Reusing one carried subtle staleness — a baked
    // release-server predating the current seed, an older image, a missing add-on — that failed
    // deep in resource apply. A fresh build every time is the one predictable path.
    let clusters = output(Command::new("kind").args(["get", "clusters"]))?;
    if clusters.lines().any(|name| name == cluster) {
        println!("[demo] tearing down the previous demo cluster for a clean rebuild");
        delete_demo_cluster(&cluster)?;
    }
    println!("Setting up the real operator demo. The build takes a few minutes.");
    println!("The HTTP endpoint will become live after the cluster and agents are ready.\n");
    let status = Command::new(root.join("scripts/kind-updatec-e2e.sh"))
        .args(["--fuzz-rounds", "0"])
        .env("UPDATEC_KIND_CLUSTER", &cluster)
        .env("UPDATEC_KEEP_KIND_CLUSTER", "1")
        .status()?;
    if !status.success() {
        return Err("demo setup failed; see the setup output above".into());
    }

    println!("\n[demo] selecting the demo cluster and preparing fleet resources");
    use_demo_context(&cluster)?;
    let pod_capacity = demo_cluster_pod_capacity(&cluster);
    if pod_capacity < DEMO_REQUIRED_POD_CAPACITY {
        return Err(format!(
            "demo node advertises capacity for {pod_capacity} pods; at least {DEMO_REQUIRED_POD_CAPACITY} are required for {DEMO_NODE_COUNT} services plus system workloads"
        )
        .into());
    }
    println!(
        "[demo] node pod capacity: {pod_capacity} ({DEMO_NODE_COUNT} managed services, {} reserved for system/demo workloads)",
        DEMO_REQUIRED_POD_CAPACITY - DEMO_NODE_COUNT
    );
    println!("[demo] removing the base E2E's intentionally ambiguous group");
    run(Command::new("kubectl").args([
        "-n",
        "updated-system",
        "delete",
        "updategroup",
        "overlapping-edge",
        "--ignore-not-found",
    ]))?;
    let _ = run(Command::new("kubectl").args([
        "-n",
        "updated-system",
        "delete",
        "updategroup",
        "demo-failure",
        "demo-good",
        "demo-alpha",
        "demo-beta",
        "demo-gamma",
        "demo-delta",
        "--ignore-not-found",
    ]));
    println!("[demo] scaling the managed fleet from 5 to {DEMO_NODE_COUNT} agents");
    run(Command::new("kubectl").args([
        "-n",
        "updated-system",
        "scale",
        "statefulset/agent",
        &format!("--replicas={DEMO_TOTAL_AGENTS}"),
    ]))?;
    let magnolia_enabled = prepare_demo_layer().await?;
    // The out-of-cluster VM is the manual Magnolia node, so it only makes sense where Magnolia
    // is available.
    if magnolia_enabled {
        if let Some((ssh_target, _)) = external_vm_target() {
            println!("[demo] provisioning the out-of-cluster Magnolia VM {ssh_target} (crude, best-effort)");
            match provision_external_vm(&ssh_target) {
                Ok(()) => {
                    if let Err(error) = label_external_vm_agent() {
                        println!("[demo] could not label the external VM's agent ({error}); it will not get Magnolia");
                    }
                }
                Err(error) => {
                    println!(
                        "[demo] external VM provisioning failed ({error}); continuing without it"
                    )
                }
            }
        }
    }
    println!("[demo] deploying the healthproxy reconciler for the out-of-cluster slice");
    deploy_external_reconciler(magnolia_enabled)?;
    with_demo_port_forward(&port, |url| async move {
        if automated {
            exercise_demo(&url, exit_after).await?;
        } else {
            // Diverge only once the fleet has actually reached the baseline. Otherwise the
            // chaos loop detects the wrong baseline major (there are no versions to read yet,
            // so it falls back to 1) and rolls *downgrades* the agents reject and hold on —
            // nothing progresses and every generation times out.
            let client = reqwest::Client::new();
            println!("[demo] waiting for the fleet to reach baseline 22.0.0 before diverging");
            wait_for_fleet_convergence(&client, &url, "22.0.0", 240).await?;
            start_fleet_chaos(&client, &url, None, None).await?;
        }
        println!("\n[demo] READY: {url}");
        println!("The UI shows group rollouts, rollback, and lifecycle convergence live.");
        println!("Press Ctrl-C when finished; reset with: cargo run -p updatec-demo -- reset");
        if !exit_after {
            open_browser(&url);
            tokio::signal::ctrl_c().await?;
        }
        Ok(())
    })
    .await
}

/// Apply the demo layer onto an already-provisioned, already-scaled fleet: detect the platform
/// and whether Magnolia is published for it, deploy the Magnolia fleet when it is, assign every
/// enrolled node its labels, apply the UI/RBAC/per-set/per-agent resources, and wait for the
/// managed StatefulSet to roll out. Returns whether Magnolia is enabled for this platform, which
/// the callers use to decide the external-VM labeling and reconciler. The one shared body behind
/// the initial bring-up (`start_demo`) and the ansible-driven `setup_demo`; each caller keeps its
/// own cluster preamble and external-VM handling around this call.
async fn prepare_demo_layer() -> Result<bool, Box<dyn std::error::Error>> {
    // Magnolia is only published for linux-x86_64 (its install provider fetches an x86_64 JRE),
    // so on any other platform — e.g. an arm64 kind cluster on Apple Silicon — its bundle is
    // absent. Detect that from the repo and skip the Magnolia nodes and the out-of-cluster VM
    // entirely, running the rest of the demo. Run the full test (with Magnolia) on an x86_64 box.
    let platform = repository_platform()?.trim().to_string();
    let magnolia_path = format!("products/magnolia/stable/1.0.0/{platform}/app");
    let magnolia_enabled = repository_target_sha(&magnolia_path).is_ok();
    if magnolia_enabled {
        println!("[demo] deploying {DEMO_MAGNOLIA_TOTAL} in-cluster Magnolia CMS nodes (author + publisher pairs); the manual node is the out-of-cluster VM (if provisioned), rolled by `updatectl deploy` against its own UpdateGroup");
        apply_magnolia_fleet()?;
    } else {
        println!("[demo] Magnolia is not published for {platform} (x86_64 only) — skipping the Magnolia nodes and the out-of-cluster VM");
    }
    println!("[demo] waiting for enrollment and assigning every new node");
    label_demo_agents()?;
    if magnolia_enabled {
        label_magnolia_agents()?;
    }
    label_external_agents()?;
    // The sample-app cohorts resolve their provider set from MinIO; its sha is published and
    // returned by `bootstrap_minio_release_repo`, not read from the release-server repo here.
    let provider_path = "provider-sets/rube-goldberg.json";
    // Magnolia bundle refs, resolved only when it is published for this platform.
    let (magnolia_sha, magnolia_provider_path, magnolia_provider_sha) = if magnolia_enabled {
        (
            repository_target_sha(&magnolia_path)?,
            "provider-sets/magnolia.json".to_string(),
            repository_target_sha("provider-sets/magnolia.json")?,
        )
    } else {
        (String::new(), String::new(), String::new())
    };
    println!("[demo] applying the UI, RBAC, per-set services/ingress, and per-agent groups");
    apply_demo_resources(
        provider_path,
        magnolia_enabled,
        &magnolia_path,
        magnolia_sha.trim(),
        &magnolia_provider_path,
        magnolia_provider_sha.trim(),
    )?;
    println!("[demo] waiting for all assigned agents to become ready");
    run(Command::new("kubectl").args([
        "-n",
        "updated-system",
        "rollout",
        "status",
        "statefulset/agent",
        "--timeout=480s",
    ]))?;
    // The updated-managed HAProxy tier: 2 HAProxies (installed from a signed tarball, upgraded in
    // place) fronting the external slice, with a HAProxy-mode healthproxy programming their backend
    // membership from signed CDN health. Runs after the release keys + external slice exist. Sits
    // outside the cohort/set/chaos machinery, so it never perturbs the convergence/SLA math.
    prepare_haproxy_tier(&platform).await?;
    Ok(magnolia_enabled)
}

/// Apply the demo layer onto an already-provisioned cluster, then exit. This is the entry
/// point the ansible playbook drives on the server: it assumes the cluster, control plane, CDN,
/// base fleet, and ingress are already up (ansible provisioned them), and it does not
/// port-forward or serve — the in-cluster UI pod serves the UI, reached through nginx. The
/// co-located out-of-cluster agent (also provisioned by ansible) is labeled into the manual
/// Magnolia group here, once it has enrolled.
pub(crate) async fn setup_demo() -> Result<(), Box<dyn std::error::Error>> {
    let cluster = demo_cluster();
    use_demo_context(&cluster)?;
    println!("[demo] removing the base E2E's intentionally ambiguous group");
    run(Command::new("kubectl").args([
        "-n",
        "updated-system",
        "delete",
        "updategroup",
        "overlapping-edge",
        "--ignore-not-found",
    ]))?;
    println!("[demo] scaling the managed fleet to {DEMO_TOTAL_AGENTS} agents");
    run(Command::new("kubectl").args([
        "-n",
        "updated-system",
        "scale",
        "statefulset/agent",
        &format!("--replicas={DEMO_TOTAL_AGENTS}"),
    ]))?;
    let magnolia_enabled = prepare_demo_layer().await?;
    // The co-located out-of-cluster agent (provisioned by ansible on this host) is the manual
    // Magnolia node: label its enrolled UpdateAgent into the manual group so the control plane
    // assigns it Magnolia. Best-effort — it retries until the agent has registered.
    if magnolia_enabled {
        if let Err(error) = label_external_vm_agent() {
            println!("[demo] could not label the co-located Magnolia agent ({error}); is it enrolled yet?");
        }
    }
    deploy_external_reconciler(magnolia_enabled)?;
    println!(
        "[demo] setup complete: fleet, groups, per-set services/ingress, and reconciler applied"
    );
    Ok(())
}

/// Driving adapter for CI. The UI is observational: this verifies the prepared fleet
/// and provider-owned durable state independently, then starts the same group scenario
/// the browser exposes.
pub(crate) async fn exercise_demo(
    url: &str,
    exit_after: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    wait_for_fleet_convergence(&client, url, "22.0.0", 240).await?;
    assert_set_isolation().await?;
    assert_external_endpoints_reconciled().await?;
    // The reconciler protocol has four operations, so one update transaction is exactly one
    // `apply` invocation: the audit proves the transaction ran to completion, and the ordered
    // sub-phases inside it are proven by the completion markers the reconciler leaves in the
    // attempt's effects directory. Each sub-phase requires its predecessor's marker, so the
    // full marker set is the ordering evidence.
    let mut transaction = None;
    for _ in 0..60 {
        if let Ok(lifecycle) = lifecycle_audit() {
            if let Some(attempt) = latest_completed_transaction(&lifecycle) {
                transaction = Some(attempt);
                break;
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let Some(attempt) = transaction else {
        return Err("no lifecycle update transaction completed its apply operation".into());
    };
    let missing = missing_sub_phase_markers(&lifecycle_attempt_markers(&attempt)?);
    if !missing.is_empty() {
        return Err(format!(
            "lifecycle transaction {attempt} completed without its ordered sub-phases: missing {missing:?}"
        )
        .into());
    }
    let receipt = output(Command::new("kubectl").args([
        "-n",
        "updated-system",
        "exec",
        "agent-4",
        "-c",
        "agent",
        "--",
        "cat",
        &format!("{DEMO_LIFECYCLE_STATE}/legacy-java-home/change-ticket.receipt"),
    ]))?;
    if !receipt.contains("green release 22.0.0") {
        return Err(format!("missing lifecycle audit receipt: {receipt:?}").into());
    }
    assert_haproxy_zero_downtime_upgrade().await?;
    exercise_fleet_actions(&client, url, CHAOS_SEED_BASE, exit_after).await?;
    println!("E2E PASS: {DEMO_COHORT_COUNT} stable cohorts exercised ordered lifecycle hooks, group rollback, and exact fleet convergence");
    Ok(())
}

/// Prove the per-set ingress isolation end to end: every endpoint backing a set's
/// load-balancer Service is a pod that belongs to that set, and every set has at least one
/// ready endpoint. Because the ingress routes `/set-<n>` only to set n's Service, this is
/// the structural guarantee that no other set's pod can ever answer for a set — the whole
/// point of the per-set routing. It waits for endpoints to populate (a timing concern), but
/// a *cross-set* endpoint is an immediate hard failure, not something to wait out.
pub(crate) async fn assert_set_isolation() -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..90 {
        let mut all_populated = true;
        for set in 0..DEMO_SET_COUNT {
            let service = set_service_name(set);
            let mut ready_here = 0usize;
            for (pod, ready) in set_service_endpoints(&service)? {
                if node_set_index(&pod) != Some(set) {
                    return Err(format!(
                        "ingress isolation violated: set {set}'s Service {service} is backed by {pod}, which is not in set {set}"
                    )
                    .into());
                }
                if ready {
                    ready_here += 1;
                }
            }
            if ready_here == 0 {
                all_populated = false;
            }
        }
        if all_populated {
            println!(
                "[demo] verified per-set ingress isolation: each of {DEMO_SET_COUNT} sets' Service admits only its own pods"
            );
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err("per-set load-balancer Services never populated their endpoints".into())
}

/// Prove the reconciler dogfood: the real `updated-healthproxy` binary programmed the
/// selectorless `external` Service's EndpointSlice — stamped with its manager label — from the
/// out-of-cluster nodes' CDN health, and every external node came up ready. This exercises the
/// exact product code path (the one that fronts VMs) end to end against a live cluster.
pub(crate) async fn assert_external_endpoints_reconciled() -> Result<(), Box<dyn std::error::Error>>
{
    for _ in 0..90 {
        let json = output(Command::new("kubectl").args([
            "-n",
            "updated-system",
            "get",
            "endpointslices",
            "-l",
            &format!("kubernetes.io/service-name={DEMO_EXTERNAL_SERVICE}"),
            "-o",
            "json",
        ]))?;
        let parsed: serde_json::Value = serde_json::from_str(&json)?;
        let mut managed_by_reconciler = false;
        let mut ready = 0usize;
        for slice in parsed["items"].as_array().into_iter().flatten() {
            if slice["metadata"]["labels"]["endpointslice.kubernetes.io/managed-by"].as_str()
                == Some("updated-healthproxy")
            {
                managed_by_reconciler = true;
            }
            for endpoint in slice["endpoints"].as_array().into_iter().flatten() {
                if endpoint["conditions"]["ready"].as_bool().unwrap_or(false) {
                    ready += 1;
                }
            }
        }
        // `>=`, not `==`: a provisioned out-of-cluster VM adds another ready endpoint on top of
        // the pod stand-ins, and it may still be installing Magnolia when this runs.
        if managed_by_reconciler && ready >= DEMO_EXTERNAL_COUNT {
            println!(
                "[demo] verified the healthproxy reconciler programmed {DEMO_EXTERNAL_COUNT} out-of-cluster endpoints from CDN health"
            );
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err("the external healthproxy never programmed the expected ready endpoints".into())
}

/// The `(pod name, ready)` endpoints currently backing a per-set Service, read from its
/// EndpointSlices. Every endpoint is checked for set membership regardless of readiness (a
/// stray cross-set pod is a violation even while draining); readiness only decides whether
/// the set is currently serving.
fn set_service_endpoints(service: &str) -> Result<Vec<(String, bool)>, Box<dyn std::error::Error>> {
    let json = output(Command::new("kubectl").args([
        "-n",
        "updated-system",
        "get",
        "endpointslices",
        "-l",
        &format!("kubernetes.io/service-name={service}"),
        "-o",
        "json",
    ]))?;
    let parsed: serde_json::Value = serde_json::from_str(&json)?;
    let mut endpoints = Vec::new();
    for slice in parsed["items"].as_array().into_iter().flatten() {
        for endpoint in slice["endpoints"].as_array().into_iter().flatten() {
            let Some(pod) = endpoint["targetRef"]["name"].as_str() else {
                continue;
            };
            let ready = endpoint["conditions"]["ready"].as_bool().unwrap_or(false);
            endpoints.push((pod.to_string(), ready));
        }
    }
    Ok(endpoints)
}

pub(crate) async fn exercise_fleet_actions(
    client: &reqwest::Client,
    url: &str,
    seed: u64,
    exit_after: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    start_fleet_chaos(client, url, Some(seed), exit_after.then_some(1)).await?;
    // One epoch's own budget, so a slow-but-healthy run is not failed by its driver.
    for _ in 0..DEMO_EPOCH_TIMEOUT_SECS {
        let body = client
            .get(format!("{url}/chaos"))
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        let state: serde_json::Value = serde_json::from_str(&body)?;
        if let Some(error) = state["error"].as_str() {
            return Err(format!("fleet chaos failed: {error}").into());
        }
        // `completedEpochs` counts the epochs finished by the run just started —
        // `ChaosState::begin_run` zeroes it — so this waits on progress made by *this*
        // pass. A pass that never converges an epoch times out below instead of reading
        // the previous pass's converged fleet.
        if state["completedEpochs"].as_u64().unwrap_or(0) >= 1 {
            // Scope to the cohort fleet: the external slice rides the same `/fleet` listing
            // (total is 32 cohort + `DEMO_EXTERNAL_COUNT`) and is verified separately, so check
            // that exactly the cohort members are healthy on one shared version.
            let nodes = fetch_fleet(client, url).await?;
            let cohort: Vec<&FleetNode> =
                nodes.iter().filter(|node| is_cohort_member(node)).collect();
            let converged = cohort.first().and_then(|node| node.version.clone());
            if cohort.len() != DEMO_NODE_COUNT
                || converged.is_none()
                || cohort
                    .iter()
                    .any(|node| !node.healthy || node.version != converged)
            {
                return Err(
                    "fleet chaos completed without a healthy fleet converged onto one version"
                        .into(),
                );
            }
            println!(
                "FLEET PASS: all {DEMO_NODE_COUNT} agents diverged through broken and valid rollouts under pod-kill chaos, then converged onto {} while staying healthy",
                converged.unwrap_or_default()
            );
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(
        format!("seeded fleet chaos did not converge within {DEMO_EPOCH_TIMEOUT_SECS} seconds")
            .into(),
    )
}

pub(crate) async fn start_fleet_chaos(
    client: &reqwest::Client,
    url: &str,
    seed: Option<u64>,
    loops: Option<usize>,
) -> Result<(), Box<dyn std::error::Error>> {
    let loops = loops
        .map(|count| count.to_string())
        .unwrap_or_else(|| "forever".to_owned());
    let seed = seed
        .map(|value| format!("&seed={value}"))
        .unwrap_or_default();
    client
        .post(format!("{url}/chaos/start?loops={loops}{seed}"))
        .send()
        .await?
        .error_for_status()?;
    Ok(())
}

pub(crate) async fn wait_for_fleet_convergence(
    client: &reqwest::Client,
    url: &str,
    version: &str,
    timeout_seconds: usize,
) -> Result<Vec<FleetNode>, Box<dyn std::error::Error>> {
    let mut last = Vec::new();
    for second in 0..timeout_seconds {
        last = fetch_fleet(client, url).await?;
        if fleet_converged(&last, version) {
            println!("[demo] all {DEMO_NODE_COUNT} cohort members are healthy at {version}");
            return Ok(last);
        }
        if second % 10 == 0 {
            println!(
                "[demo] waiting for fleet API convergence ({}/{DEMO_NODE_COUNT} exact)",
                last.iter()
                    .filter(|node| fleet_node_converged(node, version))
                    .count()
            );
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    let lagging = last
        .iter()
        .filter(|node| is_cohort_member(node) && !fleet_node_converged(node, version))
        .map(|node| {
            format!(
                "{}={{healthy:{},version:{},group:{}}}",
                node.node,
                node.healthy,
                node.version.as_deref().unwrap_or("unreachable"),
                node.selected_group.as_deref().unwrap_or("unassigned")
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    Err(format!(
        "fleet did not converge at {version}: observed {} nodes; lagging [{lagging}]",
        last.len()
    )
    .into())
}

pub(crate) fn fleet_converged(nodes: &[FleetNode], version: &str) -> bool {
    // Scope convergence to the cohort fleet. The `/fleet` listing also carries the external
    // slice (group `external`), whose health is a separate concern verified by
    // `assert_external_endpoints_reconciled` — so a raw length check against the full listing
    // (32 cohort + `DEMO_EXTERNAL_COUNT`) would never settle. Require exactly the cohort count,
    // all converged.
    let cohort: Vec<&FleetNode> = nodes.iter().filter(|node| is_cohort_member(node)).collect();
    cohort.len() == DEMO_NODE_COUNT
        && cohort
            .iter()
            .all(|node| fleet_node_converged(node, version))
}

/// A node that belongs to a demo *cohort* (`demo-cohort-<n>`), as opposed to the external
/// slice (`external`) or an unassigned/enrolling node.
pub(crate) fn is_cohort_member(node: &FleetNode) -> bool {
    node.selected_group
        .as_deref()
        .is_some_and(|group| group.starts_with("demo-cohort-"))
}

pub(crate) fn fleet_node_converged(node: &FleetNode, version: &str) -> bool {
    node.healthy
        && node.version.as_deref() == Some(version)
        && node
            .selected_group
            .as_deref()
            .is_some_and(|group| group.starts_with("demo-"))
}

pub(crate) async fn fetch_fleet(
    client: &reqwest::Client,
    url: &str,
) -> Result<Vec<FleetNode>, Box<dyn std::error::Error>> {
    let body = client
        .get(format!("{url}/fleet"))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    Ok(serde_json::from_str(&body)?)
}

pub(crate) fn lifecycle_audit() -> Result<String, Box<dyn std::error::Error>> {
    output(Command::new("kubectl").args([
        "-n",
        "updated-system",
        "exec",
        "agent-4",
        "-c",
        "agent",
        "--",
        "cat",
        &format!("{DEMO_LIFECYCLE_STATE}/audit/lifecycle.tsv"),
    ]))
}

/// The attempt id of the newest completed update transaction in the reconciler's audit log.
///
/// The reconciler appends one `<operation>\t<attempt>\t<event>` row per invocation. An update
/// transaction is exactly one [`Operation::Apply`] under a deployment attempt id; the reserved
/// ids (`boot`, `periodic`, `fingerprint`) name observations that belong to no transaction and
/// must never be mistaken for one.
pub(crate) fn latest_completed_transaction(audit: &str) -> Option<String> {
    audit.lines().rev().find_map(|line| {
        let mut fields = line.split('\t');
        let (operation, attempt, event) = (fields.next()?, fields.next()?, fields.next()?);
        (operation == Operation::Apply.as_str()
            && event == "completed"
            && !attempt::is_reserved(attempt))
        .then(|| attempt.to_owned())
    })
}

/// The ordered sub-phases whose completion markers are absent from one attempt's effects
/// directory — an empty result is proof the whole enterprise sequence ran.
pub(crate) fn missing_sub_phase_markers(markers: &[String]) -> Vec<&'static str> {
    LIFECYCLE_SUB_PHASES
        .into_iter()
        .filter(|phase| {
            let marker = format!("{phase}.done");
            !markers.contains(&marker)
        })
        .collect()
}

/// The completion markers the reconciler left in one attempt's effects directory.
pub(crate) fn lifecycle_attempt_markers(
    attempt: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(output(Command::new("kubectl").args([
        "-n",
        "updated-system",
        "exec",
        "agent-4",
        "-c",
        "agent",
        "--",
        "ls",
        "-1",
        &format!("{DEMO_LIFECYCLE_STATE}/attempts/{attempt}"),
    ]))?
    .lines()
    .map(|name| name.trim().to_owned())
    .filter(|name| !name.is_empty())
    .collect())
}

pub(crate) fn demo_cluster_pod_capacity(cluster: &str) -> usize {
    output(Command::new("kubectl").args([
        "--context",
        &format!("kind-{cluster}"),
        "get",
        "nodes",
        "-o",
        "jsonpath={.items[0].status.allocatable.pods}",
    ]))
    .ok()
    .and_then(|capacity| capacity.trim().parse().ok())
    .unwrap_or(0)
}

pub(crate) fn repository_target_sha(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    output(Command::new("kubectl").args(RELEASE_SERVER_EXEC).args([
        "--",
        "server",
        "target-sha256",
        "--repo",
        "/data/repository",
        "--name",
        name,
    ]))
}

pub(crate) fn repository_platform() -> Result<String, Box<dyn std::error::Error>> {
    output(
        Command::new("kubectl")
            .args(RELEASE_SERVER_EXEC)
            .args(["--", "cat", "/data/platform"]),
    )
}

/// Retry-patch one node's demo labels until the operator has registered its `UpdateAgent`.
/// One path for every node kind; the label set is the only thing that differs.
pub(crate) fn patch_agent_labels(
    resource: &str,
    labels: serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let patch = serde_json::to_string(&serde_json::json!({ "spec": { "labels": labels } }))?;
    for _ in 0..60 {
        let ok = Command::new("kubectl")
            .args([
                "-n",
                "updated-system",
                "patch",
                "updateagent",
                resource,
                "--type=merge",
                "-p",
                &patch,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?
            .success();
        if ok {
            return Ok(());
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Err(format!("dynamic inventory never registered {resource}").into())
}

pub(crate) fn label_demo_agents() -> Result<(), Box<dyn std::error::Error>> {
    for ordinal in 0..DEMO_NODE_COUNT {
        patch_agent_labels(
            &agent_resource_name(ordinal as u8),
            serde_json::json!({
                "demo.updated.dev/node": format!("agent-{ordinal}"),
                "demo.updated.dev/cohort": cohort_label(ordinal / DEMO_COHORT_SIZE),
                "demo.updated.dev/track": null,
                "updated.dev/role": null
            }),
        )?;
    }
    Ok(())
}

/// The real-Magnolia nodes get a `kind=magnolia` marker (the UI badges them), their instance
/// `role` (author/publisher — the role UpdateGroup selects on), and their node name. No
/// cohort/set/fleet labels, so they sit entirely outside the convergence state machine and
/// pod-kill chaos — their slow ~4-minute installs never gate the fast sample-app cohorts.
pub(crate) fn label_magnolia_agents() -> Result<(), Box<dyn std::error::Error>> {
    for (role, _instance, _context, replicas) in MAGNOLIA_COHORTS {
        for ordinal in 0..replicas {
            let node = format!("magnolia-{role}-{ordinal}");
            patch_agent_labels(
                &resource_name(&node),
                serde_json::json!({
                    "demo.updated.dev/node": node,
                    "demo.updated.dev/kind": "magnolia",
                    "demo.updated.dev/role": role
                }),
            )?;
        }
    }
    Ok(())
}

/// Deploy the real-Magnolia cohorts: one StatefulSet per instance role (author, publisher) on
/// the Magnolia tower image, in the same headless `agents` Service (so `magnolia-<role>-N.agents`
/// resolves for the uniform readyz probe) and enrolling through the same gateway as every
/// other node. Each pod keeps its installed state and JCR repository on a persistent volume,
/// so a restart reuses the already-installed Magnolia (~30-60s) instead of the multi-minute
/// first install.
pub(crate) fn apply_magnolia_fleet() -> Result<(), Box<dyn std::error::Error>> {
    let items: Vec<serde_json::Value> = MAGNOLIA_COHORTS
        .iter()
        .map(|(role, instance, _context, replicas)| magnolia_statefulset(role, instance, *replicas))
        .collect();
    apply_json(&serde_json::json!({ "apiVersion": "v1", "kind": "List", "items": items }))
}

pub(crate) fn magnolia_statefulset(
    role: &str,
    instance: &str,
    replicas: usize,
) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": { "name": format!("magnolia-{role}"), "namespace": "updated-system" },
        "spec": {
            "serviceName": "agents",
            "replicas": replicas,
            "podManagementPolicy": "Parallel",
            "selector": { "matchLabels": { "app": "updated-agent", "demo.updated.dev/kind": "magnolia", "demo.updated.dev/role": role } },
            "template": {
                "metadata": { "labels": { "app": "updated-agent", "demo.updated.dev/kind": "magnolia", "demo.updated.dev/role": role } },
                "spec": {
                    "securityContext": { "fsGroup": 65532, "seccompProfile": { "type": "RuntimeDefault" } },
                    "containers": [{
                        "name": "agent",
                        // The very same plain Ubuntu + agent image as every other node — no
                        // Magnolia-specific image. The pre-start install provider installs
                        // Magnolia into this vanilla container at runtime.
                        "image": "updatec-e2e:kind",
                        "imagePullPolicy": "Never",
                        "command": ["/usr/local/bin/run-agent"],
                        "env": [
                            { "name": "MAGNOLIA_INSTANCE", "value": instance },
                            { "name": "MAGNOLIA_DATA", "value": "/var/lib/magnolia" },
                            // A separate disk (its own PVC) the activate phase writes the
                            // pre-upgrade JCR backup tar to, and rollback restores from.
                            { "name": "MAGNOLIA_BACKUPS", "value": "/var/lib/magnolia-backups" }
                        ],
                        "ports": [{ "name": "http", "containerPort": 8080 }, { "name": "guardian", "containerPort": 9090 }],
                        // Magnolia's first install is minutes; the startup probe gives it up to
                        // ~10 minutes before liveness applies, and readiness reflects the
                        // supervisor's real Magnolia health check the whole time.
                        "startupProbe": { "httpGet": { "path": "/startupz", "port": "guardian" }, "periodSeconds": 3, "failureThreshold": 200 },
                        // failureThreshold: 1 so a withdrawn-readiness pod leaves the Service
                        // endpoints on the very next probe (~1s), not after 3 — the drain hold
                        // above only has to cover that plus kube-proxy propagation.
                        "readinessProbe": { "httpGet": { "path": "/readyz", "port": "guardian" }, "periodSeconds": 1, "failureThreshold": 1 },
                        "livenessProbe": { "httpGet": { "path": "/livez", "port": "guardian" }, "periodSeconds": 5, "failureThreshold": 6 },
                        "securityContext": { "allowPrivilegeEscalation": false, "capabilities": { "drop": ["ALL"] }, "runAsNonRoot": true, "runAsUser": 65532 },
                        "resources": { "requests": { "cpu": "250m", "memory": "1Gi" }, "limits": { "memory": "1500Mi" } },
                        "volumeMounts": [
                            { "name": "state", "mountPath": "/var/lib/updated" },
                            { "name": "magnolia-data", "mountPath": "/var/lib/magnolia" },
                            { "name": "magnolia-backups", "mountPath": "/var/lib/magnolia-backups" },
                            { "name": "agent-tls", "mountPath": "/etc/agent-tls", "readOnly": true },
                            { "name": "tmp", "mountPath": "/tmp" }
                        ]
                    }],
                    "volumes": [
                        { "name": "tmp", "emptyDir": {} },
                        { "name": "agent-tls", "secret": { "secretName": "agent-tls" } }
                    ]
                }
            },
            "volumeClaimTemplates": [
                { "metadata": { "name": "state" }, "spec": { "accessModes": ["ReadWriteOnce"], "resources": { "requests": { "storage": "1Gi" } } } },
                { "metadata": { "name": "magnolia-data" }, "spec": { "accessModes": ["ReadWriteOnce"], "resources": { "requests": { "storage": "2Gi" } } } },
                // A distinct volume — "another disk" — for the pre-upgrade JCR backup tars.
                { "metadata": { "name": "magnolia-backups" }, "spec": { "accessModes": ["ReadWriteOnce"], "resources": { "requests": { "storage": "2Gi" } } } }
            ]
        }
    })
}

/// The enrollment name a host asserts, and hence the `UpdateAgent` resource name that node's
/// CR carries: the enrollment nonce is `sha256(hostname)` and the registration (hence the CR
/// name) is `sha256(that)`. One derivation for every node kind — sample-app pods, Magnolia pods,
/// and the out-of-cluster demo VM alike — so the demo can address any node's CR without special
/// cases.
///
/// **This is the only implementation of that derivation.** The nodes that assert the name
/// (`crates/updatec/e2e/agent.sh`), the kind e2e that looks the CRs up
/// (`scripts/kind-updatec-e2e.sh`), and the demo playbook (`deploy/ansible/demo.yml`) all read it
/// out of this function through `updatec-demo agent-name <hostname>` rather than re-deriving it,
/// so the name cannot drift between producer and consumers.
pub(crate) fn resource_name(hostname: &str) -> String {
    let nonce = updated::hash::sha256_bytes(hostname.as_bytes());
    let registration = updated::hash::sha256_bytes(nonce.as_bytes());
    format!("agent-{}", &registration[..24])
}

pub(crate) fn agent_resource_name(ordinal: u8) -> String {
    resource_name(&format!("agent-{ordinal}"))
}

/// The kind cluster name for the demo (override with `UPDATEC_DEMO_CLUSTER`).
pub(crate) fn demo_cluster() -> String {
    env::var("UPDATEC_DEMO_CLUSTER").unwrap_or_else(|_| "updatec-demo".into())
}

/// The local port the in-cluster demo service is forwarded to (override with `UPDATEC_DEMO_PORT`).
pub(crate) fn demo_port() -> String {
    env::var("UPDATEC_DEMO_PORT").unwrap_or_else(|_| "8088".into())
}

/// Point kubectl at the demo's kind cluster.
pub(crate) fn use_demo_context(cluster: &str) -> Result<(), Box<dyn std::error::Error>> {
    run(Command::new("kubectl").args(["config", "use-context", &format!("kind-{cluster}")]))
}

/// Delete the demo's kind cluster (idempotent — kind treats a missing cluster as success).
pub(crate) fn delete_demo_cluster(cluster: &str) -> Result<(), Box<dyn std::error::Error>> {
    run(Command::new("kind").args(["delete", "cluster", "--name", cluster]))
}

/// Wait for the in-cluster demo service to be ready, port-forward it to `127.0.0.1:{port}`, run
/// `body` against its URL, and always tear the forward down afterward. Shared by the initial
/// bring-up (`start_demo`) and the repeatable fleet exercise (`exercise_existing_cluster`).
pub(crate) async fn with_demo_port_forward<F, Fut>(
    port: &str,
    body: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnOnce(String) -> Fut,
    Fut: std::future::Future<Output = Result<(), Box<dyn std::error::Error>>>,
{
    println!("[demo] waiting for the Rust demo service to become ready");
    run(Command::new("kubectl").args([
        "-n",
        "updated-system",
        "rollout",
        "status",
        "deployment/updatec-demo",
        "--timeout=120s",
    ]))?;
    let mut forward = Command::new("kubectl")
        .args([
            "-n",
            "updated-system",
            "port-forward",
            "service/updatec-demo",
            &format!("{port}:80"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let url = format!("http://127.0.0.1:{port}");
    println!("[demo] forwarding the service to {url}");
    wait_for_url(&format!("{url}/healthz")).await?;
    let result = body(url).await;
    let _ = forward.kill();
    result
}

/// Run the fleet-chaos test `passes` times against an already-provisioned cluster, then exit.
/// Requires a cluster already brought up by `e2e` / `start`; that expensive build happens once and
/// leaves the cluster live. Each pass diverges from the fleet's
/// current converged version (the chaos detects the baseline), climbs through broken and valid
/// rollouts under pod-kill chaos, and reconverges — no cluster rebuild. A failing pass leaves the
/// cluster up for diagnosis.
pub(crate) async fn exercise_existing_cluster(
    passes: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    use_demo_context(&demo_cluster())?;
    with_demo_port_forward(&demo_port(), |url| async move {
        let client = reqwest::Client::new();
        for pass in 1..=passes {
            // Distinct, reproducible seed per pass (pass 1 = the canonical CHAOS_SEED_BASE): each
            // pass drives a different chaos schedule — kill timing, controller-crash rounds, victim
            // pods, and per-wave rollout width — and the printed seed makes any failure replayable.
            let seed = CHAOS_SEED_BASE ^ (pass as u64 - 1).wrapping_mul(CHAOS_SEED_SPREAD);
            if passes != 1 {
                println!("\n[demo] fleet-exercise pass {pass}/{passes} (seed {seed:#x})");
            }
            exercise_fleet_actions(&client, &url, seed, true).await?;
        }
        Ok(())
    })
    .await
}

pub(crate) fn reset_demo() -> Result<(), Box<dyn std::error::Error>> {
    delete_demo_cluster(&demo_cluster())
}

pub(crate) fn command_exists(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new(name)
        .arg("--help")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| format!("required command {name:?} is not installed"))?;
    if status.success() || status.code().is_some() {
        Ok(())
    } else {
        Err(format!("could not execute required command {name:?}").into())
    }
}

pub(crate) fn workspace_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
    let mut path = env::current_exe()?;
    while path.pop() {
        if path.join("Cargo.toml").is_file() && path.join("crates/updatec").is_dir() {
            return Ok(path);
        }
    }
    let current = env::current_dir()?;
    if current.join("Cargo.toml").is_file() {
        return Ok(current);
    }
    Err("run the demo from the updatedc workspace".into())
}

/// The base64 value of one key in a Secret, as the API stores it — used to hand the fleet
/// client certificate (from the cert-manager-issued `agent-tls`) to the external-VM Ansible run.
pub(crate) fn secret_value(name: &str, key: &str) -> Result<String, Box<dyn std::error::Error>> {
    kubectl_value(
        "secret",
        name,
        &format!("{{.data.{}}}", key.replace('.', "\\.")),
    )
}

pub(crate) fn kubectl_value(
    kind: &str,
    name: &str,
    path: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    output(Command::new("kubectl").args([
        "-n",
        "updated-system",
        "get",
        kind,
        name,
        "-o",
        &format!("jsonpath={path}"),
    ]))
}

/// The node's pinned public key (hex EC point) the control plane recorded on its `UpdateAgent` at
/// enrollment. The healthproxy verifies each node's signed health report against it, so it must be
/// handed the same key the throttle pins — read here from the trusted in-cluster resource (never the
/// CDN). Enrollment is asynchronous, so retry until the key appears rather than deploy a healthproxy
/// that can never mark the node ready.
pub(crate) fn agent_pinned_public_key(
    resource: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    for _ in 0..60 {
        if let Ok(key) = kubectl_value("updateagent", resource, "{.spec.identity.publicKey}") {
            let key = key.trim().to_string();
            if !key.is_empty() {
                return Ok(key);
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    Err(format!("UpdateAgent {resource} never published a pinned public key to verify its health reports against").into())
}

/// Label the external agents into the `external` cohort the external UpdateGroup selects. No
/// set/fleet label — they sit outside the per-set machinery on purpose.
pub(crate) fn label_external_agents() -> Result<(), Box<dyn std::error::Error>> {
    for index in 0..DEMO_EXTERNAL_COUNT {
        let ordinal = external_ordinal(index);
        patch_agent_labels(
            &agent_resource_name(ordinal as u8),
            serde_json::json!({
                "demo.updated.dev/node": format!("agent-{ordinal}"),
                "demo.updated.dev/cohort": DEMO_EXTERNAL_COHORT,
                "demo.updated.dev/track": null,
                "updated.dev/role": null
            }),
        )?;
    }
    Ok(())
}

/// Deploy the real `updated-healthproxy` reconciler for the external slice. It is handed a
/// **static** `node=address` inventory — exactly as a real deployment would hand it an
/// OpenStack/VMware VM list — built here from the external pods' identities and current IPs.
/// The reconciler then programs the selectorless `external` Service's EndpointSlice purely
/// from those nodes' CDN health, with no knowledge that they happen to be pods.
pub(crate) fn deploy_external_reconciler(
    magnolia_enabled: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut members = Vec::with_capacity(DEMO_EXTERNAL_COUNT);
    for index in 0..DEMO_EXTERNAL_COUNT {
        let ordinal = external_ordinal(index);
        let pod = format!("agent-{ordinal}");
        let ip = kubectl_value("pod", &pod, "{.status.podIP}")?;
        let ip = ip.trim();
        if ip.is_empty() {
            return Err(format!("external agent {pod} has no pod IP yet").into());
        }
        // The node key is the enrolled identity its NodeReport is written under, not the pod
        // name — the reconciler reads `<report>/telemetry/<identity>.json`. The pinned public key
        // is appended so the healthproxy verifies the report's signature, not merely its shape.
        let node = agent_resource_name(ordinal as u8);
        let key = agent_pinned_public_key(&node)?;
        members.push(format!("{node}={ip}={key}"));
    }
    // A real out-of-cluster VM, if one was provisioned, joins the same inventory — a static
    // `node=address=pubkeyhex` entry indistinguishable from a genuine VM's, which is exactly the
    // point.
    if magnolia_enabled {
        if let Some((_, address)) = external_vm_target() {
            let node = resource_name(DEMO_EXTERNAL_VM_HOSTNAME);
            let key = agent_pinned_public_key(&node)?;
            members.push(format!("{node}={address}={key}"));
        }
    }
    let members = members.join(",");
    apply_json(&serde_json::json!({
        "apiVersion":"apps/v1","kind":"Deployment",
        "metadata":{"name":"external-healthproxy","namespace":"updated-system"},
        "spec":{"replicas":1,"selector":{"matchLabels":{"app":"external-healthproxy"}},
            "template":{"metadata":{"labels":{"app":"external-healthproxy"}},
            "spec":{"serviceAccountName":"external-healthproxy","containers":[{
                "name":"healthproxy","image":"updatec-e2e:kind","imagePullPolicy":"Never",
                "command":["/usr/local/bin/updated-healthproxy"],
                "env":[
                    {"name":"HEALTHPROXY_HEALTH_BASE","value":DEMO_HEALTH_CDN},
                    {"name":"HEALTHPROXY_NAMESPACE","value":"updated-system"},
                    {"name":"HEALTHPROXY_SERVICE","value":DEMO_EXTERNAL_SERVICE},
                    {"name":"HEALTHPROXY_PORT","value":"8080"},
                    {"name":"HEALTHPROXY_MEMBERS","value":members}
                ]
            }]}}
        }
    }))?;
    run(Command::new("kubectl").args([
        "-n",
        "updated-system",
        "rollout",
        "status",
        "deployment/external-healthproxy",
        "--timeout=120s",
    ]))
}

/// The out-of-cluster VM to provision, if configured and reachable over passwordless SSH:
/// `(ssh_target, address)`. `None` — unset, or no key-based SSH — skips the crude VM path
/// entirely (it is demo-only and best-effort, and this guard is exactly "only if sudoless SSH").
pub(crate) fn external_vm_target() -> Option<(String, String)> {
    let target = env::var("DEMO_EXTERNAL_VM")
        .ok()
        .filter(|value| !value.is_empty())?;
    let reachable = Command::new("ssh")
        .args([
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "ConnectTimeout=5",
            &target,
            "true",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false);
    if !reachable {
        println!("[demo] DEMO_EXTERNAL_VM={target} unreachable over passwordless SSH; skipping the out-of-cluster VM");
        return None;
    }
    let address = target.rsplit('@').next().unwrap_or(&target).to_string();
    Some((target, address))
}

/// Best-effort, deliberately crude for the live demo: install the agent on a real
/// out-of-cluster VM via **ansible** (the VM-fleet deliverable — the same role a customer would
/// run). Ansible builds the agent from source on the target and runs it as a systemd service,
/// pointed — through a `socat`/`/etc/hosts` shim — at the in-cluster gateway, which we expose to
/// the LAN with `kubectl port-forward --address 0.0.0.0`. The VM then enrolls, phones home, and
/// gets Magnolia like any node. Driven entirely from the laptop over its passwordless SSH.
pub(crate) fn provision_external_vm(ssh_target: &str) -> Result<(), Box<dyn std::error::Error>> {
    command_exists("ansible-playbook")?;
    let root = workspace_root()?;
    // The LAN IP the VM dials back to reach the exposed gateway — the host running the demo,
    // which is this laptop locally or the build/demo server when run over SSH. Detected across
    // platforms: `ipconfig` on macOS, `hostname -I` on Linux; override with DEMO_HOST_IP.
    let host_ip = env::var("DEMO_HOST_IP")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| {
            output(Command::new("ipconfig").args(["getifaddr", "en0"]))
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .or_else(|| {
            output(Command::new("hostname").arg("-I"))
                .ok()
                .and_then(|value| value.split_whitespace().next().map(str::to_string))
                .filter(|value| !value.is_empty())
        })
        .ok_or("could not determine the host LAN IP (set DEMO_HOST_IP) to expose the gateway")?;

    // Expose the in-cluster gateway on the Mac's LAN so the VM's socat shim can reach it. Leaked
    // on purpose: it must outlive this call and stay up for the demo's duration.
    Command::new("kubectl")
        .args([
            "-n",
            "updated-system",
            "port-forward",
            "--address",
            "0.0.0.0",
            "service/updatec-gateway",
            &format!("{DEMO_EXTERNAL_VM_GATEWAY_PORT}:80"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    // A one-host inventory for the target, then run the shipped role against it.
    let (user, host) = ssh_target.split_once('@').unwrap_or(("root", ssh_target));
    let dir = owner_only_scratch_dir("updatec-demo-external-vm")?;
    let inventory = dir.path().join("inventory.ini");
    std::fs::write(
        &inventory,
        format!("[updated_agents]\n{host} ansible_user={user}\n"),
    )?;

    // The external VM presents the same fleet client certificate as the in-cluster agents, read
    // from the cert-manager-issued secret (base64; Ansible b64decodes it onto the VM). These go in
    // an owner-only vars FILE, never on the command line: `-e key=<private key>` puts the fleet
    // client key in every process listing on this machine for as long as the playbook runs.
    let vars = dir.path().join("enrollment-vars.json");
    write_owner_only(
        &vars,
        serde_json::to_vec(&serde_json::json!({
            "updated_enrollment_client_cert": secret_value("agent-tls", "tls.crt")?,
            "updated_enrollment_client_key": secret_value("agent-tls", "tls.key")?,
            "updated_enrollment_ca": secret_value("agent-tls", "ca.crt")?,
        }))?
        .as_slice(),
    )?;

    run(Command::new("ansible-playbook")
        .env("ANSIBLE_HOST_KEY_CHECKING", "False")
        .arg("-i")
        .arg(&inventory)
        .arg(root.join("deploy/ansible/install-agent.yml"))
        .args(["-e", &format!("updatedc_source={}", root.display())])
        .args(["-e", "updated_enrollment_url=https://updatec-gateway"])
        .args(["-e", &format!("@{}", vars.display())])
        // `updated_hostname` is the one variable the role writes as the self-asserted enrollment
        // name, and it must be the sha-derived resource name the demo addresses the VM's
        // UpdateAgent by (`label_external_vm_agent` uses the same), not the raw hostname.
        .args([
            "-e",
            &format!(
                "updated_hostname={}",
                resource_name(DEMO_EXTERNAL_VM_HOSTNAME)
            ),
        ])
        .args(["-e", &format!("updated_demo_shim_host={host_ip}")])
        .args([
            "-e",
            &format!("updated_demo_shim_port={DEMO_EXTERNAL_VM_GATEWAY_PORT}"),
        ]))
}

/// A fresh, unpredictable, owner-only directory under the system temp dir, removed when it drops.
///
/// The demo drops the fleet client key in here, so the directory must be one no other local user
/// could have pre-created or could read: [`tempfile`] mints an unpredictable name, creates it
/// exclusively at mode 0700, and removes the tree on drop — the workspace's one way to hold a
/// private scratch directory. What it does not cover is a run killed by a signal, which never
/// drops anything: [`sweep_stale_scratch_dirs`] collects those.
fn owner_only_scratch_dir(prefix: &str) -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    sweep_stale_scratch_dirs(prefix);
    Ok(tempfile::Builder::new()
        .prefix(&format!("{prefix}-"))
        .tempdir()?)
}

/// How long a scratch directory must have sat untouched before the sweep treats it as abandoned.
///
/// A run that still owns its scratch keeps writing under it (and finishes in minutes), so an entry
/// this old belongs to no live run — while anything younger might be a concurrent demo's, whose
/// enrollment vars its playbook still needs.
const SCRATCH_SWEEP_MIN_IDLE: std::time::Duration = std::time::Duration::from_secs(6 * 60 * 60);

/// Remove the scratch directories of runs that died before their [`tempfile::TempDir`] could drop.
///
/// A `Drop` guard does not run for a Ctrl-C at the terminal or a kill during the playbook — the
/// long part of this call — so without this, every interrupted demo leaves another copy of the
/// fleet client key under the temp directory. The name shape `<prefix>-<entropy>` is one only
/// [`owner_only_scratch_dir`] writes, so a matching entry is this demo's scratch and nothing else,
/// but a *live* run's scratch looks exactly like a dead one's: only idleness separates them, hence
/// [`SCRATCH_SWEEP_MIN_IDLE`]. Best effort throughout — a directory another user planted under the
/// prefix is one we cannot remove, and refusing to run the demo over it would gain nothing, since
/// the create below still refuses to adopt any existing entry.
fn sweep_stale_scratch_dirs(prefix: &str) {
    let Ok(entries) = std::fs::read_dir(env::temp_dir()) else {
        return;
    };
    let prefix = format!("{prefix}-");
    let now = std::time::SystemTime::now();
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with(&prefix) {
            continue;
        }
        let idle = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|modified| now.duration_since(modified).ok());
        if !scratch_dir_is_abandoned(idle) {
            continue;
        }
        let path = entry.path();
        if let Err(error) = std::fs::remove_dir_all(&path) {
            println!(
                "[demo] could not remove {}, the scratch directory an interrupted run left \
                 behind: {error}",
                path.display()
            );
        }
    }
}

/// Whether a scratch directory idle for `idle` is old enough to have outlived its run.
///
/// An unreadable or future-dated timestamp yields `None`, which counts as *not* abandoned: leaving
/// a stale key behind is loud (the next sweep gets it) where deleting a live run's is not.
fn scratch_dir_is_abandoned(idle: Option<std::time::Duration>) -> bool {
    idle.is_some_and(|idle| idle >= SCRATCH_SWEEP_MIN_IDLE)
}

/// Write `bytes` to `path` readable only by this user — the demo's one place secret material
/// lands on local disk.
///
/// The 0600 mode only applies to a file this call creates, so the file is opened `create_new`: a
/// pre-existing entry (whose mode, or symlink target, we would otherwise inherit) is unlinked and
/// the create retried once, and a second collision is an error rather than a permissive write.
fn write_owner_only(
    path: &std::path::Path,
    bytes: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            std::fs::remove_file(path)?;
            options.open(path)?
        }
        Err(error) => return Err(error.into()),
    };
    std::io::Write::write_all(&mut file, bytes)?;
    Ok(())
}

/// Label the enrolled VM's UpdateAgent into the `external-vm` cohort the Magnolia group selects.
pub(crate) fn label_external_vm_agent() -> Result<(), Box<dyn std::error::Error>> {
    patch_agent_labels(
        &resource_name(DEMO_EXTERNAL_VM_HOSTNAME),
        serde_json::json!({
            "demo.updated.dev/node": DEMO_EXTERNAL_VM_HOSTNAME,
            "demo.updated.dev/cohort": DEMO_EXTERNAL_VM_COHORT,
            "demo.updated.dev/kind": "magnolia"
        }),
    )
}

#[allow(clippy::too_many_arguments)]
/// Initialize the MinIO release repository the demo's app cohorts roll through `updatectl
/// deploy`, and seed the baseline they converge to. Everything runs inside the release-server
/// pod — it has `updatectl`, reaches MinIO in-cluster, and mounts the shared release-repository
/// PVC at `/data`, so the signing keys we mint there are the same ones the demo's serve pod
/// reads at `/release-data/release-keys`. Returns `(root.json, baseline path, baseline sha256)`.
///
/// Idempotent: re-running against an already-initialized repo is a no-op for the keys and a
/// content-addressed republish for the baseline (same bytes → same target).
/// `(release_root, baseline_path, baseline_sha, provider_sha)` — the
/// signed identities [`bootstrap_minio_release_repo`] mints and republishes onto the shared PVC.
type ReleaseBootstrap = (String, String, String, String);

/// The MinIO release repository every demo group resolves its bundles from, pinned to the root
/// `bootstrap_minio_release_repo` minted onto the shared release PVC. Built from the same
/// endpoint/bucket/prefix constants [`release_repository_flags`] addresses, so what `updatectl`
/// publishes into and what a group resolves out of are one fact.
pub(crate) fn minio_release_repository(release_root: &str) -> serde_json::Value {
    serde_json::json!({
        "metadataUrl": release_repository_url("metadata"),
        "targetsUrl": release_repository_url("targets"),
        "rootJson": release_root,
    })
}

/// A seed group's deployment: a full clone of the fully-valid `edge` deployment (so every
/// CRD-required field is present) with only its release repository pointed at MinIO. Its selector
/// matches nothing, so no node adopts it; `updatectl deploy` overwrites its `application` and the
/// published bundle's product/entrypoint come from the deploy flags, so the runtime here is unused.
pub(crate) fn seed_deployment(edge: &serde_json::Value, release_root: &str) -> serde_json::Value {
    let mut deployment = edge["spec"]["deployment"].clone();
    deployment["releaseRepository"] = minio_release_repository(release_root);
    deployment
}

pub(crate) fn bootstrap_minio_release_repo(
    edge: &serde_json::Value,
    platform: &str,
) -> Result<ReleaseBootstrap, Box<dyn std::error::Error>> {
    // Returns (release_root, baseline_path, baseline_sha, provider_sha).
    // Every `updatectl` below addresses the one release repository the groups resolve from.
    let repository = release_repository_flags();
    // 1. Mint keys + initialize the repo once, onto the shared PVC (skip if already there).
    run(Command::new("kubectl").args(RELEASE_SERVER_EXEC).args([
        "--",
        "sh",
        "-c",
        &format!(
            "set -e; export AWS_ACCESS_KEY_ID=minio AWS_SECRET_ACCESS_KEY=minio123; \
             if [ ! -f /data/release-keys/root.json ]; then mkdir -p /data/release-keys; \
             updatectl trust-root --keys-dir /data/release-keys {repository} \
             --root-out /data/release-keys/root.json; fi"
        ),
    ]))?;
    let release_root = output(Command::new("kubectl").args(RELEASE_SERVER_EXEC).args([
        "--",
        "cat",
        "/data/release-keys/root.json",
    ]))?;

    // 2. Seed the baseline. `updatectl deploy` publishes AND patches a group, so deploy to a
    //    throwaway group whose repo is MinIO, read back the content-addressed path+sha the
    //    cohorts start on, then delete it. Its selector matches nothing, so no node adopts it.
    let seed_deployment = seed_deployment(edge, &release_root);
    apply_json(&serde_json::json!({
        "apiVersion": "updated.dev/v1alpha1",
        "kind": "UpdateGroup",
        "metadata": {"name": "release-seed", "namespace": "updated-system"},
        "spec": {
            "repositoryRef": {"name": "default"},
            "selector": {"matchLabels": {"demo.updated.dev/cohort": "__release-seed-unmatched__"}},
            "deployment": seed_deployment
        }
    }))?;
    run(Command::new("kubectl").args(RELEASE_SERVER_EXEC).args([
        "--",
        "sh",
        "-c",
        &format!(
            "set -e; export AWS_ACCESS_KEY_ID=minio AWS_SECRET_ACCESS_KEY=minio123; \
             rm -rf /tmp/seed && mkdir -p /tmp/seed/bin /tmp/seed/config; \
             cp /usr/local/bin/sampleapp /tmp/seed/bin/app; \
             printf 'version = \"22.0.0\"\\n' >/tmp/seed/config/release.toml; \
             updatectl deploy --keys-dir /data/release-keys {repository} \
             --namespace updated-system --group release-seed --product app --channel stable --version 22.0.0 \
             --entrypoint bin/app --platform {platform} --source /tmp/seed"
        ),
    ]))?;
    let baseline_path = output(Command::new("kubectl").args([
        "-n",
        "updated-system",
        "get",
        "updategroup",
        "release-seed",
        "-o",
        "jsonpath={.spec.deployment.application.path}",
    ]))?;
    let baseline_sha = output(Command::new("kubectl").args([
        "-n",
        "updated-system",
        "get",
        "updategroup",
        "release-seed",
        "-o",
        "jsonpath={.spec.deployment.application.sha256}",
    ]))?;
    run(Command::new("kubectl").args([
        "-n",
        "updated-system",
        "delete",
        "updategroup",
        "release-seed",
        "--ignore-not-found",
    ]))?;
    // 3. Publish the demo node reconciler into MinIO. The sample-app cohorts resolve both the
    //    application and reconciler from this repository.
    let provider_timeout_ms = demo_lifecycle::PROVIDER_TIMEOUT_MS;
    let provider_sets = output(Command::new("kubectl").args(RELEASE_SERVER_EXEC).args([
        "--",
        "sh",
        "-c",
        &format!(
            "set -e; export AWS_ACCESS_KEY_ID=minio AWS_SECRET_ACCESS_KEY=minio123; \
             rm -rf /tmp/rube && mkdir -p /tmp/rube/bin; \
             cp /usr/local/bin/demo-lifecycle /tmp/rube/bin/lifecycle; \
             chmod 0755 /tmp/rube/bin/lifecycle; \
             art=$(updatectl publish-provider-artifact --keys-dir /data/release-keys \
               {repository} --product demo-enterprise-lifecycle --version 1.0.0 --entrypoint bin/lifecycle \
               --source /tmp/rube --platform {platform}); \
             set -- $art; \
             reconciler=$(updatectl publish-provider-set --keys-dir /data/release-keys \
               {repository} --id rube-goldberg --provider-path \"$1\" --provider-sha256 \"$2\" \
               --provider-timeout-ms {provider_timeout_ms}); \
             echo \"$reconciler\" | awk '{{print $NF}}'"
        ),
    ]))?;
    let provider_sha = provider_sets.trim().to_owned();
    if provider_sha.is_empty() {
        return Err("publish-provider-set printed no set sha".into());
    }
    Ok((
        release_root,
        baseline_path.trim().to_owned(),
        baseline_sha.trim().to_owned(),
        provider_sha,
    ))
}

// The five `magnolia_*` parameters are what push this over the argument threshold; they collapse
// into one struct once the Magnolia demo wiring is finalized (it is currently being pared back).
#[allow(clippy::too_many_arguments)]
pub(crate) fn apply_demo_resources(
    provider_path: &str,
    magnolia_enabled: bool,
    magnolia_path: &str,
    magnolia_sha: &str,
    magnolia_provider_path: &str,
    magnolia_provider_sha: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let edge: serde_json::Value = serde_json::from_str(&output(Command::new("kubectl").args([
        "-n",
        "updated-system",
        "get",
        "updategroup",
        "edge",
        "-o",
        "json",
    ]))?)?;
    // Bootstrap the MinIO release repository the app cohorts roll through `updatectl deploy` —
    // the real CI release path, not the in-cluster `server publish-app`. Idempotent init of the
    // repo + signing keys, then seed the baseline the cohorts converge to so its content hash is
    // authoritative. Runs inside release-server (it carries `updatectl`, reaches MinIO, and
    // shares the release-repository PVC where the keys land for the serve pod to reuse).
    //
    // `updatectl deploy` runs inside the release-server pod, which carries no explicit
    // serviceAccountName and so authenticates as the namespace `default` SA. Grant that SA the
    // updategroups/updategroupsets access the deploy needs BEFORE the bootstrap runs — otherwise
    // the very first `updatectl deploy` 403s trying to get the release-seed UpdateGroup. (The
    // `updatec-demo` Role applied further down covers only the UI's SA, not the deploy's.)
    apply_json(&serde_json::json!({
        "apiVersion": "v1", "kind": "List", "items": [
            {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"release-server-deployer","namespace":"updated-system"},"rules":[
                {"apiGroups":["updated.dev"],"resources":["updategroups"],"verbs":["get","list","patch"]},
                {"apiGroups":["updated.dev"],"resources":["updategroupsets"],"verbs":["get","list","create","patch"]}
            ]},
            {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"release-server-deployer","namespace":"updated-system"},"subjects":[{"kind":"ServiceAccount","name":"default","namespace":"updated-system"}],"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"release-server-deployer"}}
        ]
    }))?;
    let platform = repository_platform()?;
    let (release_root, baseline_path, baseline_sha, provider_sha) =
        bootstrap_minio_release_repo(&edge, &platform)?;
    let provider = serde_json::json!({"path": provider_path, "sha256": provider_sha});
    let minio_release_repository = minio_release_repository(&release_root);
    // The sample-app cohorts (and the external slice) start on the MinIO-published baseline the
    // demo then rolls with `updatectl deploy`, not the release-server baseline the callers pass.
    let success_path = baseline_path.as_str();
    let success_sha = baseline_sha.as_str();
    let group = |name: &str, cohort: &str, set: &str, path: &str, sha256: &str| {
        let mut deployment = edge["spec"]["deployment"].clone();
        deployment["name"] = name.into();
        deployment["application"] = serde_json::json!({"path": path, "sha256": sha256});
        // Point the cohort at MinIO: this is the repository `updatectl deploy` publishes to and
        // patches. The Magnolia groups below keep edge's release-server repo (the default path).
        deployment["releaseRepository"] = minio_release_repository.clone();
        deployment["providerSet"] = provider.clone();
        // Nodes write rollout telemetry here so the control plane can throttle the fleet.
        deployment["reportUrl"] = DEMO_REPORT_URL.into();
        // Signed opt-in to first-install ordered fallback: a killed, stateless agent
        // pod returns cold and must descend from its assigned version to the newest
        // healthy release rather than stranding on a broken head. This is what makes
        // the pod-kill chaos survivable across every cohort under rollout.
        deployment["orderedInstallFallback"] = serde_json::json!(true);
        // Fast test cadence so the live demo reacts within a second or two instead of
        // the production-shaped 5-60s defaults: agents check for new desired state
        // every second, retry and refresh quickly, and don't linger in a long health
        // grace. These are signed into each cohort's assignment (the agent reads
        // intervals only from its signed config, never from environment).
        deployment["runtime"]["timeouts"] = serde_json::json!({
            "checkIntervalSeconds": 1,
            "healthGraceSeconds": 8,
            "healthSuccesses": 1,
            "healthIntervalSeconds": 1,
            "refreshRetrySeconds": 1,
            "confirmationWindowSeconds": 3,
            "supervisorCheckIntervalSeconds": 3600,
            // Hold the drain up to 4s after withdrawing readiness so kube-proxy drops this pod
            // from the per-set Service endpoints before the app is stopped — otherwise a rollout
            // restart drops the ~2s of in-flight requests that land while the endpoint lingers
            // (a bare readiness flip is not enough; the removal must propagate first). Paired with
            // the readiness probe's failureThreshold: 1 below, the endpoint clears in ~1-2s, well
            // inside this ceiling. (Externally-managed cohorts could set this to null/indefinite
            // once the intermediary signs the drain acknowledgement into the status.)
            "drainHoldSeconds": 4
        });
        // Every group carries the fleet label (its single throttle set) and its display
        // pair label (UI grouping / per-pair load balancer only, not a throttle).
        let mut labels = serde_json::Map::new();
        labels.insert(DEMO_FLEET_LABEL.into(), DEMO_FLEET_VALUE.into());
        labels.insert(SET_LABEL.into(), set.into());
        serde_json::json!({
            "apiVersion":"updated.dev/v1alpha1",
            "kind":"UpdateGroup",
            "metadata":{
                "name":name,
                "namespace":"updated-system",
                "labels":labels
            },
            "spec":{
                "repositoryRef":{"name":"default"},
                "selector":{"matchLabels":{"demo.updated.dev/cohort":cohort}},
                "deployment":deployment
            }
        })
    };
    let mut items = serde_json::json!([
            {"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"updatec-demo","namespace":"updated-system"}},
            {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"updatec-demo","namespace":"updated-system"},"rules":[
                {"apiGroups":["updated.dev"],"resources":["updateagents"],"verbs":["get","list","patch"]},
                {"apiGroups":["updated.dev"],"resources":["updategroups"],"verbs":["get","list","patch"]},
                {"apiGroups":["updated.dev"],"resources":["updategroupsets"],"verbs":["get","list","create","patch"]},
                {"apiGroups":[""],"resources":["pods"],"verbs":["get","list","watch","delete","patch"]}
            ]},
            {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"updatec-demo","namespace":"updated-system"},"subjects":[{"kind":"ServiceAccount","name":"updatec-demo","namespace":"updated-system"}],"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"updatec-demo"}}
    ])
    .as_array()
    .cloned()
    .expect("demo resource list is an array");
    for index in 0..DEMO_COHORT_COUNT {
        items.push(group(
            &cohort_group(index),
            &cohort_label(index),
            &set_name(cohort_set_index(index)),
            success_path,
            success_sha,
        ));
    }
    // The two real-Magnolia cohorts (author, publisher): same clean group path, just
    // different data. Each selects its `role` nodes and assigns the magnolia product with that
    // instance's readiness URL and a boot-time-sized health grace. Neither carries a
    // fleet/set label — so they are upgraded one node at a time by the same supervisor
    // mechanism (zero downtime across each pair) yet sit entirely outside the convergence
    // throttling and pod-kill chaos that drive the sample-app cohorts.
    // One Magnolia UpdateGroup builder: the author/publisher cohorts and the manual
    // out-of-cluster VM group are identical apart from their name, readiness URL context, and
    // selector. Every group clones edge's deployment, assigns the magnolia product with custom
    // activation, and uses the boot-sized health grace and relaxed cadence Magnolia's
    // multi-minute install needs.
    let magnolia_group = |name: &str,
                          selector: serde_json::Value,
                          magnolia_path: &str,
                          magnolia_sha: &str,
                          magnolia_provider_path: &str,
                          magnolia_provider_sha: &str|
     -> serde_json::Value {
        let mut deployment = edge["spec"]["deployment"].clone();
        deployment["name"] = name.into();
        deployment["application"] =
            serde_json::json!({"path": magnolia_path, "sha256": magnolia_sha});
        deployment["providerSet"] =
            serde_json::json!({"path": magnolia_provider_path, "sha256": magnolia_provider_sha});
        deployment["reportUrl"] = DEMO_REPORT_URL.into();
        deployment["orderedInstallFallback"] = serde_json::json!(false);
        deployment["runtime"]["product"] = "magnolia".into();
        deployment["runtime"]["mode"] = "managed".into();
        deployment["runtime"]["args"] = serde_json::json!([]);
        // The Magnolia reconciler backs the JCR up before activation and reuses the repository.
        // Managed mode supplies the process stop/start; rollback restores the backup.
        // Magnolia's first install runs for minutes; give it a boot-sized health grace and a
        // relaxed cadence rather than the fleet's sub-second timings.
        deployment["runtime"]["timeouts"] = serde_json::json!({
            "checkIntervalSeconds": 5,
            "healthGraceSeconds": 360,
            "healthSuccesses": 1,
            "healthIntervalSeconds": 3,
            "refreshRetrySeconds": 5,
            "confirmationWindowSeconds": 10,
            "supervisorCheckIntervalSeconds": 3600
        });
        serde_json::json!({
            "apiVersion":"updated.dev/v1alpha1",
            "kind":"UpdateGroup",
            "metadata":{"name": name, "namespace":"updated-system"},
            "spec":{
                "repositoryRef":{"name":"default"},
                "selector": selector,
                "deployment": deployment
            }
        })
    };
    for (role, _instance, _context, _replicas) in
        MAGNOLIA_COHORTS.into_iter().filter(|_| magnolia_enabled)
    {
        items.push(magnolia_group(
            &format!("magnolia-{role}"),
            serde_json::json!({"matchLabels":{"demo.updated.dev/kind":"magnolia", "demo.updated.dev/role": role}}),
            magnolia_path,
            magnolia_sha,
            magnolia_provider_path,
            magnolia_provider_sha,
        ));
    }
    // The out-of-cluster VM IS the manual Magnolia node (no in-cluster pod stands in): the
    // `magnolia-manual` group selects the VM's `external-vm` cohort. It installs Magnolia through
    // the identical mechanism as the in-cluster pods; the only difference is it runs on a real VM
    // the reconciler fronts.
    if magnolia_enabled {
        items.push(magnolia_group(
            MAGNOLIA_MANUAL_GROUP,
            serde_json::json!({"matchLabels":{"demo.updated.dev/cohort": DEMO_EXTERNAL_VM_COHORT}}),
            magnolia_path,
            magnolia_sha,
            magnolia_provider_path,
            magnolia_provider_sha,
        ));
    }
    // Per-set UpdateGroupSet (default maxConcurrent = members-1): never both groups of a
    // set roll at once, so every set always keeps a group serving and holds its own SLA.
    for set in 0..DEMO_SET_COUNT {
        items.push(serde_json::json!({
            "apiVersion":"updated.dev/v1alpha1",
            "kind":"UpdateGroupSet",
            "metadata":{"name":set_name(set),"namespace":"updated-system"},
            "spec":{"selector":{"matchLabels":{"demo.updated.dev/set":set_name(set)}}}
        }));
    }
    // One fleet-wide UpdateGroupSet over every managed group, on top of the per-set caps:
    // the control plane keeps at most DEMO_FLEET_CONCURRENCY groups rolling at once, and —
    // because each group is in both its set and the fleet set — admits a group only when
    // BOTH have a slot. So the rollout pipelines DEMO_FLEET_CONCURRENCY groups across that
    // many DISTINCT sets, each set keeping its other group up: fleet-wide pacing without
    // ever draining a set below its SLA. As one group settles the next (in set order)
    // starts, so the pipeline stays full without pausing set-by-set.
    items.push(serde_json::json!({
        "apiVersion":"updated.dev/v1alpha1",
        "kind":"UpdateGroupSet",
        "metadata":{"name":DEMO_FLEET_SET,"namespace":"updated-system"},
        "spec":{
            "selector":{"matchLabels":{"demo.updated.dev/fleet":DEMO_FLEET_VALUE}},
            "maxConcurrent":DEMO_FLEET_CONCURRENCY
        }
    }));
    // The external slice: same app + fast cadence as a cohort, but with NO fleet/set labels —
    // deliberately outside the per-set load balancers and the fleet throttle. It stands in for
    // a fleet that lives outside Kubernetes; the reconciler, not a selector, gives it endpoints.
    let mut external_group = group(
        DEMO_EXTERNAL_COHORT,
        DEMO_EXTERNAL_COHORT,
        DEMO_EXTERNAL_COHORT,
        success_path,
        success_sha,
    );
    external_group["metadata"]
        .as_object_mut()
        .expect("group metadata is an object")
        .remove("labels");
    items.push(external_group);
    // RBAC for the `updated-healthproxy` reconciler that programs the external Service's
    // EndpointSlice from the external nodes' CDN health.
    items.push(serde_json::json!({"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"external-healthproxy","namespace":"updated-system"}}));
    items.push(serde_json::json!({"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"external-healthproxy","namespace":"updated-system"},"rules":[
        {"apiGroups":["discovery.k8s.io"],"resources":["endpointslices"],"verbs":["get","list","watch","create","update","patch"]}
    ]}));
    items.push(serde_json::json!({"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"external-healthproxy","namespace":"updated-system"},"subjects":[{"kind":"ServiceAccount","name":"external-healthproxy","namespace":"updated-system"}],"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"external-healthproxy"}}));
    // Per-set load-balancer Services + one ingress: the load test enters at
    // `<ingress>/set-<n>/…`, and each set's Service selects only that set's pods (by the set
    // label the pod labeler keeps current). So Kubernetes — not the demo's own routing —
    // guarantees a set is only ever answered by its own pods. `publishNotReadyAddresses`
    // is intentionally omitted so a draining/unready pod leaves the Service and the ingress
    // stops routing to it, which is what keeps a set's availability honest under rollout.
    for set in 0..DEMO_SET_COUNT {
        items.push(serde_json::json!({
            "apiVersion":"v1","kind":"Service",
            "metadata":{"name":set_service_name(set),"namespace":"updated-system"},
            "spec":{
                "selector":{"app":"updated-agent", SET_LABEL: set_name(set)},
                "ports":[{"name":"http","port":8080,"targetPort":"http"}]
            }
        }));
    }
    // The external slice pretends to live outside Kubernetes: its Service is *selectorless*,
    // so nothing is auto-attached. The real `updated-healthproxy` reconciler (deployed once
    // the external pods have addresses) programs its EndpointSlice from the nodes' CDN health
    // — the same product path that fronts VMs. Traffic still enters the shared ingress at
    // `/external/…`, proving reconciler-managed endpoints route identically to native ones.
    items.push(serde_json::json!({
        "apiVersion":"v1","kind":"Service",
        "metadata":{"name":DEMO_EXTERNAL_SERVICE,"namespace":"updated-system"},
        "spec":{"ports":[{"name":"http","port":8080,"targetPort":8080}]}
    }));
    let mut ingress_paths: Vec<serde_json::Value> = (0..DEMO_SET_COUNT)
        .map(|set| {
            serde_json::json!({
                "path": format!("/set-{set}(/|$)(.*)"),
                "pathType": "ImplementationSpecific",
                "backend": {"service": {"name": set_service_name(set), "port": {"number": 8080}}}
            })
        })
        .collect();
    ingress_paths.push(serde_json::json!({
        "path": "/external(/|$)(.*)",
        "pathType": "ImplementationSpecific",
        "backend": {"service": {"name": DEMO_EXTERNAL_SERVICE, "port": {"number": 8080}}}
    }));
    items.push(serde_json::json!({
        "apiVersion":"networking.k8s.io/v1","kind":"Ingress",
        "metadata":{
            "name":"demo-load","namespace":"updated-system",
            // Strip the `/set-<n>` prefix so the pod sees a plain `/version`.
            "annotations":{"nginx.ingress.kubernetes.io/rewrite-target":"/$2"}
        },
        "spec":{
            "ingressClassName":"nginx",
            "rules":[{"http":{"paths":ingress_paths}}]
        }
    }));
    items.extend(
        serde_json::json!([
            {"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"updatec-demo","namespace":"updated-system"},"spec":{"replicas":1,"selector":{"matchLabels":{"app":"updatec-demo"}},"template":{"metadata":{"labels":{"app":"updatec-demo"}},"spec":{"serviceAccountName":"updatec-demo","containers":[{"name":"demo","image":"updatec-e2e:kind","imagePullPolicy":"Never","command":["/usr/local/bin/updatec-demo","serve"],"env":[
                {"name":"DEMO_PROVIDER_PATH","value":provider_path},
                {"name":"DEMO_PROVIDER_SHA256","value":provider_sha},
                {"name":"DEMO_REPOSITORY_DATA","value":"/release-data"},
                {"name":"AWS_ACCESS_KEY_ID","value":"minio"},
                {"name":"AWS_SECRET_ACCESS_KEY","value":"minio123"}
            ],"volumeMounts":[{"name":"release-repository","mountPath":"/release-data"}],"ports":[{"name":"http","containerPort":8080}],"readinessProbe":{"httpGet":{"path":"/healthz","port":"http"}}}],"volumes":[{"name":"release-repository","persistentVolumeClaim":{"claimName":"release-repository"}}]}}}},
            {"apiVersion":"v1","kind":"Service","metadata":{"name":"updatec-demo","namespace":"updated-system"},"spec":{"selector":{"app":"updatec-demo"},"ports":[{"name":"http","port":80,"targetPort":"http"}]}}
        ])
        .as_array()
        .cloned()
        .expect("demo workload resource list is an array"),
    );
    apply_json(&serde_json::json!({
        "apiVersion": "v1",
        "kind": "List",
        "items": items
    }))
}

/// Pipe a JSON resource (typically a `List`) into `kubectl apply -f -`. The one path every
/// demo resource takes to the cluster.
pub(crate) fn apply_json(resources: &serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new("kubectl")
        .args(["apply", "-f", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;
    use std::io::Write;
    child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(serde_json::to_string(resources)?.as_bytes())?;
    if child.wait()?.success() {
        Ok(())
    } else {
        Err("applying resources failed".into())
    }
}

pub(crate) fn run(command: &mut Command) -> Result<(), Box<dyn std::error::Error>> {
    let status = command.status()?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("command failed with {status}").into())
    }
}

pub(crate) fn output(command: &mut Command) -> Result<String, Box<dyn std::error::Error>> {
    let output = command.output()?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr)
            .trim()
            .to_owned()
            .into());
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

pub(crate) async fn wait_for_url(url: &str) -> Result<(), Box<dyn std::error::Error>> {
    let client = reqwest::Client::new();
    for _ in 0..30 {
        if client
            .get(url)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
    Err(format!("demo did not become reachable at {url}").into())
}

pub(crate) fn open_browser(url: &str) {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let _ = Command::new(opener)
        .arg(url)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The audit log mixes transactions with the reserved observation identities. Only a
    /// completed `apply` under a deployment attempt is a transaction; a green `healthcheck`
    /// under `periodic` or `boot` must never be mistaken for one.
    #[test]
    fn only_a_completed_apply_under_a_deployment_attempt_counts_as_a_transaction() {
        let audit = "\
healthcheck\tboot\tstarted
healthcheck\tboot\tcompleted
apply\ta-1\tstarted
apply\ta-1\tcompleted
healthcheck\tperiodic\tcompleted
inspect\tfingerprint\tcompleted
apply\ta-2\tstarted
";
        assert_eq!(latest_completed_transaction(audit).as_deref(), Some("a-1"));
    }

    #[test]
    fn the_newest_completed_transaction_wins() {
        let audit = "\
apply\ta-1\tcompleted
rollback\ta-1\tcompleted
apply\ta-2\tcompleted
healthcheck\tperiodic\tcompleted
";
        assert_eq!(latest_completed_transaction(audit).as_deref(), Some("a-2"));
    }

    /// Without a completed transaction there is nothing to assert against, and the driver must
    /// keep waiting rather than accept an unfinished or observation-only audit.
    #[test]
    fn an_audit_without_a_completed_transaction_yields_nothing() {
        let audit = "\
apply\ta-1\tstarted
healthcheck\tperiodic\tcompleted
inspect\tfingerprint\tcompleted
";
        assert_eq!(latest_completed_transaction(audit), None);
    }

    /// A transaction that reported success while skipping sub-phases is the failure this check
    /// exists to catch; unrelated files in the effects directory must not mask a missing marker.
    #[test]
    fn a_skipped_sub_phase_is_reported_as_a_missing_marker() {
        let mut markers = LIFECYCLE_SUB_PHASES
            .iter()
            .map(|phase| format!("{phase}.done"))
            .collect::<Vec<_>>();
        markers.push("generated-install.properties".to_owned());
        markers.push("stopped-process.pid".to_owned());
        assert!(missing_sub_phase_markers(&markers).is_empty());

        markers.retain(|marker| marker != "verify.done" && marker != "drain.done");
        assert_eq!(
            missing_sub_phase_markers(&markers),
            vec!["drain", "verify"],
            "the check must name every skipped sub-phase"
        );
    }

    /// The sweep runs while another demo may be mid-playbook, holding the enrollment vars its
    /// `ansible-playbook` reads for minutes. Only a directory idle far longer than a run may be
    /// removed; a freshly touched one — or one whose timestamp we could not read — stays.
    #[test]
    fn only_a_long_idle_scratch_directory_is_swept() {
        assert!(!scratch_dir_is_abandoned(Some(
            std::time::Duration::from_secs(0)
        )));
        assert!(!scratch_dir_is_abandoned(Some(
            SCRATCH_SWEEP_MIN_IDLE - std::time::Duration::from_secs(1)
        )));
        assert!(!scratch_dir_is_abandoned(None));
        assert!(scratch_dir_is_abandoned(Some(SCRATCH_SWEEP_MIN_IDLE)));
    }
}
