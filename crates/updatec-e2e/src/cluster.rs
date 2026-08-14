use crate::*;
use std::env;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
/// The reconciler protocol vocabulary is defined once, in the contracts crate; this driver reads
/// the audit log in exactly those terms rather than re-spelling operations locally.
use updated_contracts::reconciler::{attempt, Operation};

/// `kubectl` argument prefix that execs into the in-cluster release-server container. Every
/// release-repository query and mutation runs through it, so it lives in one place: that pod is
/// the only one holding the repository's signing keys, reaching MinIO, and carrying `updatectl`.
pub(crate) const RELEASE_SERVER_EXEC: [&str; 6] = [
    "-n",
    NAMESPACE,
    "exec",
    "deployment/release-server",
    "-c",
    "release-server",
];

const LIFECYCLE_STATE: &str = "/var/lib/updated/providers/state/demo-enterprise-lifecycle";

/// The enterprise sub-phases the lifecycle reconciler runs, in order, inside one `apply`. Each one
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

/// The node the ordered-lifecycle assertions read the reconciler's audit log and receipt from.
const LIFECYCLE_NODE: &str = "agent-4";

/// The kind cluster this run drives — the same name and override
/// `scripts/kind-updatec-e2e.sh` uses, so the script and this driver always address one cluster.
pub(crate) fn cluster_name() -> String {
    env::var("UPDATEC_KIND_CLUSTER").unwrap_or_else(|_| "updatec-e2e".into())
}

pub(crate) fn kube_context() -> String {
    format!("kind-{}", cluster_name())
}

/// Every cluster call is pinned to this run's context rather than kubectl's process-global
/// current context, so a developer's separate cluster (or a concurrent run) can never receive
/// half of it.
pub(crate) fn kubectl_context_args() -> [String; 2] {
    ["--context".to_owned(), kube_context()]
}

pub(crate) fn kubectl() -> Command {
    let mut command = Command::new("kubectl");
    command.args(kubectl_context_args());
    command
}

/// Build the kind environment this e2e runs against: the operator, CDN, gateway, and base fleet
/// from `scripts/kind-updatec-e2e.sh`, scaled up to the fleet layout this driver exercises.
pub(crate) async fn bring_up_cluster() -> Result<(), Box<dyn std::error::Error>> {
    for command in ["docker", "kind", "kubectl", "cargo", "curl"] {
        command_exists(command)?;
    }
    let root = workspace_root()?;
    let cluster = cluster_name();
    // Always start from a clean cluster. Reusing one carried subtle staleness — a baked
    // release-server predating the current seed, an older image, a missing add-on — that failed
    // deep in resource apply. A fresh build every time is the one predictable path.
    let clusters = output(Command::new("kind").args(["get", "clusters"]))?;
    if clusters.lines().any(|name| name == cluster) {
        println!("[e2e] tearing down the previous cluster for a clean rebuild");
        run(Command::new("kind").args(["delete", "cluster", "--name", &cluster]))?;
    }
    println!("[e2e] building the operator environment; this takes a few minutes");
    let status = Command::new(root.join("scripts/kind-updatec-e2e.sh"))
        .args(["--fuzz-rounds", "0"])
        .env("UPDATEC_KIND_CLUSTER", &cluster)
        .env("UPDATEC_KEEP_KIND_CLUSTER", "1")
        .status()?;
    if !status.success() {
        return Err("kind environment setup failed; see the output above".into());
    }

    let pod_capacity = cluster_pod_capacity();
    if pod_capacity < REQUIRED_POD_CAPACITY {
        return Err(format!(
            "node advertises capacity for {pod_capacity} pods; at least {REQUIRED_POD_CAPACITY} are required for {NODE_COUNT} services plus system workloads"
        )
        .into());
    }
    println!(
        "[e2e] node pod capacity: {pod_capacity} ({NODE_COUNT} managed services, {} reserved for system workloads)",
        REQUIRED_POD_CAPACITY - NODE_COUNT
    );
    println!("[e2e] removing the base kind run's intentionally ambiguous group");
    run(kubectl().args([
        "-n",
        NAMESPACE,
        "delete",
        "updategroup",
        "overlapping-edge",
        "--ignore-not-found",
    ]))?;
    println!("[e2e] scaling the managed fleet to {TOTAL_AGENTS} agents");
    run(kubectl().args([
        "-n",
        NAMESPACE,
        "scale",
        "statefulset/agent",
        &format!("--replicas={TOTAL_AGENTS}"),
    ]))
}

/// The signed identities the fleet layout is built on: the reconciler set every cohort release
/// ships with, and the platform its bundles are published for.
pub(crate) struct FleetLayout {
    pub(crate) platform: String,
    pub(crate) provider_path: String,
    pub(crate) provider_sha: String,
}

/// Apply the fleet layout onto the provisioned, scaled cluster: detect the platform and whether
/// Jenkins is published for it, deploy the Jenkins fleet when it is, assign every enrolled node
/// its labels, apply the per-set/per-cohort resources, wait for the StatefulSet to roll out,
/// bring up the HAProxy tier, and deploy the healthproxy that fronts the out-of-cluster slice.
pub(crate) async fn prepare_fleet() -> Result<FleetLayout, Box<dyn std::error::Error>> {
    // Jenkins is only published for linux-x86_64 (its install provider fetches an x86_64 JRE),
    // so on any other platform — e.g. an arm64 kind cluster on Apple Silicon — its bundle is
    // absent. Detect that from the repo and skip the Jenkins nodes entirely, running the rest.
    // Run the full test (with Jenkins) on an x86_64 box.
    let platform = repository_platform()?.trim().to_string();
    let jenkins_path = format!("products/jenkins/stable/1.0.0/{platform}/app");
    let jenkins_enabled = repository_target_sha(&jenkins_path).is_ok();
    if jenkins_enabled {
        println!("[e2e] deploying {JENKINS_TOTAL} Jenkins nodes (ci + release controller pairs)");
        apply_jenkins_fleet()?;
    } else {
        println!("[e2e] Jenkins is not published for {platform} (x86_64 only) — skipping the Jenkins nodes");
    }
    println!("[e2e] waiting for enrollment and assigning every new node");
    label_cohort_agents()?;
    if jenkins_enabled {
        label_jenkins_agents()?;
    }
    label_external_agents()?;
    // The sample-app cohorts resolve their provider set from MinIO; its sha is published and
    // returned by `bootstrap_minio_release_repo`, not read from the release-server repo here.
    let provider_path = "provider-sets/rube-goldberg.json".to_owned();
    // Jenkins bundle refs, resolved only when it is published for this platform.
    let (jenkins_sha, jenkins_provider_path, jenkins_provider_sha) = if jenkins_enabled {
        (
            repository_target_sha(&jenkins_path)?,
            "provider-sets/jenkins.json".to_string(),
            repository_target_sha("provider-sets/jenkins.json")?,
        )
    } else {
        (String::new(), String::new(), String::new())
    };
    println!("[e2e] applying the RBAC, per-set services, and per-cohort groups");
    let provider_sha = apply_resources(
        &provider_path,
        jenkins_enabled,
        &jenkins_path,
        jenkins_sha.trim(),
        &jenkins_provider_path,
        jenkins_provider_sha.trim(),
    )?;
    println!("[e2e] waiting for all assigned agents to become ready");
    run(kubectl().args([
        "-n",
        NAMESPACE,
        "rollout",
        "status",
        "statefulset/agent",
        "--timeout=480s",
    ]))?;
    // The updated-managed HAProxy tier: 2 HAProxies (installed from a signed tarball, upgraded in
    // place) fronting the external slice, with a HAProxy-mode healthproxy programming their backend
    // membership from signed CDN health. Runs after the release keys + external slice exist. Sits
    // outside the cohort/set/chaos machinery, so it never perturbs the convergence math.
    prepare_haproxy_tier(&platform).await?;
    println!("[e2e] deploying the healthproxy reconciler for the out-of-cluster slice");
    deploy_external_reconciler()?;
    Ok(FleetLayout {
        platform,
        provider_path,
        provider_sha,
    })
}

/// Prove the per-set isolation end to end: every endpoint backing a set's load-balancer Service
/// is a pod that belongs to that set, and every set has at least one ready endpoint. This is the
/// structural guarantee that no other set's pod can ever answer for a set. It waits for endpoints
/// to populate (a timing concern), but a *cross-set* endpoint is an immediate hard failure, not
/// something to wait out.
pub(crate) async fn assert_set_isolation() -> Result<(), Box<dyn std::error::Error>> {
    for _ in 0..90 {
        let mut all_populated = true;
        for set in 0..SET_COUNT {
            let service = set_service_name(set);
            let mut ready_here = 0usize;
            for (pod, ready) in set_service_endpoints(&service)? {
                if node_set_index(&pod) != Some(set) {
                    return Err(format!(
                        "set isolation violated: set {set}'s Service {service} is backed by {pod}, which is not in set {set}"
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
                "[e2e] verified per-set isolation: each of {SET_COUNT} sets' Service admits only its own pods"
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
        let json = output(kubectl().args([
            "-n",
            NAMESPACE,
            "get",
            "endpointslices",
            "-l",
            &format!("kubernetes.io/service-name={EXTERNAL_SERVICE}"),
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
        if managed_by_reconciler && ready >= EXTERNAL_COUNT {
            println!(
                "[e2e] verified the healthproxy reconciler programmed {EXTERNAL_COUNT} out-of-cluster endpoints from CDN health"
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
    let json = output(kubectl().args([
        "-n",
        NAMESPACE,
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

/// Prove the red→green lifecycle transaction ran through the real operator: the reconciler
/// protocol has four operations, so one update transaction is exactly one `apply` invocation.
/// The audit proves the transaction ran to completion, the ordered sub-phases inside it are
/// proven by the completion markers the reconciler leaves in the attempt's effects directory
/// (each sub-phase requires its predecessor's marker, so the full marker set is the ordering
/// evidence), and the receipt proves it ran for the green release.
pub(crate) async fn assert_lifecycle_transaction() -> Result<(), Box<dyn std::error::Error>> {
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
    let receipt = output(kubectl().args([
        "-n",
        NAMESPACE,
        "exec",
        LIFECYCLE_NODE,
        "-c",
        "agent",
        "--",
        "cat",
        &format!("{LIFECYCLE_STATE}/legacy-java-home/change-ticket.receipt"),
    ]))?;
    if !receipt.contains(&format!("green release {BASELINE_VERSION}")) {
        return Err(format!("missing lifecycle audit receipt: {receipt:?}").into());
    }
    println!("[e2e] verified the ordered lifecycle transaction {attempt} and its audit receipt");
    Ok(())
}

fn lifecycle_audit() -> Result<String, Box<dyn std::error::Error>> {
    output(kubectl().args([
        "-n",
        NAMESPACE,
        "exec",
        LIFECYCLE_NODE,
        "-c",
        "agent",
        "--",
        "cat",
        &format!("{LIFECYCLE_STATE}/audit/lifecycle.tsv"),
    ]))
}

/// The attempt id of the newest completed update transaction in the reconciler's audit log.
///
/// The reconciler appends one `<operation>\t<attempt>\t<event>` row per invocation. An update
/// transaction is exactly one [`Operation::Apply`] under a deployment attempt id; the reserved
/// ids (`boot`, `periodic`, `fingerprint`) name observations that belong to no transaction and
/// must never be mistaken for one.
fn latest_completed_transaction(audit: &str) -> Option<String> {
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
fn missing_sub_phase_markers(markers: &[String]) -> Vec<&'static str> {
    LIFECYCLE_SUB_PHASES
        .into_iter()
        .filter(|phase| {
            let marker = format!("{phase}.done");
            !markers.contains(&marker)
        })
        .collect()
}

/// The completion markers the reconciler left in one attempt's effects directory.
fn lifecycle_attempt_markers(attempt: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(output(kubectl().args([
        "-n",
        NAMESPACE,
        "exec",
        LIFECYCLE_NODE,
        "-c",
        "agent",
        "--",
        "ls",
        "-1",
        &format!("{LIFECYCLE_STATE}/attempts/{attempt}"),
    ]))?
    .lines()
    .map(|name| name.trim().to_owned())
    .filter(|name| !name.is_empty())
    .collect())
}

fn cluster_pod_capacity() -> usize {
    output(kubectl().args([
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
    output(kubectl().args(RELEASE_SERVER_EXEC).args([
        "--",
        "server",
        "target-sha256",
        "--repo",
        "/data/repository",
        "--name",
        name,
    ]))
}

fn repository_platform() -> Result<String, Box<dyn std::error::Error>> {
    output(
        kubectl()
            .args(RELEASE_SERVER_EXEC)
            .args(["--", "cat", "/data/platform"]),
    )
}

/// Retry-patch one node's labels until the operator has registered its `UpdateAgent`.
/// One path for every node kind; the label set is the only thing that differs.
pub(crate) fn patch_agent_labels(
    resource: &str,
    labels: serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let patch = serde_json::to_string(&serde_json::json!({ "spec": { "labels": labels } }))?;
    for _ in 0..60 {
        let ok = kubectl()
            .args([
                "-n",
                NAMESPACE,
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

fn label_cohort_agents() -> Result<(), Box<dyn std::error::Error>> {
    for ordinal in 0..NODE_COUNT {
        patch_agent_labels(
            &agent_resource_name(ordinal as u8),
            serde_json::json!({
                NODE_LABEL: format!("agent-{ordinal}"),
                COHORT_LABEL: cohort_label(ordinal / COHORT_SIZE),
                "updated.dev/role": null
            }),
        )?;
    }
    Ok(())
}

/// The real-Jenkins nodes get a `kind=jenkins` marker, their instance `role` (ci/release — the
/// role its UpdateGroup selects on), and their node name. No cohort/set/fleet labels, so they sit
/// entirely outside the convergence state machine and pod-kill chaos — their slow ~4-minute
/// installs never gate the fast sample-app cohorts.
fn label_jenkins_agents() -> Result<(), Box<dyn std::error::Error>> {
    for (role, replicas) in JENKINS_COHORTS {
        for ordinal in 0..replicas {
            let node = format!("jenkins-{role}-{ordinal}");
            patch_agent_labels(
                &resource_name(&node),
                serde_json::json!({
                    NODE_LABEL: node,
                    KIND_LABEL: "jenkins",
                    ROLE_LABEL: role
                }),
            )?;
        }
    }
    Ok(())
}

/// Deploy the real-Jenkins cohorts: one StatefulSet per instance role (ci, release) on
/// the same plain agent image, in the same headless `agents` Service and enrolling through the
/// same gateway as every other node. Each pod keeps its installed state and JENKINS_HOME data on
/// a persistent volume, so a restart reuses the already-installed Jenkins (~30-60s) instead of
/// the multi-minute first install.
fn apply_jenkins_fleet() -> Result<(), Box<dyn std::error::Error>> {
    let items: Vec<serde_json::Value> = JENKINS_COHORTS
        .iter()
        .map(|(role, replicas)| jenkins_statefulset(role, *replicas))
        .collect();
    apply_json(&serde_json::json!({ "apiVersion": "v1", "kind": "List", "items": items }))
}

fn jenkins_statefulset(role: &str, replicas: usize) -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": { "name": format!("jenkins-{role}"), "namespace": NAMESPACE },
        "spec": {
            "serviceName": "agents",
            "replicas": replicas,
            "podManagementPolicy": "Parallel",
            "selector": { "matchLabels": { "app": "updated-agent", KIND_LABEL: "jenkins", ROLE_LABEL: role } },
            "template": {
                "metadata": { "labels": { "app": "updated-agent", KIND_LABEL: "jenkins", ROLE_LABEL: role } },
                "spec": {
                    "securityContext": { "fsGroup": 65532, "seccompProfile": { "type": "RuntimeDefault" } },
                    "containers": [{
                        "name": "agent",
                        // The very same plain Ubuntu + agent image as every other node — no
                        // Jenkins-specific image. The pre-start install provider installs
                        // Jenkins into this vanilla container at runtime.
                        "image": "updatec-e2e:kind",
                        "imagePullPolicy": "Never",
                        "command": ["/usr/local/bin/run-agent"],
                        "env": [
                            { "name": "JENKINS_DATA", "value": "/var/lib/jenkins" },
                            // A separate disk (its own PVC) the activate phase writes the
                            // pre-upgrade JENKINS_HOME backup tar to, and rollback restores from.
                            { "name": "JENKINS_BACKUPS", "value": "/var/lib/jenkins-backups" }
                        ],
                        "ports": [{ "name": "http", "containerPort": 8080 }],
                        // The workload's own endpoint, which the release's `healthcheck` hook also
                        // uses. Node health has one path — reconciler hook verdict -> signed
                        // NodeReport -> healthproxy — and the kubelet is never asked to judge the
                        // agent: it only learns whether Jenkins itself answers.
                        "readinessProbe": { "httpGet": { "path": "/login", "port": "http" }, "periodSeconds": 3, "failureThreshold": 200 },
                        "securityContext": { "allowPrivilegeEscalation": false, "capabilities": { "drop": ["ALL"] }, "runAsNonRoot": true, "runAsUser": 65532 },
                        "resources": { "requests": { "cpu": "250m", "memory": "1Gi" }, "limits": { "memory": "1500Mi" } },
                        "volumeMounts": [
                            { "name": "state", "mountPath": "/var/lib/updated" },
                            { "name": "jenkins-data", "mountPath": "/var/lib/jenkins" },
                            { "name": "jenkins-backups", "mountPath": "/var/lib/jenkins-backups" },
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
                { "metadata": { "name": "jenkins-data" }, "spec": { "accessModes": ["ReadWriteOnce"], "resources": { "requests": { "storage": "2Gi" } } } },
                // A distinct volume — "another disk" — for the pre-upgrade JENKINS_HOME backup tars.
                { "metadata": { "name": "jenkins-backups" }, "spec": { "accessModes": ["ReadWriteOnce"], "resources": { "requests": { "storage": "2Gi" } } } }
            ]
        }
    })
}

/// The enrollment name a host asserts, and hence the `UpdateAgent` resource name that node's
/// CR carries: the enrollment nonce is `sha256(hostname)` and the registration (hence the CR
/// name) is `sha256(that)`. One derivation for every node kind — sample-app pods, Jenkins pods,
/// and HAProxy pods alike — so any node's CR can be addressed without special cases.
///
/// **This is the only implementation of that derivation.** The nodes that assert the name
/// (`crates/updatec/e2e/agent.sh`) and the kind script that looks the CRs up
/// (`scripts/kind-updatec-e2e.sh`) both read it out of this function through
/// `updatec-e2e agent-name <hostname>` rather than re-deriving it, so the name cannot drift
/// between producer and consumers.
pub(crate) fn resource_name(hostname: &str) -> String {
    let nonce = updated::hash::sha256_bytes(hostname.as_bytes());
    let registration = updated::hash::sha256_bytes(nonce.as_bytes());
    format!("agent-{}", &registration[..24])
}

pub(crate) fn agent_resource_name(ordinal: u8) -> String {
    resource_name(&format!("agent-{ordinal}"))
}

fn command_exists(name: &str) -> Result<(), Box<dyn std::error::Error>> {
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

fn workspace_root() -> Result<PathBuf, Box<dyn std::error::Error>> {
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
    Err("run this e2e from the updatedc workspace".into())
}

pub(crate) fn kubectl_value(
    kind: &str,
    name: &str,
    path: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    output(kubectl().args([
        "-n",
        NAMESPACE,
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
fn label_external_agents() -> Result<(), Box<dyn std::error::Error>> {
    for index in 0..EXTERNAL_COUNT {
        let ordinal = external_ordinal(index);
        patch_agent_labels(
            &agent_resource_name(ordinal as u8),
            serde_json::json!({
                NODE_LABEL: format!("agent-{ordinal}"),
                COHORT_LABEL: EXTERNAL_COHORT,
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
fn deploy_external_reconciler() -> Result<(), Box<dyn std::error::Error>> {
    let mut members = Vec::with_capacity(EXTERNAL_COUNT);
    for index in 0..EXTERNAL_COUNT {
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
    let members = members.join(",");
    apply_json(&serde_json::json!({
        "apiVersion":"apps/v1","kind":"Deployment",
        "metadata":{"name":"external-healthproxy","namespace":NAMESPACE},
        "spec":{"replicas":1,"selector":{"matchLabels":{"app":"external-healthproxy"}},
            "template":{"metadata":{"labels":{"app":"external-healthproxy"}},
            "spec":{"serviceAccountName":"external-healthproxy","containers":[{
                "name":"healthproxy","image":"updatec-e2e:kind","imagePullPolicy":"Never",
                "command":["/usr/local/bin/updated-healthproxy"],
                "env":[
                    {"name":"HEALTHPROXY_HEALTH_BASE","value":HEALTH_CDN},
                    {"name":"HEALTHPROXY_NAMESPACE","value":NAMESPACE},
                    {"name":"HEALTHPROXY_SERVICE","value":EXTERNAL_SERVICE},
                    {"name":"HEALTHPROXY_PORT","value":"8080"},
                    {"name":"HEALTHPROXY_MEMBERS","value":members}
                ]
            }]}}
        }
    }))?;
    run(kubectl().args([
        "-n",
        NAMESPACE,
        "rollout",
        "status",
        "deployment/external-healthproxy",
        "--timeout=120s",
    ]))
}

/// `(release_root, baseline_path, baseline_sha, provider_sha)` — the signed identities
/// [`bootstrap_minio_release_repo`] mints and republishes onto the shared release PVC.
type ReleaseBootstrap = (String, String, String, String);

/// The MinIO release repository every cohort group resolves its bundles from, pinned to the root
/// [`bootstrap_minio_release_repo`] minted onto the shared release PVC. Built from the same
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

/// Mint the release repository's signing keys, seed the baseline release every cohort starts on,
/// and publish the lifecycle reconciler the green release runs. Everything runs inside the
/// release-server pod — it has `updatectl`, reaches MinIO in-cluster, and mounts the shared
/// release-repository PVC at `/data`, where the signing keys land.
///
/// Idempotent: re-running against an already-initialized repo is a no-op for the keys and a
/// content-addressed republish for the baseline (same bytes → same target).
fn bootstrap_minio_release_repo(
    edge: &serde_json::Value,
    platform: &str,
) -> Result<ReleaseBootstrap, Box<dyn std::error::Error>> {
    // Every `updatectl` below addresses the one release repository the groups resolve from.
    let repository = release_repository_flags();
    // 1. Mint keys + initialize the repo once, onto the shared PVC (skip if already there).
    run(kubectl().args(RELEASE_SERVER_EXEC).args([
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
    let release_root = output(kubectl().args(RELEASE_SERVER_EXEC).args([
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
        "metadata": {"name": "release-seed", "namespace": NAMESPACE},
        "spec": {
            "repositoryRef": {"name": "default"},
            "selector": {"matchLabels": {COHORT_LABEL: "__release-seed-unmatched__"}},
            "deployment": seed_deployment
        }
    }))?;
    run(kubectl().args(RELEASE_SERVER_EXEC).args([
        "--",
        "sh",
        "-c",
        &format!(
            "set -e; export AWS_ACCESS_KEY_ID=minio AWS_SECRET_ACCESS_KEY=minio123; \
             rm -rf /tmp/seed && mkdir -p /tmp/seed/bin /tmp/seed/config; \
             cp /usr/local/bin/sampleapp /tmp/seed/bin/app; \
             printf 'version = \"{BASELINE_VERSION}\"\\n' >/tmp/seed/config/release.toml; \
             updatectl deploy --keys-dir /data/release-keys {repository} \
             --namespace {NAMESPACE} --group release-seed --product app --channel stable \
             --version {BASELINE_VERSION} --entrypoint bin/app --platform {platform} --source /tmp/seed"
        ),
    ]))?;
    let baseline_path = kubectl_value(
        "updategroup",
        "release-seed",
        "{.spec.deployment.application.path}",
    )?;
    let baseline_sha = kubectl_value(
        "updategroup",
        "release-seed",
        "{.spec.deployment.application.sha256}",
    )?;
    run(kubectl().args([
        "-n",
        NAMESPACE,
        "delete",
        "updategroup",
        "release-seed",
        "--ignore-not-found",
    ]))?;
    // 3. Publish the lifecycle reconciler into MinIO. The sample-app cohorts resolve both the
    //    application and reconciler from this repository.
    let provider_timeout_ms = demo_lifecycle::PROVIDER_TIMEOUT_MS;
    let provider_sets = output(kubectl().args(RELEASE_SERVER_EXEC).args([
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

/// Apply every resource the fleet layout needs and return the published reconciler set's sha —
/// the identity each cohort release is signed with.
// The four `jenkins_*` parameters are what push this over the argument threshold; they are the
// data of one optional tier, resolved by the caller that detects whether it is published.
#[allow(clippy::too_many_arguments)]
fn apply_resources(
    provider_path: &str,
    jenkins_enabled: bool,
    jenkins_path: &str,
    jenkins_sha: &str,
    jenkins_provider_path: &str,
    jenkins_provider_sha: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let edge: serde_json::Value = serde_json::from_str(&output(kubectl().args([
        "-n",
        NAMESPACE,
        "get",
        "updategroup",
        "edge",
        "-o",
        "json",
    ]))?)?;
    // Bootstrap the MinIO release repository the app cohorts roll through `updatectl deploy` —
    // the real CI release path, not the in-cluster `server publish-app`. Idempotent init of the
    // repo + signing keys, then seed the baseline the cohorts converge to so its content hash is
    // authoritative.
    //
    // `updatectl deploy` runs inside the release-server pod, which carries no explicit
    // serviceAccountName and so authenticates as the namespace `default` SA. Grant that SA the
    // updategroups/updategroupsets access the deploy needs BEFORE the bootstrap runs — otherwise
    // the very first `updatectl deploy` 403s trying to get the release-seed UpdateGroup.
    apply_json(&serde_json::json!({
        "apiVersion": "v1", "kind": "List", "items": [
            {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"release-server-deployer","namespace":NAMESPACE},"rules":[
                {"apiGroups":["updated.dev"],"resources":["updategroups"],"verbs":["get","list","patch"]},
                {"apiGroups":["updated.dev"],"resources":["updategroupsets"],"verbs":["get","list","create","patch"]}
            ]},
            {"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"release-server-deployer","namespace":NAMESPACE},"subjects":[{"kind":"ServiceAccount","name":"default","namespace":NAMESPACE}],"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"release-server-deployer"}}
        ]
    }))?;
    let platform = repository_platform()?;
    let (release_root, baseline_path, baseline_sha, provider_sha) =
        bootstrap_minio_release_repo(&edge, &platform)?;
    let provider = serde_json::json!({"path": provider_path, "sha256": provider_sha});
    let minio_release_repository = minio_release_repository(&release_root);
    // The sample-app cohorts (and the external slice) start on the MinIO-published baseline the
    // chaos then rolls with `updatectl deploy`.
    let group = |name: &str, cohort: &str, set: &str| {
        let mut deployment = edge["spec"]["deployment"].clone();
        deployment["name"] = name.into();
        deployment["application"] =
            serde_json::json!({"path": baseline_path, "sha256": baseline_sha});
        // Point the cohort at MinIO: this is the repository `updatectl deploy` publishes to and
        // patches. The Jenkins groups below keep edge's release-server repo (the default path).
        deployment["releaseRepository"] = minio_release_repository.clone();
        deployment["providerSet"] = provider.clone();
        // Nodes write rollout telemetry here so the control plane can throttle the fleet.
        deployment["reportUrl"] = REPORT_URL.into();
        // Signed opt-in to first-install ordered fallback: a killed, stateless agent
        // pod returns cold and must descend from its assigned version to the newest
        // healthy release rather than stranding on a broken head. This is what makes
        // the pod-kill chaos survivable across every cohort under rollout.
        deployment["orderedInstallFallback"] = serde_json::json!(true);
        // Fast test cadence so the fleet reacts within a second or two instead of the
        // production-shaped 5-60s defaults: agents check for new desired state every second,
        // retry and refresh quickly, and don't linger in a long health grace. These are signed
        // into each cohort's assignment (the agent reads intervals only from its signed config,
        // never from environment).
        deployment["runtime"]["timeouts"] = serde_json::json!({
            "checkIntervalSeconds": 1,
            "healthGraceSeconds": 8,
            "healthSuccesses": 1,
            "healthIntervalSeconds": 1,
            "refreshRetrySeconds": 1,
            "confirmationWindowSeconds": 3,
            "agentCheckIntervalSeconds": 3600
        });
        // Every group carries the fleet label (its single throttle set) and its set label.
        let mut labels = serde_json::Map::new();
        labels.insert(FLEET_LABEL.into(), FLEET_VALUE.into());
        labels.insert(SET_LABEL.into(), set.into());
        serde_json::json!({
            "apiVersion":"updated.dev/v1alpha1",
            "kind":"UpdateGroup",
            "metadata":{
                "name":name,
                "namespace":NAMESPACE,
                "labels":labels
            },
            "spec":{
                "repositoryRef":{"name":"default"},
                "selector":{"matchLabels":{COHORT_LABEL:cohort}},
                "deployment":deployment
            }
        })
    };
    let mut items: Vec<serde_json::Value> = Vec::new();
    for index in 0..COHORT_COUNT {
        items.push(group(
            &cohort_group(index),
            &cohort_label(index),
            &set_name(cohort_set_index(index)),
        ));
    }
    // The two real-Jenkins cohorts (ci, release): same clean group path, just different data.
    // Each selects its `role` nodes and assigns the jenkins product with that instance's
    // readiness URL and a boot-time-sized health grace. Neither carries a fleet/set label — so
    // they are upgraded one node at a time by the same agent mechanism (zero downtime across each
    // pair) yet sit entirely outside the convergence throttling and pod-kill chaos that drive the
    // sample-app cohorts.
    for (role, _replicas) in JENKINS_COHORTS.into_iter().filter(|_| jenkins_enabled) {
        let name = format!("jenkins-{role}");
        let mut deployment = edge["spec"]["deployment"].clone();
        deployment["name"] = name.clone().into();
        deployment["application"] =
            serde_json::json!({"path": jenkins_path, "sha256": jenkins_sha});
        deployment["providerSet"] =
            serde_json::json!({"path": jenkins_provider_path, "sha256": jenkins_provider_sha});
        deployment["reportUrl"] = REPORT_URL.into();
        deployment["orderedInstallFallback"] = serde_json::json!(false);
        deployment["runtime"]["product"] = "jenkins".into();
        // The Jenkins reconciler backs JENKINS_HOME up before activation and reuses it; the
        // hook owns the process, and rollback restores the backup. Jenkins's first install
        // runs for minutes; give it a boot-sized health grace and a relaxed cadence rather
        // than the fleet's sub-second timings.
        deployment["runtime"]["timeouts"] = serde_json::json!({
            "checkIntervalSeconds": 5,
            "healthGraceSeconds": 360,
            "healthSuccesses": 1,
            "healthIntervalSeconds": 3,
            "refreshRetrySeconds": 5,
            "confirmationWindowSeconds": 10,
            "agentCheckIntervalSeconds": 3600
        });
        items.push(serde_json::json!({
            "apiVersion":"updated.dev/v1alpha1",
            "kind":"UpdateGroup",
            "metadata":{"name": name, "namespace":NAMESPACE},
            "spec":{
                "repositoryRef":{"name":"default"},
                "selector": {"matchLabels":{KIND_LABEL:"jenkins", ROLE_LABEL: role}},
                "deployment": deployment
            }
        }));
    }
    // Per-set UpdateGroupSet (default maxConcurrent = members-1): never both groups of a
    // set roll at once, so every set always keeps a group serving.
    for set in 0..SET_COUNT {
        items.push(serde_json::json!({
            "apiVersion":"updated.dev/v1alpha1",
            "kind":"UpdateGroupSet",
            "metadata":{"name":set_name(set),"namespace":NAMESPACE},
            "spec":{"selector":{"matchLabels":{SET_LABEL:set_name(set)}}}
        }));
    }
    // One fleet-wide UpdateGroupSet over every managed group, on top of the per-set caps:
    // the control plane keeps at most FLEET_CONCURRENCY groups rolling at once, and —
    // because each group is in both its set and the fleet set — admits a group only when
    // BOTH have a slot. So the rollout pipelines FLEET_CONCURRENCY groups across that
    // many DISTINCT sets, each set keeping its other group up: fleet-wide pacing without
    // ever draining a set. As one group settles the next (in set order) starts, so the
    // pipeline stays full without pausing set-by-set.
    items.push(serde_json::json!({
        "apiVersion":"updated.dev/v1alpha1",
        "kind":"UpdateGroupSet",
        "metadata":{"name":FLEET_SET,"namespace":NAMESPACE},
        "spec":{
            "selector":{"matchLabels":{FLEET_LABEL:FLEET_VALUE}},
            "maxConcurrent":FLEET_CONCURRENCY
        }
    }));
    // The external slice: same app + fast cadence as a cohort, but with NO fleet/set labels —
    // deliberately outside the per-set Services and the fleet throttle. It stands in for a fleet
    // that lives outside Kubernetes; the reconciler, not a selector, gives it endpoints.
    let mut external_group = group(EXTERNAL_COHORT, EXTERNAL_COHORT, EXTERNAL_COHORT);
    external_group["metadata"]
        .as_object_mut()
        .expect("group metadata is an object")
        .remove("labels");
    items.push(external_group);
    // RBAC for the `updated-healthproxy` reconciler that programs the external Service's
    // EndpointSlice from the external nodes' CDN health.
    items.push(serde_json::json!({"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"external-healthproxy","namespace":NAMESPACE}}));
    items.push(serde_json::json!({"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","metadata":{"name":"external-healthproxy","namespace":NAMESPACE},"rules":[
        {"apiGroups":["discovery.k8s.io"],"resources":["endpointslices"],"verbs":["get","list","watch","create","update","patch"]}
    ]}));
    items.push(serde_json::json!({"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"external-healthproxy","namespace":NAMESPACE},"subjects":[{"kind":"ServiceAccount","name":"external-healthproxy","namespace":NAMESPACE}],"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":"Role","name":"external-healthproxy"}}));
    // Per-set load-balancer Services: each selects only that set's pods (by the set label the pod
    // labeler keeps current), so Kubernetes — not this driver — guarantees a set is only ever
    // answered by its own pods. `publishNotReadyAddresses` is intentionally omitted so a
    // draining/unready pod leaves the Service, which is what keeps the isolation assertion honest
    // under rollout.
    for set in 0..SET_COUNT {
        items.push(serde_json::json!({
            "apiVersion":"v1","kind":"Service",
            "metadata":{"name":set_service_name(set),"namespace":NAMESPACE},
            "spec":{
                "selector":{"app":"updated-agent", SET_LABEL: set_name(set)},
                "ports":[{"name":"http","port":8080,"targetPort":"http"}]
            }
        }));
    }
    // The external slice pretends to live outside Kubernetes: its Service is *selectorless*,
    // so nothing is auto-attached. The real `updated-healthproxy` reconciler (deployed once
    // the external pods have addresses) programs its EndpointSlice from the nodes' CDN health
    // — the same product path that fronts VMs.
    items.push(serde_json::json!({
        "apiVersion":"v1","kind":"Service",
        "metadata":{"name":EXTERNAL_SERVICE,"namespace":NAMESPACE},
        "spec":{"ports":[{"name":"http","port":8080,"targetPort":8080}]}
    }));
    apply_json(&serde_json::json!({
        "apiVersion": "v1",
        "kind": "List",
        "items": items
    }))?;
    Ok(provider_sha)
}

/// Pipe a JSON resource (typically a `List`) into `kubectl apply -f -`. The one path every
/// resource takes to the cluster.
pub(crate) fn apply_json(resources: &serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
    let mut child = kubectl()
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
