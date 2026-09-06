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

/// A `kubectl` invocation that execs into one node's agent container, ready for the command to
/// run. Every per-node read the e2e makes (durable rejection records, reconciler audit logs and
/// receipts, resolved inputs, signals) goes through it for the same reason
/// [`RELEASE_SERVER_EXEC`] exists: the namespace and the container name are stated once, so
/// renaming either cannot leave half the assertions addressing a container that is gone.
pub(crate) fn agent_exec(pod: &str) -> Command {
    let mut command = kubectl();
    command.args(["-n", NAMESPACE, "exec", pod, "-c", "agent", "--"]);
    command
}

fn lifecycle_state() -> PathBuf {
    let install = std::path::Path::new("/var/lib/updated");
    updated::config::Paths::resolve(install, install).reconciler_state_dir("app")
}

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

/// `helm`, pinned to this run's cluster for the same reason [`kubectl`] is.
pub(crate) fn helm() -> Command {
    let mut command = Command::new("helm");
    command.args(["--kube-context", &kube_context()]);
    command
}

/// The published chart directory for `name`. The e2e installs the *shipped* charts rather than
/// manifests written for the test, so the thing an operator runs is the thing this suite proves.
pub(crate) fn chart_path(name: &str) -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(workspace_root()?.join("deploy/charts").join(name))
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
        .args(["--fuzz-rounds", "0", "--preserve-repository"])
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
#[derive(Clone)]
pub(crate) struct FleetLayout {
    pub(crate) platform: String,
}

/// The signed package that the Jenkins tier installs.
struct JenkinsResources {
    application_path: String,
    application_sha: String,
}

/// Apply the fleet layout onto the provisioned, scaled cluster: detect the platform,
/// deploy the required Jenkins fleet, assign every enrolled node
/// its labels, apply the per-set/per-cohort resources, wait for the StatefulSet to roll out,
/// bring up the HAProxy tier, and deploy the healthproxy that fronts the out-of-cluster slice.
pub(crate) async fn prepare_fleet() -> Result<FleetLayout, Box<dyn std::error::Error>> {
    let platform = repository_platform()?.trim().to_string();
    let (os, arch) = platform
        .split_once('-')
        .ok_or("invalid repository platform")?;
    let jenkins_path = updated_tuf::repo::PublishTarget::application_name(
        "jenkins", "stable", "1.0.0", os, arch, "jenkins",
    );
    let jenkins = JenkinsResources {
        application_sha: repository_target_sha(&jenkins_path)?,
        application_path: jenkins_path,
    };
    // Publish the product assignment and reserve identities before these machines enroll.
    // Otherwise they first install the repository's default sample app on Jenkins's port.
    println!("[e2e] applying the RBAC, per-set services, and per-cohort groups");
    apply_resources(&jenkins)?;
    reserve_jenkins_agents()?;
    println!("[e2e] deploying {JENKINS_TOTAL} Jenkins nodes (ci + release controller pairs)");
    apply_jenkins_fleet()?;
    println!("[e2e] waiting for enrollment and assigning every new node");
    label_cohort_agents()?;
    label_external_agents()?;
    println!("[e2e] waiting for all assigned agents to become ready");
    run(kubectl().args([
        "-n",
        NAMESPACE,
        "rollout",
        "status",
        "statefulset/agent",
        "--timeout=480s",
    ]))?;
    // Every `UpdateBackend` resolves its members' routable addresses from
    // `UpdateAgent.spec.backendAddress`, and both backends below select the external slice — so
    // the addresses are recorded FIRST, in one place. Creating the HAProxy backend before them
    // left the operator refusing the whole projection (`AgentAddressMissing`) for agents whose
    // addresses were only patched by a later step.
    assign_external_backend_addresses()?;
    // The updated-managed HAProxy tier: 2 HAProxies (installed from a signed tarball, upgraded in
    // place) fronting the external slice, with a HAProxy-mode healthproxy programming their backend
    // membership from signed CDN health. Runs after the release keys + external slice exist. Sits
    // outside the cohort/set/chaos machinery, so it never perturbs the convergence math.
    prepare_haproxy_tier(&platform).await?;
    println!("[e2e] deploying the healthproxy reconciler for the out-of-cluster slice");
    deploy_external_reconciler().await?;
    deploy_alert_sink().await?;
    Ok(FleetLayout { platform })
}

/// A deployed JVM is not proof that Jenkins initialized. Require every expected identity's
/// signed health/version report as well as the workload's own HTTP readiness probe.
pub(crate) async fn assert_jenkins_installed(
    fleet: &Fleet,
) -> Result<(), Box<dyn std::error::Error>> {
    for (role, _) in JENKINS_COHORTS {
        run(kubectl().args([
            "-n",
            NAMESPACE,
            "rollout",
            "status",
            &format!("statefulset/jenkins-{role}"),
            "--timeout=480s",
        ]))?;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        let nodes = fleet.nodes().await?;
        let installed = JENKINS_COHORTS.iter().all(|(role, replicas)| {
            (0..*replicas).all(|ordinal| {
                nodes.iter().any(|node| {
                    node.node == format!("jenkins-{role}-{ordinal}")
                        && node.selected_group.as_deref() == Some(&format!("jenkins-{role}"))
                        && node_converged(node, "1.0.0")
                })
            })
        });
        if installed {
            println!("[e2e] all {JENKINS_TOTAL} Jenkins controllers are serving and confirmed healthy at 1.0.0");
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(
                "Jenkins did not confirm healthy installation on every reserved node".into(),
            );
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// Stand up the webhook receiver and point the controller's alert sink at it.
///
/// `updatec` takes its alert URL from the environment at startup, so the receiver is deployed and
/// the controller is restarted onto it HERE — before any cohort rolls — rather than at the moment
/// the assertion wants a delivery: an alert is edge-triggered on a condition TRANSITION, so a sink
/// configured after the transition receives nothing at all and the assertion would be asserting on
/// the wrong run of the loop.
async fn deploy_alert_sink() -> Result<(), Box<dyn std::error::Error>> {
    println!("[e2e] deploying the alert webhook receiver and pointing the controller at it");
    apply_json(&serde_json::json!({
        "apiVersion": "v1", "kind": "List", "items": [
            {
                "apiVersion":"apps/v1","kind":"Deployment",
                "metadata":{"name":ALERT_SINK,"namespace":NAMESPACE},
                "spec":{"replicas":1,"selector":{"matchLabels":{"app":ALERT_SINK}},
                    "template":{"metadata":{"labels":{"app":ALERT_SINK}},
                    "spec":{"containers":[{
                        "name":"sink","image":"updatec-e2e:kind","imagePullPolicy":"Never",
                        "command":["/usr/local/bin/updatec-e2e","alert-sink"],
                        "ports":[{"name":"http","containerPort":ALERT_PORT}],
                        "readinessProbe":{"tcpSocket":{"port":"http"},"periodSeconds":2}
                    }]}}
                }
            },
            {
                "apiVersion":"v1","kind":"Service",
                "metadata":{"name":ALERT_SINK,"namespace":NAMESPACE},
                "spec":{"selector":{"app":ALERT_SINK},
                    "ports":[{"name":"http","port":ALERT_PORT,"targetPort":"http"}]}
            }
        ]
    }))?;
    run(kubectl().args([
        "-n",
        NAMESPACE,
        "rollout",
        "status",
        &format!("deployment/{ALERT_SINK}"),
        "--timeout=120s",
    ]))?;
    // Through the chart, not `kubectl set env`: the alert sink is a supported chart value, and a
    // hand-patched Deployment would both skip that path and be silently reverted by the next
    // `helm upgrade`. `--reuse-values` keeps the install's image and URL overrides.
    run(helm().args([
        "upgrade",
        "updatec",
        chart_path("updatec")?
            .to_str()
            .ok_or("chart path is not valid UTF-8")?,
        "--namespace",
        NAMESPACE,
        "--reuse-values",
        "--set",
        &format!("controller.alerting.url={}", alert_url()),
    ]))?;
    run(kubectl().args([
        "-n",
        NAMESPACE,
        "rollout",
        "status",
        "deployment/updatec-controller",
        "--timeout=180s",
    ]))
}

/// Every alert document the receiver has recorded, newest last, parsed. An unreadable record (the
/// pod not yet scheduled, no delivery yet) is an empty list, never an error: the assertion polls.
pub(crate) fn delivered_alerts() -> Vec<serde_json::Value> {
    output(kubectl().args([
        "-n",
        NAMESPACE,
        "exec",
        &format!("deployment/{ALERT_SINK}"),
        "--",
        "cat",
        ALERT_RECORD,
    ]))
    .map(|record| {
        record
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    })
    .unwrap_or_default()
}

/// Prove the per-set isolation end to end: every endpoint backing a set's load-balancer Service
/// is a pod that belongs to that set, and every set has at least one ready endpoint. This is the
/// structural guarantee that no other set's pod can ever answer for a set. It waits for endpoints
/// to populate (a timing concern), but a *cross-set* endpoint is an immediate hard failure, not
/// something to wait out.
pub(crate) async fn assert_set_isolation() -> Result<(), Box<dyn std::error::Error>> {
    let mut last = String::new();
    for _ in 0..90 {
        let mut all_populated = true;
        for set in 0..SET_COUNT {
            let service = set_service_name(set);
            // A transient read failure is not a verdict: it is retried like a Service whose
            // endpoints have not populated yet, and reported only if the wait runs out. Only a
            // *cross-set* endpoint below is an immediate hard failure.
            let endpoints = match service_endpoints(&service) {
                Ok((_, endpoints)) => endpoints,
                Err(error) => {
                    last = error.to_string();
                    all_populated = false;
                    continue;
                }
            };
            let mut ready_here = 0usize;
            // Every endpoint is checked for set membership regardless of readiness (a stray
            // cross-set pod is a violation even while draining); readiness only decides whether
            // the set is currently serving.
            for endpoint in endpoints {
                let Some(pod) = endpoint.pod else {
                    continue;
                };
                if node_set_index(&pod) != Some(set) {
                    return Err(format!(
                        "set isolation violated: set {set}'s Service {service} is backed by {pod}, which is not in set {set}"
                    )
                    .into());
                }
                if endpoint.ready {
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
    Err(format!(
        "per-set load-balancer Services never populated their endpoints{}{last}",
        if last.is_empty() {
            ""
        } else {
            "; last error: "
        }
    )
    .into())
}

/// Prove the reconciler dogfood: the real `updated-healthproxy` binary programmed the
/// selectorless `external` Service's EndpointSlice — stamped with its manager label — from the
/// out-of-cluster nodes' CDN health, and every external node came up ready. This exercises the
/// exact product code path (the one that fronts VMs) end to end against a live cluster.
pub(crate) async fn assert_external_endpoints_reconciled() -> Result<(), Box<dyn std::error::Error>>
{
    await_for(
        90,
        "the external healthproxy to program its ready endpoints",
        || {
            let (managers, endpoints) = service_endpoints(EXTERNAL_SERVICE)?;
            let ready = endpoints.iter().filter(|endpoint| endpoint.ready).count();
            Ok(managers
                .iter()
                .any(|manager| manager == "updated-healthproxy")
                && ready >= EXTERNAL_COUNT)
        },
    )
    .await?;
    println!(
        "[e2e] verified the healthproxy reconciler programmed {EXTERNAL_COUNT} out-of-cluster endpoints from CDN health"
    );
    Ok(())
}

/// One endpoint backing a Service, as its EndpointSlices report it.
pub(crate) struct ServiceEndpoint {
    /// The pod behind the endpoint (`targetRef.name`), absent for the selectorless `external`
    /// Service: the healthproxy fronts machines that are not pods at all, so what it programs is
    /// an address literal per member and nothing else.
    pub(crate) pod: Option<String>,
    pub(crate) addresses: Vec<String>,
    pub(crate) ready: bool,
}

/// Every endpoint currently backing `service`, read from its EndpointSlices, together with the
/// `endpointslice.kubernetes.io/managed-by` value each of those slices carries.
///
/// **The only reading of that document.** Readiness is decided here once (`conditions.ready`), so
/// the scenarios that ask about backing pods, programmed addresses, or the controller that
/// programmed them cannot disagree about which endpoints are serving.
pub(crate) fn service_endpoints(
    service: &str,
) -> Result<(Vec<String>, Vec<ServiceEndpoint>), Box<dyn std::error::Error>> {
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
    let mut managers = Vec::new();
    let mut endpoints = Vec::new();
    for slice in parsed["items"].as_array().into_iter().flatten() {
        if let Some(manager) =
            slice["metadata"]["labels"]["endpointslice.kubernetes.io/managed-by"].as_str()
        {
            managers.push(manager.to_string());
        }
        for endpoint in slice["endpoints"].as_array().into_iter().flatten() {
            endpoints.push(ServiceEndpoint {
                pod: endpoint["targetRef"]["name"].as_str().map(str::to_string),
                addresses: endpoint["addresses"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|address| address.as_str().map(str::to_string))
                    .collect(),
                ready: endpoint["conditions"]["ready"].as_bool().unwrap_or(false),
            });
        }
    }
    Ok((managers, endpoints))
}

/// Prove the red→green lifecycle transaction ran through the real operator: the reconciler
/// protocol has four operations, so one update transaction is exactly one `apply` invocation.
/// The audit proves the transaction ran to completion, the ordered sub-phases inside it are
/// proven by the completion markers the reconciler leaves in the attempt's effects directory
/// (each sub-phase requires its predecessor's marker, so the full marker set is the ordering
/// evidence), and the receipt proves it ran for the green release.
pub(crate) async fn assert_lifecycle_transaction() -> Result<(), Box<dyn std::error::Error>> {
    let mut attempt = String::new();
    await_for(
        60,
        "a lifecycle update transaction to complete its apply operation",
        || {
            let Some(completed) = latest_completed_transaction(&lifecycle_audit()?) else {
                return Ok(false);
            };
            attempt = completed;
            Ok(true)
        },
    )
    .await?;
    let missing = missing_sub_phase_markers(&lifecycle_attempt_markers(&attempt)?);
    if !missing.is_empty() {
        return Err(format!(
            "lifecycle transaction {attempt} completed without its ordered sub-phases: missing {missing:?}"
        )
        .into());
    }
    let receipt = output(
        agent_exec(LIFECYCLE_NODE).args([
            "cat",
            &lifecycle_state()
                .join("legacy-java-home/change-ticket.receipt")
                .to_string_lossy(),
        ]),
    )?;
    if !receipt.contains(&format!("green release {BASELINE_VERSION}")) {
        return Err(format!("missing lifecycle audit receipt: {receipt:?}").into());
    }
    println!("[e2e] verified the ordered lifecycle transaction {attempt} and its audit receipt");
    Ok(())
}

fn lifecycle_audit() -> Result<String, Box<dyn std::error::Error>> {
    output(
        agent_exec(LIFECYCLE_NODE).args([
            "cat",
            &lifecycle_state()
                .join("audit/lifecycle.tsv")
                .to_string_lossy(),
        ]),
    )
}

/// The attempt id of the newest completed update transaction in the reconciler's audit log.
///
/// The reconciler appends one `<operation>\t<attempt>\t<event>` row per invocation. An update
/// transaction is exactly one [`Operation::Converge`] under a deployment attempt id; the reserved
/// ids (`boot`, `converge`, `periodic`, `fingerprint`) name operations that belong to no transaction and
/// must never be mistaken for one.
fn latest_completed_transaction(audit: &str) -> Option<String> {
    audit.lines().rev().find_map(|line| {
        let mut fields = line.split('\t');
        let (operation, attempt, event) = (fields.next()?, fields.next()?, fields.next()?);
        (operation == Operation::Converge.as_str()
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
    Ok(output(
        agent_exec(LIFECYCLE_NODE).args([
            "ls",
            "-1",
            &lifecycle_state()
                .join("attempts")
                .join(attempt)
                .to_string_lossy(),
        ]),
    )?
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
            &agent_resource_name(ordinal),
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
fn reserve_jenkins_agents() -> Result<(), Box<dyn std::error::Error>> {
    for (role, replicas) in JENKINS_COHORTS {
        for ordinal in 0..replicas {
            let node = format!("jenkins-{role}-{ordinal}");
            apply_json(&serde_json::json!({
                "apiVersion": "updated.dev/v1alpha1", "kind": "UpdateAgent",
                "metadata": {"name": resource_name(&node), "namespace": NAMESPACE},
                "spec": {
                    "repositoryRef": {"name": fixture::REPOSITORY_NAME},
                    "identity": {"kind": "reserved"},
                    "labels": {NODE_LABEL: node, KIND_LABEL: "jenkins", ROLE_LABEL: role}
                }
            }))?;
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
                        "volumeMounts": agent_volume_mounts(vec![
                            serde_json::json!({ "name": "state", "mountPath": "/var/lib/updated" }),
                            serde_json::json!({ "name": "jenkins-data", "mountPath": "/var/lib/jenkins" }),
                            serde_json::json!({ "name": "jenkins-backups", "mountPath": "/var/lib/jenkins-backups" })
                        ])
                    }],
                    "volumes": agent_volumes(vec![])
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
    let nonce = updated_contracts::digest::sha256_bytes(hostname.as_bytes());
    // The registration digest a node is pinned to, through the one function that defines it.
    let registration = updated_contracts::telemetry::node_object_digest(&nonce);
    format!("agent-{}", &registration[..24])
}

/// [`resource_name`] for the sample-app node with this fleet ordinal. `usize`, the type every
/// caller's ordinal already has: the layout constants are tunable, and narrowing here would let a
/// fleet grown past 255 nodes silently wrap onto another node's CR.
pub(crate) fn agent_resource_name(ordinal: usize) -> String {
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

/// Label the external agents into the `external` cohort the external UpdateGroup selects. No
/// set/fleet label — they sit outside the per-set machinery on purpose.
fn label_external_agents() -> Result<(), Box<dyn std::error::Error>> {
    for index in 0..EXTERNAL_COUNT {
        let ordinal = external_ordinal(index);
        patch_agent_labels(
            &agent_resource_name(ordinal),
            serde_json::json!({
                NODE_LABEL: format!("agent-{ordinal}"),
                COHORT_LABEL: EXTERNAL_COHORT,
                "updated.dev/role": null
            }),
        )?;
    }
    Ok(())
}

/// Wait for an operator-created Deployment to EXIST, then for its rollout to land. The operator
/// materializes a backend's workload on its own reconcile cadence after the `UpdateBackend` is
/// applied, and `kubectl rollout status` fails instantly on a name that is not there yet — a
/// bounded existence poll first is what makes waiting on operator output race-free.
pub(crate) async fn await_operator_deployment(
    name: &str,
    seconds: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    await_for(
        seconds,
        &format!("the operator to create deployment {name}"),
        || {
            Ok(kubectl()
                .args(["-n", NAMESPACE, "get", "deployment", name])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?
                .success())
        },
    )
    .await?;
    run(kubectl().args([
        "-n",
        NAMESPACE,
        "rollout",
        "status",
        &format!("deployment/{name}"),
        "--timeout=180s",
    ]))
}

/// Record each external machine's routable address on its `UpdateAgent` — the one inventory
/// fact the e2e supplies, exactly as a VM inventory controller would. Runs before ANY
/// `UpdateBackend` that selects these agents exists, because the operator fails a backend closed
/// over a selected agent with no address.
fn assign_external_backend_addresses() -> Result<(), Box<dyn std::error::Error>> {
    for index in 0..EXTERNAL_COUNT {
        let ordinal = external_ordinal(index);
        let pod = format!("agent-{ordinal}");
        let ip = kubectl_value("pod", &pod, "{.status.podIP}")?;
        let ip = ip.trim();
        if ip.is_empty() {
            return Err(format!("external agent {pod} has no pod IP yet").into());
        }
        let node = agent_resource_name(ordinal);
        run(kubectl().args([
            "-n",
            NAMESPACE,
            "patch",
            "updateagent",
            &node,
            "--type=merge",
            "-p",
            &serde_json::json!({"spec": {"backendAddress": ip}}).to_string(),
        ]))?;
    }
    Ok(())
}

/// Declare the external slice backend. The operator derives membership, public-key pins, workload,
/// and exact EndpointSlice RBAC from this CRD and the selected agents; the e2e supplies only each
/// external machine's routable address, just as a VM inventory controller would.
async fn deploy_external_reconciler() -> Result<(), Box<dyn std::error::Error>> {
    apply_json(&serde_json::json!({
        "apiVersion": "updated.dev/v1alpha1",
        "kind": "UpdateBackend",
        "metadata": {"name": "external", "namespace": NAMESPACE},
        "spec": {
            "repositoryRef": {"name": fixture::REPOSITORY_NAME},
            "selector": {"matchLabels": {COHORT_LABEL: EXTERNAL_COHORT}},
            "healthBase": HEALTH_CDN,
            "target": {
                "kind": "endpointSlice",
                "service": EXTERNAL_SERVICE,
                "port": 8080,
                "portName": "http"
            }
        }
    }))?;
    await_operator_deployment("updated-backend-external", 120).await
}

/// `(release_root, baseline_path, baseline_sha, provider_sha)` — the signed identities
/// [`bootstrap_minio_release_repo`] mints and republishes onto the shared release PVC.
type ReleaseBootstrap = (String, String, String);

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

/// Read the immutable reference printed by the real CI publisher. Fixtures consume that output
/// directly; they never need temporary Kubernetes groups just to discover a package digest.
pub(crate) fn published_reference(
    output: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let document: serde_json::Value = serde_json::from_str(output)?;
    let path = document["target"]
        .as_str()
        .ok_or("publication has no target")?;
    let sha = document["sha256"]
        .as_str()
        .ok_or("publication has no digest")?;
    if !updated_contracts::path::is_confined_relative(path)
        || !updated_contracts::is_canonical_sha256(sha)
    {
        return Err("invalid publication reference".into());
    }
    Ok((path.into(), sha.into()))
}

/// Mint the release repository's signing keys, seed the baseline release every cohort starts on,
/// and publish the lifecycle reconciler the green release runs. Everything runs inside the
/// release-server pod — it has `updatectl`, reaches MinIO in-cluster, and mounts the shared
/// release-repository PVC at `/data`, where the signing keys land.
///
/// Idempotent: re-running against an already-initialized repo is a no-op for the keys and a
/// content-addressed republish for the baseline (same bytes → same target).
fn bootstrap_minio_release_repo(
    platform: &str,
) -> Result<ReleaseBootstrap, Box<dyn std::error::Error>> {
    // Every `updatectl` below addresses the one release repository the groups resolve from.
    let repository = release_repository_flags();
    // 1. Mint keys + initialize the repo once, onto the shared PVC (skip if already there).
    let execution = demo_execution_flags();
    run(kubectl().args(RELEASE_SERVER_EXEC).args([
        "--",
        "sh",
        "-c",
        &format!(
            "set -e; export AWS_ACCESS_KEY_ID=minio AWS_SECRET_ACCESS_KEY=minio123; \
             if [ ! -f /data/release-keys/root.json ]; then mkdir -p /data/release-keys; \
             server init --keys /data/release-keys --repo /data/minio-release-origin {repository}; fi"
        ),
    ]))?;
    let release_root = output(kubectl().args(RELEASE_SERVER_EXEC).args([
        "--",
        "cat",
        "/data/release-keys/root.json",
    ]))?;

    // CI publication returns the reference; selecting a live rollout is a separate YAML operation.
    let published = output(kubectl().args(RELEASE_SERVER_EXEC).args([
        "--",
        "sh",
        "-c",
        &format!(
            "set -e; export AWS_ACCESS_KEY_ID=minio AWS_SECRET_ACCESS_KEY=minio123; \
             rm -rf /tmp/seed && mkdir -p /tmp/seed/bin /tmp/seed/config; \
             cp /usr/local/bin/sampleapp /tmp/seed/bin/app; cp /usr/local/bin/demo-lifecycle /tmp/seed/bin/lifecycle; \
             printf 'version = \"{BASELINE_VERSION}\"\\n' >/tmp/seed/config/release.toml; \
             updatectl publish --keys-dir /data/release-keys {repository} \
             --output json --product app --channel stable \
             --version {BASELINE_VERSION} --platform {platform} --source /tmp/seed {execution}"
        ),
    ]))?;
    let (baseline_path, baseline_sha) = published_reference(&published)?;
    Ok((release_root, baseline_path, baseline_sha))
}

/// Apply every resource the fleet layout needs and return the published reconciler set's sha —
/// the identity each cohort release is signed with.
fn apply_resources(jenkins: &JenkinsResources) -> Result<(), Box<dyn std::error::Error>> {
    let edge: serde_json::Value = serde_json::from_str(&output(kubectl().args([
        "-n",
        NAMESPACE,
        "get",
        "updategroup",
        "edge",
        "-o",
        "json",
    ]))?)?;
    // The fixture provisions MinIO. CI publication needs object-store access, not Kubernetes RBAC.
    let platform = repository_platform()?;
    let (release_root, baseline_path, baseline_sha) = bootstrap_minio_release_repo(&platform)?;
    let minio_release_repository = minio_release_repository(&release_root);
    let baseline_graph = fixture::fleet_baseline_graph(
        serde_json::from_value(edge["spec"]["deployment"]["application"].clone())?,
        updated_contracts::artifact::TargetReference {
            path: baseline_path,
            sha256: baseline_sha,
        },
    );
    let baseline_graph = serde_json::to_value(baseline_graph)?;
    // The sample-app cohorts (and the external slice) start on the MinIO-published baseline the
    // chaos then rolls with `updatectl publish`.
    let group = |name: &str, cohort: &str, set: &str| {
        let mut deployment = edge["spec"]["deployment"].clone();
        deployment["name"] = name.into();
        deployment["application"] = baseline_graph.clone();
        // Point the cohort at MinIO, the repository used by `updatectl publish`.
        // The Jenkins groups below keep edge's release-server repo (the default path).
        deployment["releaseRepository"] = minio_release_repository.clone();
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
            "confirmationWindowSeconds": 3
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
                "repositoryRef":{"name":fixture::REPOSITORY_NAME},
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
    for (role, _replicas) in JENKINS_COHORTS {
        let name = format!("jenkins-{role}");
        let mut deployment = edge["spec"]["deployment"].clone();
        deployment["name"] = name.clone().into();
        deployment["application"] = serde_json::json!({
            "target": "1.0.0", "releases": {"1.0.0": {"package": {
            "path": jenkins.application_path,
            "sha256": jenkins.application_sha.trim()
            }, "installable": true}}
        });

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
            "confirmationWindowSeconds": 10
        });
        items.push(serde_json::json!({
            "apiVersion":"updated.dev/v1alpha1",
            "kind":"UpdateGroup",
            "metadata":{"name": name, "namespace":NAMESPACE},
            "spec":{
                "repositoryRef":{"name":fixture::REPOSITORY_NAME},
                "selector": {"matchLabels":{KIND_LABEL:"jenkins", ROLE_LABEL: role}},
                "deployment": deployment
            }
        }));
    }
    // Per-set UpdateGroupSet (default maxConcurrent = members-1): never both groups of a
    // set roll at once, so every set always keeps a group serving.
    for set in 0..SET_COUNT {
        let name = set_name(set);
        items.push(serde_json::to_value(fixture::group_set_resource(
            &name,
            std::collections::BTreeMap::from([(SET_LABEL.into(), name.clone())]),
            None,
        ))?);
    }
    // One fleet-wide UpdateGroupSet over every managed group, on top of the per-set caps:
    // the control plane keeps at most FLEET_CONCURRENCY groups rolling at once, and —
    // because each group is in both its set and the fleet set — admits a group only when
    // BOTH have a slot. So the rollout pipelines FLEET_CONCURRENCY groups across that
    // many DISTINCT sets, each set keeping its other group up: fleet-wide pacing without
    // ever draining a set. As one group settles the next (in set order) starts, so the
    // pipeline stays full without pausing set-by-set.
    items.push(serde_json::to_value(fixture::group_set_resource(
        FLEET_SET,
        std::collections::BTreeMap::from([(FLEET_LABEL.into(), FLEET_VALUE.into())]),
        Some(FLEET_CONCURRENCY),
    ))?);
    // The external slice: same app + fast cadence as a cohort, but with NO fleet/set labels —
    // deliberately outside the per-set Services and the fleet throttle. It stands in for a fleet
    // that lives outside Kubernetes; the reconciler, not a selector, gives it endpoints.
    let mut external_group = group(EXTERNAL_COHORT, EXTERNAL_COHORT, EXTERNAL_COHORT);
    external_group["metadata"]
        .as_object_mut()
        .expect("group metadata is an object")
        .remove("labels");
    items.push(external_group);
    // No healthproxy RBAC here: the operator mints it. `runtime::reconcile_backend_access` converges
    // the ServiceAccount, the Role from `runtime::backend_role`, and the RoleBinding per
    // UpdateBackend, owner-referenced to the CR — so there is exactly one definition of what that
    // reconciler is allowed to do, and this run exercises the shipping one rather than a copy.
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
    Ok(())
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

/// The demo has one command implementation selected by ordinary runtime context.
pub(crate) fn demo_execution_flags() -> String {
    format!("--entrypoint bin/lifecycle --healthcheck bin/lifecycle --inspect bin/lifecycle --recover bin/lifecycle --replay safe --recovery-replay safe --timeout-seconds {}", demo_lifecycle::PROVIDER_TIMEOUT_MS.div_ceil(1000))
}
