//! The updated-managed HAProxy tier of the fleet e2e.
//!
//! Two HAProxy pods stand up as ordinary `updated` agents — plain Ubuntu + agent, no bespoke
//! image — that install HAProxy from a signed tarball bundle and upgrade it **in place** via the
//! provider's SIGUSR2 master-worker re-exec (`scripts/haproxy/{lifecycle,launch,lib.sh}`). They
//! front the e2e's external slice (the pods that stand in for out-of-cluster VMs); a HAProxy-mode
//! `updated-healthproxy` programs their `fleet` backend membership from the same signed CDN health
//! the EndpointSlice reconciler reads. A ClusterIP front Service fans traffic across the two
//! HAProxies, and the e2e drives it across a 1.0.0 → 2.0.0 HAProxy upgrade proving zero dropped
//! requests — the whole point of `updated` over a plain Kubernetes rollout: it manages
//! infrastructure (a load balancer) that fronts real services and that k8s cannot roll seamlessly.
//!
//! This tier sits entirely outside the sample-app cohort/set machinery and the pod-kill chaos
//! (like the Jenkins tier), so it never perturbs the finely-tuned convergence math.

use crate::*;
use std::process::Stdio;
use std::time::{Duration, Instant};

/// Execution ceiling signed into the `haproxy-lifecycle` provider set. The agent bounds the
/// WHOLE hook invocation by it, and this reconciler is the shell program in `scripts/haproxy`:
/// a config validation (`haproxy -c`) plus a SIGUSR2 master-worker re-exec, both sub-second, with
/// room for a cold install unpacking the bundle on a loaded kind cluster. It is deliberately not
/// the Rust lifecycle fixture's `PROVIDER_TIMEOUT_MS`, which is sized by that fixture's own dwell
/// arithmetic — two unrelated programs whose budgets only ever coincided by accident.
const HAPROXY_PROVIDER_TIMEOUT_MS: u64 = 30_000;

/// A backend server the HAProxy `fleet` section pre-declares: its control-plane node name (the
/// key its NodeReport is written under and the name the healthproxy flips state for) and the
/// in-cluster address HAProxy proxies to.
struct BackendServer {
    node: String,
    address: String,
}

/// The e2e's external slice, reused as HAProxy's backend: the two pods that stand in for
/// out-of-cluster VMs. HAProxy fronting them is the thesis in miniature — a load balancer
/// `updated` manages, in front of infrastructure that lives (conceptually) outside the cluster.
fn backend_servers() -> Vec<BackendServer> {
    (0..EXTERNAL_COUNT)
        .map(|index| {
            let ordinal = external_ordinal(index);
            BackendServer {
                node: agent_resource_name(ordinal),
                address: format!("agent-{ordinal}.agents:8080"),
            }
        })
        .collect()
}

/// The HAProxy configuration for one release version. The `fleet` backend pre-declares every
/// backend server (the healthproxy only ever flips their `ready`/`drain` state at runtime — it
/// never adds or removes servers), the frontend proxies real traffic to them, and `/haproxy-version`
/// returns this release's version so the e2e can observe the in-place re-exec actually swapping
/// the running configuration. `master-worker` + the admin stats socket are what the provider's
/// `apply` operation drives (SIGUSR2 re-exec) and what the healthproxy programs.
fn haproxy_cfg(version: &str, servers: &[BackendServer]) -> String {
    let mut cfg = String::new();
    cfg.push_str(&format!(
        "global\n\
         \x20   stats socket ipv4@0.0.0.0:{admin} level admin\n\
         \x20   stats timeout 30s\n\
         \x20   maxconn 2000\n\
         \n\
         defaults\n\
         \x20   mode http\n\
         \x20   timeout connect 5s\n\
         \x20   timeout client 30s\n\
         \x20   timeout server 30s\n\
         \n\
         frontend fe\n\
         \x20   bind :8080\n\
         \x20   monitor-uri /haproxy-healthz\n\
         \x20   http-request return status 200 content-type text/plain \
         lf-string \"haproxy {version}\" if {{ path /haproxy-version }}\n\
         \x20   default_backend {backend}\n\
         \n\
         backend {backend}\n",
        admin = HAPROXY_ADMIN_PORT,
        backend = HAPROXY_BACKEND,
    ));
    for server in servers {
        // No `check`: the HAProxy-mode healthproxy is the single authority on membership (it flips
        // `set server <backend>/<node> state ready|drain` from signed CDN health), so HAProxy's own
        // active health checks must not fight it. Servers start routable and the healthproxy drains
        // any node whose signed report is not healthy.
        cfg.push_str(&format!(
            "\x20   server {node} {address}\n",
            node = server.node,
            address = server.address,
        ));
    }
    cfg
}

/// The HAProxy StatefulSet: `HAPROXY_REPLICAS` pods, each the same plain Ubuntu + agent image
/// as every other node, enrolling through the same gateway and installing HAProxy from the signed
/// bundle at runtime. In the headless `agents` Service so `haproxy-<n>.agents` resolves for the
/// healthproxy's admin-socket reach.
pub(crate) fn haproxy_statefulset() -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": { "name": "haproxy", "namespace": NAMESPACE },
        "spec": {
            "serviceName": "agents",
            "replicas": HAPROXY_REPLICAS,
            "podManagementPolicy": "Parallel",
            "selector": { "matchLabels": { "app": "updated-agent", KIND_LABEL: "haproxy" } },
            "template": {
                "metadata": { "labels": { "app": "updated-agent", KIND_LABEL: "haproxy" } },
                "spec": {
                    "securityContext": { "fsGroup": 65532, "seccompProfile": { "type": "RuntimeDefault" } },
                    "containers": [{
                        "name": "agent",
                        "image": "updatec-e2e:kind",
                        "imagePullPolicy": "Never",
                        "command": ["/usr/local/bin/run-agent"],
                        "ports": [
                            { "name": "http", "containerPort": 8080 },
                            { "name": "admin", "containerPort": HAPROXY_ADMIN_PORT }
                        ],
                        // The workload's own frontend, which is what "this pod can serve" means
                        // here. Node health has one path — reconciler hook verdict -> signed
                        // NodeReport -> healthproxy — and the kubelet never judges the agent.
                        "readinessProbe": { "tcpSocket": { "port": "http" }, "periodSeconds": 1, "failureThreshold": 180 },
                        "securityContext": { "allowPrivilegeEscalation": false, "capabilities": { "drop": ["ALL"] }, "runAsNonRoot": true, "runAsUser": 65532 },
                        "resources": { "requests": { "cpu": "50m", "memory": "64Mi" }, "limits": { "memory": "256Mi" } },
                        "volumeMounts": agent_volume_mounts(vec![
                            serde_json::json!({ "name": "state", "mountPath": "/var/lib/updated" })
                        ])
                    }],
                    "volumes": agent_volumes(vec![])
                }
            },
            // Persistent, like every enrolling node: the per-node minted key/cert and the install
            // state live only here, so an emptyDir would churn identity on restart.
            "volumeClaimTemplates": [
                { "metadata": { "name": "state" }, "spec": { "accessModes": ["ReadWriteOnce"], "resources": { "requests": { "storage": "1Gi" } } } }
            ]
        }
    })
}

/// The signed HAProxy artifacts published into MinIO: the shared `haproxy-lifecycle` provider set
/// and the two app releases the tier upgrades between.
pub(crate) struct HaproxyRelease {
    pub(crate) v1_path: String,
    pub(crate) v1_sha: String,
    pub(crate) v2_path: String,
    pub(crate) v2_sha: String,
}

/// Publish the HAProxy provider chain and both app releases into the MinIO release repository,
/// entirely inside the release-server pod (it carries `updatectl`, reaches MinIO, and shares the
/// signing keys `bootstrap_minio_release_repo` already minted onto the release PVC).
///
/// The provider bundle is `scripts/haproxy/{lifecycle,lib.sh}` (the exact reexec provider proven by
/// `scripts/linux-haproxy-e2e.sh`). Each app release carries the real distro `haproxy` binary, a
/// version-stamped `haproxy.cfg`, and `scripts/haproxy/launch` as `bin/launch` — the start line the
/// provider's `apply` runs when no master is up yet, since the reconciler hooks own every workload
/// process and the agent starts none of its own. The two releases differ only in the version their
/// config reports, so applying 2.0.0 is a pure SIGUSR2 config re-exec of the same master.
pub(crate) fn publish_haproxy_bundles(
    platform: &str,
) -> Result<HaproxyRelease, Box<dyn std::error::Error>> {
    // Publish both versions without assigning either one to a group.
    let servers = backend_servers();
    let (v1_path, v1_sha) = publish_haproxy_app(platform, HAPROXY_V1, &servers)?;
    let (v2_path, v2_sha) = publish_haproxy_app(platform, HAPROXY_V2, &servers)?;
    Ok(HaproxyRelease {
        v1_path,
        v1_sha,
        v2_path,
        v2_sha,
    })
}

/// Publish one version-stamped HAProxy app bundle and return its `(path, sha256)`.
fn publish_haproxy_app(
    platform: &str,
    version: &str,
    servers: &[BackendServer],
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let repository = release_repository_flags();
    let timeout = HAPROXY_PROVIDER_TIMEOUT_MS.div_ceil(1000);
    let cfg = haproxy_cfg(version, servers);
    // Stage the bundle tree: the real distro haproxy binary + the launch entrypoint.
    run(kubectl().args(RELEASE_SERVER_EXEC).args([
        "--",
        "sh",
        "-c",
        "set -e; rm -rf /tmp/hap-app && mkdir -p /tmp/hap-app/bin /tmp/hap-app/config; \
         hap=$(command -v haproxy || true); \
         for c in \"$hap\" /usr/sbin/haproxy /usr/bin/haproxy; do \
           if [ -x \"$c\" ]; then cp \"$c\" /tmp/hap-app/bin/haproxy; break; fi; done; \
         [ -x /tmp/hap-app/bin/haproxy ] || { echo 'haproxy binary not found in release-server image' >&2; exit 1; }; \
         chmod 0755 /tmp/hap-app/bin/haproxy; \
         cp /usr/local/share/haproxy/lifecycle /tmp/hap-app/bin/lifecycle; cp /usr/local/share/haproxy/lib.sh /tmp/hap-app/bin/lib.sh; cp /usr/local/share/haproxy/launch /tmp/hap-app/bin/launch; chmod 0755 /tmp/hap-app/bin/launch",
    ]))?;
    // Pipe the generated config in over stdin — no shell escaping of its quotes/braces/newlines.
    pipe_into_release_server("cat > /tmp/hap-app/config/haproxy.cfg", &cfg)?;
    let published = output(kubectl().args(RELEASE_SERVER_EXEC).args([
        "--",
        "sh",
        "-c",
        &format!(
            "set -e; export AWS_ACCESS_KEY_ID=minio AWS_SECRET_ACCESS_KEY=minio123; \
             updatectl publish --keys-dir /data/release-keys {repository} \
             --output json --product haproxy --channel stable --version {version} \
             --platform {platform} --source /tmp/hap-app --entrypoint bin/lifecycle --healthcheck bin/lifecycle --inspect bin/lifecycle --recover bin/lifecycle --replay safe --recovery-replay safe --timeout-seconds {timeout}"
        ),
    ]))?;
    published_reference(&published)
}

/// Run `sh -c "<command>"` in the release-server pod with `stdin` piped to it — the escaping-free
/// way to land arbitrary bytes (a generated config) inside the pod. Built from
/// [`RELEASE_SERVER_EXEC`] with `-i` added, so the pod and container this addresses stay stated in
/// exactly one place.
fn pipe_into_release_server(command: &str, stdin: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut child = kubectl()
        .args(RELEASE_SERVER_EXEC)
        .args(["-i", "--", "sh", "-c", command])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()?;
    use std::io::Write;
    child
        .stdin
        .take()
        .ok_or("release-server exec stdin unavailable")?
        .write_all(stdin.as_bytes())?;
    if !child.wait()?.success() {
        return Err("piping bytes into the release-server pod failed".into());
    }
    Ok(())
}

/// The real `haproxy` UpdateGroup's deployment: clone `edge` (for CRD-field completeness), then
/// override everything that makes it a HAProxy node — the app bundle, the HAProxy lifecycle
/// provider set, the MinIO repo, the HAProxy product, and a fast cadence with a short boot grace
/// for HAProxy's few-second install.
///
/// The invariant this tier's whole claim rests on: the release's signed reconciler hooks own the
/// HAProxy master. `apply` starts it on first install and thereafter re-execs that same master in
/// place (SIGUSR2), which is what keeps the bound listeners — and therefore the traffic — alive
/// across the switchover. The agent never starts or stops a workload process, so there is no stop
/// to sequence around.
fn haproxy_group_deployment(
    edge: &serde_json::Value,
    release_root: &str,
    release: &HaproxyRelease,
) -> serde_json::Value {
    let mut deployment = edge["spec"]["deployment"].clone();
    deployment["name"] = versioned_deployment_name(HAPROXY_GROUP, HAPROXY_V1).into();
    deployment["application"] =
        serde_json::to_value(updated_contracts::releases::testing::install(
            HAPROXY_V1,
            updated_contracts::artifact::TargetReference {
                path: release.v1_path.clone(),
                sha256: release.v1_sha.clone(),
            },
        ))
        .expect("the typed release graph is serializable");

    deployment["releaseRepository"] = minio_release_repository(release_root);
    deployment["runtime"]["product"] = "haproxy".into();
    // No install-root override: a node's install root is pinned at enrollment and the agent fails
    // closed on an assignment that would move it. Each node runs exactly one product, so the
    // enrollment-verified root is the right one for HAProxy too — overriding it made the tier
    // install only when labelling happened to win the race against the node's first assignment.
    deployment["runtime"]["timeouts"] = serde_json::json!({
        "checkIntervalSeconds": 1,
        "healthGraceSeconds": 12,
        "healthSuccesses": 1,
        "healthIntervalSeconds": 1,
        "refreshRetrySeconds": 1,
        "confirmationWindowSeconds": 3
    });
    deployment
}

/// Bring up the whole HAProxy tier onto an already-provisioned cluster: the StatefulSet, the
/// published bundles, the `haproxy` UpdateGroup at 1.0.0 (annotated with the pre-published 2.0.0
/// target the e2e upgrade patches in), the HAProxy-mode healthproxy that programs backend
/// membership, and the front Service. Idempotent enough to re-run: converges are declarative.
pub(crate) async fn prepare_haproxy_tier(platform: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("[e2e] deploying the updated-managed HAProxy tier ({HAPROXY_REPLICAS} HAProxies fronting the external slice)");
    // Clone the fully-valid `edge` deployment as the template for every HAProxy deployment spec, so
    // no CRD-required field is ever missing. The MinIO root is what the HAProxy bundles are pinned to.
    let edge: serde_json::Value = serde_json::from_str(&output(kubectl().args([
        "-n",
        NAMESPACE,
        "get",
        "updategroup",
        "edge",
        "-o",
        "json",
    ]))?)?;
    let release_root = output(kubectl().args(RELEASE_SERVER_EXEC).args([
        "--",
        "cat",
        "/data/release-keys/root.json",
    ]))?;
    let release = publish_haproxy_bundles(platform)?;
    let base = haproxy_group_deployment(&edge, &release_root, &release);
    // One self-protecting group owns both HAProxy nodes. `maxUnavailable: 1` makes the control
    // plane publish the new assignment to one node at a time; no synthetic set/group split is
    // needed merely to obtain availability.
    apply_json(&serde_json::json!({
        "apiVersion": "updated.dev/v1alpha1",
        "kind": "UpdateGroup",
        "metadata": {
            "name": HAPROXY_GROUP,
            "namespace": NAMESPACE,
            "annotations": {
                HAPROXY_NEXT_PATH_ANNOTATION: &release.v2_path,
                HAPROXY_NEXT_SHA_ANNOTATION: &release.v2_sha,
            }
        },
        "spec": {
            "repositoryRef": {"name": fixture::REPOSITORY_NAME},
            "selector": {"matchLabels": {COHORT_LABEL: HAPROXY_COHORT}},
            "deployment": base,
            "maxUnavailable": 1
        }
    }))?;
    // Reserve each HAProxy node's identity, WITH its cohort labels, before any pod exists to
    // enroll — and only after the group above is applied, so the very first assignment such a
    // node ever resolves is its own group's. The previous shape (enroll first, label the
    // registered agent afterwards) left a window in which the node was an unmatched member of
    // the fleet: it was routed to the DEFAULT deployment, installed the sample application, and
    // — that deployment's version colliding with the HAProxy tier's `1.0.0` — held those foreign
    // bytes by the same-version rule. The stowaway workload kept `:8080` bound, so the tier's
    // first real upgrade failed activation on that node, was durably rejected, and halted the
    // deployment fleet-wide. Reserving first closes the window structurally instead of narrowing
    // it: there is no instant at which the node is enrolled but unlabeled.
    for ordinal in 0..HAPROXY_REPLICAS {
        let node = format!("haproxy-{ordinal}");
        apply_json(&serde_json::json!({
            "apiVersion": "updated.dev/v1alpha1",
            "kind": "UpdateAgent",
            "metadata": {"name": resource_name(&node), "namespace": NAMESPACE},
            "spec": {
                "repositoryRef": {"name": fixture::REPOSITORY_NAME},
                "identity": {"kind": "reserved"},
                "labels": {
                    NODE_LABEL: node,
                    COHORT_LABEL: HAPROXY_COHORT,
                    KIND_LABEL: "haproxy"
                }
            }
        }))?;
    }
    apply_json(&haproxy_statefulset())?;
    apply_haproxy_front_service()?;
    deploy_haproxy_healthproxy().await?;
    println!("[e2e] waiting for the HAProxy tier to install and become ready");
    run(kubectl().args([
        "-n",
        NAMESPACE,
        "rollout",
        "status",
        "statefulset/haproxy",
        "--timeout=300s",
    ]))?;
    Ok(())
}

/// The ClusterIP front Service fanning traffic across the HAProxy pods. Selects the HAProxy pods
/// by their `kind=haproxy` label and only the ready ones (no `publishNotReadyAddresses`), so a
/// HAProxy pod that is re-execing/unready leaves the front until it is healthy again.
pub(crate) fn apply_haproxy_front_service() -> Result<(), Box<dyn std::error::Error>> {
    apply_json(&serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": HAPROXY_FRONT_SERVICE, "namespace": NAMESPACE},
        "spec": {
            "selector": {"app": "updated-agent", KIND_LABEL: "haproxy"},
            "ports": [{"name": "http", "port": 80, "targetPort": "http"}]
        }
    }))
}

/// Declare the HAProxy Runtime API backend. The same external-agent selector used by the
/// EndpointSlice backend drives this independent projection; the operator resolves addresses and
/// pinned identities and creates a tokenless workload identity with no Role.
pub(crate) async fn deploy_haproxy_healthproxy() -> Result<(), Box<dyn std::error::Error>> {
    let endpoints: Vec<String> = (0..HAPROXY_REPLICAS)
        .map(|ordinal| format!("haproxy-{ordinal}.agents:{}", HAPROXY_ADMIN_PORT))
        .collect();
    apply_json(&serde_json::json!({
        "apiVersion": "updated.dev/v1alpha1",
        "kind": "UpdateBackend",
        "metadata": {"name": "haproxy", "namespace": NAMESPACE},
        "spec": {
            "repositoryRef": {"name": fixture::REPOSITORY_NAME},
            "selector": {"matchLabels": {COHORT_LABEL: EXTERNAL_COHORT}},
            "healthBase": HEALTH_CDN,
            "target": {
                "kind": "haProxy",
                "endpoints": endpoints,
                "backend": HAPROXY_BACKEND
            }
        }
    }))?;
    await_operator_deployment("updated-backend-haproxy", 120).await
}

/// Drive the HAProxy tier through a 1.0.0 → 2.0.0 in-place upgrade while a synthetic client hits
/// the front Service continuously, and assert **zero-downtime**: the front stays available across
/// the whole re-exec (the two HAProxies roll one at a time, each SIGUSR2-re-execing its master with
/// no dropped connection), and both HAProxies durably report 2.0.0.
///
/// The upgrade is a pure group patch to the pre-published 2.0.0 target (read from the annotation
/// `prepare_haproxy_tier` stamped), so it is signed-store-driven, never a live publish. Convergence
/// is gated on the durable control-plane `reportedVersion`, never on transient probing.
/// The in-cluster load-probe pod behind the zero-lost-requests assertion, and the shape of the
/// claim it enforces. The pod runs `updatec-e2e load-probe` (see `crate::probe`) against the
/// front Service from INSIDE the cluster, so the measurement rides the exact path production
/// traffic does and carries none of the `kubectl port-forward` reconnect noise the previous
/// probe's availability tolerance existed to absorb. With that noise gone the tolerance goes
/// with it: a correct SIGUSR2 re-exec keeps the listeners bound and `-sf` drains the old worker,
/// so across the whole upgrade NOTHING on this path may fail — the assertion is `failed == 0`,
/// with a bounded blackout window (`max_gap_ms`) so a stall that merely queues requests cannot
/// hide behind requests that eventually succeeded.
const LOAD_PROBE_POD: &str = "haproxy-load-probe";
/// Pacing between sequential probe requests: ~40 req/s of steady load.
const LOAD_PROBE_INTERVAL_MS: u64 = 25;
/// The fewest observations a verdict may rest on, counted from the instant the group is patched —
/// a DELTA, never the cumulative total. At 25ms pacing 400 samples is ~10s, but the window the
/// verdict certifies runs to the convergence deadline, so a cumulative floor was cleared by a
/// probe that watched the first ten seconds and then died (evicted, OOM-killed; `restartPolicy:
/// Never` leaves the pod's last cumulative line readable by `kubectl logs` forever). The delta,
/// together with the pod still being `Running` when the verdict is read, is what makes "the probe
/// was alive across the re-exec" a checked fact rather than an assumption.
const LOAD_PROBE_MIN_SAMPLES: u64 = 400;
/// The longest the front may go without a successful response. Two seconds is far above any
/// healthy in-cluster round trip and far below what a dropped listener costs.
const LOAD_PROBE_MAX_GAP_MS: u64 = 2000;

pub(crate) async fn assert_haproxy_zero_downtime_upgrade() -> Result<(), Box<dyn std::error::Error>>
{
    println!("[e2e] verifying the updated-managed HAProxy tier and its zero-downtime upgrade");
    // Both HAProxies must already be serving 1.0.0 before we start.
    wait_for_haproxy_version(HAPROXY_V1, 240).await?;
    // And the front must proxy real backend traffic before anything is measured or touched.
    wait_for_front(120, "a backend /version response", |body| {
        !body.trim().is_empty()
    })
    .await?;

    apply_json(&serde_json::json!({
        "apiVersion": "v1", "kind": "Pod",
        "metadata": {"name": LOAD_PROBE_POD, "namespace": NAMESPACE},
        "spec": {
            "restartPolicy": "Never",
            "containers": [{
                "name": "probe",
                "image": "updatec-e2e:kind",
                "imagePullPolicy": "Never",
                "command": [
                    "/usr/local/bin/updatec-e2e", "load-probe",
                    format!("http://{HAPROXY_FRONT_SERVICE}/version"),
                    LOAD_PROBE_INTERVAL_MS.to_string(),
                ],
            }],
        }
    }))?;
    let result = drive_haproxy_upgrade().await;
    // The probe has no stop of its own; the pod's deletion is the stop, on every exit path.
    let _ = kubectl()
        .args([
            "-n",
            NAMESPACE,
            "delete",
            "pod",
            LOAD_PROBE_POD,
            "--ignore-not-found",
        ])
        .stdout(Stdio::null())
        .status();
    result
}

async fn drive_haproxy_upgrade() -> Result<(), Box<dyn std::error::Error>> {
    // The probe must be observing BEFORE the upgrade starts, or the re-exec happens off camera.
    await_for(120, "the load probe to start observing the front", || {
        Ok(probe_summary().is_some_and(|summary| summary.total > 0))
    })
    .await?;
    println!("[e2e] in-cluster load probe is observing the front; starting the upgrade");

    // Upgrade the self-protecting group to the pre-published 2.0.0 target. Intra-group admission
    // publishes it to the two HAProxies one at a time. Bracket notation for the annotation key — and
    // kubectl's jsonpath still requires the DOTS escaped even inside the brackets, so
    // `e2e.updated.dev/...` must be written `e2e\.updated\.dev/...` or the selector returns empty.
    let path_key = HAPROXY_NEXT_PATH_ANNOTATION.replace('.', "\\.");
    let sha_key = HAPROXY_NEXT_SHA_ANNOTATION.replace('.', "\\.");
    let annotated = HAPROXY_GROUP;
    let next_path = kubectl_value(
        "updategroup",
        annotated,
        &format!("{{.metadata.annotations['{path_key}']}}"),
    )?;
    let next_sha = kubectl_value(
        "updategroup",
        annotated,
        &format!("{{.metadata.annotations['{sha_key}']}}"),
    )?;
    let next_path = next_path.trim();
    let next_sha = next_sha.trim();
    if next_path.is_empty() || next_sha.is_empty() {
        return Err("HAProxy group carries no pre-published 2.0.0 target annotation".into());
    }
    // The probe's counters are cumulative, so the samples that certify the upgrade are the ones
    // taken after this line. Everything before it belongs to the pre-flight, and counting it would
    // let a probe that died early clear the coverage floor on requests nobody was upgrading during.
    let before_patch = probe_summary().map_or(0, |summary| summary.total);
    run(kubectl().args([
        "-n",
        NAMESPACE,
        "patch",
        "updategroup",
        HAPROXY_GROUP,
        "--type=merge",
        "-p",
        &serde_json::to_string(&serde_json::json!({"spec": {"deployment": {
            "name": versioned_deployment_name(HAPROXY_GROUP, HAPROXY_V2),
            "application": {"target": HAPROXY_V2, "releases": {HAPROXY_V2: updated_contracts::releases::Release {
                package: updated_contracts::artifact::TargetReference {
                    path: next_path.into(), sha256: next_sha.into(),
                },
                upgrade_from: std::collections::BTreeSet::from([HAPROXY_V1.into()]),
                rollback_from: std::collections::BTreeSet::new(),
                installable: true,
            }}}
        }}}))?,
    ]))?;

    // Gate convergence on the durable control-plane reportedVersion — never on the probe.
    wait_for_haproxy_version(HAPROXY_V2, 240).await?;
    // Both instances really re-execed: the Service balances across the pair, so only a run of
    // consecutive 2.0.0 answers proves no old worker is still answering behind it.
    let want = format!("haproxy {HAPROXY_V2}");
    let mut consecutive = 0usize;
    wait_for_front_path(
        60,
        "/haproxy-version",
        "every instance re-execed to 2.0.0",
        |body| {
            if body.trim() == want {
                consecutive += 1;
            } else {
                consecutive = 0;
            }
            consecutive >= 10
        },
    )
    .await?;

    // Keep observing past convergence, then read the probe's cumulative verdict. The lines are
    // cumulative, so the last one covers the whole run.
    tokio::time::sleep(Duration::from_secs(3)).await;
    // The probe must still be ALIVE to have watched the window it certifies. A pod with
    // `restartPolicy: Never` that was evicted or OOM-killed keeps serving its last cumulative line
    // to `kubectl logs`, so reading a summary proves nothing about when it was written.
    let phase = kubectl_value("pod", LOAD_PROBE_POD, "{.status.phase}")?;
    if phase.trim() != "Running" {
        return Err(format!(
            "the load probe pod is {} and not Running, so its summary does not cover the re-exec \
             it would certify",
            phase.trim()
        )
        .into());
    }
    let summary =
        probe_summary().ok_or("the load probe emitted no summary to judge the upgrade by")?;
    let during_upgrade = summary.total.saturating_sub(before_patch);
    if during_upgrade < LOAD_PROBE_MIN_SAMPLES {
        return Err(format!(
            "the load probe recorded too few samples ({during_upgrade} of {}) after the group was \
             patched to judge the upgrade",
            summary.total
        )
        .into());
    }
    if summary.failed != 0 {
        return Err(format!(
            "HAProxy upgrade dropped traffic: {}/{} requests failed (first: {})",
            summary.failed, summary.total, summary.first_failure
        )
        .into());
    }
    if summary.max_gap_ms > LOAD_PROBE_MAX_GAP_MS {
        return Err(format!(
            "HAProxy upgrade stalled the front for {}ms (bound {LOAD_PROBE_MAX_GAP_MS}ms) even \
             though no request failed outright",
            summary.max_gap_ms
        )
        .into());
    }
    println!(
        "HAPROXY PASS: {HAPROXY_REPLICAS} updated-managed HAProxies upgraded {HAPROXY_V1} -> {HAPROXY_V2} in place with 0/{} requests lost ({during_upgrade} of them after the patch, from a probe still running at the verdict) and a worst gap of {}ms across the SIGUSR2 re-exec",
        summary.total, summary.max_gap_ms
    );
    Ok(())
}

/// The probe pod's latest cumulative summary, or `None` while it has not emitted one (or the read
/// itself failed — every caller polls or has already bounded the run with the sample floor).
fn probe_summary() -> Option<crate::probe::Summary> {
    let logs =
        output(kubectl().args(["-n", NAMESPACE, "logs", LOAD_PROBE_POD, "--tail=5"])).ok()?;
    crate::probe::Summary::from_logs(&logs)
}

/// Wait until the front Service, reached from INSIDE the cluster (a curl from the release-server
/// pod — the same trust boundary production clients sit in), answers `path` with a body `accept`
/// approves. The single front-read primitive: pre-flight serving checks and the re-exec proof both
/// go through it, so there is no second, differently-flaky way to ask the front a question.
async fn wait_for_front_path(
    seconds: usize,
    path: &str,
    what: &str,
    mut accept: impl FnMut(&str) -> bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("http://{HAPROXY_FRONT_SERVICE}{path}");
    let deadline = Instant::now() + Duration::from_secs(seconds as u64);
    while Instant::now() < deadline {
        if let Ok(body) = cluster_curl(&url) {
            if accept(&body) {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    Err(format!("HAProxy front never satisfied: {what}").into())
}

async fn wait_for_front(
    seconds: usize,
    what: &str,
    accept: impl FnMut(&str) -> bool,
) -> Result<(), Box<dyn std::error::Error>> {
    wait_for_front_path(seconds, "/version", what, accept).await
}

/// Wait until every HAProxy node's `UpdateAgent` durably reports `version`.
async fn wait_for_haproxy_version(
    version: &str,
    seconds: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let nodes: Vec<String> = (0..HAPROXY_REPLICAS)
        .map(|ordinal| resource_name(&format!("haproxy-{ordinal}")))
        .collect();
    await_for(
        seconds,
        &format!("the HAProxy tier to report {version}"),
        || {
            Ok(nodes.iter().all(|node| {
                kubectl_value("updateagent", node, "{.status.reportedVersion}")
                    .is_ok_and(|reported| reported.trim() == version)
            }))
        },
    )
    .await
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    fn edge_group() -> serde_json::Value {
        let deployment = updatec::DeploymentSpec {
            name: versioned_deployment_name("edge", "1.0.0"),
            release_repository: updatec::ReleaseRepositorySpec {
                metadata_url: "https://release/metadata/".into(),
                targets_url: "https://release/targets/".into(),
                root_json: "{}".into(),
            },
            application: updated_contracts::releases::testing::install(
                "1.0.0",
                updated_contracts::artifact::TargetReference {
                    path: "app-1.0.0.tar.zst".into(),
                    sha256: "a".repeat(64),
                },
            ),

            runtime: updatec::RuntimeSpec {
                product: "sampleapp".into(),
                channel: "stable".into(),
                install_root: "/var/lib/updated/app".into(),
                repository: updated_contracts::assignment::ManagedRepositoryLimits {
                    metadata_limit: 1 << 20,
                    target_limit: 512 << 20,
                    transport_timeout_seconds: 30,
                },
                storage: updated_contracts::assignment::ManagedStorage {
                    inactive_releases: 2,
                    inactive_bytes: 1 << 30,
                    inactive_repository_caches: 2,
                },
                timeouts: updated_contracts::assignment::ManagedTimeouts {
                    check_interval_seconds: 15,
                    health_grace_seconds: 30,
                    health_successes: 1,
                    health_interval_seconds: 1,
                    refresh_retry_seconds: 5,
                    confirmation_window_seconds: 120,
                },
            },
        };
        serde_json::json!({
            "spec": { "deployment": serde_json::to_value(deployment).unwrap() }
        })
    }

    /// This driver writes its CRs as untyped JSON, so a field the contract has dropped is silently
    /// pruned by the API server instead of failing anywhere the author can see. Round-tripping
    /// through the typed spec is what makes any key the spec cannot express fail loudly: a bare
    /// deserialize would not, since equality is what proves nothing was dropped.
    #[test]
    fn the_haproxy_deployment_says_only_what_the_contract_can_express() {
        let built = haproxy_group_deployment(
            &edge_group(),
            "{\"signed\":{}}",
            &HaproxyRelease {
                v1_path: "haproxy-1.0.0.tar.zst".into(),
                v1_sha: "d".repeat(64),
                v2_path: "haproxy-2.0.0.tar.zst".into(),
                v2_sha: "e".repeat(64),
            },
        );
        let typed: updatec::DeploymentSpec = serde_json::from_value(built.clone())
            .expect("the built deployment must deserialize into the published spec");
        assert_eq!(
            serde_json::to_value(typed).unwrap(),
            built,
            "the built deployment wrote a key the typed deployment spec cannot express"
        );
    }
}
