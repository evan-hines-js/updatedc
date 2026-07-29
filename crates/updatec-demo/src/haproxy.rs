//! The updated-managed HAProxy tier of the demo.
//!
//! Two HAProxy pods stand up as ordinary `updated` agents — plain Ubuntu + agent, no bespoke
//! image — that install HAProxy from a signed tarball bundle and upgrade it **in place** via the
//! provider's SIGUSR2 master-worker re-exec (`scripts/haproxy/{lifecycle,launch,lib.sh}`). They
//! front the demo's external slice (the pods that stand in for out-of-cluster VMs); a HAProxy-mode
//! `updated-healthproxy` programs their `fleet` backend membership from the same signed CDN health
//! the EndpointSlice reconciler reads. A ClusterIP front Service fans traffic across the two
//! HAProxies, and the e2e drives it across a 1.0.0 → 2.0.0 HAProxy upgrade proving zero dropped
//! requests — the whole point of `updated` over a plain Kubernetes rollout: it manages
//! infrastructure (a load balancer) that fronts real services and that k8s cannot roll seamlessly.
//!
//! This tier sits entirely outside the sample-app cohort/set machinery and the pod-kill chaos
//! (like the Magnolia tier), so it never perturbs the finely-tuned convergence/SLA math.

use crate::*;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A backend server the HAProxy `fleet` section pre-declares: its control-plane node name (the
/// key its NodeReport is written under and the name the healthproxy flips state for) and the
/// in-cluster address HAProxy proxies to.
struct BackendServer {
    node: String,
    address: String,
}

/// The demo's external slice, reused as HAProxy's backend: the two pods that stand in for
/// out-of-cluster VMs. HAProxy fronting them is the thesis in miniature — a load balancer
/// `updated` manages, in front of infrastructure that lives (conceptually) outside the cluster.
fn backend_servers() -> Vec<BackendServer> {
    (0..DEMO_EXTERNAL_COUNT)
        .map(|index| {
            let ordinal = external_ordinal(index);
            BackendServer {
                node: agent_resource_name(ordinal as u8),
                address: format!("agent-{ordinal}.agents:8080"),
            }
        })
        .collect()
}

/// The HAProxy configuration for one release version. The `fleet` backend pre-declares every
/// backend server (the healthproxy only ever flips their `ready`/`drain` state at runtime — it
/// never adds or removes servers), the frontend proxies real traffic to them, and `/haproxy-version`
/// returns this release's version so the demo can observe the in-place re-exec actually swapping
/// the running configuration. `master-worker` + the admin stats socket are what the provider's
/// `activate` phase drives (SIGUSR2 re-exec) and what the healthproxy programs.
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
        admin = DEMO_HAPROXY_ADMIN_PORT,
        backend = DEMO_HAPROXY_BACKEND,
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

/// The HAProxy StatefulSet: `DEMO_HAPROXY_REPLICAS` pods, each the same plain Ubuntu + agent image
/// as every other node, enrolling through the same gateway and installing HAProxy from the signed
/// bundle at runtime. In the headless `agents` Service so `haproxy-<n>.agents` resolves for the
/// healthproxy's admin-socket reach and the uniform guardian readyz probe.
fn haproxy_statefulset() -> serde_json::Value {
    serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": { "name": "haproxy", "namespace": "updated-system" },
        "spec": {
            "serviceName": "agents",
            "replicas": DEMO_HAPROXY_REPLICAS,
            "podManagementPolicy": "Parallel",
            "selector": { "matchLabels": { "app": "updated-agent", "demo.updated.dev/kind": "haproxy" } },
            "template": {
                "metadata": { "labels": { "app": "updated-agent", "demo.updated.dev/kind": "haproxy" } },
                "spec": {
                    "securityContext": { "fsGroup": 65532, "seccompProfile": { "type": "RuntimeDefault" } },
                    "containers": [{
                        "name": "agent",
                        "image": "updatec-e2e:kind",
                        "imagePullPolicy": "Never",
                        "command": ["/usr/local/bin/run-agent"],
                        "ports": [
                            { "name": "http", "containerPort": 8080 },
                            { "name": "admin", "containerPort": DEMO_HAPROXY_ADMIN_PORT },
                            { "name": "guardian", "containerPort": 9090 }
                        ],
                        // HAProxy installs in a few seconds, so a short startup budget suffices;
                        // readiness tracks the supervisor's real HAProxy health check thereafter.
                        "startupProbe": { "httpGet": { "path": "/startupz", "port": "guardian" }, "periodSeconds": 1, "failureThreshold": 180 },
                        "readinessProbe": { "httpGet": { "path": "/readyz", "port": "guardian" }, "periodSeconds": 1, "failureThreshold": 1 },
                        "livenessProbe": { "httpGet": { "path": "/livez", "port": "guardian" }, "periodSeconds": 5, "failureThreshold": 6 },
                        "securityContext": { "allowPrivilegeEscalation": false, "capabilities": { "drop": ["ALL"] }, "runAsNonRoot": true, "runAsUser": 65532 },
                        "resources": { "requests": { "cpu": "50m", "memory": "64Mi" }, "limits": { "memory": "256Mi" } },
                        "volumeMounts": [
                            { "name": "state", "mountPath": "/var/lib/updated" },
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
    pub(crate) provider_path: String,
    pub(crate) provider_sha: String,
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
/// `scripts/linux-haproxy-e2e.sh`) published with an `activate` script so the reload-in-place phase
/// runs. Each app release carries the real distro `haproxy` binary, a version-stamped `haproxy.cfg`,
/// and `scripts/haproxy/launch` as `bin/launch` (the first-launch entrypoint the guardian execs).
/// The two releases differ only in the version their config reports, so activating 2.0.0 is a pure
/// SIGUSR2 config re-exec of the same master.
pub(crate) fn publish_haproxy_bundles(
    seed_deployment: &serde_json::Value,
    platform: &str,
) -> Result<HaproxyRelease, Box<dyn std::error::Error>> {
    // 1. The provider set (activate-bearing, so the reload-in-place phase runs).
    let provider = output(Command::new("kubectl").args(RELEASE_SERVER_EXEC).args([
        "--",
        "sh",
        "-c",
        &format!(
            "set -e; export AWS_ACCESS_KEY_ID=minio AWS_SECRET_ACCESS_KEY=minio123; \
             rm -rf /tmp/hap-provider && mkdir -p /tmp/hap-provider/bin; \
             cp /usr/local/share/haproxy/lifecycle /tmp/hap-provider/bin/lifecycle; \
             cp /usr/local/share/haproxy/lib.sh /tmp/hap-provider/bin/lib.sh; \
             chmod 0755 /tmp/hap-provider/bin/lifecycle; \
             art=$(updatectl publish-provider-artifact --keys-dir /data/release-keys \
               --bucket updates --prefix releases --endpoint http://minio:9000 --region us-east-1 \
               --product haproxy-lifecycle --version 1.0.0 --entrypoint bin/lifecycle \
               --source /tmp/hap-provider --platform {platform}); \
             set -- $art; \
             set_out=$(updatectl publish-provider-set --keys-dir /data/release-keys \
               --bucket updates --prefix releases --endpoint http://minio:9000 --region us-east-1 \
               --id haproxy-lifecycle --provider-path \"$1\" --provider-sha256 \"$2\" \
               --provider-timeout-ms 15000); \
             printf 'set %s\\n' \"$(echo $set_out | awk '{{print $NF}}')\""
        ),
    ]))?;
    let provider_sha = provider
        .lines()
        .find_map(|line| line.strip_prefix("set ")?.split_whitespace().next())
        .ok_or("publish-provider-set printed no haproxy provider set sha")?
        .to_owned();
    let provider_path = "provider-sets/haproxy-lifecycle.json".to_owned();

    // 2. The two app releases, published to a throwaway seed group (unmatched selector, so no node
    //    adopts it) purely to read back each content-addressed path+sha. `updatectl deploy`
    //    publishes AND patches, so a seed group is how we publish without assigning a live cohort —
    //    the same pattern the sample-app baseline uses.
    let servers = backend_servers();
    let (v1_path, v1_sha) =
        publish_haproxy_app(seed_deployment, platform, DEMO_HAPROXY_V1, &servers)?;
    let (v2_path, v2_sha) =
        publish_haproxy_app(seed_deployment, platform, DEMO_HAPROXY_V2, &servers)?;
    Ok(HaproxyRelease {
        provider_path,
        provider_sha,
        v1_path,
        v1_sha,
        v2_path,
        v2_sha,
    })
}

/// Publish one version-stamped HAProxy app bundle and return its `(path, sha256)`.
fn publish_haproxy_app(
    seed_deployment: &serde_json::Value,
    platform: &str,
    version: &str,
    servers: &[BackendServer],
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let cfg = haproxy_cfg(version, servers);
    let seed = format!("haproxy-seed-{version}");
    apply_json(&serde_json::json!({
        "apiVersion": "updated.dev/v1alpha1",
        "kind": "UpdateGroup",
        "metadata": {"name": seed, "namespace": "updated-system"},
        "spec": {
            "repositoryRef": {"name": "default"},
            "selector": {"matchLabels": {"demo.updated.dev/cohort": "__haproxy-seed-unmatched__"}},
            // A full clone of edge's deployment (CRD-valid); `updatectl deploy` overwrites application.
            "deployment": seed_deployment
        }
    }))?;
    // Stage the bundle tree: the real distro haproxy binary + the launch entrypoint.
    run(Command::new("kubectl").args(RELEASE_SERVER_EXEC).args([
        "--",
        "sh",
        "-c",
        "set -e; rm -rf /tmp/hap-app && mkdir -p /tmp/hap-app/bin /tmp/hap-app/config; \
         hap=$(command -v haproxy || true); \
         for c in \"$hap\" /usr/sbin/haproxy /usr/bin/haproxy; do \
           if [ -x \"$c\" ]; then cp \"$c\" /tmp/hap-app/bin/haproxy; break; fi; done; \
         [ -x /tmp/hap-app/bin/haproxy ] || { echo 'haproxy binary not found in release-server image' >&2; exit 1; }; \
         chmod 0755 /tmp/hap-app/bin/haproxy; \
         cp /usr/local/share/haproxy/launch /tmp/hap-app/bin/launch; chmod 0755 /tmp/hap-app/bin/launch",
    ]))?;
    // Pipe the generated config in over stdin — no shell escaping of its quotes/braces/newlines.
    pipe_into_release_server("cat > /tmp/hap-app/config/haproxy.cfg", &cfg)?;
    run(Command::new("kubectl").args(RELEASE_SERVER_EXEC).args([
        "--",
        "sh",
        "-c",
        &format!(
            "set -e; export AWS_ACCESS_KEY_ID=minio AWS_SECRET_ACCESS_KEY=minio123; \
             updatectl deploy --keys-dir /data/release-keys --bucket updates --prefix releases \
             --endpoint http://minio:9000 --region us-east-1 --namespace updated-system \
             --group {seed} --product haproxy --channel stable --version {version} \
             --entrypoint bin/launch --platform {platform} --source /tmp/hap-app"
        ),
    ]))?;
    let path = kubectl_value("updategroup", &seed, "{.spec.deployment.application.path}")?;
    let sha = kubectl_value(
        "updategroup",
        &seed,
        "{.spec.deployment.application.sha256}",
    )?;
    run(Command::new("kubectl").args([
        "-n",
        "updated-system",
        "delete",
        "updategroup",
        &seed,
        "--ignore-not-found",
    ]))?;
    Ok((path.trim().to_owned(), sha.trim().to_owned()))
}

/// Run `sh -c "<command>"` in the release-server pod with `stdin` piped to it — the escaping-free
/// way to land arbitrary bytes (a generated config) inside the pod.
fn pipe_into_release_server(command: &str, stdin: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut child = Command::new("kubectl")
        .args([
            "-n",
            "updated-system",
            "exec",
            "-i",
            "deployment/release-server",
            "-c",
            "release-server",
            "--",
            "sh",
            "-c",
            command,
        ])
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

/// The MinIO release repository the HAProxy bundles live in, pinned to the MinIO root
/// `bootstrap_minio_release_repo` minted onto the shared release PVC.
fn minio_release_repository(release_root: &str) -> serde_json::Value {
    serde_json::json!({
        "metadataUrl": "http://minio:9000/updates/releases/metadata/",
        "targetsUrl": "http://minio:9000/updates/releases/targets/",
        "rootJson": release_root,
    })
}

/// The seed group's deployment: a full clone of the fully-valid `edge` deployment (so every
/// CRD-required field is present) with only its release repository pointed at MinIO. Its selector
/// matches nothing, so no node adopts it; `updatectl deploy` overwrites its `application` and the
/// published bundle's product/entrypoint come from the deploy flags, so the runtime here is unused.
fn seed_deployment(edge: &serde_json::Value, release_root: &str) -> serde_json::Value {
    let mut deployment = edge["spec"]["deployment"].clone();
    deployment["releaseRepository"] = minio_release_repository(release_root);
    deployment
}

/// The real `haproxy` UpdateGroup's deployment: clone `edge` (for CRD-field completeness), then
/// override everything that makes it a HAProxy node — the app bundle, the HAProxy lifecycle
/// provider set, the MinIO repo, the HAProxy product, an empty arg list (the launch entrypoint
/// takes none), the readiness health check on HAProxy's monitor-uri, and a fast cadence with a
/// short boot grace for HAProxy's few-second install.
fn haproxy_group_deployment(
    edge: &serde_json::Value,
    release_root: &str,
    release: &HaproxyRelease,
) -> serde_json::Value {
    let mut deployment = edge["spec"]["deployment"].clone();
    deployment["name"] = format!("{DEMO_HAPROXY_GROUP}@{DEMO_HAPROXY_V1}").into();
    deployment["application"] =
        serde_json::json!({"path": release.v1_path, "sha256": release.v1_sha});
    deployment["providerSet"] =
        serde_json::json!({"path": release.provider_path, "sha256": release.provider_sha});
    deployment["releaseRepository"] = minio_release_repository(release_root);
    deployment["reportUrl"] = DEMO_REPORT_URL.into();
    deployment["orderedInstallFallback"] = serde_json::json!(false);
    deployment["runtime"]["product"] = "haproxy".into();
    deployment["runtime"]["mode"] = "managed".into();
    deployment["runtime"]["installRoot"] = "/var/lib/updated/haproxy".into();
    deployment["runtime"]["args"] = serde_json::json!([]);
    deployment["runtime"]["timeouts"] = serde_json::json!({
        "checkIntervalSeconds": 1,
        "healthGraceSeconds": 12,
        "healthSuccesses": 1,
        "healthIntervalSeconds": 1,
        "retryAfterSeconds": 2,
        "refreshRetrySeconds": 1,
        "confirmationWindowSeconds": 3,
        "supervisorCheckIntervalSeconds": 3600
    });
    deployment
}

/// Bring up the whole HAProxy tier onto an already-provisioned demo cluster: the StatefulSet, the
/// published bundles, the `haproxy` UpdateGroup at 1.0.0 (annotated with the pre-published 2.0.0
/// target the e2e upgrade patches in), the HAProxy-mode healthproxy that programs backend
/// membership, and the front Service. Idempotent enough to re-run: applies are declarative.
pub(crate) async fn prepare_haproxy_tier(platform: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("[demo] deploying the updated-managed HAProxy tier ({DEMO_HAPROXY_REPLICAS} HAProxies fronting the external slice)");
    // Start the pods enrolling now; they install HAProxy while we publish the bundles below.
    apply_json(&haproxy_statefulset())?;
    // Clone the fully-valid `edge` deployment as the template for every HAProxy deployment spec, so
    // no CRD-required field is ever missing. The MinIO root is what the HAProxy bundles are pinned to.
    let edge: serde_json::Value = serde_json::from_str(&output(Command::new("kubectl").args([
        "-n",
        "updated-system",
        "get",
        "updategroup",
        "edge",
        "-o",
        "json",
    ]))?)?;
    let release_root = output(Command::new("kubectl").args(RELEASE_SERVER_EXEC).args([
        "--",
        "cat",
        "/data/release-keys/root.json",
    ]))?;
    let release = publish_haproxy_bundles(&seed_deployment(&edge, &release_root), platform)?;
    let base = haproxy_group_deployment(&edge, &release_root, &release);
    // One self-protecting group owns both HAProxy nodes. `maxUnavailable: 1` makes the control
    // plane publish the new assignment to one node at a time; no synthetic set/group split is
    // needed merely to obtain availability.
    apply_json(&serde_json::json!({
        "apiVersion": "updated.dev/v1alpha1",
        "kind": "UpdateGroup",
        "metadata": {
            "name": DEMO_HAPROXY_GROUP,
            "namespace": "updated-system",
            "annotations": {
                DEMO_HAPROXY_NEXT_PATH_ANNOTATION: &release.v2_path,
                DEMO_HAPROXY_NEXT_SHA_ANNOTATION: &release.v2_sha,
            }
        },
        "spec": {
            "repositoryRef": {"name": "default"},
            "selector": {"matchLabels": {"demo.updated.dev/cohort": DEMO_HAPROXY_COHORT}},
            "deployment": base,
            "maxUnavailable": 1
        }
    }))?;
    label_haproxy_agents()?;
    apply_haproxy_front_service()?;
    deploy_haproxy_healthproxy()?;
    println!("[demo] waiting for the HAProxy tier to install and become ready");
    run(Command::new("kubectl").args([
        "-n",
        "updated-system",
        "rollout",
        "status",
        "statefulset/haproxy",
        "--timeout=300s",
    ]))?;
    Ok(())
}

/// Label each HAProxy pod's enrolled `UpdateAgent` into the `haproxy` cohort the group selects.
/// Retries until the agent has registered (`patch_agent_labels` waits).
pub(crate) fn label_haproxy_agents() -> Result<(), Box<dyn std::error::Error>> {
    for ordinal in 0..DEMO_HAPROXY_REPLICAS {
        let node = format!("haproxy-{ordinal}");
        patch_agent_labels(
            &resource_name(&node),
            serde_json::json!({
                "demo.updated.dev/node": node,
                "demo.updated.dev/cohort": DEMO_HAPROXY_COHORT,
                "demo.updated.dev/kind": "haproxy"
            }),
        )?;
    }
    Ok(())
}

/// The ClusterIP front Service fanning traffic across the HAProxy pods. Selects the HAProxy pods
/// by their `kind=haproxy` label and only the ready ones (no `publishNotReadyAddresses`), so a
/// HAProxy pod that is re-execing/unready leaves the front until it is healthy again.
pub(crate) fn apply_haproxy_front_service() -> Result<(), Box<dyn std::error::Error>> {
    apply_json(&serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": DEMO_HAPROXY_FRONT_SERVICE, "namespace": "updated-system"},
        "spec": {
            "selector": {"app": "updated-agent", "demo.updated.dev/kind": "haproxy"},
            "ports": [{"name": "http", "port": 80, "targetPort": "http"}]
        }
    }))
}

/// Deploy a HAProxy-mode `updated-healthproxy`: it reads the backend nodes' signed CDN health and
/// programs each HAProxy's `fleet` backend membership over the admin runtime API
/// (`set server fleet/<node> state ready|drain`). Setting `HEALTHPROXY_HAPROXY_ENDPOINTS` is what
/// flips the binary from the EndpointSlice backend to the HAProxy backend; it needs no kube client,
/// hence no RBAC (unlike the EndpointSlice reconciler).
pub(crate) fn deploy_haproxy_healthproxy() -> Result<(), Box<dyn std::error::Error>> {
    let members = backend_servers()
        .into_iter()
        .map(|server| {
            // Append each node's pinned public key so the healthproxy verifies the signed report,
            // not merely its shape — the same key the control-plane throttle pins.
            let key = crate::setup::agent_pinned_public_key(&server.node)?;
            Ok(format!("{}={}={key}", server.node, server.address))
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?
        .join(",");
    let endpoints = (0..DEMO_HAPROXY_REPLICAS)
        .map(|ordinal| format!("haproxy-{ordinal}.agents:{}", DEMO_HAPROXY_ADMIN_PORT))
        .collect::<Vec<_>>()
        .join(",");
    apply_json(&serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "haproxy-healthproxy", "namespace": "updated-system"},
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"app": "haproxy-healthproxy"}},
            "template": {
                "metadata": {"labels": {"app": "haproxy-healthproxy"}},
                "spec": {
                    "containers": [{
                        "name": "healthproxy",
                        "image": "updatec-e2e:kind",
                        "imagePullPolicy": "Never",
                        "command": ["/usr/local/bin/updated-healthproxy"],
                        "env": [
                            {"name": "HEALTHPROXY_HEALTH_BASE", "value": DEMO_HEALTH_CDN},
                            {"name": "HEALTHPROXY_MEMBERS", "value": members},
                            {"name": "HEALTHPROXY_HAPROXY_ENDPOINTS", "value": endpoints},
                            {"name": "HEALTHPROXY_HAPROXY_BACKEND", "value": DEMO_HAPROXY_BACKEND}
                        ]
                    }]
                }
            }
        }
    }))?;
    run(Command::new("kubectl").args([
        "-n",
        "updated-system",
        "rollout",
        "status",
        "deployment/haproxy-healthproxy",
        "--timeout=120s",
    ]))
}

/// Drive the HAProxy tier through a 1.0.0 → 2.0.0 in-place upgrade while a synthetic client hits
/// the front Service continuously, and assert **zero-downtime**: the front stays available across
/// the whole re-exec (the two HAProxies roll one at a time, each SIGUSR2-re-execing its master with
/// no dropped connection), and both HAProxies durably report 2.0.0.
///
/// The upgrade is a pure group patch to the pre-published 2.0.0 target (read from the annotation
/// `prepare_haproxy_tier` stamped), so it is signed-store-driven, never a live publish. Convergence
/// is gated on the durable control-plane `reportedVersion`, never on transient probing.
pub(crate) async fn assert_haproxy_zero_downtime_upgrade() -> Result<(), Box<dyn std::error::Error>>
{
    println!("[demo] verifying the updated-managed HAProxy tier and its zero-downtime upgrade");
    // Both HAProxies must already be serving 1.0.0 before we start.
    wait_for_haproxy_version(DEMO_HAPROXY_V1, 240).await?;

    // Port-forward the front Service and confirm traffic proxies THROUGH HAProxy to a backend
    // service (a non-empty /version body) before we touch anything.
    let port = std::env::var("UPDATEC_DEMO_HAPROXY_PORT").unwrap_or_else(|_| "8099".into());
    let mut forward = Command::new("kubectl")
        .args([
            "-n",
            "updated-system",
            "port-forward",
            &format!("service/{DEMO_HAPROXY_FRONT_SERVICE}"),
            &format!("{port}:80"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    let result = drive_haproxy_upgrade(&port).await;
    let _ = forward.kill();
    result
}

async fn drive_haproxy_upgrade(port: &str) -> Result<(), Box<dyn std::error::Error>> {
    let front = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(800))
        .build()?;
    wait_for_front_serving(&client, &front).await?;
    println!(
        "[demo] HAProxy front is serving backend traffic; starting the load probe and upgrade"
    );

    // A continuous readiness-respecting probe against the front, exactly like the fleet's synthetic
    // load test: it records every outcome while the upgrade runs.
    let stop = Arc::new(AtomicBool::new(false));
    let total = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicU64::new(0));
    let probe = {
        let (stop, total, failed) = (stop.clone(), total.clone(), failed.clone());
        let client = client.clone();
        let url = format!("{front}/version");
        tokio::spawn(async move {
            while !stop.load(Ordering::Relaxed) {
                let ok = matches!(client.get(&url).send().await, Ok(r) if r.status().is_success());
                total.fetch_add(1, Ordering::Relaxed);
                if !ok {
                    failed.fetch_add(1, Ordering::Relaxed);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
    };

    // Upgrade the self-protecting group to the pre-published 2.0.0 target. Intra-group admission
    // publishes it to the two HAProxies one at a time. Bracket notation for the annotation key — and
    // kubectl's jsonpath still requires the DOTS escaped even inside the brackets, so
    // `demo.updated.dev/...` must be written `demo\.updated\.dev/...` or the selector returns empty.
    let path_key = DEMO_HAPROXY_NEXT_PATH_ANNOTATION.replace('.', "\\.");
    let sha_key = DEMO_HAPROXY_NEXT_SHA_ANNOTATION.replace('.', "\\.");
    let annotated = DEMO_HAPROXY_GROUP;
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
        stop.store(true, Ordering::Relaxed);
        let _ = probe.await;
        return Err("HAProxy group carries no pre-published 2.0.0 target annotation".into());
    }
    run(Command::new("kubectl").args([
        "-n",
        "updated-system",
        "patch",
        "updategroup",
        DEMO_HAPROXY_GROUP,
        "--type=merge",
        "-p",
        &serde_json::to_string(&serde_json::json!({"spec": {"deployment": {
            "name": format!("{DEMO_HAPROXY_GROUP}@{DEMO_HAPROXY_V2}"),
            "application": {"path": next_path, "sha256": next_sha}
        }}}))?,
    ]))?;

    // Gate convergence on the durable control-plane reportedVersion — never on the probe.
    let converged = wait_for_haproxy_version(DEMO_HAPROXY_V2, 240).await;
    // And confirm the running config actually re-execed (the front now reports 2.0.0).
    let reexeced = converged.is_ok()
        && wait_for_front_version(&client, &front, DEMO_HAPROXY_V2)
            .await
            .is_ok();

    // Let the probe run past convergence and collect a window large enough to measure the stated
    // SLA. At 99.5%, fewer than 200 observations cannot tolerate even one transient failure, which
    // turns an otherwise identical upgrade into a pass or failure based only on how quickly it
    // converged. Keep the wall-clock bound so a wedged probe still fails promptly below.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let sample_deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while total.load(Ordering::Relaxed) < 200 && tokio::time::Instant::now() < sample_deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    stop.store(true, Ordering::Relaxed);
    let _ = probe.await;
    converged?;
    if !reexeced {
        return Err(
            "HAProxy converged to 2.0.0 but the front never reported the re-execed version".into(),
        );
    }

    let total = total.load(Ordering::Relaxed);
    let failed = failed.load(Ordering::Relaxed);
    let availability = if total == 0 {
        0.0
    } else {
        (total - failed) as f64 / total as f64 * 100.0
    };
    // The SLA line the whole demo holds the fleet to. A correct SIGUSR2 re-exec (and rolling the two
    // HAProxies one at a time) drops no connection, so availability stays pinned here; a botched
    // upgrade that dropped the front would tank it far below. A tiny tolerance absorbs port-forward
    // reconnect blips (the probe crosses the host↔cluster boundary), not a real outage.
    if total < 200 {
        return Err(format!(
            "HAProxy load probe recorded too few samples ({total}) to judge availability"
        )
        .into());
    }
    if availability < DEMO_SLA_TARGET {
        return Err(format!(
            "HAProxy upgrade dropped traffic: {failed}/{total} requests failed ({availability:.2}% available, SLA {DEMO_SLA_TARGET}%)"
        )
        .into());
    }
    println!(
        "HAPROXY PASS: {DEMO_HAPROXY_REPLICAS} updated-managed HAProxies upgraded {DEMO_HAPROXY_V1}\u{2192}{DEMO_HAPROXY_V2} in place with {availability:.2}% front availability ({failed}/{total} failed) across the SIGUSR2 re-exec"
    );
    Ok(())
}

/// Wait until every HAProxy node's `UpdateAgent` durably reports `version`.
async fn wait_for_haproxy_version(
    version: &str,
    attempts: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let nodes: Vec<String> = (0..DEMO_HAPROXY_REPLICAS)
        .map(|ordinal| resource_name(&format!("haproxy-{ordinal}")))
        .collect();
    for _ in 0..attempts {
        let converged = nodes.iter().all(|node| {
            kubectl_value("updateagent", node, "{.status.reportedVersion}")
                .map(|v| v.trim() == version)
                .unwrap_or(false)
        });
        if converged {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    Err(format!("HAProxy tier never converged to {version}").into())
}

/// Wait until the front Service proxies a non-empty `/version` body from a backend service.
async fn wait_for_front_serving(
    client: &reqwest::Client,
    front: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{front}/version");
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        if let Ok(response) = client.get(&url).send().await {
            if response.status().is_success() {
                if let Ok(body) = response.text().await {
                    if !body.trim().is_empty() {
                        return Ok(());
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    Err("HAProxy front never proxied a backend /version response".into())
}

/// Wait until the front's `/haproxy-version` reports `version` — proof the in-place re-exec swapped
/// the running configuration, not just the control-plane record.
async fn wait_for_front_version(
    client: &reqwest::Client,
    front: &str,
    version: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let url = format!("{front}/haproxy-version");
    let want = format!("haproxy {version}");
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        if let Ok(response) = client.get(&url).send().await {
            if let Ok(body) = response.text().await {
                if body.trim() == want {
                    return Ok(());
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    Err(format!("HAProxy front never reported the re-execed version {version}").into())
}
