#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Fail with the tool's name rather than mid-provision inside a command substitution,
# where `set -euo pipefail` kills the run with no diagnostic. The digest tool is
# coreutils `sha256sum` here and in every container job below — one spelling only.
for command in kind kubectl helm docker curl openssl awk sha256sum cargo; do
  command -v "$command" >/dev/null || { echo "FAIL: missing required command: $command" >&2; exit 2; }
done
# shellcheck source=scripts/lib/publish-fuzz-plan.sh
. "$ROOT/scripts/lib/publish-fuzz-plan.sh"
FUZZ_ROUNDS=${UPDATEC_FUZZ_ROUNDS:-1}
PRESERVE_REPOSITORY=false
# Kubernetes, its ingress implementation, and their manifests are one tested platform tuple. Pin
# all three inputs: Kind's moving default silently advanced this fixture from Kubernetes 1.30 to
# 1.35 while the old controller only supported 1.30. The URLs are immutable release artifacts and
# every downloaded byte is verified before kubectl sees it.
KIND_NODE_IMAGE='kindest/node:v1.35.0@sha256:452d707d4862f52530247495d180205e029056831160e22870e37e3f6c1ac31f'
INGRESS_MANIFEST_URL='https://raw.githubusercontent.com/kubernetes/ingress-nginx/0a5901f3c64f11e92e487799b8da3f00cca37515/deploy/static/provider/kind/deploy.yaml'
INGRESS_MANIFEST_SHA256='2a3ae008c8786431115502644e77ab398fdebfb721a5d1195ed3089cde3299df'
CERT_MANAGER_MANIFEST_URL='https://github.com/cert-manager/cert-manager/releases/download/v1.21.1/cert-manager.yaml'
CERT_MANAGER_MANIFEST_SHA256='5f6a499b8c1857d57f560f536e0dcc830914b45c420899fe7ad0692c8624e408'
# Managed repository object keys have one controller-owned namespace/name scope. Keep the fixture's
# direct MinIO probes on that same identity; the Rust e2e asserts this value against the production
# prefix constructor.
MANAGED_REPOSITORY_PREFIX="routing/updated-system/default"
while (( $# > 0 )); do
  case "$1" in
    --fuzz-rounds)
      [[ $# -ge 2 ]] || { echo "FAIL: --fuzz-rounds needs a value" >&2; exit 2; }
      FUZZ_ROUNDS=$2
      shift 2
      ;;
    --preserve-repository)
      PRESERVE_REPOSITORY=true
      shift
      ;;
    --help|-h)
      echo "usage: $0 [--fuzz-rounds N] [--preserve-repository]"
      echo "  N=0 skips fleet fuzz; default: ${UPDATEC_FUZZ_ROUNDS:-1}"
      echo "  --preserve-repository leaves the converged fixture available to the fleet E2E"
      exit 0
      ;;
    *)
      echo "FAIL: unknown argument $1" >&2
      exit 2
      ;;
  esac
done
[[ "$FUZZ_ROUNDS" =~ ^[0-9]+$ ]] || {
  echo "FAIL: fuzz rounds must be a non-negative integer, got '$FUZZ_ROUNDS'" >&2
  exit 2
}
echo "Kind E2E fleet-fuzz rounds: $FUZZ_ROUNDS"

# ---------------------------- timing, decided once ----------------------------
#
# Every wait in this suite bounds one of three facts. Each fact gets one number here, and every
# call site derives from it, because the alternative is what this script used to do: the same
# deployment given 180s in one place and 120s in another, and a verifier whose own retry budget
# (90s per agent, five agents) sat above the job deadline (120s) that killed it — so the retry
# count past the first agent was configuration that could never run, and the failure arrived as an
# opaque DeadlineExceeded with the pod deleted and the diagnostic gone.
#
# They are deliberately generous. A wait that is too short does not catch a bug; it invents a flake.

# A cluster dependency (deployment, statefulset, pod, certificate) becomes ready.
READY_TIMEOUT=${UPDATEC_READY_TIMEOUT:-240}
# The fleet reaches an exact desired state. Spent by the in-cluster verifier itself.
FLEET_CONVERGE_SECONDS=${UPDATEC_FLEET_CONVERGE_SECONDS:-240}
# How far a Job's own deadline sits ABOVE the budget its script spends, and how far the outer
# `kubectl wait` sits above that deadline. This ordering is the point: the script must be what
# fails, because it is the only layer that can say which agent was behind and on what version.
JOB_SLACK=60
WAIT_SLACK=10

# A node reacts to a local event: a relaunch, a workload crash, a certificate rotation, a durable
# rejection. Four host-side loops each expressed this as a retry COUNT times a sleep interval —
# 90x1s, 30x1s, 90x2s, 90x2s — so the bound each one actually enforced (90s, 30s, 180s, 180s) was
# nowhere written down and no two agreed.
NODE_SETTLE_TIMEOUT=${UPDATEC_NODE_SETTLE_TIMEOUT:-180}
# A one-shot Job: start a pod, make a single request, exit. No retry loop to bound, so this is the
# whole budget.
ONESHOT_JOB_SECONDS=${UPDATEC_ONESHOT_JOB_SECONDS:-30}

# Poll `$2...` once a second until it succeeds or $1 seconds pass. Non-zero on timeout; the caller
# reports the failure, because only the caller knows what it was waiting for.
poll_until() {
  local budget="$1"
  shift
  local deadline=$(( $(date +%s) + budget ))
  while :; do
    if "$@"; then
      return 0
    fi
    if [[ "$(date +%s)" -ge "$deadline" ]]; then
      return 1
    fi
    sleep 1
  done
}

# The deadline for a Job whose script is bounded by $1 seconds.
job_deadline() { echo $(( $1 + JOB_SLACK )); }

# Await a Job whose script is bounded by $2 seconds, dumping its logs if it does not complete.
await_job() {
  local job="$1" budget="$2"
  if ! kubectl -n updated-system wait --for=condition=complete "job/$job" \
    --timeout=$(( budget + JOB_SLACK + WAIT_SLACK ))s; then
    kubectl -n updated-system logs "job/$job" >&2 || true
    return 1
  fi
}

NAME="${UPDATEC_KIND_CLUSTER:-updatec-e2e}"
# These values become destructive-operation names and literal YAML scalars below. Validate them
# before the first `kind delete` or `rm -rf`: quoting prevents shell expansion, but it does not stop
# `../` path traversal in `$WORK` or a newline from changing the generated Kind document.
[[ ${#NAME} -le 63 && "$NAME" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || {
  echo "FAIL: UPDATEC_KIND_CLUSTER must be a lowercase DNS label, got '$NAME'" >&2
  exit 2
}
# The host ports nginx is published on. Overridable so two clusters built from this script can
# coexist on one machine (the default 80/443 pair is a host-wide singleton): a second run sets
# UPDATEC_KIND_HTTP_PORT/UPDATEC_KIND_HTTPS_PORT (and UPDATEC_KIND_CLUSTER) and shares nothing.
HTTP_PORT="${UPDATEC_KIND_HTTP_PORT:-80}"
HTTPS_PORT="${UPDATEC_KIND_HTTPS_PORT:-443}"
for port in "$HTTP_PORT" "$HTTPS_PORT"; do
  if [[ ${#port} -gt 5 || ! "$port" =~ ^[0-9]+$ ]]; then
    echo "FAIL: Kind host ports must be integers from 1 through 65535, got '$port'" >&2
    exit 2
  fi
  if (( 10#$port < 1 || 10#$port > 65535 )); then
    echo "FAIL: Kind host ports must be integers from 1 through 65535, got '$port'" >&2
    exit 2
  fi
done
[[ "$HTTP_PORT" != "$HTTPS_PORT" ]] || {
  echo "FAIL: Kind HTTP and HTTPS host ports must differ" >&2
  exit 2
}
KUBE_CONTEXT="kind-$NAME"
# Never depend on kubectl's process-global current context. The fleet e2e, CI, and a
# developer's separate Kind run may execute concurrently; pinning every operation is
# the only way namespace creation and all later resources remain in the same cluster.
kubectl() { command kubectl --context "$KUBE_CONTEXT" "$@"; }
WORK="$ROOT/target/kind-$NAME"
cleanup() { kind delete cluster --name "$NAME" >/dev/null 2>&1 || true; }
finish() {
  local status=$?
  if (( status == 0 )) && [[ "${UPDATEC_KEEP_KIND_CLUSTER:-0}" != 1 ]]; then
    cleanup
    # The work tree contains extracted fleet-CA and node private keys. Keep it with a failed or
    # explicitly preserved cluster for diagnosis, but never retain credentials after a normal run.
    rm -rf "$WORK"
    return
  fi
  echo >&2
  if (( status == 0 )); then
    echo "Kind E2E succeeded; preserving cluster '$NAME' because UPDATEC_KEEP_KIND_CLUSTER=1" >&2
  else
    echo "Kind E2E failed (exit $status); preserving cluster '$NAME' for diagnosis" >&2
    "$ROOT/scripts/kind-diagnostics.sh" || true
  fi
  echo "inspect with: kubectl -n updated-system get pods,jobs" >&2
  echo "agent logs:   kubectl -n updated-system logs agent-4" >&2
  echo "remove with:  kind delete cluster --name $NAME" >&2
}
kubectl_log_contains() {
  local resource=$1
  local needle=$2
  local log
  shift 2
  # Capture before matching: `grep -q` closes a live pipe after the first match,
  # which can SIGPIPE kubectl and falsely fail under `set -o pipefail`.
  log="$(kubectl -n updated-system logs "$resource" "$@" 2>/dev/null || true)"
  [[ "$log" == *"$needle"* ]]
}
apply_verified_manifest() {
  local name=$1
  local url=$2
  local expected_sha256=$3
  local manifest="$WORK/$name.yaml"
  local actual_sha256

  curl --fail --location --silent --show-error --output "$manifest" "$url"
  actual_sha256="$(openssl dgst -sha256 "$manifest" | awk '{print $NF}')"
  [[ "$actual_sha256" == "$expected_sha256" ]] || {
    echo "FAIL: $name manifest digest is $actual_sha256, expected $expected_sha256" >&2
    exit 1
  }
  kubectl apply -f "$manifest"
}
trap finish EXIT
cleanup
# The run provisions everything from scratch, so its working directory starts empty too: keys,
# CA material and rendered manifests left by a previous run are not inputs to this one, and
# `server init` fails closed rather than reuse a signing key it finds already there.
rm -rf "$WORK"
mkdir -p "$WORK"

cat >"$WORK/kind.yaml" <<YAML
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    image: $KIND_NODE_IMAGE
    # Publish the ingress controller on the host's ports, so both the browser AND the
    # co-located out-of-cluster agent reach every endpoint through nginx — the agent resolves
    # updatec-gateway/release-default to 127.0.0.1 (nginx), no socat or LAN-IP needed.
    extraPortMappings:
      - { containerPort: 80, hostPort: $HTTP_PORT, protocol: TCP }
      - { containerPort: 443, hostPort: $HTTPS_PORT, protocol: TCP }
    kubeadmConfigPatches:
      - |
        kind: KubeletConfiguration
        apiVersion: kubelet.config.k8s.io/v1beta1
        maxPods: 250
YAML
kind create cluster --name "$NAME" --config "$WORK/kind.yaml"
# The CRDs the CHART ships, not a fresh generation from the Rust types. An operator installing this
# product has no Rust toolchain, so what they apply is this file — and this is the run that proves
# the file works. CI separately fails the build if it has drifted from the types.
kubectl apply -f "$ROOT/deploy/charts/updatec/crds/"
kubectl create namespace updated-system

kubectl -n updated-system create deployment minio --image=minio/minio:RELEASE.2025-04-22T22-12-26Z
kubectl -n updated-system patch deployment minio --type=json -p='[{"op":"add","path":"/spec/template/spec/containers/0/args","value":["server","/data"]}]'
kubectl -n updated-system set env deployment/minio MINIO_ROOT_USER=minio MINIO_ROOT_PASSWORD=minio123
kubectl -n updated-system expose deployment minio --port=9000
kubectl -n updated-system rollout status deployment/minio --timeout=${READY_TIMEOUT}s
kubectl -n updated-system run minio-init --restart=Never --image=minio/mc:RELEASE.2025-04-16T18-13-26Z --command -- sh -c \
  "until mc alias set local http://minio:9000 minio minio123; do sleep 1; done; mc mb --ignore-existing local/updates; mc anonymous set download local/updates/releases; mc anonymous set download local/updates/${MANAGED_REPOSITORY_PREFIX}/telemetry"
# Deliberately one second, and deliberately not a readiness bound: this is a best-effort nudge that
# lets the pod leave Pending before the Succeeded wait below, which is the one that actually bounds.
kubectl -n updated-system wait pod/minio-init --for=condition=Ready=false --timeout=1s >/dev/null 2>&1 || true
kubectl -n updated-system wait pod/minio-init --for=jsonpath='{.status.phase}'=Succeeded --timeout=${READY_TIMEOUT}s

# Ingress controller: cluster infrastructure, provisioned here alongside minio so every
# environment built from this script is ingress-capable. The fleet e2e fronts each set's
# load-balancer Service with a per-set Ingress on this controller, so Kubernetes — not the
# driver's own routing — guarantees a set is only ever answered by its own pods. Scheduled
# onto the Linux control-plane node. Controller 1.15.1 is the ingress-nginx release tested against
# Kubernetes 1.35; the manifest itself pins both controller images by digest.
apply_verified_manifest ingress-nginx "$INGRESS_MANIFEST_URL" "$INGRESS_MANIFEST_SHA256"
kubectl -n ingress-nginx rollout status deployment/ingress-nginx-controller --timeout=${READY_TIMEOUT}s

# cert-manager itself — the controller only. The fleet's mTLS material (a self-signed root CA, the
# gateway's server certificate, and the agents' client certificate, all from that one CA) is
# declared by the chart below, not here. The gateway, the only externally exposed listener,
# requires a client cert that CA signed: that mutual TLS is the enrollment identity, so there is no
# shared secret anywhere.
# cert-manager 1.21 is tested on Kubernetes 1.35. The old 1.15 fixture was EOL and only supported
# through Kubernetes 1.32, so leaving it in place would merely move this same drift failure later.
apply_verified_manifest cert-manager "$CERT_MANAGER_MANIFEST_URL" "$CERT_MANAGER_MANIFEST_SHA256"
kubectl -n cert-manager rollout status deployment/cert-manager-webhook --timeout=${READY_TIMEOUT}s
kubectl -n cert-manager rollout status deployment/cert-manager --timeout=${READY_TIMEOUT}s
kubectl -n cert-manager rollout status deployment/cert-manager-cainjector --timeout=${READY_TIMEOUT}s
# Build and side-load the operator image BEFORE the chart installs, so the control plane starts on
# the image this commit produced rather than backing off against a registry that has never heard
# of `updatec:kind`.
docker build -f crates/updatec/Dockerfile -t updatec:kind .
kind load docker-image --name "$NAME" updatec:kind

# The control plane goes in through the SHIPPED HELM CHART — the same one-command install an
# operator runs — not through a hand-maintained manifest that could drift from what we publish.
# `certManager.enabled` makes the chart issue the fleet root, the gateway's server certificate, and
# the shared bootstrap client certificate, which is the whole mTLS identity: no shared secret.
#
# `publicUrl` is set here, at install, rather than patched in afterwards. The controller mints it
# into IMMUTABLE signed enrollment bundles, so a reconcile that ran on a placeholder would wedge
# that node's first boot in a way no later edit repairs.
# The fixture repository uses one static S3 credential Secret, so the externally exposed gateway
# receives the chart's exact-name read for that Secret and no namespace-wide Secret authority.
helm upgrade --install updatec "$ROOT/deploy/charts/updatec" \
  --kube-context "$KUBE_CONTEXT" \
  --namespace updated-system \
  --set image.repository=updatec \
  --set image.tag=kind \
  --set image.pullPolicy=Never \
  --set healthproxy.image.repository=updatec-e2e \
  --set healthproxy.image.tag=kind \
  --set healthproxy.image.pullPolicy=Never \
  --set controller.metrics.enabled=true \
  --set 'gateway.secretResourceNames={s3-credentials}' \
  --set publicUrl=https://updatec-gateway \
  --set certManager.enabled=true \
  --set certManager.agentCertificate.create=true \
  --set 'certManager.gatewayCertificate.dnsNames={release-default,release-edge,release-batch,localhost}'
# Deliberately no `--wait`: the gateway opens liveness immediately but keeps readiness closed until
# its UpdateRepository exists, and that resource is applied further down. Readiness is asserted
# below after the repository is in place; waiting here would time out on a control plane that is
# behaving exactly as designed.

cat <<'YAML' | kubectl apply -f -
# An intruder identity issued by the chart's self-signed bootstrap issuer DIRECTLY (never the fleet
# CA), so the gateway rejects it — proving the mTLS gate fails closed for a non-fleet client. This
# one is a test fixture, so it is the one certificate the chart has no business creating.
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: intruder-tls, namespace: updated-system}
spec:
  secretName: intruder-tls
  commonName: intruder
  usages: [client auth]
  issuerRef: {name: updatec-selfsigned, kind: Issuer}
YAML
kubectl -n updated-system wait --for=condition=Ready certificate/gateway-tls --timeout=${READY_TIMEOUT}s
kubectl -n updated-system wait --for=condition=Ready certificate/agent-tls --timeout=${READY_TIMEOUT}s
kubectl -n updated-system wait --for=condition=Ready certificate/intruder-tls --timeout=${READY_TIMEOUT}s

# Direct artifact downloads leave the mTLS gateway only after authorization, then land on this
# TLS-terminating MinIO load balancer. The public signing name is a namespace-local ExternalName
# for ingress-nginx: every agent resolves one stable address, nginx balances the MinIO Service,
# and MinIO receives the original host/path/query needed to verify AWS SigV4. Its leaf chains to
# the same CA agents already pin for the gateway, so the redirect never weakens transport security.
cat <<'YAML' | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: minio-direct-tls, namespace: updated-system}
spec:
  secretName: minio-direct-tls
  dnsNames: [minio-direct.updated-system.svc]
  usages: [server auth]
  issuerRef: {name: updatec-ca-issuer, kind: Issuer}
---
apiVersion: v1
kind: Service
metadata: {name: minio-direct, namespace: updated-system}
spec:
  type: ExternalName
  # ExternalName is a DNS CNAME target, not a Service reference. Keep it absolute so CoreDNS does
  # not return a namespace-relative CNAME that libc cannot resolve from another namespace.
  externalName: ingress-nginx-controller.ingress-nginx.svc.cluster.local
  ports: [{name: https, port: 443, targetPort: 443}]
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: minio-direct
  namespace: updated-system
  annotations:
    nginx.ingress.kubernetes.io/proxy-body-size: "0"
    nginx.ingress.kubernetes.io/proxy-buffering: "off"
spec:
  ingressClassName: nginx
  tls:
    - hosts: [minio-direct.updated-system.svc]
      secretName: minio-direct-tls
  rules:
    - host: minio-direct.updated-system.svc
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service: {name: minio, port: {number: 9000}}
YAML
kubectl -n updated-system wait --for=condition=Ready certificate/minio-direct-tls --timeout=${READY_TIMEOUT}s

# The fleet CA's own key, used exactly where an operator's out-of-band provisioning would use it:
# to issue a node's steady-state leaf without the gateway. One issuing function, so the offline
# node's preplaced identity and the rotation test's short-lived replacement cannot describe the
# node differently — a node's identity is `CN=<agent>` plus its SPIFFE node SAN, and nothing else.
FLEET_CA="$WORK/fleet-ca"
mkdir -p "$FLEET_CA"
kubectl -n updated-system get secret fleet-ca -o jsonpath='{.data.tls\.crt}' \
  | openssl base64 -d -A >"$FLEET_CA/ca.crt"
kubectl -n updated-system get secret fleet-ca -o jsonpath='{.data.tls\.key}' \
  | openssl base64 -d -A >"$FLEET_CA/ca.key"
sign_node_leaf() {
  local name=$1 key=$2 out=$3 days=$4
  openssl req -new -key "$key" -subj "/CN=$name" -out "$out.csr"
  cat >"$out.cnf" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=URI:spiffe://updated.fleet/scope/default/node/$name
EOF
  openssl x509 -req -in "$out.csr" -CA "$FLEET_CA/ca.crt" -CAkey "$FLEET_CA/ca.key" \
    -CAcreateserial -days "$days" -extfile "$out.cnf" -out "$out"
}

# Every repository read uses a live, key-pinned UpdateAgent. Keep one manually provisioned inventory
# probe for transport assertions that are not tied to a running agent: using either the shared
# bootstrap certificate or an unregistered fleet leaf here would create a second authorization path
# that production deliberately does not have.
ROUTING_PROBE="$WORK/routing-probe"
mkdir -p "$ROUTING_PROBE"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out "$ROUTING_PROBE/tls.key" 2>/dev/null
ROUTING_PROBE_PUBLIC_KEY="$(cargo run -q -p updatectl -- node-public-key \
  --key "$ROUTING_PROBE/tls.key")"
sign_node_leaf kind-routing-probe \
  "$ROUTING_PROBE/tls.key" "$ROUTING_PROBE/tls.crt" 1
kubectl -n updated-system create secret generic routing-probe-tls \
  --from-file=tls.crt="$ROUTING_PROBE/tls.crt" \
  --from-file=tls.key="$ROUTING_PROBE/tls.key" \
  --from-file=ca.crt="$FLEET_CA/ca.crt"

docker build -f crates/updatec/Dockerfile.e2e -t updatec-e2e:kind .
kind load docker-image --name "$NAME" updatec-e2e:kind
cat <<'YAML' | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: release-repository, namespace: updated-system}
spec:
  accessModes: [ReadWriteOnce]
  resources: {requests: {storage: 4Gi}}
---
apiVersion: apps/v1
kind: Deployment
metadata: {name: release-server, namespace: updated-system}
spec:
  replicas: 1
  selector: {matchLabels: {app: release-server}}
  template:
    metadata: {labels: {app: release-server}}
    spec:
      securityContext: {fsGroup: 65532}
      containers:
        - name: release-server
          image: updatec-e2e:kind
          command: [/usr/local/bin/release-server]
          ports: [{name: https, containerPort: 8080}]
          volumeMounts:
            - {name: repository, mountPath: /data}
            # Reuse the fleet server leaf as this fixture's HTTPS identity. The release origin is
            # anonymous and never requests a client certificate; only the gateway uses the CA to
            # authenticate nodes.
            - {name: gateway-tls, mountPath: /etc/gateway-tls, readOnly: true}
      volumes:
        - name: repository
          persistentVolumeClaim: {claimName: release-repository}
        - name: gateway-tls
          secret: {secretName: gateway-tls}
---
apiVersion: v1
kind: Service
metadata: {name: release-server, namespace: updated-system}
spec:
  selector: {app: release-server}
  ports: [{name: https, port: 443, targetPort: https}]
---
apiVersion: v1
kind: Service
metadata: {name: release-edge, namespace: updated-system}
spec:
  selector: {app: release-server}
  ports: [{name: https, port: 443, targetPort: https}]
---
apiVersion: v1
kind: Service
metadata: {name: release-batch, namespace: updated-system}
spec:
  selector: {app: release-server}
  ports: [{name: https, port: 443, targetPort: https}]
---
apiVersion: v1
kind: Service
metadata: {name: release-default, namespace: updated-system}
spec:
  selector: {app: release-server}
  ports: [{name: https, port: 443, targetPort: https}]
YAML
kubectl -n updated-system rollout status deployment/release-server --timeout=${READY_TIMEOUT}s
echo "waiting for the in-cluster release repository"
for attempt in {1..60}; do
  if kubectl -n updated-system exec deployment/release-server -c release-server -- \
    test -f /data/ready 2>/dev/null; then break; fi
  if (( attempt % 5 == 0 )); then
    echo "still waiting for release publication (${attempt}/60)"
    kubectl -n updated-system logs deployment/release-server --tail=5 || true
  fi
  sleep 2
done
if ! kubectl -n updated-system exec deployment/release-server -c release-server -- \
  test -f /data/ready 2>/dev/null; then
  echo "FAIL: release repository did not finish publishing within 120s" >&2
  kubectl -n updated-system get pods -l app=release-server >&2 || true
  kubectl -n updated-system logs deployment/release-server -c release-server --tail=100 >&2 || true
  exit 1
fi
echo "release repository published versions 1.0.0 through 20.0.0"
kubectl -n updated-system exec deployment/release-server -c release-server -- \
  cat /data/repository/metadata/root.json >"$WORK/release-root.json"
PLATFORM="$(kubectl -n updated-system exec deployment/release-server -c release-server -- \
  cat /data/platform)"
echo "release repository platform: $PLATFORM"
app_sha() {
  kubectl -n updated-system exec deployment/release-server -c release-server -- server target-sha256 \
    --repo /data/repository --name "products/app/stable/$1/$PLATFORM/app"
}
APP_V1_SHA="$(app_sha 1.0.0)"
APP_V2_SHA="$(app_sha 2.0.0)"
APP_V3_SHA="$(app_sha 3.0.0)"
PROVIDER_SHA="$(kubectl -n updated-system exec deployment/release-server -c release-server -- server target-sha256 \
  --repo /data/repository --name provider-sets/default.json)"

cargo run -q -p server -- init --repo "$WORK/seed-repo" --keys "$WORK/keys"
kubectl -n updated-system create secret generic tuf-signing-keys \
  --from-file="$WORK/keys/root.pk8" --from-file="$WORK/keys/root.next.pk8" \
  --from-file="$WORK/keys/targets.pk8" --from-file="$WORK/keys/snapshot.pk8" \
  --from-file="$WORK/keys/timestamp.pk8"
kubectl -n updated-system create secret generic s3-credentials --from-literal=AWS_ACCESS_KEY_ID=minio --from-literal=AWS_SECRET_ACCESS_KEY=minio123

cargo run -q -p updatec-e2e -- resources \
  "$PLATFORM" "$APP_V1_SHA" "$APP_V2_SHA" "$APP_V3_SHA" "$PROVIDER_SHA" \
  "$WORK/release-root.json" >"$WORK/resources.yaml"
kubectl apply -f "$WORK/resources.yaml"
cat <<YAML | kubectl apply -f -
apiVersion: updated.dev/v1alpha1
kind: UpdateAgent
metadata: {name: kind-routing-probe, namespace: updated-system}
spec:
  repositoryRef: {name: default}
  identity: {kind: manual, publicKey: "$ROUTING_PROBE_PUBLIC_KEY"}
  labels: {}
YAML

# The control plane was installed from the chart before cert-manager's material was minted; its
# UpdateRepository now exists, so the gateway can finish opening its listeners and both workloads
# become ready.
kubectl -n updated-system rollout status deployment/updatec-controller --timeout=${READY_TIMEOUT}s
kubectl -n updated-system rollout status deployment/updatec-gateway --timeout=${READY_TIMEOUT}s

# Exercise the gateway's field boundary at the API server, independently of the honest gateway
# process. The service account can CREATE UpdateAgents by RBAC, so only the fail-closed validating
# policy prevents a compromised internet-facing pod from creating held/cordoned inventory or
# enrolling into another repository. First prove the forbidden shape is denied, then prove the one
# intended create shape remains usable (the later five-node enrollment proves reserved UPDATE).
GATEWAY_USER=system:serviceaccount:updated-system:updatec-gateway
if kubectl -n updated-system --as="$GATEWAY_USER" create -f - <<'YAML'
apiVersion: updated.dev/v1alpha1
kind: UpdateAgent
metadata: {name: forbidden-gateway-agent}
spec:
  repositoryRef: {name: default}
  identity:
    kind: enrolled
    registrationSha256: "0000000000000000000000000000000000000000000000000000000000000000"
    publicKey: "0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  labels: {}
  hold: true
  cordon: false
YAML
then
  echo "FAIL: gateway service account created a held UpdateAgent through the admission boundary" >&2
  exit 1
fi
if kubectl -n updated-system --as="$GATEWAY_USER" create -f - <<'YAML'
apiVersion: updated.dev/v1alpha1
kind: UpdateAgent
metadata: {name: forbidden-gateway-label}
spec:
  repositoryRef: {name: default}
  identity:
    kind: enrolled
    registrationSha256: "0000000000000000000000000000000000000000000000000000000000000000"
    publicKey: "0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  labels: {updated.dev/role: edge}
  hold: false
  cordon: false
YAML
then
  echo "FAIL: gateway service account bypassed the repository's operator-owned enrollment labels" >&2
  exit 1
fi
if kubectl -n updated-system --as="$GATEWAY_USER" create -f - <<'YAML'
apiVersion: updated.dev/v1alpha1
kind: UpdateAgent
metadata:
  name: forbidden-gateway-metadata
  annotations: {attacker.example/persist: "true"}
spec:
  repositoryRef: {name: default}
  identity:
    kind: enrolled
    registrationSha256: "0000000000000000000000000000000000000000000000000000000000000000"
    publicKey: "0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  labels: {}
  hold: false
  cordon: false
YAML
then
  echo "FAIL: gateway service account added user-controlled metadata to an UpdateAgent" >&2
  exit 1
fi
kubectl -n updated-system --as="$GATEWAY_USER" create -f - <<'YAML'
apiVersion: updated.dev/v1alpha1
kind: UpdateAgent
metadata: {name: gateway-admission-probe}
spec:
  repositoryRef: {name: default}
  identity:
    kind: enrolled
    registrationSha256: "0000000000000000000000000000000000000000000000000000000000000000"
    publicKey: "0400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  labels: {}
  hold: false
  cordon: false
YAML
kubectl -n updated-system delete updateagent gateway-admission-probe --wait=true
echo "gateway UpdateAgent admission denies unsafe fields and admits only the enrollment shape"

# The deletion finalizer is allowed to prune only the storage scope the object was created to own.
# Prove the generated CRD refuses physical-coordinate retargets before one can turn deletion into
# an attacker-selected object-store delete. Prefix is not part of the managed-repository API.
if kubectl -n updated-system patch updaterepository default --type=merge \
  -p='{"spec":{"s3":{"bucket":"another-bucket"}}}'; then
  echo "FAIL: UpdateRepository storage bucket was mutable" >&2
  exit 1
fi
if kubectl -n updated-system patch updaterepository default --type=merge \
  -p='{"spec":{"s3":{"endpoint":"https://another-store.example"}}}'; then
  echo "FAIL: UpdateRepository storage endpoint was mutable" >&2
  exit 1
fi
if kubectl -n updated-system patch updaterepository default --type=merge \
  -p='{"spec":{"s3":{"credentialsSecretRef":{"name":"another-identity"}}}}'; then
  echo "FAIL: UpdateRepository storage credential identity was mutable" >&2
  exit 1
fi
echo "UpdateRepository storage coordinates are write-once at the API server"

echo "waiting for updatec to publish the first complete routing generation"
for attempt in {1..60}; do
  if kubectl_log_contains deployment/updatec-controller 'desired state reconciled'; then break; fi
  if (( attempt % 5 == 0 )); then
    echo "still waiting for publication (${attempt}/60); latest controller log:"
    kubectl -n updated-system logs deployment/updatec-controller --tail=3 || true
  fi
  sleep 2
done
if ! kubectl_log_contains deployment/updatec-controller 'desired state reconciled'; then
  echo "FAIL: updatec did not publish within 120s" >&2
  kubectl -n updated-system get pods >&2 || true
  kubectl -n updated-system logs deployment/updatec-controller --tail=100 >&2 || true
  kubectl -n updated-system logs deployment/updatec-gateway --tail=100 >&2 || true
  exit 1
fi
echo "initial routing generation published"

# The controller log above proves a complete repository generation exists, but it is not tied to a
# particular watch event. Bind the transport assertion to the probe's own published status so a
# fast repository-only reconcile cannot race the immediately following UpdateAgent creation.
routing_probe_has_assignment() {
  [[ -n "$(kubectl -n updated-system get updateagent kind-routing-probe \
    -o jsonpath='{.status.assignmentPath}' 2>/dev/null || true)" ]]
}
if ! poll_until "$READY_TIMEOUT" routing_probe_has_assignment; then
  echo "FAIL: routing probe never received a published assignment" >&2
  kubectl -n updated-system get updateagent kind-routing-probe -o yaml >&2 || true
  exit 1
fi

# Prove direct download as a transport contract, not merely as a successful agent fetch. The root
# is present in every complete generation. Require a real, live, key-pinned inventory identity to
# receive a 307 to the MinIO TLS load balancer, require that signed URL to download, and require the
# same object URL without its signature to be refused. This avoids a privileged bucket listing and
# tests the same single repository-read authorization path used by metadata, assignments, configs,
# and artifacts.
DIRECT_PATH=metadata/root.json
cat >"$WORK/direct-download-check.yaml" <<YAML
apiVersion: v1
kind: Pod
metadata: {name: direct-download-check, namespace: updated-system}
spec:
  restartPolicy: Never
  containers:
    - name: check
      image: updatec-e2e:kind
      imagePullPolicy: Never
      command: [/bin/sh, -ec]
      args:
        - |
          target='https://updatec-gateway/$DIRECT_PATH'
          status="\$(curl -sS --max-time 15 --cert /tls/tls.crt --key /tls/tls.key \
            --cacert /tls/ca.crt -D /tmp/headers -o /dev/null -w '%{http_code}' "\$target")"
          if [ "\$status" != 307 ]; then
            echo "gateway repository read returned HTTP \$status, expected 307" >&2
            exit 1
          fi
          location="\$(awk 'BEGIN {IGNORECASE=1} /^location:/ {sub(/\r\$/, ""); print \$2}' /tmp/headers)"
          case "\$location" in
            https://minio-direct.updated-system.svc/*?X-Amz-*) ;;
            *) echo "unexpected direct-download Location shape" >&2; exit 1 ;;
          esac
          # Spend the bearer URL with no client identity. The agent uses two clients for this same
          # reason: mTLS authenticates only the gateway request; S3 sees only the exact capability.
          curl -fsS --max-time 30 --cacert /tls/ca.crt "\$location" -o /tmp/root.json
          test -s /tmp/root.json
          unsigned="\${location%%\?*}"
          if curl -fsS --max-time 15 --cacert /tls/ca.crt "\$unsigned" -o /dev/null 2>/dev/null; then
            echo "private routing target was downloadable without its signature" >&2
            exit 1
          fi
          echo "signed direct download verified: \$status exact HTTPS capability"
      volumeMounts:
        - {name: tls, mountPath: /tls, readOnly: true}
  volumes:
    - {name: tls, secret: {secretName: routing-probe-tls}}
YAML
kubectl apply -f "$WORK/direct-download-check.yaml"
for attempt in {1..60}; do
  DIRECT_PHASE="$(kubectl -n updated-system get pod direct-download-check \
    -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  [[ "$DIRECT_PHASE" == Succeeded || "$DIRECT_PHASE" == Failed ]] && break
  sleep 1
done
if [[ "${DIRECT_PHASE:-}" != Succeeded ]]; then
  echo "FAIL: signed direct download check did not succeed" >&2
  kubectl -n updated-system logs direct-download-check >&2 || true
  kubectl -n updated-system logs deployment/updatec-gateway --tail=100 >&2 || true
  exit 1
fi
kubectl -n updated-system logs direct-download-check
echo "private MinIO routing objects are reachable only through the gateway's signed HTTPS redirect"

# `stateMaxShards` is a live CRD control, not an install-time or compiled ceiling. Start from the
# default eight-shard projection that performed the initial publication, then change it in place.
# Reconcile must atomically move the same durable state to exactly three shards and reclaim both the
# old slot and every unused name; otherwise lowering the knob would not actually lower the steady
# etcd footprint.
ADMITTED_INDEX=updatec-admitted-default
INITIAL_STATE_INDEX="$(kubectl -n updated-system get configmap "$ADMITTED_INDEX" \
  -o jsonpath='{.data.index\.json}')"
if [[ "$INITIAL_STATE_INDEX" != *'"maxShards":8'* ]]; then
  echo "FAIL: initial durable state did not use the CRD default of eight shards: $INITIAL_STATE_INDEX" >&2
  exit 1
fi
kubectl -n updated-system patch updaterepository default --type=merge \
  -p='{"spec":{"stateMaxShards":3}}'
echo "waiting for live durable-state rebalance from eight shards to three"
STATE_INDEX=""
for attempt in {1..60}; do
  STATE_INDEX="$(kubectl -n updated-system get configmap "$ADMITTED_INDEX" \
    -o jsonpath='{.data.index\.json}' 2>/dev/null || true)"
  case "$STATE_INDEX" in
    *'"maxShards":3'*'"aShards":3,"bShards":0'* | \
    *'"maxShards":3'*'"aShards":0,"bShards":3'*) break ;;
  esac
  sleep 1
done
case "$STATE_INDEX" in
  *'"maxShards":3'*'"aShards":3,"bShards":0'*) ACTIVE_STATE_SLOT=a ;;
  *'"maxShards":3'*'"aShards":0,"bShards":3'*) ACTIVE_STATE_SLOT=b ;;
  *)
    echo "FAIL: durable-state rebalance did not settle on exactly three active shards: $STATE_INDEX" >&2
    exit 1
    ;;
esac
EXPECTED_STATE_MAPS="configmap/$ADMITTED_INDEX
configmap/$ADMITTED_INDEX-$ACTIVE_STATE_SLOT-00
configmap/$ADMITTED_INDEX-$ACTIVE_STATE_SLOT-01
configmap/$ADMITTED_INDEX-$ACTIVE_STATE_SLOT-02"
ACTUAL_STATE_MAPS="$(kubectl -n updated-system get configmaps \
  -l app.kubernetes.io/component=controller-state -o name | sort)"
if [[ "$ACTUAL_STATE_MAPS" != "$EXPECTED_STATE_MAPS" ]]; then
  echo "FAIL: stateMaxShards=3 did not leave exactly the index and three active ConfigMaps" >&2
  echo "expected:" >&2
  echo "$EXPECTED_STATE_MAPS" >&2
  echo "actual:" >&2
  echo "$ACTUAL_STATE_MAPS" >&2
  exit 1
fi
echo "live durable-state rebalance converged to exactly three shards"

# Exercise the offline provisioning route end to end. The operator first creates the node key and
# pins its public half in inventory. The controller then turns that manual UpdateAgent into a
# content-addressed signed enrollment object in S3. A `manual` identity is never completable over
# the shared fleet bootstrap certificate — `/enroll` refuses it — so the operator provisions both
# the signed bundle and the matching leaf out of band. After bootstrap, the pin gives this node the
# exact same key-bound capabilities and signed-telemetry path as an online-enrolled node.
MANUAL_IDENTITY="$WORK/manual-offline-identity"
mkdir -p "$MANUAL_IDENTITY"
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
  -out "$MANUAL_IDENTITY/agent.key" 2>/dev/null
MANUAL_PUBLIC_KEY="$(cargo run -q -p updatectl -- node-public-key \
  --key "$MANUAL_IDENTITY/agent.key")"
sign_node_leaf manual-offline "$MANUAL_IDENTITY/agent.key" "$MANUAL_IDENTITY/agent.crt" 90
cat <<YAML | kubectl apply -f -
apiVersion: updated.dev/v1alpha1
kind: UpdateAgent
metadata: {name: manual-offline, namespace: updated-system}
spec:
  repositoryRef: {name: default}
  identity: {kind: manual, publicKey: "$MANUAL_PUBLIC_KEY"}
  labels: {}
YAML
echo "waiting for the manual agent's signed installer artifact"
for attempt in {1..60}; do
  MANUAL_ENROLLMENT_OBJECT="$(kubectl -n updated-system get updateagent manual-offline \
    -o jsonpath='{.status.enrollmentObjectKey}' 2>/dev/null || true)"
  [[ -n "$MANUAL_ENROLLMENT_OBJECT" ]] && break
  sleep 2
done
if [[ -z "${MANUAL_ENROLLMENT_OBJECT:-}" ]]; then
  echo "FAIL: manual agent never received an enrollment object" >&2
  kubectl -n updated-system get updateagent manual-offline -o yaml >&2 || true
  exit 1
fi
# Model the operator's offline copy: read the exact S3 object named on status, materialize it as a
# file, then hand that file to the machine. The temporary Secret below is only how this Kubernetes
# test projects the copied file into its pod; updatec never writes or reads enrollment Secrets.
kubectl -n updated-system run manual-enrollment-export --restart=Never \
  --image=minio/mc:RELEASE.2025-04-16T18-13-26Z --command -- sh -ec \
  "mc alias set local http://minio:9000 minio minio123 >/dev/null; mc cat local/updates/${MANAGED_REPOSITORY_PREFIX}/$MANUAL_ENROLLMENT_OBJECT"
kubectl -n updated-system wait pod/manual-enrollment-export \
  --for=jsonpath='{.status.phase}'=Succeeded --timeout=${READY_TIMEOUT}s
kubectl -n updated-system logs manual-enrollment-export >"$WORK/manual-enrollment.json"
kubectl -n updated-system create secret generic manual-offline-enrollment \
  --from-file=enrollment.json="$WORK/manual-enrollment.json"
kubectl -n updated-system create secret generic manual-offline-identity \
  --from-file="$MANUAL_IDENTITY/agent.crt" --from-file="$MANUAL_IDENTITY/agent.key"
# The manually provisioned node needs the public fleet trust anchor, never the shared enrollment
# private key. A ConfigMap makes that least-authority boundary visible in the test topology.
kubectl -n updated-system create configmap manual-offline-trust \
  --from-file=ca.crt="$FLEET_CA/ca.crt"
cat >"$WORK/manual-offline.yaml" <<YAML
apiVersion: v1
kind: ConfigMap
metadata: {name: manual-offline-config, namespace: updated-system}
data:
  config.toml: |
    [enrollment]
    # The preplaced signed bundle gives this node its routing/assignment/initial config for a
    # network-free first start, and the preplaced leaf gives it its steady-state identity, so it
    # reaches the gateway only for the repository content its assignment names. A manual identity
    # never receives the fleet enrollment private key.
    url = "https://updatec-gateway"
    name = "manual-offline"
    ca = "/etc/fleet-trust/ca.crt"
---
apiVersion: v1
kind: Pod
metadata:
  name: manual-offline
  namespace: updated-system
  labels: {test: manual-offline}
spec:
  restartPolicy: Never
  securityContext: {fsGroup: 65532, seccompProfile: {type: RuntimeDefault}}
  initContainers:
    - name: external-installer
      image: updatec-e2e:kind
      imagePullPolicy: IfNotPresent
      command: [/bin/sh, -ec]
      args:
        - |
          mkdir -p /var/lib/updated/launcher
          cp /signed/enrollment.json /var/lib/updated/launcher/enrollment.json
          cp /identity/agent.crt /var/lib/updated/launcher/agent.crt
          cp /identity/agent.key /var/lib/updated/launcher/agent.key
          chmod 0600 /var/lib/updated/launcher/agent.key
      volumeMounts:
        - {name: state, mountPath: /var/lib/updated}
        - {name: enrollment, mountPath: /signed, readOnly: true}
        - {name: identity, mountPath: /identity, readOnly: true}
  containers:
    - name: agent
      image: updatec-e2e:kind
      imagePullPolicy: IfNotPresent
      command: [/usr/local/bin/updated-launcher]
      args: [--state-dir, /var/lib/updated/launcher, --config, /launcher-config/config.toml, --agent, /usr/local/bin/updated-agent, --ready-timeout, "30", --confirm-timeout, "2"]
      ports: [{name: http, containerPort: 8080}]
      securityContext:
        allowPrivilegeEscalation: false
        capabilities: {drop: [ALL]}
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 65532
      volumeMounts:
        - {name: state, mountPath: /var/lib/updated}
        - {name: launcher-config, mountPath: /launcher-config, readOnly: true}
        - {name: fleet-trust, mountPath: /etc/fleet-trust, readOnly: true}
  volumes:
    - {name: state, emptyDir: {}}
    - name: enrollment
      secret: {secretName: manual-offline-enrollment}
    - {name: identity, secret: {secretName: manual-offline-identity}}
    - name: launcher-config
      configMap: {name: manual-offline-config}
    - {name: fleet-trust, configMap: {name: manual-offline-trust}}
YAML
kubectl apply -f "$WORK/manual-offline.yaml"
kubectl -n updated-system wait pod/manual-offline --for=condition=Ready --timeout=${READY_TIMEOUT}s
# The workload belongs to the release's own reconciler, so the proof it converged is the
# application answering — reached with a bounded wait rather than assumed to be up the instant the
# container reports ready.
MANUAL_VERSION=""
for attempt in {1..60}; do
  MANUAL_VERSION="$(kubectl -n updated-system exec manual-offline -c agent -- \
    curl -fsS --max-time 2 http://127.0.0.1:8080/version 2>/dev/null || true)"
  [[ "$MANUAL_VERSION" == 1.0.0 ]] && break
  sleep 2
done
[[ "$MANUAL_VERSION" == 1.0.0 ]] || {
  echo "FAIL: offline-provisioned manual agent runs version '$MANUAL_VERSION', expected 1.0.0" >&2
  kubectl -n updated-system logs manual-offline -c agent --tail=100 >&2 || true
  exit 1
}
kubectl_log_contains manual-offline \
  'cold-installed application 1.0.0 from the first trusted assignment' -c agent || {
  echo "FAIL: manual agent did not cold-install from its preplaced enrollment bundle" >&2
  exit 1
}
# A manual node must not be operationally blind: its pinned key authorizes the same bounded report
# upload as online enrollment, and the controller must verify and surface that report.
MANUAL_REPORTED_VERSION=""
MANUAL_REPORTED_READY=""
for attempt in {1..60}; do
  MANUAL_REPORTED_VERSION="$(kubectl -n updated-system get updateagent manual-offline \
    -o jsonpath='{.status.reportedVersion}' 2>/dev/null || true)"
  MANUAL_REPORTED_READY="$(kubectl -n updated-system get updateagent manual-offline \
    -o jsonpath='{.status.reportedReady}' 2>/dev/null || true)"
  [[ "$MANUAL_REPORTED_VERSION" == 1.0.0 && "$MANUAL_REPORTED_READY" == true ]] && break
  sleep 2
done
if [[ "$MANUAL_REPORTED_VERSION" != 1.0.0 || "$MANUAL_REPORTED_READY" != true ]]; then
  echo "FAIL: manual agent telemetry was not accepted (version=$MANUAL_REPORTED_VERSION ready=$MANUAL_REPORTED_READY)" >&2
  kubectl -n updated-system get updateagent manual-offline -o yaml >&2 || true
  kubectl -n updated-system logs manual-offline -c agent --tail=100 >&2 || true
  exit 1
fi
echo "manual CRD export cold-installed offline, started 1.0.0, and reported healthy"

# A malformed enrollment artifact is terminal: it must never fall back to the URL/key or install
# an application. `timeout` bounds the launcher's intentional relaunch retries so Kubernetes
# records an observable failed container for this negative test.
cat >"$WORK/manual-bad-enrollment.yaml" <<YAML
apiVersion: v1
kind: Pod
metadata: {name: manual-bad-enrollment, namespace: updated-system}
spec:
  restartPolicy: Never
  hostAliases:
    - ip: 127.0.0.1
      hostnames: [updatec-gateway, release-default]
  initContainers:
    - name: corrupt-external-installer
      image: updatec-e2e:kind
      command: [/bin/sh, -ec]
      args:
        - |
          mkdir -p /var/lib/updated/launcher
          cp /signed/enrollment.json /var/lib/updated/launcher/enrollment.json
          printf tampered >>/var/lib/updated/launcher/enrollment.json
      volumeMounts:
        - {name: state, mountPath: /var/lib/updated}
        - {name: enrollment, mountPath: /signed, readOnly: true}
  containers:
    - name: agent
      image: updatec-e2e:kind
      command: [/bin/sh, -ec]
      args: ["timeout 15 updated-launcher --state-dir /var/lib/updated/launcher --config /launcher-config/config.toml --agent /usr/local/bin/updated-agent --ready-timeout 5 --confirm-timeout 2"]
      volumeMounts:
        - {name: state, mountPath: /var/lib/updated}
        - {name: launcher-config, mountPath: /launcher-config, readOnly: true}
  volumes:
    - {name: state, emptyDir: {}}
    - name: enrollment
      secret: {secretName: manual-offline-enrollment}
    - name: launcher-config
      configMap: {name: manual-offline-config}
YAML
kubectl apply -f "$WORK/manual-bad-enrollment.yaml"
for attempt in {1..30}; do
  BAD_PHASE="$(kubectl -n updated-system get pod manual-bad-enrollment -o jsonpath='{.status.phase}')"
  [[ "$BAD_PHASE" == Failed ]] && break
  sleep 1
done
[[ "${BAD_PHASE:-}" == Failed ]] || {
  echo "FAIL: corrupted enrollment container did not fail" >&2
  kubectl -n updated-system logs manual-bad-enrollment -c agent >&2 || true
  exit 1
}
BAD_LOG="$(kubectl -n updated-system logs manual-bad-enrollment -c agent)"
[[ "$BAD_LOG" == *"resolving signed managed configuration"* ]]
[[ "$BAD_LOG" != *"cold-installed application"* ]]
echo "corrupted installer enrollment failed closed before any application was installed"

# Invalid online credentials are also fail-closed and may not leave registration state. The gateway
# creates the UpdateAgent under the name the node self-asserts in its config file, so that is the
# object this must prove was never created.
BAD_AGENT_NAME=intruder
cat <<'YAML' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata: {name: bad-online-enrollment, namespace: updated-system}
spec:
  restartPolicy: Never
  containers:
    - name: agent
      image: updatec-e2e:kind
      command: [/bin/sh, -ec]
      args:
        - |
          mkdir -p /var/lib/updated/launcher
          # Present an intruder client cert NOT signed by the fleet CA: the gateway must reject
          # it at the mTLS handshake so enrollment fails closed. It still trusts the real fleet
          # CA for the gateway's server cert.
          cat >/tmp/config.toml <<EOF
          [enrollment]
          url = "https://updatec-gateway"
          name = "intruder"
          ca = "/etc/agent-tls/ca.crt"
          [enrollment.bootstrap]
          client_cert = "/etc/intruder-tls/tls.crt"
          client_key = "/etc/intruder-tls/tls.key"
          EOF
          timeout 15 updated-launcher --state-dir /var/lib/updated/launcher \
            --config /tmp/config.toml --agent /usr/local/bin/updated-agent \
            --ready-timeout 5 --confirm-timeout 2
      volumeMounts:
        - {name: state, mountPath: /var/lib/updated}
        - {name: intruder-tls, mountPath: /etc/intruder-tls, readOnly: true}
        - {name: agent-tls, mountPath: /etc/agent-tls, readOnly: true}
  volumes:
    - {name: state, emptyDir: {}}
    - {name: intruder-tls, secret: {secretName: intruder-tls}}
    - {name: agent-tls, secret: {secretName: agent-tls}}
YAML
for attempt in {1..30}; do
  BAD_ONLINE_PHASE="$(kubectl -n updated-system get pod bad-online-enrollment -o jsonpath='{.status.phase}')"
  [[ "$BAD_ONLINE_PHASE" == Failed ]] && break
  sleep 1
done
[[ "${BAD_ONLINE_PHASE:-}" == Failed ]]
if kubectl -n updated-system get updateagent "$BAD_AGENT_NAME" >/dev/null 2>&1; then
  echo "FAIL: invalid enrollment credentials created $BAD_AGENT_NAME" >&2
  exit 1
fi
echo "invalid online enrollment credentials failed closed without registering an agent"

# A valid holder of the shared bootstrap certificate is still bounded by repository policy. Switch
# to reserved-only temporarily and exercise the real TLS listener and `/enroll` handler with an
# absent name; neither the handler nor its API-server identity may turn that name into inventory.
kubectl -n updated-system patch updaterepository default --type=merge \
  -p='{"spec":{"enrollment":{"mode":"reservedOnly"}}}'
UNRESERVED_AGENT_NAME=unreserved-online
cat <<'YAML' | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata: {name: unreserved-online-enrollment, namespace: updated-system}
spec:
  restartPolicy: Never
  containers:
    - name: agent
      image: updatec-e2e:kind
      command: [/bin/sh, -ec]
      args:
        - |
          mkdir -p /var/lib/updated/launcher
          cat >/tmp/config.toml <<EOF
          [enrollment]
          url = "https://updatec-gateway"
          name = "unreserved-online"
          ca = "/etc/agent-tls/ca.crt"
          [enrollment.bootstrap]
          client_cert = "/etc/agent-tls/tls.crt"
          client_key = "/etc/agent-tls/tls.key"
          EOF
          timeout 15 updated-launcher --state-dir /var/lib/updated/launcher \
            --config /tmp/config.toml --agent /usr/local/bin/updated-agent \
            --ready-timeout 5 --confirm-timeout 2
      volumeMounts:
        - {name: state, mountPath: /var/lib/updated}
        - {name: agent-tls, mountPath: /etc/agent-tls, readOnly: true}
  volumes:
    - {name: state, emptyDir: {}}
    - {name: agent-tls, secret: {secretName: agent-tls}}
YAML
for attempt in {1..30}; do
  UNRESERVED_PHASE="$(kubectl -n updated-system get pod unreserved-online-enrollment -o jsonpath='{.status.phase}')"
  [[ "$UNRESERVED_PHASE" == Failed ]] && break
  sleep 1
done
[[ "${UNRESERVED_PHASE:-}" == Failed ]]
UNRESERVED_LOG="$(kubectl -n updated-system logs unreserved-online-enrollment -c agent)"
[[ "$UNRESERVED_LOG" == *"enrollment returned HTTP 403 Forbidden"* ]] || {
  echo "FAIL: reserved-only enrollment did not return the policy's 403 response" >&2
  echo "$UNRESERVED_LOG" >&2
  exit 1
}
if kubectl -n updated-system get updateagent "$UNRESERVED_AGENT_NAME" >/dev/null 2>&1; then
  echo "FAIL: reserved-only enrollment created $UNRESERVED_AGENT_NAME" >&2
  exit 1
fi
kubectl -n updated-system patch updaterepository default --type=merge \
  -p='{"spec":{"enrollment":{"mode":"open"}}}'
echo "reserved-only enrollment rejected an absent name presented with valid bootstrap credentials"

cat <<'YAML' | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata: {name: poison-preinstalled-apps, namespace: updated-system}
data:
  sampleapp: |
    #!/bin/sh
    echo "FAIL: agent used the image-baked sampleapp instead of a verified bundle" >&2
    exit 97
  stateful-like: |
    #!/bin/sh
    echo "FAIL: agent used the image-baked stateful-like app instead of a verified bundle" >&2
    exit 98
---
apiVersion: v1
kind: Service
metadata: {name: agents, namespace: updated-system}
spec:
  clusterIP: None
  publishNotReadyAddresses: true
  selector: {app: updated-agent}
  ports: [{name: http, port: 8080, targetPort: http}]
---
apiVersion: apps/v1
kind: StatefulSet
metadata: {name: agent, namespace: updated-system}
spec:
  serviceName: agents
  replicas: 5
  podManagementPolicy: Parallel
  selector: {matchLabels: {app: updated-agent}}
  template:
    metadata: {labels: {app: updated-agent}}
    spec:
      securityContext: {fsGroup: 65532, seccompProfile: {type: RuntimeDefault}}
      containers:
        - name: agent
          image: updatec-e2e:kind
          imagePullPolicy: IfNotPresent
          command: [/usr/local/bin/run-agent]
          ports: [{name: http, containerPort: 8080}]
          securityContext:
            allowPrivilegeEscalation: false
            capabilities: {drop: [ALL]}
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            runAsUser: 65532
          resources:
            requests: {cpu: 25m, memory: 32Mi}
            limits: {cpu: "1", memory: 256Mi}
          volumeMounts:
            - {name: state, mountPath: /var/lib/updated}
            - {name: tmp, mountPath: /tmp}
            - {name: agent-tls, mountPath: /etc/agent-tls, readOnly: true}
            - {name: poison-preinstalled-apps, mountPath: /usr/local/bin/sampleapp, subPath: sampleapp, readOnly: true}
            - {name: poison-preinstalled-apps, mountPath: /usr/local/bin/stateful-like, subPath: stateful-like, readOnly: true}
      volumes:
        - {name: tmp, emptyDir: {medium: Memory, sizeLimit: 64Mi}}
        # cert-manager issues the agents' shared client identity here. In mount mode this fleet cert
        # now ONLY authenticates the /enroll handshake; the node mints its own per-node cert (kept on
        # the persistent `state` volume) and uses it for all steady-state traffic.
        - {name: agent-tls, secret: {secretName: agent-tls}}
        - name: poison-preinstalled-apps
          configMap: {name: poison-preinstalled-apps, defaultMode: 365}
  # Persistent storage is now REQUIRED, not optional: the per-node minted key/cert and the install
  # state live only here, so an emptyDir would lose the node's identity on every restart (a churn of
  # re-enrollments and dead UpdateAgents) and re-cold-install every boot. Sized to the install
  # footprint (installed app + retained inactive releases).
  volumeClaimTemplates:
    - metadata: {name: state}
      spec: {accessModes: [ReadWriteOnce], resources: {requests: {storage: 1Gi}}}
YAML
echo "waiting for all five real agent nodes to reach their assigned versions"
kubectl -n updated-system rollout status statefulset/agent --timeout=${READY_TIMEOUT}s
# The `UpdateAgent` name pod `agent-<ordinal>` enrolls under. Read from the single definition of
# that derivation (`resource_name`, crates/updatec-e2e/src/cluster.rs) — the same one the pods
# themselves use through `updatec-e2e agent-name` — never re-derived here. Derived once for all
# five ordinals, in assignment position: a substitution in *argument* position would not abort
# under `set -e` on failure, and would hand kubectl an empty resource name.
agent_resource_name() {
  cargo run -q -p updatec-e2e -- agent-name "agent-$1"
}
declare -a AGENT_RESOURCES
for ordinal in 0 1 2 3 4; do
  AGENT_RESOURCES[ordinal]="$(agent_resource_name "$ordinal")"
done
agent_is_enrolled() {
  [[ "$(kubectl -n updated-system get updateagent "$1" \
    -o jsonpath='{.spec.identity.kind}' 2>/dev/null || true)" == enrolled ]]
}
for ordinal in 0 1 2 3 4; do
  resource="${AGENT_RESOURCES[ordinal]}"
  poll_until "$NODE_SETTLE_TIMEOUT" agent_is_enrolled "$resource" || {
    echo "FAIL: agent-$ordinal did not create enrolled UpdateAgent $resource" >&2
    kubectl -n updated-system logs "agent-$ordinal" -c agent --tail=200 >&2 || true
    exit 1
  }
  identity="$(kubectl -n updated-system get updateagent "$resource" -o jsonpath='{.spec.identity.kind}')"
  [[ "$identity" == enrolled ]] || {
    echo "FAIL: agent-$ordinal registered with identity '$identity', expected enrolled" >&2
    exit 1
  }
  kubectl -n updated-system exec "agent-$ordinal" -c agent -- \
    grep -q '"routingBaseUrl":"https://updatec-gateway/"' \
      /var/lib/updated/launcher/enrollment.json || {
    echo "FAIL: agent-$ordinal did not persist the reachable in-cluster routing URL" >&2
    exit 1
  }
  poll_until "$NODE_SETTLE_TIMEOUT" kubectl_log_contains "agent-$ordinal" \
    'cold-installed application 1.0.0 from the first trusted assignment' -c agent || {
    echo "FAIL: agent-$ordinal did not cold-install through online enrollment" >&2
    kubectl -n updated-system logs "agent-$ordinal" -c agent --tail=200 >&2 || true
    exit 1
  }
  log="$(kubectl -n updated-system logs "agent-$ordinal" -c agent)"
  [[ "$log" != *"FAIL: agent used the image-baked"* ]] || {
    echo "FAIL: agent-$ordinal executed a masked image-baked application" >&2
    exit 1
  }
done
echo "all five empty agents enrolled online and cold-installed the network assignment"

# Prove the direct WRITE boundary independently of the honest agent client. A live node asks the
# mTLS gateway for its exact report capability, then tries to spend that capability on a payload
# one byte past the report ceiling. The policy itself must name the ceiling and MinIO must reject
# the POST: merely bounding controller reads would still let a compromised node consume unbounded
# object-store capacity and ingress bandwidth.
# shellcheck disable=SC2016 # The script is intentionally evaluated by the shell inside the pod.
kubectl -n updated-system exec agent-0 -c agent -- sh -ec '
  state=/var/lib/updated/launcher
  capability=$(curl -fsS --max-time 15 \
    --cert "$state/agent.crt" --key "$state/agent.key" --cacert /etc/agent-tls/ca.crt \
    https://updatec-gateway/v1/node/report)
  field() {
    printf "%s" "$capability" | sed -n "s/.*\"$1\":\"\([^\"]*\)\".*/\1/p"
  }
  action=$(field url)
  key=$(field key)
  policy=$(field policy)
  algorithm=$(field x-amz-algorithm)
  credential=$(field x-amz-credential)
  date=$(field x-amz-date)
  signature=$(field x-amz-signature)
  case "$action" in https://minio-direct.updated-system.svc/updates/) ;; *) exit 1 ;; esac
  printf "%s" "$policy" | base64 -d >/tmp/report-policy.json
  grep -q '\''\["content-length-range",1,65536\]'\'' /tmp/report-policy.json
  head -c 65537 /dev/zero >/tmp/oversized-report.json
  status=$(curl -sS --max-time 15 -o /tmp/oversized-response -w "%{http_code}" \
    --cacert /etc/agent-tls/ca.crt \
    -F "key=$key" -F "policy=$policy" -F "x-amz-algorithm=$algorithm" \
    -F "x-amz-credential=$credential" -F "x-amz-date=$date" \
    -F "x-amz-signature=$signature" -F "file=@/tmp/oversized-report.json" \
    "$action")
  case "$status" in 4??) ;; *) echo "oversized signed S3 POST returned HTTP $status" >&2; exit 1 ;; esac
'
echo "MinIO enforced the signed direct-upload report ceiling"

# Exercise certificate renewal through the live gateway without restarting the pod, container, or
# workload. Replace agent-4's leaf with a fleet-CA-signed one-day leaf for the SAME durable key and
# terminate only the agent; the workload belongs to the release's reconciler, so nothing in the
# node stack can disturb it. The new agent sees the short lifetime immediately, calls /renew with
# that current identity, installs the replacement atomically, and exits once so the launcher
# rebuilds every authenticated client.
ROTATION_AGENT=agent-4
ROTATION_RESOURCE="${AGENT_RESOURCES[4]}"
ROTATION_STATE=/var/lib/updated/launcher
ROTATION_DIR="$WORK/certificate-rotation"
mkdir -p "$ROTATION_DIR"
kubectl -n updated-system exec "$ROTATION_AGENT" -c agent -- \
  cat "$ROTATION_STATE/agent.key" >"$ROTATION_DIR/agent.key"
kubectl -n updated-system exec "$ROTATION_AGENT" -c agent -- \
  cat "$ROTATION_STATE/agent.crt" >"$ROTATION_DIR/original.crt"
sign_node_leaf "$ROTATION_RESOURCE" "$ROTATION_DIR/agent.key" "$ROTATION_DIR/short.crt" 1

pod_uid_before="$(kubectl -n updated-system get pod "$ROTATION_AGENT" -o jsonpath='{.metadata.uid}')"
restart_before="$(kubectl -n updated-system get pod "$ROTATION_AGENT" \
  -o jsonpath='{.status.containerStatuses[0].restartCount}')"
key_before="$(sha256sum "$ROTATION_DIR/agent.key" | awk '{print $1}')"
original_cert="$(sha256sum "$ROTATION_DIR/original.crt" | awk '{print $1}')"
short_cert="$(sha256sum "$ROTATION_DIR/short.crt" | awk '{print $1}')"
[[ "$short_cert" != "$original_cert" ]]
# `/proc/<pid>/comm` is the kernel's 15-character name, so the process this looks for is named by
# exactly what the kernel records: the agent runs as `updated-agent`, the workload the release's
# reconciler started runs as its entrypoint, `app`.
process_pid() {
  local process="$1"
  # shellcheck disable=SC2016 # $path and $1 belong to the shell running inside the pod.
  kubectl -n updated-system exec "$ROTATION_AGENT" -c agent -- sh -ec '
    for path in /proc/[0-9]*; do
      [ "$(cat "$path/comm" 2>/dev/null || true)" = "$1" ] || continue
      echo "${path##*/}"
      exit 0
    done
    exit 1
  ' sh "$process"
}
agent_before="$(process_pid updated-agent)"
application_before="$(process_pid app)"

# The observer samples once a second for exactly this long; both bounds below derive from it.
ROTATION_OBSERVE_SECONDS=45
cat <<YAML | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata: {name: observe-certificate-rotation, namespace: updated-system}
spec:
  backoffLimit: 0
  activeDeadlineSeconds: $(job_deadline "$ROTATION_OBSERVE_SECONDS")
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: observe
          image: updatec-e2e:kind
          command: [/bin/sh, -ec]
          env:
            - {name: OBSERVE_SECONDS, value: "$ROTATION_OBSERVE_SECONDS"}
          args:
            - |
              failures=0
              attempt=0
              while [ "\$attempt" -lt "\$OBSERVE_SECONDS" ]; do
                attempt=\$((attempt + 1))
                version=\$(curl -fsS --max-time 1 http://agent-4.agents:8080/version || true)
                [ "\$version" = 1.0.0 ] || failures=\$((failures + 1))
                sleep 1
              done
              [ "\$failures" -eq 0 ] || {
                echo "application was unavailable for \$failures observation(s)" >&2
                exit 1
              }
              echo "application stayed available throughout certificate renewal"
YAML
kubectl -n updated-system wait --for=condition=ready \
  pod -l job-name=observe-certificate-rotation --timeout=${READY_TIMEOUT}s

# Install the near-expiry leaf completely before signalling the agent. Existing clients keep
# using their in-memory identity until the launcher relaunches the agent.
kubectl -n updated-system exec -i "$ROTATION_AGENT" -c agent -- \
  sh -c "cat >'$ROTATION_STATE/agent.crt'" <"$ROTATION_DIR/short.crt"
kubectl -n updated-system exec "$ROTATION_AGENT" -c agent -- \
  kill -TERM "$agent_before"

rotation_relaunched_the_agent() {
  kubectl -n updated-system exec "$ROTATION_AGENT" -c agent -- \
    cat "$ROTATION_STATE/agent.crt" >"$ROTATION_DIR/renewed.crt"
  renewed_cert="$(sha256sum "$ROTATION_DIR/renewed.crt" | awk '{print $1}')"
  agent_after="$(process_pid updated-agent 2>/dev/null || true)"
  [[ "$renewed_cert" != "$short_cert" && -n "$agent_after" \
    && "$agent_after" != "$agent_before" ]]
}
poll_until "$NODE_SETTLE_TIMEOUT" rotation_relaunched_the_agent || {
  echo "FAIL: agent-4 did not renew its short-lived certificate and relaunch its agent" >&2
  kubectl -n updated-system logs "$ROTATION_AGENT" -c agent --tail=200 >&2 || true
  exit 1
}

pod_uid_after="$(kubectl -n updated-system get pod "$ROTATION_AGENT" -o jsonpath='{.metadata.uid}')"
restart_after="$(kubectl -n updated-system get pod "$ROTATION_AGENT" \
  -o jsonpath='{.status.containerStatuses[0].restartCount}')"
application_after="$(process_pid app)"
kubectl -n updated-system exec "$ROTATION_AGENT" -c agent -- \
  cat "$ROTATION_STATE/agent.key" >"$ROTATION_DIR/renewed.key"
key_after="$(sha256sum "$ROTATION_DIR/renewed.key" | awk '{print $1}')"
[[ "$pod_uid_after" == "$pod_uid_before" ]]
[[ "$restart_after" == "$restart_before" ]]
[[ "$application_after" == "$application_before" ]]
[[ "$key_after" == "$key_before" ]]
openssl x509 -in "$ROTATION_DIR/renewed.crt" -noout -checkend $((60 * 24 * 60 * 60))
renewed_subject="$(openssl x509 -in "$ROTATION_DIR/renewed.crt" \
  -noout -subject -nameopt RFC2253)"
[[ "$renewed_subject" == "subject=CN=$ROTATION_RESOURCE" ]]
kubectl -n updated-system exec "$ROTATION_AGENT" -c agent -- \
  curl -fsS --cert "$ROTATION_STATE/agent.crt" --key "$ROTATION_STATE/agent.key" \
    --cacert /etc/agent-tls/ca.crt https://updatec-gateway/metadata/timestamp.json \
    >/dev/null
kubectl -n updated-system exec "$ROTATION_AGENT" -c agent -- \
  curl -fsS --cert "$ROTATION_STATE/agent.crt" --key "$ROTATION_STATE/agent.key" \
    --cacert /etc/agent-tls/ca.crt https://updatec-gateway/v1/node/report \
    >/dev/null
# The shared fleet bootstrap certificate authenticates the one /enroll handshake and NOTHING else.
# It is signed by the same fleet CA, so it completes the mTLS handshake — but it carries no SPIFFE
# node SAN, so every steady-state route must refuse it. Otherwise any holder of the fleet-wide
# enrollment Secret could mint either repository-read or node-object capabilities.
for bootstrap_path in metadata/timestamp.json v1/node/report; do
  bootstrap_status="$(kubectl -n updated-system exec "$ROTATION_AGENT" -c agent -- \
    curl -sS --max-time 15 --cert /etc/agent-tls/tls.crt --key /etc/agent-tls/tls.key \
      --cacert /etc/agent-tls/ca.crt -o /dev/null -w '%{http_code}' \
      "https://updatec-gateway/$bootstrap_path")"
  if [[ "$bootstrap_status" != 403 ]]; then
    echo "FAIL: bootstrap access to $bootstrap_path returned HTTP $bootstrap_status, expected 403" >&2
    exit 1
  fi
done
echo "the shared bootstrap certificate is refused on every steady-state route"
await_job observe-certificate-rotation "$ROTATION_OBSERVE_SECONDS"
kubectl -n updated-system logs job/observe-certificate-rotation
kubectl_log_contains deployment/updatec-gateway \
  "renewed node certificate" || {
  echo "FAIL: gateway did not record the authenticated certificate renewal" >&2
  exit 1
}
echo "agent-4 renewed its certificate with no pod/container/app restart and retained mTLS access"

for ordinal in 0 1; do
  kubectl -n updated-system patch updateagent "${AGENT_RESOURCES[ordinal]}" --type merge \
    -p '{"spec":{"labels":{"updated.dev/role":"edge"}}}'
done
for ordinal in 2 3; do
  kubectl -n updated-system patch updateagent "${AGENT_RESOURCES[ordinal]}" --type merge \
    -p '{"spec":{"labels":{"updated.dev/role":"batch"}}}'
done
echo "dynamic enrollments registered; waiting for group assignments"
sleep 5
cat <<YAML | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata: {name: verify-agent-versions, namespace: updated-system}
spec:
  backoffLimit: 0
  # Above the verifier's own budget, so the script reports which agent is behind rather than the
  # job controller deleting the pod and its diagnostic. See FLEET_CONVERGE_SECONDS.
  activeDeadlineSeconds: $(job_deadline "$FLEET_CONVERGE_SECONDS")
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: verify
          image: updatec-e2e:kind
          imagePullPolicy: IfNotPresent
          command: [/bin/sh, -ec]
          env:
            - {name: BUDGET, value: "$FLEET_CONVERGE_SECONDS"}
          args:
            - |
              # One wall-clock budget for the whole fleet, not a retry count per agent: these checks
              # run in sequence, so a per-agent count bounds nothing the name claims to bound.
              deadline=\$(( \$(date +%s) + BUDGET ))
              check() {
                agent="\$1" expected="\$2" expected_artifact="\$3"
                while :; do
                  actual=\$(curl -fsS "http://\${agent}.agents:8080/version" || true)
                  artifact=\$(curl -fsS "http://\${agent}.agents:8080/artifact" || true)
                  if [ "\$actual" = "\$expected" ] && [ "\$artifact" = "\$expected_artifact" ]; then
                    echo "\$agent: \$actual (\$artifact)"
                    return 0
                  fi
                  if [ "\$(date +%s)" -ge "\$deadline" ]; then
                    echo "\$agent: expected \$expected/\$expected_artifact, got \${actual:-unreachable}/\${artifact:-unreachable}" >&2
                    return 1
                  fi
                  sleep 1
                done
              }
              check agent-0 2.0.0 stateful
              check agent-1 2.0.0 stateful
              check agent-2 3.0.0 sampleapp
              check agent-3 3.0.0 sampleapp
              check agent-4 1.0.0 sampleapp
              echo "all 5 agents reached their control-plane-selected versions (2/2/1)"
YAML
await_job verify-agent-versions "$FLEET_CONVERGE_SECONDS"
kubectl -n updated-system logs job/verify-agent-versions

# A workload crash is the release's problem, not the node stack's: the agent runs packages and
# holds no handle on the process, so a crashed application must leave the agent, the container and
# the pod exactly where they were. Continuous convergence is the one recovery path: the next
# verified steady-state cycle invokes the committed reconciler's `apply`, which must replace the
# crashed process with the SAME committed release.
restart_before="$(kubectl -n updated-system get pod agent-4 -o jsonpath='{.status.containerStatuses[0].restartCount}')"
agent_before="$(process_pid updated-agent)"
workload_before="$(process_pid app)"
kubectl -n updated-system exec agent-4 -c agent -- \
  sh -c 'curl -fsS http://127.0.0.1:8080/crash >/dev/null || true' || true
# A sampled outage is not an invariant: continuous convergence can close the gap between two
# one-second polls. Process identity is durable evidence that the old workload exited, while the
# recovered version proves the reconciler restored the committed release.
recovered_workload=""
recovered_version=""
workload_was_replaced_and_recovered() {
  recovered_workload="$(process_pid app 2>/dev/null || true)"
  recovered_version="$(kubectl -n updated-system exec agent-4 -c agent -- \
    curl -fsS --max-time 2 http://127.0.0.1:8080/version 2>/dev/null || true)"
  [[ -n "$recovered_workload" && "$recovered_workload" != "$workload_before" \
    && "$recovered_version" == 1.0.0 ]]
}
poll_until "$NODE_SETTLE_TIMEOUT" workload_was_replaced_and_recovered || {
  echo "FAIL: agent-4 did not replace crashed workload $workload_before with committed 1.0.0 (pid=${recovered_workload:-absent}, version=${recovered_version:-unreachable})" >&2
  kubectl -n updated-system logs agent-4 -c agent --tail=100 >&2 || true
  exit 1
}
restart_after="$(kubectl -n updated-system get pod agent-4 -o jsonpath='{.status.containerStatuses[0].restartCount}')"
[[ "$restart_after" == "$restart_before" ]] || {
  echo "FAIL: agent-4's container restarted over a workload crash the agent does not own" >&2
  exit 1
}
[[ "$(process_pid updated-agent)" == "$agent_before" ]] || {
  echo "FAIL: agent-4's agent process died with the workload it does not own" >&2
  exit 1
}
kubectl -n updated-system wait --for=condition=ready pod/agent-4 --timeout=${READY_TIMEOUT}s
echo "a workload crash replaced pid $workload_before with $recovered_workload while continuous convergence re-applied committed 1.0.0 without restarting the node stack"

if (( FUZZ_ROUNDS > 0 )); then
cat <<'YAML' | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata: {name: fleet-fuzz-scripts, namespace: updated-system}
data:
  observe.sh: |
    #!/bin/sh
    set -eu
    agent="agent-${JOB_COMPLETION_INDEX}"
    previous=""
    for attempt in $(seq 1 "$ITERATIONS"); do
      current=$(curl -fsS "http://${agent}.agents:8080/version" 2>/dev/null || true)
      artifact=$(curl -fsS "http://${agent}.agents:8080/artifact" 2>/dev/null || true)
      health=$(curl -fsS "http://${agent}.agents:8080/healthz" 2>/dev/null || true)
      state="version=${current:-unreachable} artifact=${artifact:-unreachable} health=${health:-unreachable}"
      if [ "$state" != "$previous" ]; then
        echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $agent $state"
        previous="$state"
      fi
      sleep 1
    done
  verify.sh: |
    #!/bin/sh
    set -eu
    # ONE budget for the whole fleet, spent as wall clock rather than as a per-agent retry count.
    #
    # Per-agent counts cannot express the thing being bounded. These checks run sequentially, so
    # "90 tries each" meant the fleet was allowed 90s or 450s depending on how many agents were
    # slow — and the job deadline above killed the pod long before the later agents were even
    # reached, so the count past the first agent or two was configuration that could never run.
    # A deadline shared across the loop is the actual claim: this fleet converges within BUDGET.
    echo "waiting for exact fleet convergence within ${BUDGET}s: $EXPECTED"
    deadline=$(( $(date +%s) + BUDGET ))
    for pair in $EXPECTED; do
      agent=${pair%%=*}
      wanted=${pair#*=}
      expected=${wanted%%,*}
      expected_artifact=${wanted#*,}
      waited=0
      while :; do
        actual=$(curl -fsS "http://${agent}.agents:8080/version" 2>/dev/null || true)
        artifact=$(curl -fsS "http://${agent}.agents:8080/artifact" 2>/dev/null || true)
        health=$(curl -fsS "http://${agent}.agents:8080/healthz" 2>/dev/null || true)
        if [ "$actual" = "$expected" ] && [ "$artifact" = "$expected_artifact" ] && [ "$health" = "ok" ]; then
          break
        fi
        if [ "$(date +%s)" -ge "$deadline" ]; then
          echo "$agent: expected $expected/$expected_artifact/ok, got ${actual:-unreachable}/${artifact:-unreachable}/${health:-unreachable}" >&2
          exit 1
        fi
        waited=$((waited + 1))
        if [ $((waited % 10)) -eq 0 ]; then
          echo "$agent: still waiting for $expected/$expected_artifact/ok (${waited}s); currently ${actual:-unreachable}/${artifact:-unreachable}/${health:-unreachable}"
        fi
        sleep 1
      done
      echo "$agent: $actual ($artifact) healthy"
    done
    echo "fleet converged exactly"
YAML

OBSERVER_ITERATIONS=$((FUZZ_ROUNDS * 45))
cat <<YAML | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata: {name: observe-fleet-chaos, namespace: updated-system}
spec:
  completionMode: Indexed
  completions: 5
  parallelism: 5
  backoffLimitPerIndex: 0
  activeDeadlineSeconds: $(job_deadline "$OBSERVER_ITERATIONS")
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: observe
          image: updatec-e2e:kind
          command: [/bin/sh, /scripts/observe.sh]
          env: [{name: ITERATIONS, value: "$OBSERVER_ITERATIONS"}]
          volumeMounts: [{name: scripts, mountPath: /scripts, readOnly: true}]
      volumes: [{name: scripts, configMap: {name: fleet-fuzz-scripts}}]
YAML

verify_fleet() {
  local job="$1"
  local expected="$2"
  cat <<YAML | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata: {name: $job, namespace: updated-system}
spec:
  backoffLimit: 0
  # Strictly above the verifier's own budget: the script must be the thing that fails, because it
  # is the only one that can say WHICH agent was behind and on what version. A deadline at or below
  # the budget deletes the pod and its diagnostic, leaving an opaque DeadlineExceeded.
  activeDeadlineSeconds: $(job_deadline "$FLEET_CONVERGE_SECONDS")
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: verify
          image: updatec-e2e:kind
          command: [/bin/sh, /scripts/verify.sh]
          env:
            - {name: EXPECTED, value: "$expected"}
            - {name: BUDGET, value: "$FLEET_CONVERGE_SECONDS"}
          volumeMounts: [{name: scripts, mountPath: /scripts, readOnly: true}]
      volumes: [{name: scripts, configMap: {name: fleet-fuzz-scripts}}]
YAML
  await_job "$job" "$FLEET_CONVERGE_SECONDS" || return 1
  kubectl -n updated-system logs "job/$job"
}

replace_group_deployment() {
  local name="$1"
  local version="$2"
  local sha="$3"
  local deployment
  deployment="{\"name\":\"$name-fuzz-$version\",\"releaseRepository\":{\"metadataUrl\":\"https://release-$name/metadata/\",\"targetsUrl\":\"https://release-$name/targets/\"},\"application\":{\"path\":\"products/app/stable/$version/$PLATFORM/app\",\"sha256\":\"$sha\"},\"providerSet\":{\"path\":\"provider-sets/default.json\",\"sha256\":\"$PROVIDER_SHA\"}}"
  if [ "$name" = default ]; then
    kubectl -n updated-system patch updaterepository default --type=merge \
      -p "{\"spec\":{\"defaultDeployment\":$deployment}}" >/dev/null
  else
    kubectl -n updated-system patch updategroup "$name" --type=merge \
      -p "{\"spec\":{\"deployment\":$deployment}}" >/dev/null
  fi
}

fuzz_state=${UPDATEC_FUZZ_SEED:-20260718}
echo "starting $FUZZ_ROUNDS fleet-fuzz generations (seed $fuzz_state)"
for ((round = 1; round <= FUZZ_ROUNDS; round++)); do
  first=$((4 + (round - 1) * 3))
  edge_version="${first}.0.0"
  batch_version="$((first + 1)).0.0"
  default_version="$((first + 2)).0.0"
  edge_sha="$(app_sha "$edge_version")"
  batch_sha="$(app_sha "$batch_version")"
  default_sha="$(app_sha "$default_version")"
  replace_group_deployment edge "$edge_version" "$edge_sha"
  replace_group_deployment batch "$batch_version" "$batch_sha"
  replace_group_deployment default "$default_version" "$default_sha"

  expected=""
  planned_roles=()
  for index in 0 1 2 3 4; do
    selected_role=""
    selected_version=""
    fuzz_state=$(((fuzz_state * 1103515245 + 12345) & 2147483647))
    if [ "$index" -eq 0 ]; then
      selected_role="edge"
      selected_version="$edge_version"
    else
      case $((fuzz_state % 3)) in
        0) selected_role="edge"; selected_version="$edge_version" ;;
        1) selected_role="batch"; selected_version="$batch_version" ;;
        2) selected_role="default"; selected_version="$default_version" ;;
      esac
    fi
    planned_roles[index]="$selected_role"
    if [ "$selected_role" = default ]; then
      patch='[{"op":"replace","path":"/spec/labels","value":{}}]'
    else
      patch="[{\"op\":\"replace\",\"path\":\"/spec/labels\",\"value\":{\"updated.dev/role\":\"$selected_role\"}}]"
    fi
    resource="${AGENT_RESOURCES[index]}"
    kubectl -n updated-system patch updateagent "$resource" --type=json -p "$patch" >/dev/null
    echo "fuzz generation $round plan: agent-$index -> $selected_role -> $selected_version"
  done

  # Verify the desired state which the API server actually accepted. This keeps
  # the oracle independent from the mutation loop and catches bad/missed patches
  # instead of misreporting a correctly converged agent as broken.
  expected=""
  for index in 0 1 2 3 4; do
    resource="${AGENT_RESOURCES[index]}"
    applied_role="$(kubectl -n updated-system get updateagent "$resource" \
      -o jsonpath='{.spec.labels.updated\.dev/role}')"
    case "$applied_role" in
      edge) applied_version="$edge_version" ;;
      batch) applied_version="$batch_version" ;;
      "") applied_role=default; applied_version="$default_version" ;;
      *)
        echo "FAIL: agent-$index has unexpected applied role '$applied_role'" >&2
        exit 1
        ;;
    esac
    if [ "$applied_role" != "${planned_roles[index]}" ]; then
      echo "FAIL: agent-$index planned role '${planned_roles[index]}', API stored '$applied_role'" >&2
      exit 1
    fi
    echo "fuzz generation $round applied: agent-$index -> $applied_role -> $applied_version"
    expected="$expected agent-$index=$(publish_fuzz_expectation "$applied_version")"
  done

  fuzz_state=$(((fuzz_state * 1103515245 + 12345) & 2147483647))
  case $((fuzz_state % 4)) in
    0)
      echo "fuzz generation $round: restarting controller during convergence"
      kubectl -n updated-system rollout restart deployment/updatec-controller >/dev/null
      kubectl -n updated-system rollout status deployment/updatec-controller --timeout=${READY_TIMEOUT}s >/dev/null
      ;;
    1)
      echo "fuzz generation $round: restarting gateway during convergence"
      kubectl -n updated-system rollout restart deployment/updatec-gateway >/dev/null
      kubectl -n updated-system rollout status deployment/updatec-gateway --timeout=${READY_TIMEOUT}s >/dev/null
      ;;
    2)
      echo "fuzz generation $round: replacing the release origin pod"
      kubectl -n updated-system scale deployment/release-server --replicas=0 >/dev/null
      kubectl -n updated-system wait --for=delete pod -l app=release-server --timeout=${READY_TIMEOUT}s >/dev/null
      kubectl -n updated-system scale deployment/release-server --replicas=1 >/dev/null
      kubectl -n updated-system rollout status deployment/release-server --timeout=${READY_TIMEOUT}s >/dev/null
      ;;
    3)
      echo "fuzz generation $round: briefly removing the controller"
      kubectl -n updated-system scale deployment/updatec-controller --replicas=0 >/dev/null
      sleep 3
      kubectl -n updated-system scale deployment/updatec-controller --replicas=1 >/dev/null
      kubectl -n updated-system rollout status deployment/updatec-controller --timeout=${READY_TIMEOUT}s >/dev/null
      ;;
  esac
  verify_fleet "verify-fuzz-$round" "$expected"
done

# The shared fuzz plan's failure sequence (scripts/lib/publish-fuzz-plan.sh): select
# an unlaunchable newest artifact, prove every node rolls back to its predecessor, then let
# the control plane choose a valid recovery. All three routes are changed so this
# also exercises simultaneous independent rejection state across the 2/2/1 fleet.
echo "fleet fuzz fault: assigning intentionally unlaunchable 18.0.0"
corrupt_sha="$(app_sha 18.0.0)"
for role in edge batch default; do
  replace_group_deployment "$role" 18.0.0 "$corrupt_sha"
done
# Wait for the rejection itself rather than sampling the logs once after a fixed pause: nodes are
# admitted to a deployment in the control plane's own order, so "has this node rejected these bytes
# yet" is a durable fact that arrives when it arrives.
#
# The unit of the assertion is the GROUP, not the node, because containment is the behaviour under
# test. One node's rejection is proof enough to halt the deployment (`maxRegressions` defaults to
# one), and a node that rejected keeps its group's single `maxUnavailable` slot rather than
# releasing it, so the group's remaining nodes are deliberately never handed the corrupt bytes and
# can have no record of them. Requiring every node to hold one would be requiring the bad release to
# reach every node — precisely what the regression response exists to prevent. The fleet e2e states
# the same rule (crates/updatec-e2e/src/chaos.rs).
#
# Do not pipe `kubectl logs` into `grep -q` under pipefail. Once grep finds the line it closes the
# pipe; a sufficiently large log then gives kubectl SIGPIPE and turns a successful assertion into a
# false failure. Both restart generations are read because rejection recovery may itself restart
# the container.
rejected_corrupt() {
  kubectl_log_contains "agent-$1" \
      'recovery: rejected 18.0.0 after failed activation' -c agent \
    || kubectl_log_contains "agent-$1" \
      'recovery: rejected 18.0.0 after failed activation' -c agent --previous
}

# Read the roles back out of the API rather than from the mutation loop's plan, so the oracle for
# "which nodes share a rollout slot" is the state the control plane actually acted on.
declare -a role_of=()
for index in 0 1 2 3 4; do
  applied_role="$(kubectl -n updated-system get updateagent "${AGENT_RESOURCES[index]}" \
    -o jsonpath='{.spec.labels.updated\.dev/role}')"
  role_of[index]="${applied_role:-default}"
done

declare -a rejector_of=()
for role in edge batch default; do
  members=()
  for index in 0 1 2 3 4; do
    if [[ "${role_of[index]}" == "$role" ]]; then
      members+=("$index")
    fi
  done
  [[ ${#members[@]} -gt 0 ]] || continue
  rejector=""
  a_member_rejected_the_corrupt_release() {
    local index
    for index in "${members[@]}"; do
      if rejected_corrupt "$index"; then
        rejector="$index"
        return 0
      fi
    done
    return 1
  }
  poll_until "$NODE_SETTLE_TIMEOUT" a_member_rejected_the_corrupt_release || true
  [[ -n "$rejector" ]] || {
    echo "FAIL: no $role node recorded rejection of corrupt 18.0.0 (members: ${members[*]})" >&2
    for index in "${members[@]}"; do
      kubectl -n updated-system logs "agent-$index" -c agent --tail=100 >&2 || true
    done
    exit 1
  }
  rejector_of[rejector]=1
  echo "$role: agent-$rejector rejected corrupt 18.0.0"
done
verify_fleet verify-fuzz-rollback "$expected"
# Now that the whole fleet has settled back on its predecessors, no OTHER node may hold a record of
# the corrupt bytes: the halt has had every chance to fail to contain them, and did not.
for index in 0 1 2 3 4; do
  if [[ -n "${rejector_of[index]:-}" ]]; then
    continue
  fi
  if rejected_corrupt "$index"; then
    echo "FAIL: corrupt 18.0.0 also reached agent-$index (${role_of[index]}); the halt did not \
contain it to the node that proved the regression" >&2
    exit 1
  fi
done
echo "one node per group rejected 18.0.0, the halt kept it from the rest, and every node retained its exact predecessor"

for recovery_version in 19.0.0 20.0.0; do
  recovery_sha="$(app_sha "$recovery_version")"
  for role in edge batch default; do
    replace_group_deployment "$role" "$recovery_version" "$recovery_sha"
  done
  recovery_artifact="$(publish_fuzz_artifact "$recovery_version")"
  recovery_expected=""
  for index in 0 1 2 3 4; do
    recovery_expected="$recovery_expected agent-$index=$recovery_version,$recovery_artifact"
  done
  verify_fleet "verify-fuzz-recovery-${recovery_version%%.*}" "$recovery_expected"
done
echo "fleet recovered through sampleapp 19.0.0 -> stateful-like 20.0.0"
echo "fleet observer transitions during chaos:"
kubectl -n updated-system logs -l job-name=observe-fleet-chaos --prefix --all-containers=true
kubectl -n updated-system delete job observe-fleet-chaos --wait=true >/dev/null
else
  echo "fleet fuzz skipped (--fuzz-rounds 0)"
fi

# The Rust fleet E2E uses this exact provisioning and verification path, then adds its larger
# topology. Its fixture must retain the live repository; the standalone Kind scenario continues
# below into the intentionally ambiguous generation and destructive repository-finalizer checks.
if [[ "$PRESERVE_REPOSITORY" == true ]]; then
  echo "converged Kind fixture preserved for the fleet E2E"
  exit 0
fi
cat <<YAML | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata: {name: routing-digest-before-overlap, namespace: updated-system}
spec:
  backoffLimit: 0
  activeDeadlineSeconds: $(job_deadline "$ONESHOT_JOB_SECONDS")
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: digest
          image: updatec-e2e:kind
          command: [/bin/sh, -ec]
          args: ['curl -fsS --cert /tls/tls.crt --key /tls/tls.key --cacert /tls/ca.crt https://updatec-gateway/metadata/timestamp.json | sha256sum | cut -d" " -f1']
          volumeMounts: [{name: tls, mountPath: /tls, readOnly: true}]
      volumes: [{name: tls, secret: {secretName: routing-probe-tls}}]
YAML
await_job routing-digest-before-overlap "$ONESHOT_JOB_SECONDS"
before="$(kubectl -n updated-system logs job/routing-digest-before-overlap)"
cargo run -q -p updatec-e2e -- resources \
  "$PLATFORM" "$APP_V1_SHA" "$APP_V2_SHA" "$APP_V3_SHA" "$PROVIDER_SHA" \
  "$WORK/release-root.json" overlap | kubectl apply -f -
sleep 8
cat <<YAML | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata: {name: routing-digest-after-overlap, namespace: updated-system}
spec:
  backoffLimit: 0
  activeDeadlineSeconds: $(job_deadline "$ONESHOT_JOB_SECONDS")
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: digest
          image: updatec-e2e:kind
          command: [/bin/sh, -ec]
          args: ['curl -fsS --cert /tls/tls.crt --key /tls/tls.key --cacert /tls/ca.crt https://updatec-gateway/metadata/timestamp.json | sha256sum | cut -d" " -f1']
          volumeMounts: [{name: tls, mountPath: /tls, readOnly: true}]
      volumes: [{name: tls, secret: {secretName: routing-probe-tls}}]
YAML
await_job routing-digest-after-overlap "$ONESHOT_JOB_SECONDS"
after="$(kubectl -n updated-system logs job/routing-digest-after-overlap)"
test "$before" = "$after"
ambiguous_logged=false
for attempt in {1..30}; do
  controller_logs="$(kubectl -n updated-system logs -l app=updatec-controller \
    --all-containers=true --prefix=true --tail=200 2>/dev/null || true)"
  if grep -q 'AmbiguousNode' <<<"$controller_logs"; then
    ambiguous_logged=true
    break
  fi
  sleep 1
done
if [[ "$ambiguous_logged" != true ]]; then
  echo "FAIL: controller did not report AmbiguousNode while preserving the last routing generation" >&2
  kubectl -n updated-system logs -l app=updatec-controller \
    --all-containers=true --prefix=true --tail=200 >&2 || true
  exit 1
fi

# Deletion is one repository-epoch boundary, not three eventually consistent cleanup paths. Seed
# sentinels immediately beside and outside the repository's owned S3 prefix, then require the
# finalizer to remove only the owned prefix, the fixed-name admitted-state projection, and the
# controller's local TUF epoch before Kubernetes releases the CR name.
kubectl -n updated-system run repository-delete-seed --restart=Never \
  --image=minio/mc:RELEASE.2025-04-16T18-13-26Z --command -- sh -ec \
  "mc alias set local http://minio:9000 minio minio123 >/dev/null
printf owned | mc pipe local/updates/${MANAGED_REPOSITORY_PREFIX}/deletion-owned
printf sibling | mc pipe local/updates/routing/updated-system/sibling/keep
printf outside | mc pipe local/updates/outside/keep"
kubectl -n updated-system wait pod/repository-delete-seed \
  --for=jsonpath='{.status.phase}'=Succeeded --timeout=${READY_TIMEOUT}s

kubectl -n updated-system delete updaterepository default --wait=false >/dev/null
repository_deleted() {
  ! kubectl -n updated-system get updaterepository default >/dev/null 2>&1
}
if ! poll_until "$READY_TIMEOUT" repository_deleted; then
  echo "FAIL: repository finalizer did not complete its epoch cleanup" >&2
  kubectl -n updated-system get updaterepository default -o yaml >&2 || true
  kubectl -n updated-system logs deployment/updatec-controller --tail=200 >&2 || true
  exit 1
fi

remaining_state="$(kubectl -n updated-system get configmaps \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}' \
  | grep -E '^updatec-admitted-default(-[ab]-[0-9][0-9])?$' || true)"
if [[ -n "$remaining_state" ]]; then
  echo "FAIL: deleted repository left admitted-state ConfigMaps:" >&2
  echo "$remaining_state" >&2
  exit 1
fi
if ! kubectl -n updated-system exec deployment/updatec-controller -- sh -ec '
  for path in repository keys published-generation.json pending-state.json; do
    test ! -e "/var/lib/updatec/$path" || {
      echo "repository-local state survived deletion: $path" >&2
      exit 1
    }
  done
'; then
  echo "FAIL: deleted repository left controller-local TUF state" >&2
  exit 1
fi

kubectl -n updated-system run repository-delete-check --restart=Never \
  --image=minio/mc:RELEASE.2025-04-16T18-13-26Z --command -- sh -ec \
  "mc alias set local http://minio:9000 minio minio123 >/dev/null
remaining=\$(mc ls --recursive local/updates/${MANAGED_REPOSITORY_PREFIX} 2>/dev/null || true)
test -z \"\$remaining\" || { echo \"owned prefix survived deletion: \$remaining\" >&2; exit 1; }
mc stat local/updates/routing/updated-system/sibling/keep >/dev/null
mc stat local/updates/outside/keep >/dev/null"
if ! kubectl -n updated-system wait pod/repository-delete-check \
  --for=jsonpath='{.status.phase}'=Succeeded --timeout=${READY_TIMEOUT}s; then
  echo "FAIL: repository deletion crossed its exact object-storage boundary" >&2
  kubectl -n updated-system logs repository-delete-check >&2 || true
  exit 1
fi

# The controller intentionally remains installed after its sole repository is removed. Give it two
# fresh one-second passes, then prove absence is a quiet waiting state rather than a synthetic 404
# failure loop against a status endpoint that no longer exists.
sleep 3
post_delete_logs="$(kubectl -n updated-system logs deployment/updatec-controller \
  --since=2s 2>/dev/null || true)"
if grep -q 'reconciliation failed' <<<"$post_delete_logs"; then
  echo "FAIL: ordinary repository absence is still reported as reconciliation failure" >&2
  echo "$post_delete_logs" >&2
  exit 1
fi
echo "repository deletion atomically cleared its S3, Kubernetes, local, and in-memory epoch"
echo "updatec Kind E2E passed: five real agents updated and were verified through version endpoints"
