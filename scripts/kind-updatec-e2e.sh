#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Fail with the tool's name rather than mid-provision inside a command substitution,
# where `set -euo pipefail` kills the run with no diagnostic. The digest tool is
# coreutils `sha256sum` here and in every container job below — one spelling only.
for command in kind kubectl docker curl openssl awk sha256sum cargo; do
  command -v "$command" >/dev/null || { echo "FAIL: missing required command: $command" >&2; exit 2; }
done
. "$ROOT/scripts/lib/publish-fuzz-plan.sh"
FUZZ_ROUNDS=${UPDATEC_FUZZ_ROUNDS:-1}
while (( $# > 0 )); do
  case "$1" in
    --fuzz-rounds)
      [[ $# -ge 2 ]] || { echo "FAIL: --fuzz-rounds needs a value" >&2; exit 2; }
      FUZZ_ROUNDS=$2
      shift 2
      ;;
    --help|-h)
      echo "usage: $0 [--fuzz-rounds N]"
      echo "  N=0 skips fleet fuzz; default: ${UPDATEC_FUZZ_ROUNDS:-1}"
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
NAME="${UPDATEC_KIND_CLUSTER:-updatec-e2e}"
KUBE_CONTEXT="kind-$NAME"
# Never depend on kubectl's process-global current context. The demo, CI, and a
# developer's separate Kind run may execute concurrently; pinning every operation is
# the only way namespace creation and all later resources remain in the same cluster.
kubectl() { command kubectl --context "$KUBE_CONTEXT" "$@"; }
WORK="$ROOT/target/kind-$NAME"
cleanup() { kind delete cluster --name "$NAME" >/dev/null 2>&1 || true; }
finish() {
  local status=$?
  if (( status == 0 )) && [[ "${UPDATEC_KEEP_KIND_CLUSTER:-0}" != 1 ]]; then
    cleanup
    return
  fi
  echo >&2
  if (( status == 0 )); then
    echo "Kind E2E succeeded; preserving cluster '$NAME' because UPDATEC_KEEP_KIND_CLUSTER=1" >&2
  else
    echo "Kind E2E failed (exit $status); preserving cluster '$NAME' for diagnosis" >&2
  fi
  echo "inspect with: kubectl -n updated-system get pods,jobs" >&2
  echo "agent logs:   kubectl -n updated-system logs agent-4" >&2
  echo "remove with:  kind delete cluster --name $NAME" >&2
  kubectl -n updated-system get pods,jobs >&2 || true
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
trap finish EXIT
cleanup
mkdir -p "$WORK"

cat >"$WORK/kind.yaml" <<'YAML'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
    # Lets an ingress-nginx controller schedule (its nodeSelector is ingress-ready=true),
    # so the demo can front each set's pods with a real per-set Ingress.
    labels:
      ingress-ready: "true"
    # Publish the ingress controller on the host's ports 80/443, so both the browser AND the
    # co-located out-of-cluster agent reach every endpoint through nginx — the agent resolves
    # updatec-gateway/release-default to 127.0.0.1 (nginx), no socat or LAN-IP needed.
    extraPortMappings:
      - { containerPort: 80, hostPort: 80, protocol: TCP }
      - { containerPort: 443, hostPort: 443, protocol: TCP }
    kubeadmConfigPatches:
      - |
        kind: KubeletConfiguration
        apiVersion: kubelet.config.k8s.io/v1beta1
        maxPods: 250
YAML
kind create cluster --name "$NAME" --config "$WORK/kind.yaml"
cargo run -q -p updatec --example crdgen >"$WORK/crds.yaml"
kubectl apply -f "$WORK/crds.yaml"
kubectl create namespace updated-system

kubectl -n updated-system create deployment minio --image=minio/minio:RELEASE.2025-04-22T22-12-26Z
kubectl -n updated-system patch deployment minio --type=json -p='[{"op":"add","path":"/spec/template/spec/containers/0/args","value":["server","/data"]}]'
kubectl -n updated-system set env deployment/minio MINIO_ROOT_USER=minio MINIO_ROOT_PASSWORD=minio123
kubectl -n updated-system expose deployment minio --port=9000
kubectl -n updated-system rollout status deployment/minio --timeout=120s
kubectl -n updated-system run minio-init --restart=Never --image=minio/mc:RELEASE.2025-04-16T18-13-26Z --command -- sh -c \
  'until mc alias set local http://minio:9000 minio minio123; do sleep 1; done; mc mb --ignore-existing local/updates; mc anonymous set download local/updates'
kubectl -n updated-system wait pod/minio-init --for=condition=Ready=false --timeout=1s >/dev/null 2>&1 || true
kubectl -n updated-system wait pod/minio-init --for=jsonpath='{.status.phase}'=Succeeded --timeout=120s

# Ingress controller: cluster infrastructure, provisioned here alongside minio so every
# environment built from this script is ingress-capable. The demo fronts each set's
# load-balancer Service with a per-set Ingress on this controller, so Kubernetes — not the
# demo's own routing — guarantees a set is only ever answered by its own pods. Scheduled
# onto the ingress-ready control-plane node (see the kind config above).
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.11.2/deploy/static/provider/kind/deploy.yaml
kubectl -n ingress-nginx rollout status deployment/ingress-nginx-controller --timeout=180s

# cert-manager issues the fleet mTLS material: a self-signed root CA, then the gateway's server
# certificate and the agents' client certificate, all from that one CA. The gateway (the only
# externally exposed listener) requires a client cert the CA signed — that mutual TLS is the
# enrollment identity, so there is no shared secret anywhere.
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.15.3/cert-manager.yaml
kubectl -n cert-manager rollout status deployment/cert-manager-webhook --timeout=180s
kubectl -n cert-manager rollout status deployment/cert-manager --timeout=180s
kubectl -n cert-manager rollout status deployment/cert-manager-cainjector --timeout=180s
cat <<'YAML' | kubectl apply -f -
apiVersion: cert-manager.io/v1
kind: Issuer
metadata: {name: fleet-selfsigned, namespace: updated-system}
spec: {selfSigned: {}}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: fleet-ca, namespace: updated-system}
spec:
  isCA: true
  commonName: updated-fleet-ca
  secretName: fleet-ca
  privateKey: {algorithm: ECDSA, size: 256}
  issuerRef: {name: fleet-selfsigned, kind: Issuer}
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata: {name: fleet-ca-issuer, namespace: updated-system}
spec: {ca: {secretName: fleet-ca}}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: gateway-tls, namespace: updated-system}
spec:
  secretName: gateway-tls
  commonName: updatec-gateway
  dnsNames: [updatec-gateway, release-default, release-edge, release-batch, localhost]
  usages: [server auth]
  issuerRef: {name: fleet-ca-issuer, kind: Issuer}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: agent-tls, namespace: updated-system}
spec:
  secretName: agent-tls
  commonName: updated-agent
  usages: [client auth]
  issuerRef: {name: fleet-ca-issuer, kind: Issuer}
---
# An intruder identity issued by the self-signed issuer directly (NOT the fleet CA), so the
# gateway rejects it — proving the mTLS gate fails closed for a non-fleet client.
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: intruder-tls, namespace: updated-system}
spec:
  secretName: intruder-tls
  commonName: intruder
  usages: [client auth]
  issuerRef: {name: fleet-selfsigned, kind: Issuer}
YAML
kubectl -n updated-system wait --for=condition=Ready certificate/gateway-tls --timeout=120s
kubectl -n updated-system wait --for=condition=Ready certificate/agent-tls --timeout=120s
kubectl -n updated-system wait --for=condition=Ready certificate/intruder-tls --timeout=120s

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
            # The fleet server cert + CA: release-server terminates mTLS, so it needs the same
            # gateway-tls material the gateway uses.
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
kubectl -n updated-system rollout status deployment/release-server --timeout=180s
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
kubectl -n updated-system create secret generic tuf-signing-keys --from-file="$WORK/keys/root.pk8" --from-file="$WORK/keys/targets.pk8" --from-file="$WORK/keys/snapshot.pk8" --from-file="$WORK/keys/timestamp.pk8"
kubectl -n updated-system create secret generic s3-credentials --from-literal=AWS_ACCESS_KEY_ID=minio --from-literal=AWS_SECRET_ACCESS_KEY=minio123

cargo run -q -p updatec --example kind_resources -- \
  "$PLATFORM" "$APP_V1_SHA" "$APP_V2_SHA" "$APP_V3_SHA" "$PROVIDER_SHA" \
  "$WORK/release-root.json" >"$WORK/resources.yaml"
kubectl apply -f "$WORK/resources.yaml"

docker build -f crates/updatec/Dockerfile -t updatec:kind .
kind load docker-image --name "$NAME" updatec:kind
# Deploy the operator with its public URL already pointing at the in-cluster gateway. Substituting
# it into the manifest BEFORE apply (rather than `kubectl set env` after) means the controller never
# starts on the placeholder URL — otherwise a reconcile during the env rollout can mint an
# *immutable* enrollment bundle that points a node at the placeholder, wedging that node's first boot.
sed 's#https://updates.example/routing#https://updatec-gateway#g' deploy/kubernetes/updatec.yaml \
  | kubectl apply -f -
kubectl -n updated-system rollout status deployment/updatec-controller --timeout=180s
kubectl -n updated-system rollout status deployment/updatec-gateway --timeout=180s

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

# Exercise the operator-driven enrollment route end to end. The controller turns a manual
# UpdateAgent into an immutable signed enrollment Secret. The init container places only that
# trust artifact; the supervisor then performs the same repository-backed cold install used by
# every other fresh node.
cat <<'YAML' | kubectl apply -f -
apiVersion: updated.dev/v1alpha1
kind: UpdateAgent
metadata: {name: manual-offline, namespace: updated-system}
spec:
  repositoryRef: {name: default}
  identity: {kind: manual}
  labels: {}
YAML
echo "waiting for the manual agent's signed installer artifact"
for attempt in {1..60}; do
  MANUAL_ENROLLMENT_SECRET="$(kubectl -n updated-system get updateagent manual-offline \
    -o jsonpath='{.status.enrollmentSecretRef.name}' 2>/dev/null || true)"
  if [[ -n "$MANUAL_ENROLLMENT_SECRET" ]] && \
    kubectl -n updated-system get secret "$MANUAL_ENROLLMENT_SECRET" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done
if [[ -z "${MANUAL_ENROLLMENT_SECRET:-}" ]]; then
  echo "FAIL: manual agent never received an enrollment Secret" >&2
  kubectl -n updated-system get updateagent manual-offline -o yaml >&2 || true
  exit 1
fi
cat >"$WORK/manual-offline.yaml" <<YAML
apiVersion: v1
kind: ConfigMap
metadata: {name: manual-offline-bootstrap, namespace: updated-system}
data:
  bootstrap.toml: |
    [enrollment]
    # The preplaced signed bundle gives this node its routing/assignment/initial config for a
    # network-free first start, so it never fetches the bundle over the network. Identity is
    # separate: it still mints its per-node steady-state leaf at /enroll the first time it reaches
    # the real gateway (the node generates its own key + CSR — the key never leaves the node).
    url = "https://updatec-gateway"
    name = "manual-offline"
    client_cert = "/etc/agent-tls/tls.crt"
    client_key = "/etc/agent-tls/tls.key"
    ca = "/etc/agent-tls/ca.crt"
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
          mkdir -p /var/lib/updated/guardian
          cp /signed/enrollment.json /var/lib/updated/guardian/enrollment.json
      volumeMounts:
        - {name: state, mountPath: /var/lib/updated}
        - {name: enrollment, mountPath: /signed, readOnly: true}
  containers:
    - name: agent
      image: updatec-e2e:kind
      imagePullPolicy: IfNotPresent
      command: [/usr/local/bin/bootstrap]
      args: [--state-dir, /var/lib/updated/guardian, --supervisor-config, /bootstrap/bootstrap.toml, --supervisor, /usr/local/bin/supervisor, --ready-timeout, "30", --confirm-timeout, "2", --probe-address, 0.0.0.0:9090]
      ports: [{name: http, containerPort: 8080}, {name: guardian, containerPort: 9090}]
      startupProbe: {httpGet: {path: /startupz, port: guardian}, periodSeconds: 1, failureThreshold: 60}
      readinessProbe: {httpGet: {path: /readyz, port: guardian}, periodSeconds: 1}
      livenessProbe: {httpGet: {path: /livez, port: guardian}, periodSeconds: 2}
      securityContext:
        allowPrivilegeEscalation: false
        capabilities: {drop: [ALL]}
        readOnlyRootFilesystem: true
        runAsNonRoot: true
        runAsUser: 65532
      volumeMounts:
        - {name: state, mountPath: /var/lib/updated}
        - {name: bootstrap, mountPath: /bootstrap, readOnly: true}
        # The offline agent still fronts the real gateway for routing/secrets after its
        # network-free cold install, so it carries the same shared fleet mTLS identity every
        # other agent does (its bootstrap.toml points its client cert/key/CA here).
        - {name: agent-tls, mountPath: /etc/agent-tls, readOnly: true}
  volumes:
    - {name: state, emptyDir: {}}
    - name: enrollment
      secret: {secretName: $MANUAL_ENROLLMENT_SECRET}
    - name: bootstrap
      configMap: {name: manual-offline-bootstrap}
    - {name: agent-tls, secret: {secretName: agent-tls}}
YAML
kubectl apply -f "$WORK/manual-offline.yaml"
kubectl -n updated-system wait pod/manual-offline --for=condition=Ready --timeout=120s
MANUAL_VERSION="$(kubectl -n updated-system exec manual-offline -c agent -- \
  curl -fsS http://127.0.0.1:8080/version)"
[[ "$MANUAL_VERSION" == 1.0.0 ]] || {
  echo "FAIL: pre-enrolled manual agent launched version '$MANUAL_VERSION', expected 1.0.0" >&2
  exit 1
}
kubectl_log_contains manual-offline 'started managed application pid' -c agent
echo "manual CRD export enrolled, cold-installed, and launched 1.0.0"

# A malformed enrollment artifact is terminal: it must never fall back to the URL/key or launch
# an application. `timeout` bounds bootstrap's intentional supervision retries so Kubernetes
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
          mkdir -p /var/lib/updated/guardian
          cp /signed/enrollment.json /var/lib/updated/guardian/enrollment.json
          printf tampered >>/var/lib/updated/guardian/enrollment.json
      volumeMounts:
        - {name: state, mountPath: /var/lib/updated}
        - {name: enrollment, mountPath: /signed, readOnly: true}
  containers:
    - name: agent
      image: updatec-e2e:kind
      command: [/bin/sh, -ec]
      args: ["timeout 15 bootstrap --state-dir /var/lib/updated/guardian --supervisor-config /bootstrap/bootstrap.toml --supervisor /usr/local/bin/supervisor --ready-timeout 5 --confirm-timeout 2"]
      volumeMounts:
        - {name: state, mountPath: /var/lib/updated}
        - {name: bootstrap, mountPath: /bootstrap, readOnly: true}
  volumes:
    - {name: state, emptyDir: {}}
    - name: enrollment
      secret: {secretName: $MANUAL_ENROLLMENT_SECRET}
    - name: bootstrap
      configMap: {name: manual-offline-bootstrap}
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
[[ "$BAD_LOG" != *"started application pid"* ]]
echo "corrupted installer enrollment failed closed before application launch"

# Invalid online credentials are also fail-closed and may not leave registration state. The gateway
# creates the UpdateAgent under the name the node self-asserts in its bootstrap file, so that is the
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
          mkdir -p /var/lib/updated/guardian
          # Present an intruder client cert NOT signed by the fleet CA: the gateway must reject
          # it at the mTLS handshake so enrollment fails closed. It still trusts the real fleet
          # CA for the gateway's server cert.
          cat >/tmp/bootstrap.toml <<EOF
          [enrollment]
          url = "https://updatec-gateway"
          name = "intruder"
          client_cert = "/etc/intruder-tls/tls.crt"
          client_key = "/etc/intruder-tls/tls.key"
          ca = "/etc/agent-tls/ca.crt"
          EOF
          timeout 15 bootstrap --state-dir /var/lib/updated/guardian \
            --supervisor-config /tmp/bootstrap.toml --supervisor /usr/local/bin/supervisor \
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
  ports: [{name: http, port: 8080, targetPort: http}, {name: guardian, port: 9090, targetPort: guardian}]
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
          ports: [{name: http, containerPort: 8080}, {name: guardian, containerPort: 9090}]
          startupProbe: {httpGet: {path: /startupz, port: guardian}, periodSeconds: 1, failureThreshold: 120}
          readinessProbe: {httpGet: {path: /readyz, port: guardian}, periodSeconds: 1}
          livenessProbe: {httpGet: {path: /livez, port: guardian}, periodSeconds: 2}
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
echo "waiting for all five real agent towers to reach their assigned versions"
kubectl -n updated-system rollout status statefulset/agent --timeout=240s
# The `UpdateAgent` name pod `agent-<ordinal>` enrolls under. Read from the single definition of
# that derivation (`resource_name`, crates/updatec-demo/src/setup.rs) — the same one the pods
# themselves use through `updatec-demo agent-name` — never re-derived here. Derived once for all
# five ordinals, in assignment position: a substitution in *argument* position would not abort
# under `set -e` on failure, and would hand kubectl an empty resource name.
agent_resource_name() {
  cargo run -q -p updatec-demo -- agent-name "agent-$1"
}
declare -a AGENT_RESOURCES
for ordinal in 0 1 2 3 4; do
  AGENT_RESOURCES[ordinal]="$(agent_resource_name "$ordinal")"
done
for ordinal in 0 1 2 3 4; do
  resource="${AGENT_RESOURCES[ordinal]}"
  identity="$(kubectl -n updated-system get updateagent "$resource" -o jsonpath='{.spec.identity.kind}')"
  [[ "$identity" == enrolled ]] || {
    echo "FAIL: agent-$ordinal registered with identity '$identity', expected enrolled" >&2
    exit 1
  }
  kubectl -n updated-system exec "agent-$ordinal" -c agent -- \
    grep -q '"routingBaseUrl":"https://updatec-gateway/"' \
      /var/lib/updated/guardian/enrollment.json || {
    echo "FAIL: agent-$ordinal did not persist the reachable in-cluster routing URL" >&2
    exit 1
  }
  log="$(kubectl -n updated-system logs "agent-$ordinal" -c agent)"
  [[ "$log" == *"cold-installed application 1.0.0 from the first trusted assignment"* ]] || {
    echo "FAIL: agent-$ordinal did not cold-install through online enrollment" >&2
    echo "$log" >&2
    exit 1
  }
  [[ "$log" != *"FAIL: agent used the image-baked"* ]] || {
    echo "FAIL: agent-$ordinal executed a masked image-baked application" >&2
    exit 1
  }
done
echo "all five empty agents enrolled online and cold-installed the network assignment"

# Exercise certificate renewal through the live gateway without restarting the pod, container, or
# application. Replace agent-4's leaf with a fleet-CA-signed one-day leaf for the SAME durable key,
# terminate only the supervisor, and let the guardian adopt the still-running application. The new
# supervisor sees the short lifetime immediately, calls /renew with that current identity, installs
# the replacement atomically, and exits once so the guardian rebuilds every authenticated client.
ROTATION_AGENT=agent-4
ROTATION_RESOURCE="${AGENT_RESOURCES[4]}"
ROTATION_STATE=/var/lib/updated/guardian
ROTATION_DIR="$WORK/certificate-rotation"
mkdir -p "$ROTATION_DIR"
kubectl -n updated-system exec "$ROTATION_AGENT" -c agent -- \
  cat "$ROTATION_STATE/agent.key" >"$ROTATION_DIR/agent.key"
kubectl -n updated-system exec "$ROTATION_AGENT" -c agent -- \
  cat "$ROTATION_STATE/agent.crt" >"$ROTATION_DIR/original.crt"
kubectl -n updated-system get secret fleet-ca -o jsonpath='{.data.tls\.crt}' \
  | openssl base64 -d -A >"$ROTATION_DIR/ca.crt"
kubectl -n updated-system get secret fleet-ca -o jsonpath='{.data.tls\.key}' \
  | openssl base64 -d -A >"$ROTATION_DIR/ca.key"
openssl req -new -key "$ROTATION_DIR/agent.key" \
  -subj "/CN=$ROTATION_RESOURCE" -out "$ROTATION_DIR/agent.csr"
cat >"$ROTATION_DIR/extensions.cnf" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=clientAuth
subjectAltName=URI:spiffe://updated.fleet/scope/default/node/$ROTATION_RESOURCE
EOF
openssl x509 -req -in "$ROTATION_DIR/agent.csr" \
  -CA "$ROTATION_DIR/ca.crt" -CAkey "$ROTATION_DIR/ca.key" -CAcreateserial \
  -days 1 -extfile "$ROTATION_DIR/extensions.cnf" -out "$ROTATION_DIR/short.crt"

pod_uid_before="$(kubectl -n updated-system get pod "$ROTATION_AGENT" -o jsonpath='{.metadata.uid}')"
restart_before="$(kubectl -n updated-system get pod "$ROTATION_AGENT" \
  -o jsonpath='{.status.containerStatuses[0].restartCount}')"
key_before="$(sha256sum "$ROTATION_DIR/agent.key" | awk '{print $1}')"
original_cert="$(sha256sum "$ROTATION_DIR/original.crt" | awk '{print $1}')"
short_cert="$(sha256sum "$ROTATION_DIR/short.crt" | awk '{print $1}')"
[[ "$short_cert" != "$original_cert" ]]
process_pid() {
  local process="$1"
  kubectl -n updated-system exec "$ROTATION_AGENT" -c agent -- sh -ec '
    for path in /proc/[0-9]*; do
      [ "$(cat "$path/comm" 2>/dev/null || true)" = "$1" ] || continue
      echo "${path##*/}"
      exit 0
    done
    exit 1
  ' sh "$process"
}
supervisor_before="$(process_pid supervisor)"
application_before="$(process_pid app)"

cat <<'YAML' | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata: {name: observe-certificate-rotation, namespace: updated-system}
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 90
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: observe
          image: updatec-e2e:kind
          command: [/bin/sh, -ec]
          args:
            - |
              failures=0
              for attempt in $(seq 1 45); do
                version=$(curl -fsS --max-time 1 http://agent-4.agents:8080/version || true)
                [ "$version" = 1.0.0 ] || failures=$((failures + 1))
                sleep 1
              done
              [ "$failures" -eq 0 ] || {
                echo "application was unavailable for $failures observation(s)" >&2
                exit 1
              }
              echo "application stayed available throughout certificate renewal"
YAML
kubectl -n updated-system wait --for=condition=ready \
  pod -l job-name=observe-certificate-rotation --timeout=30s

# Install the near-expiry leaf completely before signalling the supervisor. Existing clients keep
# using their in-memory identity until the guardian relaunches the supervisor.
kubectl -n updated-system exec -i "$ROTATION_AGENT" -c agent -- \
  sh -c "cat >'$ROTATION_STATE/agent.crt'" <"$ROTATION_DIR/short.crt"
kubectl -n updated-system exec "$ROTATION_AGENT" -c agent -- \
  kill -TERM "$supervisor_before"

renewed=false
for attempt in $(seq 1 90); do
  kubectl -n updated-system exec "$ROTATION_AGENT" -c agent -- \
    cat "$ROTATION_STATE/agent.crt" >"$ROTATION_DIR/renewed.crt"
  renewed_cert="$(sha256sum "$ROTATION_DIR/renewed.crt" | awk '{print $1}')"
  supervisor_after="$(process_pid supervisor 2>/dev/null || true)"
  if [[ "$renewed_cert" != "$short_cert" && -n "$supervisor_after" \
      && "$supervisor_after" != "$supervisor_before" ]]; then
    renewed=true
    break
  fi
  sleep 1
done
[[ "$renewed" == true ]] || {
  echo "FAIL: agent-4 did not renew its short-lived certificate and relaunch its supervisor" >&2
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
    --cacert /etc/agent-tls/ca.crt https://updatec-gateway/v1/node/secrets \
    >/dev/null
# The shared fleet bootstrap certificate authenticates the one /enroll handshake and NOTHING else.
# It is signed by the same fleet CA, so it completes the mTLS handshake — but it carries no SPIFFE
# node SAN, so every steady-state route must refuse it. Otherwise any holder of the fleet-wide
# enrollment Secret could read a node's assigned secrets. Repository content stays readable (it is
# not node-scoped), which the timestamp.json fetch above already proves for the same certificate.
if kubectl -n updated-system exec "$ROTATION_AGENT" -c agent -- \
  curl -fsS --cert /etc/agent-tls/tls.crt --key /etc/agent-tls/tls.key \
    --cacert /etc/agent-tls/ca.crt https://updatec-gateway/v1/node/secrets \
    >/dev/null 2>&1; then
  echo "FAIL: the shared bootstrap certificate was served node secrets" >&2
  exit 1
fi
echo "the shared bootstrap certificate is refused on steady-state node routes"
kubectl -n updated-system wait --for=condition=complete \
  job/observe-certificate-rotation --timeout=90s
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
cat <<'YAML' | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata: {name: verify-agent-versions, namespace: updated-system}
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 120
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: verify
          image: updatec-e2e:kind
          imagePullPolicy: IfNotPresent
          command: [/bin/sh, -ec]
          args:
            - |
              check() {
                agent="$1" expected="$2" expected_artifact="$3"
                for attempt in $(seq 1 60); do
                  actual=$(curl -fsS "http://${agent}.agents:8080/version" || true)
                  artifact=$(curl -fsS "http://${agent}.agents:8080/artifact" || true)
                  if [ "$actual" = "$expected" ] && [ "$artifact" = "$expected_artifact" ]; then
                    echo "$agent: $actual ($artifact)"
                    return 0
                  fi
                  sleep 1
                done
                echo "$agent: expected $expected, got ${actual:-unreachable}" >&2
                return 1
              }
              check agent-0 2.0.0 jenkins
              check agent-1 2.0.0 jenkins
              check agent-2 3.0.0 sampleapp
              check agent-3 3.0.0 sampleapp
              check agent-4 1.0.0 sampleapp
              echo "all 5 agents reached their control-plane-selected versions (2/2/1)"
YAML
kubectl -n updated-system wait --for=condition=complete job/verify-agent-versions --timeout=150s
kubectl -n updated-system logs job/verify-agent-versions

# A real application crash is not a planned drain. The guardian marks the tower
# failed, exits with the application, and lets Kubernetes restart the container.
# The pod and its emptyDir survive that container restart, so the new guardian must
# verify and relaunch the same committed bundle before readiness returns.
restart_before="$(kubectl -n updated-system get pod agent-4 -o jsonpath='{.status.containerStatuses[0].restartCount}')"
kubectl -n updated-system exec agent-4 -c agent -- \
  sh -c 'curl -fsS http://127.0.0.1:8080/crash >/dev/null || true' || true
restarted=false
for attempt in $(seq 1 60); do
  restart_after="$(kubectl -n updated-system get pod agent-4 -o jsonpath='{.status.containerStatuses[0].restartCount}')"
  if [ "$restart_after" -gt "$restart_before" ]; then
    restarted=true
    break
  fi
  sleep 1
done
[[ "$restarted" == true ]] || {
  echo "FAIL: Kubernetes did not restart agent-4 after its managed application crashed" >&2
  kubectl -n updated-system logs agent-4 -c agent --previous >&2 || true
  exit 1
}
kubectl -n updated-system wait --for=condition=ready pod/agent-4 --timeout=120s
recovered_version="$(kubectl -n updated-system exec agent-4 -c agent -- curl -fsS http://127.0.0.1:8080/version)"
[[ "$recovered_version" == 1.0.0 ]] || {
  echo "FAIL: agent-4 recovered as '$recovered_version', expected committed 1.0.0" >&2
  exit 1
}
echo "managed application crash failed the guardian tower; Kubernetes restarted it and readiness recovered"

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
    echo "waiting for exact fleet convergence: $EXPECTED"
    for pair in $EXPECTED; do
      agent=${pair%%=*}
      wanted=${pair#*=}
      expected=${wanted%%,*}
      expected_artifact=${wanted#*,}
      actual=""
      for attempt in $(seq 1 90); do
        actual=$(curl -fsS "http://${agent}.agents:8080/version" 2>/dev/null || true)
        artifact=$(curl -fsS "http://${agent}.agents:8080/artifact" 2>/dev/null || true)
        health=$(curl -fsS "http://${agent}.agents:8080/healthz" 2>/dev/null || true)
        if [ "$actual" = "$expected" ] && [ "$artifact" = "$expected_artifact" ] && [ "$health" = "ok" ]; then break; fi
        if [ $((attempt % 10)) -eq 0 ]; then
          echo "$agent: still waiting for $expected/$expected_artifact/ok (${attempt}/90); currently ${actual:-unreachable}/${artifact:-unreachable}/${health:-unreachable}"
        fi
        sleep 1
      done
      if [ "$actual" != "$expected" ] || [ "$artifact" != "$expected_artifact" ] || [ "$health" != "ok" ]; then
        echo "$agent: expected $expected/$expected_artifact/ok, got ${actual:-unreachable}/${artifact:-unreachable}/${health:-unreachable}" >&2
        exit 1
      fi
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
  activeDeadlineSeconds: $((OBSERVER_ITERATIONS + 60))
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
  activeDeadlineSeconds: 120
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: verify
          image: updatec-e2e:kind
          command: [/bin/sh, /scripts/verify.sh]
          env: [{name: EXPECTED, value: "$expected"}]
          volumeMounts: [{name: scripts, mountPath: /scripts, readOnly: true}]
      volumes: [{name: scripts, configMap: {name: fleet-fuzz-scripts}}]
YAML
  if ! kubectl -n updated-system wait --for=condition=complete "job/$job" --timeout=130s; then
    kubectl -n updated-system logs "job/$job" >&2 || true
    return 1
  fi
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
      kubectl -n updated-system rollout status deployment/updatec-controller --timeout=120s >/dev/null
      ;;
    1)
      echo "fuzz generation $round: restarting gateway during convergence"
      kubectl -n updated-system rollout restart deployment/updatec-gateway >/dev/null
      kubectl -n updated-system rollout status deployment/updatec-gateway --timeout=120s >/dev/null
      ;;
    2)
      echo "fuzz generation $round: replacing the release origin pod"
      kubectl -n updated-system scale deployment/release-server --replicas=0 >/dev/null
      kubectl -n updated-system wait --for=delete pod -l app=release-server --timeout=60s >/dev/null
      kubectl -n updated-system scale deployment/release-server --replicas=1 >/dev/null
      kubectl -n updated-system rollout status deployment/release-server --timeout=120s >/dev/null
      ;;
    3)
      echo "fuzz generation $round: briefly removing the controller"
      kubectl -n updated-system scale deployment/updatec-controller --replicas=0 >/dev/null
      sleep 3
      kubectl -n updated-system scale deployment/updatec-controller --replicas=1 >/dev/null
      kubectl -n updated-system rollout status deployment/updatec-controller --timeout=120s >/dev/null
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
sleep 8
verify_fleet verify-fuzz-rollback "$expected"
for index in 0 1 2 3 4; do
  # Do not pipe `kubectl logs` into `grep -q` under pipefail. Once grep finds
  # the line it closes the pipe; a sufficiently large log then gives kubectl
  # SIGPIPE and turns a successful assertion into a false failure. Capture both
  # restart generations because rejection recovery may itself roll the tower.
  if ! kubectl_log_contains "agent-$index" \
      'recovery: rejected 18.0.0 after failed activation' -c agent \
    && ! kubectl_log_contains "agent-$index" \
      'recovery: rejected 18.0.0 after failed activation' -c agent --previous; then
    echo "FAIL: agent-$index did not record rejection of corrupt 18.0.0" >&2
    exit 1
  fi
done
echo "all agents rejected 18.0.0 and retained their exact predecessors"

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
echo "fleet recovered through sampleapp 19.0.0 -> Jenkins-shaped 20.0.0"
echo "fleet observer transitions during chaos:"
kubectl -n updated-system logs -l job-name=observe-fleet-chaos --prefix --all-containers=true
kubectl -n updated-system delete job observe-fleet-chaos --wait=true >/dev/null
else
  echo "fleet fuzz skipped (--fuzz-rounds 0)"
fi
cat <<'YAML' | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata: {name: routing-digest-before-overlap, namespace: updated-system}
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: digest
          image: updatec-e2e:kind
          command: [/bin/sh, -ec]
          args: ['curl -fsS --cert /etc/agent-tls/tls.crt --key /etc/agent-tls/tls.key --cacert /etc/agent-tls/ca.crt https://updatec-gateway/metadata/timestamp.json | sha256sum | cut -d" " -f1']
          volumeMounts: [{name: agent-tls, mountPath: /etc/agent-tls, readOnly: true}]
      volumes: [{name: agent-tls, secret: {secretName: agent-tls}}]
YAML
kubectl -n updated-system wait --for=condition=complete job/routing-digest-before-overlap --timeout=60s
before="$(kubectl -n updated-system logs job/routing-digest-before-overlap)"
cargo run -q -p updatec --example kind_resources -- \
  "$PLATFORM" "$APP_V1_SHA" "$APP_V2_SHA" "$APP_V3_SHA" "$PROVIDER_SHA" \
  "$WORK/release-root.json" overlap | kubectl apply -f -
sleep 8
cat <<'YAML' | kubectl apply -f -
apiVersion: batch/v1
kind: Job
metadata: {name: routing-digest-after-overlap, namespace: updated-system}
spec:
  backoffLimit: 0
  template:
    spec:
      restartPolicy: Never
      containers:
        - name: digest
          image: updatec-e2e:kind
          command: [/bin/sh, -ec]
          args: ['curl -fsS --cert /etc/agent-tls/tls.crt --key /etc/agent-tls/tls.key --cacert /etc/agent-tls/ca.crt https://updatec-gateway/metadata/timestamp.json | sha256sum | cut -d" " -f1']
          volumeMounts: [{name: agent-tls, mountPath: /etc/agent-tls, readOnly: true}]
      volumes: [{name: agent-tls, secret: {secretName: agent-tls}}]
YAML
kubectl -n updated-system wait --for=condition=complete job/routing-digest-after-overlap --timeout=60s
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
echo "updatec Kind E2E passed: five real agents updated and were verified through version endpoints"
