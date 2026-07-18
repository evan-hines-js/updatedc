#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NAME="updatec-e2e"
WORK="$ROOT/target/kind-updatec-e2e"
cleanup() { kind delete cluster --name "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
mkdir -p "$WORK"

cat >"$WORK/kind.yaml" <<'YAML'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
  - role: control-plane
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

cargo run -q -p server -- init --repo "$WORK/seed-repo" --keys "$WORK/keys"
kubectl -n updated-system create secret generic tuf-signing-keys --from-file="$WORK/keys/root.pk8" --from-file="$WORK/keys/targets.pk8" --from-file="$WORK/keys/snapshot.pk8" --from-file="$WORK/keys/timestamp.pk8"
kubectl -n updated-system create secret generic s3-credentials --from-literal=AWS_ACCESS_KEY_ID=minio --from-literal=AWS_SECRET_ACCESS_KEY=minio123

deployment() { printf '{"schema":2,"deployment":"%s","metadata_url":"https://cdn.invalid/metadata/","targets_url":"https://cdn.invalid/targets/","application":{"path":"app","sha256":"%064d"},"provider_set":{"path":"providers","sha256":"%064d"}}' "$1" 1 2; }
kubectl -n updated-system create configmap deployment-default --from-literal=deployment.json="$(deployment default)"
kubectl -n updated-system create configmap deployment-edge --from-literal=deployment.json="$(deployment edge)"
kubectl -n updated-system create configmap deployment-batch --from-literal=deployment.json="$(deployment batch)"
cat >"$WORK/resources.yaml" <<'YAML'
apiVersion: updated.dev/v1alpha1
kind: UpdatedGroup
metadata: {name: default, namespace: updated-system}
spec: {match_labels: {updated.dev/default: "true"}, deployment_config_map: deployment-default}
---
apiVersion: updated.dev/v1alpha1
kind: UpdatedGroup
metadata: {name: edge, namespace: updated-system}
spec: {match_labels: {updated.dev/role: edge}, deployment_config_map: deployment-edge}
---
apiVersion: updated.dev/v1alpha1
kind: UpdatedGroup
metadata: {name: batch, namespace: updated-system}
spec: {match_labels: {updated.dev/role: batch}, deployment_config_map: deployment-batch}
---
apiVersion: updated.dev/v1alpha1
kind: UpdatedNode
metadata: {name: edge-1, namespace: updated-system}
spec: {labels: {updated.dev/role: edge}}
---
apiVersion: updated.dev/v1alpha1
kind: UpdatedNode
metadata: {name: edge-2, namespace: updated-system}
spec: {labels: {updated.dev/role: edge}}
---
apiVersion: updated.dev/v1alpha1
kind: UpdatedNode
metadata: {name: batch-1, namespace: updated-system}
spec: {labels: {updated.dev/role: batch}}
---
apiVersion: updated.dev/v1alpha1
kind: UpdatedNode
metadata: {name: default-1, namespace: updated-system}
spec: {labels: {}}
---
apiVersion: updated.dev/v1alpha1
kind: UpdatedRepository
metadata: {name: default, namespace: updated-system}
spec:
  default_group: default
  signing_secret: tuf-signing-keys
  assignment_prefix: assignments
  s3:
    bucket: updates
    region: us-east-1
    endpoint: http://minio:9000
    credentials_secret: s3-credentials
YAML
kubectl apply -f "$WORK/resources.yaml"

docker build -f crates/updatec/Dockerfile -t updatec:kind .
kind load docker-image --name "$NAME" updatec:kind
kubectl apply -f deploy/kubernetes/updatec.yaml
kubectl -n updated-system rollout status deployment/updatec --timeout=180s

for _ in {1..60}; do
  if kubectl -n updated-system logs deployment/updatec | grep -q 'desired state reconciled'; then break; fi
  sleep 2
done
kubectl -n updated-system logs deployment/updatec | grep -q 'desired state reconciled'
kubectl -n updated-system port-forward service/minio 19000:9000 >"$WORK/port-forward.log" 2>&1 &
PF=$!; trap 'kill "$PF" >/dev/null 2>&1 || true; cleanup' EXIT; sleep 2
curl -fsS http://127.0.0.1:19000/updates/metadata/timestamp.json >"$WORK/timestamp.json"
curl -fsS http://127.0.0.1:19000/updates/metadata/root.json >"$WORK/root.json"
cargo run -q -p updatec --example verify -- \
  "$WORK/root.json" http://127.0.0.1:19000/updates "assignments/nodes/edge-1.json" | grep -qx edge
cargo run -q -p updatec --example verify -- \
  "$WORK/root.json" http://127.0.0.1:19000/updates "assignments/nodes/edge-2.json" | grep -qx edge
cargo run -q -p updatec --example verify -- \
  "$WORK/root.json" http://127.0.0.1:19000/updates "assignments/nodes/batch-1.json" | grep -qx batch
cargo run -q -p updatec --example verify -- \
  "$WORK/root.json" http://127.0.0.1:19000/updates "assignments/nodes/default-1.json" | grep -qx default

before="$(sha256sum "$WORK/timestamp.json" | cut -d' ' -f1)"
cat <<'YAML' | kubectl apply -f -
apiVersion: updated.dev/v1alpha1
kind: UpdatedGroup
metadata: {name: overlapping-edge, namespace: updated-system}
spec: {match_labels: {updated.dev/role: edge}, deployment_config_map: deployment-default}
YAML
sleep 8
curl -fsS http://127.0.0.1:19000/updates/metadata/timestamp.json >"$WORK/timestamp-after.json"
after="$(sha256sum "$WORK/timestamp-after.json" | cut -d' ' -f1)"
test "$before" = "$after"
kubectl -n updated-system logs deployment/updatec | grep -q 'AmbiguousNode'
echo "updatec Kind E2E passed"
