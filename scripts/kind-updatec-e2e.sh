#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
. "$ROOT/scripts/lib/publish-fuzz-plan.sh"
NAME="${UPDATEC_KIND_CLUSTER:-updatec-e2e}"
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
trap finish EXIT
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
  'until mc alias set local http://minio:9000 minio minio123; do sleep 1; done; mc mb --ignore-existing local/updates'
kubectl -n updated-system wait pod/minio-init --for=condition=Ready=false --timeout=1s >/dev/null 2>&1 || true
kubectl -n updated-system wait pod/minio-init --for=jsonpath='{.status.phase}'=Succeeded --timeout=120s

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
          ports: [{name: http, containerPort: 8080}]
          volumeMounts: [{name: repository, mountPath: /data}]
      volumes:
        - name: repository
          persistentVolumeClaim: {claimName: release-repository}
---
apiVersion: v1
kind: Service
metadata: {name: release-server, namespace: updated-system}
spec:
  selector: {app: release-server}
  ports: [{name: http, port: 80, targetPort: http}]
---
apiVersion: v1
kind: Service
metadata: {name: release-edge, namespace: updated-system}
spec:
  selector: {app: release-server}
  ports: [{name: http, port: 80, targetPort: http}]
---
apiVersion: v1
kind: Service
metadata: {name: release-batch, namespace: updated-system}
spec:
  selector: {app: release-server}
  ports: [{name: http, port: 80, targetPort: http}]
---
apiVersion: v1
kind: Service
metadata: {name: release-default, namespace: updated-system}
spec:
  selector: {app: release-server}
  ports: [{name: http, port: 80, targetPort: http}]
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

deployment() {
  printf '{"schema":2,"deployment":"%s","metadata_url":"http://release-%s/metadata/","targets_url":"http://release-%s/targets/","application":{"path":"products/app/stable/%s/%s/app","sha256":"%s"},"provider_set":{"path":"provider-sets/default.json","sha256":"%s"}}' \
    "$1" "$2" "$2" "$3" "$PLATFORM" "$4" "$PROVIDER_SHA"
}
kubectl -n updated-system create configmap deployment-default --save-config \
  --from-literal=deployment.json="$(deployment default default 1.0.0 "$APP_V1_SHA")"
kubectl -n updated-system create configmap deployment-edge --save-config \
  --from-literal=deployment.json="$(deployment edge edge 2.0.0 "$APP_V2_SHA")"
kubectl -n updated-system create configmap deployment-batch --save-config \
  --from-literal=deployment.json="$(deployment batch batch 3.0.0 "$APP_V3_SHA")"
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
metadata: {name: agent-0, namespace: updated-system}
spec: {labels: {updated.dev/role: edge}}
---
apiVersion: updated.dev/v1alpha1
kind: UpdatedNode
metadata: {name: agent-1, namespace: updated-system}
spec: {labels: {updated.dev/role: edge}}
---
apiVersion: updated.dev/v1alpha1
kind: UpdatedNode
metadata: {name: agent-2, namespace: updated-system}
spec: {labels: {updated.dev/role: batch}}
---
apiVersion: updated.dev/v1alpha1
kind: UpdatedNode
metadata: {name: agent-3, namespace: updated-system}
spec: {labels: {updated.dev/role: batch}}
---
apiVersion: updated.dev/v1alpha1
kind: UpdatedNode
metadata: {name: agent-4, namespace: updated-system}
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
kubectl -n updated-system rollout status deployment/updatec-controller --timeout=180s
kubectl -n updated-system rollout status deployment/updatec-gateway --timeout=180s

echo "waiting for updatec to publish the first complete routing generation"
for attempt in {1..60}; do
  if kubectl -n updated-system logs deployment/updatec-controller | grep -q 'desired state reconciled'; then break; fi
  if (( attempt % 5 == 0 )); then
    echo "still waiting for publication (${attempt}/60); latest controller log:"
    kubectl -n updated-system logs deployment/updatec-controller --tail=3 || true
  fi
  sleep 2
done
if ! kubectl -n updated-system logs deployment/updatec-controller | grep -q 'desired state reconciled'; then
  echo "FAIL: updatec did not publish within 120s" >&2
  kubectl -n updated-system get pods >&2 || true
  kubectl -n updated-system logs deployment/updatec-controller --tail=100 >&2 || true
  kubectl -n updated-system logs deployment/updatec-gateway --tail=100 >&2 || true
  exit 1
fi
echo "initial routing generation published"
kubectl -n updated-system create configmap agent-roots \
  --from-file=routing-root.json="$WORK/seed-repo/metadata/root.json" \
  --from-file=release-root.json="$WORK/release-root.json"
cat <<'YAML' | kubectl apply -f -
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
          readinessProbe: {httpGet: {path: /version, port: http}, periodSeconds: 1}
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
            - {name: roots, mountPath: /etc/updated, readOnly: true}
            - {name: tmp, mountPath: /tmp}
      volumes:
        - {name: state, emptyDir: {}}
        - {name: roots, configMap: {name: agent-roots}}
        - {name: tmp, emptyDir: {medium: Memory, sizeLimit: 64Mi}}
YAML
echo "waiting for all five real agent towers to reach their assigned versions"
kubectl -n updated-system rollout status statefulset/agent --timeout=240s
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
              check agent-0 2.0.0 magnolia
              check agent-1 2.0.0 magnolia
              check agent-2 3.0.0 sampleapp
              check agent-3 3.0.0 sampleapp
              check agent-4 1.0.0 sampleapp
              echo "all 5 agents reached their control-plane-selected versions (2/2/1)"
YAML
kubectl -n updated-system wait --for=condition=complete job/verify-agent-versions --timeout=150s
kubectl -n updated-system logs job/verify-agent-versions

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

FUZZ_ROUNDS=${UPDATEC_FUZZ_ROUNDS:-5}
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
  kubectl -n updated-system create configmap "deployment-$name" --dry-run=client -o yaml \
    --from-literal=deployment.json="$(deployment "$name-fuzz-$version" "$name" "$version" "$sha")" | \
    kubectl apply -f - >/dev/null
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
    kubectl -n updated-system patch updatednode "agent-$index" --type=json -p "$patch" >/dev/null
    echo "fuzz generation $round plan: agent-$index -> $selected_role -> $selected_version"
  done

  # Verify the desired state which the API server actually accepted. This keeps
  # the oracle independent from the mutation loop and catches bad/missed patches
  # instead of misreporting a correctly converged agent as broken.
  expected=""
  for index in 0 1 2 3 4; do
    applied_role="$(kubectl -n updated-system get updatednode "agent-$index" \
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
    expected="$expected agent-$index=$applied_version,$(publish_fuzz_artifact "$applied_version")"
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

# Reuse the macOS publisher fuzzer's failure sequence: select an unlaunchable
# newest artifact, prove every node rolls back to its exact predecessor, then let
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
  kubectl -n updated-system logs "agent-$index" | grep -q 'rejected 18.0.0' || {
    echo "FAIL: agent-$index did not record rejection of corrupt 18.0.0" >&2
    exit 1
  }
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
echo "fleet recovered through sampleapp 19.0.0 -> Magnolia-shaped 20.0.0"
echo "fleet observer transitions during chaos:"
kubectl -n updated-system logs -l job-name=observe-fleet-chaos --prefix --all-containers=true
kubectl -n updated-system delete job observe-fleet-chaos --wait=true >/dev/null
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
          args: ['curl -fsS http://updatec-gateway/metadata/timestamp.json | sha256sum | cut -d" " -f1']
YAML
kubectl -n updated-system wait --for=condition=complete job/routing-digest-before-overlap --timeout=60s
before="$(kubectl -n updated-system logs job/routing-digest-before-overlap)"
cat <<'YAML' | kubectl apply -f -
apiVersion: updated.dev/v1alpha1
kind: UpdatedGroup
metadata: {name: overlapping-edge, namespace: updated-system}
spec: {match_labels: {updated.dev/role: edge}, deployment_config_map: deployment-default}
YAML
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
          args: ['curl -fsS http://updatec-gateway/metadata/timestamp.json | sha256sum | cut -d" " -f1']
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
