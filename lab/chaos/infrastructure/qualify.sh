#!/usr/bin/env bash
set -euo pipefail

[[ ${UPDATEDC_CHAOS_INTERNAL:-} == 1 ]] || {
  echo 'qualify.sh is internal; run lab/chaos/deploy.sh.' >&2
  exit 64
}
: "${KUBECONFIG:?KUBECONFIG is required}"

namespace=updatedc-chaos-qualification
image='docker.io/library/busybox:1.36.1@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662'

cleanup() {
  kubectl -n "$namespace" delete networkchaos,iochaos --all --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kubectl delete namespace "$namespace" --ignore-not-found --wait=true >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

cat <<YAML | kubectl apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: $namespace
  annotations:
    chaos-mesh.org/inject: "enabled"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: echo
  namespace: $namespace
spec:
  replicas: 1
  selector: {matchLabels: {app: echo}}
  template:
    metadata:
      labels:
        app: echo
        updated.dev/chaos-target: "true"
    spec:
      nodeSelector: {updated.dev/chaos-role: agent-a}
      containers:
        - name: echo
          image: $image
          command: [sh, -c, 'mkdir -p /www; echo ok >/www/index.html; exec httpd -f -p 8080 -h /www']
          ports: [{name: http, containerPort: 8080}]
---
apiVersion: v1
kind: Service
metadata:
  name: echo
  namespace: $namespace
spec:
  selector: {app: echo}
  ports: [{name: http, port: 8080, targetPort: http}]
---
apiVersion: v1
kind: Pod
metadata:
  name: probe
  namespace: $namespace
  labels:
    app: probe
    updated.dev/chaos-target: "true"
spec:
  nodeSelector: {updated.dev/chaos-role: agent-b}
  containers:
    - name: probe
      image: $image
      command: [sh, -c, 'sleep 3600']
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: io-state
  namespace: $namespace
spec:
  accessModes: [ReadWriteOnce]
  resources: {requests: {storage: 1Gi}}
---
apiVersion: v1
kind: Pod
metadata:
  name: io-target
  namespace: $namespace
  labels:
    app: io-target
    updated.dev/chaos-target: "true"
spec:
  nodeSelector: {updated.dev/chaos-role: storage}
  containers:
    - name: writer
      image: $image
      command: [sh, -c, 'while :; do date +%s > /var/lib/updated/heartbeat; sleep 1; done']
      # Match the soak pod's nested-mount topology: toda needs a writable parent in which to move
      # the PVC while its FUSE mount is active. If cleanup loses the nested mount, restarting the
      # container must remount the same PVC before qualification can pass.
      livenessProbe:
        exec: {command: [/bin/mountpoint, -q, /var/lib/updated]}
        periodSeconds: 2
        failureThreshold: 5
      volumeMounts:
        - {name: chaos-mount-workspace, mountPath: /var/lib}
        - {name: state, mountPath: /var/lib/updated}
  volumes:
    - {name: chaos-mount-workspace, emptyDir: {}}
    - {name: state, persistentVolumeClaim: {claimName: io-state}}
YAML

kubectl -n "$namespace" rollout status deployment/echo --timeout=180s
kubectl -n "$namespace" wait --for=condition=Ready pod/probe pod/io-target --timeout=180s
[[ $(kubectl -n "$namespace" exec probe -- wget -qO- http://echo:8080) == ok ]]
kubectl -n "$namespace" exec io-target -- sh -c 'echo baseline > /var/lib/updated/probe'

cat <<YAML | kubectl apply -f -
apiVersion: chaos-mesh.org/v1alpha1
kind: NetworkChaos
metadata:
  name: qualified-partition
  namespace: $namespace
spec:
  action: partition
  mode: all
  selector:
    namespaces: [$namespace]
    labelSelectors: {app: probe, updated.dev/chaos-target: "true"}
  direction: to
  target:
    mode: all
    selector:
      namespaces: [$namespace]
      labelSelectors: {app: echo, updated.dev/chaos-target: "true"}
YAML

partition_observed=false
for _attempt in {1..60}; do
  if ! kubectl -n "$namespace" exec probe -- wget -qO- --timeout=2 http://echo:8080 >/dev/null 2>&1; then
    partition_observed=true
    break
  fi
  sleep 1
done
$partition_observed || { echo 'NetworkChaos never partitioned the selected pods.' >&2; exit 1; }
kubectl -n "$namespace" delete networkchaos qualified-partition --wait=true

network_recovered=false
for _attempt in {1..60}; do
  if [[ $(kubectl -n "$namespace" exec probe -- wget -qO- --timeout=2 http://echo:8080 2>/dev/null || true) == ok ]]; then
    network_recovered=true
    break
  fi
  sleep 1
done
$network_recovered || { echo 'Pod network did not recover after deleting NetworkChaos.' >&2; exit 1; }

cat <<YAML | kubectl apply -f -
apiVersion: chaos-mesh.org/v1alpha1
kind: IOChaos
metadata:
  name: qualified-io-error
  namespace: $namespace
spec:
  action: fault
  mode: all
  selector:
    namespaces: [$namespace]
    labelSelectors: {app: io-target, updated.dev/chaos-target: "true"}
  volumePath: /var/lib/updated
  path: /var/lib/updated/*
  errno: 5
  percent: 100
YAML

io_fault_observed=false
for _attempt in {1..60}; do
  if ! kubectl -n "$namespace" exec io-target -- sh -c 'echo fault-probe > /var/lib/updated/probe' >/dev/null 2>&1; then
    io_fault_observed=true
    break
  fi
  sleep 1
done
$io_fault_observed || { echo 'IOChaos never returned EIO from the selected persistent volume.' >&2; exit 1; }
kubectl -n "$namespace" delete iochaos qualified-io-error --wait=true

io_recovered=false
for _attempt in {1..60}; do
  if kubectl -n "$namespace" exec io-target -- sh -c \
    'mountpoint -q /var/lib/updated && test "$(cat /var/lib/updated/probe)" = baseline && echo recovered > /var/lib/updated/probe' \
    >/dev/null 2>&1; then
    io_recovered=true
    break
  fi
  sleep 1
done
$io_recovered || { echo 'Persistent-volume I/O did not recover after deleting IOChaos.' >&2; exit 1; }

echo 'Chaos lab qualified: real cross-node partition and persistent-volume EIO both injected and recovered.'
