#!/usr/bin/env bash
# One best-effort diagnostic path for both Kind suites and their GitHub Actions failure hooks.
# Never hide the original failure behind a missing resource or a pod that has not started.
set -u

CLUSTER=${UPDATEC_KIND_CLUSTER:-updatec-e2e}
NAMESPACE=${UPDATEC_NAMESPACE:-updated-system}
KUBE_CONTEXT="kind-$CLUSTER"

cluster() { command kubectl --context "$KUBE_CONTEXT" --request-timeout=15s "$@"; }
kube() { cluster -n "$NAMESPACE" "$@"; }
infra() { cluster -n ingress-nginx "$@"; }

cluster get nodes -o wide >&2 || true
cluster describe nodes >&2 || true
cluster get pods,jobs -A -o wide >&2 || true
kube get pods,jobs,updateagents,updategroups,updaterepositories -o wide >&2 || true
kube logs deployment/updatec-controller --all-containers=true --tail=200 >&2 || true
kube logs deployment/updatec-gateway --all-containers=true --tail=200 >&2 || true
# CrashLoopBackOff's useful error is in the terminated container, not the newly started one.
kube logs deployment/updatec-gateway --all-containers=true --previous --tail=200 >&2 || true
# Readiness failures belong to the workload pod. Preserve both its termination reason and the
# preceding container's logs; controller/gateway logs cannot explain an agent or JVM crash.
while IFS= read -r pod; do
  kube describe pod "$pod" >&2 || true
  kube logs "$pod" --all-containers=true --tail=200 >&2 || true
  kube logs "$pod" --all-containers=true --previous --tail=200 >&2 || true
done < <(kube get pods -o json | python3 -c '
import json, sys
try:
    pods = json.load(sys.stdin).get("items", [])
except (ValueError, OSError):
    pods = []
for pod in pods:
    status = pod.get("status", {})
    if status.get("phase") == "Succeeded":
        continue
    if not any(c.get("type") == "Ready" and c.get("status") == "True" for c in status.get("conditions", [])):
        print(pod["metadata"]["name"])
')
infra get pods,jobs -o wide >&2 || true
infra logs deployment/ingress-nginx-controller --all-containers=true --tail=200 >&2 || true
infra logs deployment/ingress-nginx-controller --all-containers=true --previous --tail=200 >&2 || true
# The local-path volumes outlive container restarts, including the one with the original
# activation failure. Read them from the Kind node even if the workload is in CrashLoopBackOff.
while IFS= read -r node; do
  python3 - "$node" <<'PY' >&2
import subprocess, sys
try:
    subprocess.run([
        "docker", "exec", sys.argv[1], "find", "/var/local-path-provisioner",
        "-maxdepth", "2", "-type", "f", "(", "-name", "agent.log", "-o",
        "-name", "jenkins.log", ")", "-exec", "tail", "-n", "200", "-v", "{}", "+",
    ], timeout=20, check=False)
except (OSError, subprocess.TimeoutExpired) as error:
    print(f"persistent fixture logs unavailable: {error}", file=sys.stderr)
PY
done < <(cluster get nodes -o 'jsonpath={range .items[*]}{.metadata.name}{"\n"}{end}')
cluster get events -A --sort-by=.metadata.creationTimestamp >&2 || true
