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
infra get pods,jobs -o wide >&2 || true
infra logs deployment/ingress-nginx-controller --all-containers=true --tail=200 >&2 || true
infra logs deployment/ingress-nginx-controller --all-containers=true --previous --tail=200 >&2 || true
cluster get events -A --sort-by=.metadata.creationTimestamp >&2 || true
