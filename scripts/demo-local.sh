#!/usr/bin/env bash
# Bring the WHOLE demo up natively on THIS machine (macOS or Linux) — no ansible, no sudo.
#
#   ./scripts/demo-local.sh              # stand it up and leave it browsable at http://localhost/
#   ./scripts/demo-local.sh e2e --exit   # run the automated demo e2e instead, then exit
#
# The full ansible playbook (scripts/demo.sh) is Linux-only: its deps/ingress/agent roles use apt,
# systemd, and /etc/hosts. This script is the ansible-free equivalent — it drives `updatec-demo`,
# which stands up the kind cluster (via scripts/kind-updatec-e2e.sh) AND applies the UI, RBAC, and
# per-set services/ingress. Driving the raw provisioner alone would leave the bare fleet with no
# UI (nginx 404 at /), which is exactly what this used to do.
#
# Any arguments pass straight through to `updatec-demo` (start | setup | e2e [--exit] | serve |
# reset); with none it runs `start`, which leaves the demo up and browsable.
#
# You need Docker running plus kind, kubectl, cargo, and curl on PATH. Remove the cluster with:
#     kind delete cluster --name updatec-demo
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Fail early with a clear message rather than deep inside the provisioner.
command -v docker >/dev/null 2>&1 || { echo "docker not found — install Docker and start it" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "Docker isn't running — start Docker Desktop first" >&2; exit 1; }

# Default to `start`: stand the whole thing up and leave it browsable at http://localhost/.
[[ $# -eq 0 ]] && set -- start

echo "Bringing the whole demo up locally in kind — this takes a few minutes on a clean machine."
cd "$ROOT"
exec cargo run -p updatec-demo -- "$@"
