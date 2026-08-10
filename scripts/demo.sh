#!/usr/bin/env bash
# One command to bring up the entire demo.
#
#   ./scripts/demo.sh                  # locally  — this machine needs Docker + ansible
#   ./scripts/demo.sh root@10.0.0.206  # remotely — on that server over SSH, UI tunnelled to you
#
# Either way it runs the SAME single ansible playbook (deploy/ansible/demo.yml), which stands the
# whole thing up: Docker/kind/kubectl/Rust, the kind demo (operator + CDN + fleet + Jenkins), the
# co-located out-of-cluster agent, and nginx serving the UI on port 80. Releases roll through the
# real `updatectl deploy` (published to the in-cluster MinIO release repo the playbook bootstraps).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOST="${1:-}"
PORT="${UPDATEC_DEMO_PORT:-8088}"
PLAYBOOK="deploy/ansible/demo.yml"

# ---- Local: no endpoint given, bring it up on this machine. --------------------------------
if [[ -z "$HOST" ]]; then
  echo "Bringing the demo up locally — browse to http://localhost/ when it finishes."
  exec ansible-playbook "$ROOT/$PLAYBOOK"
fi

# ---- Remote: an endpoint was given, run the same playbook there and tunnel its UI back. -----
SSH=(ssh -o StrictHostKeyChecking=accept-new)

echo "Bringing the demo up on $HOST — this takes a few minutes on a clean box."
# The server only needs ansible to run the playbook; the playbook installs everything else.
"${SSH[@]}" "$HOST" \
  'command -v ansible-playbook >/dev/null 2>&1 || { apt-get update && apt-get install -y ansible rsync; }'
# Ship the workspace (source only — the server builds native binaries itself).
rsync -az --delete --exclude target --exclude .git --exclude .DS_Store \
  -e "${SSH[*]}" "$ROOT/" "$HOST:updated-demo/"
# Run the one playbook on the server.
"${SSH[@]}" -t "$HOST" 'cd updated-demo && ansible-playbook deploy/ansible/demo.yml'

# The cluster + UI keep running on the server; tunnel its nginx (port 80) to your browser.
# LogLevel=QUIET silences ssh's "connect refused" spam while the browser polls the tunnel.
echo
echo "Demo is up on $HOST. Tunnelling its UI to http://127.0.0.1:$PORT/ — Ctrl-C to close."
exec "${SSH[@]}" -t -o LogLevel=QUIET -L "$PORT:127.0.0.1:80" "$HOST" \
  "echo 'Open http://127.0.0.1:$PORT/ in your browser.'; sleep infinity"
