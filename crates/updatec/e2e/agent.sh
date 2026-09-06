#!/bin/bash
set -eu

# Model a machine's init: reap detached workload children and keep the agent signalable.
# Namespace PID 1 ignores SIGSTOP from peers, which otherwise makes the stale-report fault
# injection silently leave the agent running. Every test node uses this same entrypoint.
if [ "$$" -eq 1 ]; then
  exec /usr/bin/tini -- "$0" "$@"
fi

install=/var/lib/updated
state="$install/state"
mkdir -p "$state"
# This node's self-asserted enrollment name — the `CN` the gateway mints and the `UpdateAgent` it
# creates. Derived deterministically from the hostname so it is stable across restarts, and read
# from the single definition of that derivation (`resource_name`, crates/updatec-e2e/src/cluster.rs)
# rather than re-implemented here, so the name a node asserts and the name the e2e addresses it
# by cannot drift.
node_name="$(updatec-e2e agent-name "$(hostname)")"
# Identity is mutual TLS: the agent presents the shared fleet enrollment certificate (issued by
# cert-manager and mounted at /etc/agent-tls) that the gateway verifies against the fleet CA. The
# config file holds only a name and paths — no secret.
cat >/tmp/config.toml <<EOF
[enrollment]
url = "https://updatec-gateway"
name = "$node_name"
ca = "/etc/agent-tls/ca.crt"

[enrollment.bootstrap]
client_cert = "/etc/agent-tls/tls.crt"
client_key = "/etc/agent-tls/tls.key"
EOF

export UPDATED_STATE_DIR="$state"
# Kubernetes keeps only the most recent terminated container's logs. Preserve the first
# activation failure across restarts on this fixture's volume, while keeping the agent's PID.
exec /usr/local/bin/updated-agent --config /tmp/config.toml 2> >(tee -a "$install/agent.log" >&2)
