#!/bin/sh
set -eu

install=/var/lib/updated
launcher="$install/launcher"
mkdir -p "$launcher"
# This node's self-asserted enrollment name — the `CN` the gateway mints and the `UpdateAgent` it
# creates. Derived deterministically from the hostname so it is stable across restarts, and read
# from the single definition of that derivation (`resource_name`, crates/updatec-e2e/src/cluster.rs)
# rather than re-implemented here, so the name a node asserts and the name the e2e addresses it
# by cannot drift.
node_name="$(updatec-e2e agent-name "$HOSTNAME")"
# Identity is mutual TLS: the agent presents the shared fleet enrollment certificate (issued by
# cert-manager and mounted at /etc/agent-tls) that the gateway verifies against the fleet CA. The
# config file holds only a name and paths — no secret.
cat >/tmp/config.toml <<EOF
[enrollment]
url = "https://updatec-gateway"
name = "$node_name"
client_cert = "/etc/agent-tls/tls.crt"
client_key = "/etc/agent-tls/tls.key"
ca = "/etc/agent-tls/ca.crt"
EOF

exec /usr/local/bin/updated-launcher --state-dir "$launcher" --config /tmp/config.toml \
  --agent /usr/local/bin/updated-agent --ready-timeout 30 --confirm-timeout 2
