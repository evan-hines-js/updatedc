#!/bin/sh
set -eu

install=/var/lib/updated
guardian="$install/guardian"
mkdir -p "$guardian"
# This node's self-asserted enrollment name — the `CN` the gateway mints and the `UpdateAgent` it
# creates. Derived deterministically from the hostname so it is stable across restarts, and read
# from the single definition of that derivation (`resource_name`, crates/updatec-demo/src/setup.rs)
# rather than re-implemented here, so the name a node asserts and the name the demo/e2e address it
# by cannot drift.
node_name="$(updatec-demo agent-name "$HOSTNAME")"
# Identity is mutual TLS: the agent presents the shared fleet enrollment certificate (issued by
# cert-manager and mounted at /etc/agent-tls) that the gateway verifies against the fleet CA. The
# config file holds only a name and paths — no secret.
cat >/tmp/bootstrap.toml <<EOF
[enrollment]
url = "https://updatec-gateway"
name = "$node_name"
client_cert = "/etc/agent-tls/tls.crt"
client_key = "/etc/agent-tls/tls.key"
ca = "/etc/agent-tls/ca.crt"
EOF

exec bootstrap --state-dir "$guardian" --supervisor-config /tmp/bootstrap.toml \
  --supervisor /usr/local/bin/supervisor --ready-timeout 30 --confirm-timeout 2
