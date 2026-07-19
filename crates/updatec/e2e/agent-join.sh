#!/bin/sh
set -eu

# Join-mode agent entrypoint (contrast with agent.sh, the mount-mode one). This node has NO
# pre-provisioned client certificate: it authenticates its *join* with a shared group token, and
# the control plane signs a CSR it generates locally into a client certificate. That minted
# identity — and all install state — lives on a persistent volume (mounted at /var/lib/updated),
# because unlike mount mode the key exists nowhere else: an emptyDir would lose it on restart and
# the node would churn to a brand-new identity. See docs/group-enrollment-design.md.
install=/var/lib/updated
guardian="$install/guardian"
mkdir -p "$guardian"

# The durable per-node instance names the agent and makes the join idempotent on restart. Derived
# from the (stable) StatefulSet pod hostname and persisted on the PVC, so a restart re-joins as the
# SAME node (an upgrade), while a fresh pod with an empty PVC cold-installs (a reinstall).
if [ ! -e "$guardian/registration-nonce" ]; then
  nonce=$(printf %s "$HOSTNAME" | sha256sum | cut -d' ' -f1)
  printf %s "$nonce" >"$guardian/registration-nonce"
fi

# Identity is a group join token, not a mounted cert. The bootstrap carries the group id and the
# shared secret nonce (injected from the controller-minted Secret) plus the fleet CA it trusts for
# the join server. The join endpoint is the gateway's server-TLS-only port (8443); steady-state
# traffic afterwards uses the certificate the node mints and the routing URL from its bundle.
cat >/tmp/bootstrap.toml <<EOF
[enrollment]
url = "https://updatec-gateway:8443"
ca = "/etc/agent-tls/ca.crt"
group_id = "${JOIN_GROUP_ID}"
nonce = "${JOIN_NONCE}"
EOF

exec bootstrap --state-dir "$guardian" --supervisor-config /tmp/bootstrap.toml \
  --supervisor /usr/local/bin/supervisor --ready-timeout 30 --confirm-timeout 2 \
  --probe-address 0.0.0.0:9090
