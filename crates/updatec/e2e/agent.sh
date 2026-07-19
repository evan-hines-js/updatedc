#!/bin/sh
set -eu

install=/var/lib/updated
guardian="$install/guardian"
mkdir -p "$guardian"
if [ ! -e "$guardian/registration-nonce" ]; then
  nonce=$(printf %s "$HOSTNAME" | sha256sum | cut -d' ' -f1)
  printf %s "$nonce" >"$guardian/registration-nonce"
fi
# Identity is mutual TLS: the agent presents a client certificate (issued by cert-manager and
# mounted at /etc/agent-tls) that the gateway verifies against the fleet CA. The config file
# holds only paths — no secret.
cat >/tmp/bootstrap.toml <<EOF
[enrollment]
url = "https://updatec-gateway"
client_cert = "/etc/agent-tls/tls.crt"
client_key = "/etc/agent-tls/tls.key"
ca = "/etc/agent-tls/ca.crt"
EOF

exec bootstrap --state-dir "$guardian" --supervisor-config /tmp/bootstrap.toml \
  --supervisor /usr/local/bin/supervisor --ready-timeout 30 --confirm-timeout 2 \
  --probe-address 0.0.0.0:9090
