#!/bin/sh
set -eu

install=/var/lib/updated
case $(uname -m) in
  aarch64|arm64) platform=linux-aarch64 ;;
  x86_64|amd64) platform=linux-x86_64 ;;
  *) echo "unsupported E2E architecture: $(uname -m)" >&2; exit 1 ;;
esac
if [ ! -f "$install/state/installed.json" ]; then
  fixture=/tmp/baseline
  mkdir -p "$fixture/bin" "$fixture/config"
  cp /usr/local/bin/sampleapp "$fixture/bin/app"
  printf 'version = "1.0.0"\n' >"$fixture/config/release.toml"
  server install-app --install-root "$install" --bundle "$fixture" \
    --product app --version 1.0.0 --platform "$platform" --entrypoint bin/app \
    --metadata-url "http://updatec-gateway/metadata/"
fi

cat > /tmp/updated.toml <<EOF
[routing]
root = "/etc/updated/routing-root.json"
base_url = "http://updatec-gateway/"
assignment = "assignments/agents/${HOSTNAME}.json"
transport_timeout = "5s"

[repository]
root = "/etc/updated/release-root.json"
transport_timeout = "5s"

[application]
product = "app"
channel = "stable"
install_root = "$install"
args = ["--addr", "0.0.0.0:8080"]
health_url = "http://127.0.0.1:8080/healthz"

[timeouts]
check_interval = "1s"
refresh_retry = "1s"
health_grace = "1s"
confirmation_window = "2s"
EOF

exec bootstrap --state-dir "$install/guardian" --supervisor-config /tmp/updated.toml \
  --supervisor /usr/local/bin/supervisor --ready-timeout 30 --confirm-timeout 2
