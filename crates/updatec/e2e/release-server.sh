#!/bin/sh
set -eu
. /usr/local/lib/publish-fuzz-plan.sh

repo=/data/repository
keys=/data/keys
fixtures=/data/fixtures
case $(uname -m) in
  aarch64|arm64) platform=linux-aarch64 ;;
  x86_64|amd64) platform=linux-x86_64 ;;
  *) echo "unsupported E2E architecture: $(uname -m)" >&2; exit 1 ;;
esac
if [ ! -f /data/ready ]; then
  rm -rf "$repo" "$keys" "$fixtures"
  server init --repo "$repo" --keys "$keys"
  for major in $(seq 1 22); do
    version="${major}.0.0"
    source="$fixtures/$version"
    mkdir -p "$source/bin" "$source/config"
    if [ "$major" -eq 18 ] || [ "$major" -eq 21 ]; then
      # An unlaunchable entrypoint (not a valid executable): the supervisor must reject this
      # release at activation and roll back, rather than crash-loop it.
      printf 'intentionally corrupt bundle entrypoint\n' >"$source/bin/app"
      chmod 0755 "$source/bin/app"
    else
      artifact=$(publish_fuzz_artifact "$version")
      case "$artifact" in
        magnolia) cp /usr/local/bin/magnolia-like "$source/bin/app" ;;
        sampleapp) cp /usr/local/bin/sampleapp "$source/bin/app" ;;
        *) echo "unknown fuzz artifact: $artifact" >&2; exit 1 ;;
      esac
    fi
    printf 'version = "%s"\n' "$version" >"$source/config/release.toml"
    server publish-app --repo "$repo" --keys "$keys" \
      --product app --channel stable --version "$version" --entrypoint bin/app \
      --bundle "$platform=$source"
  done
  server publish-provider-set --repo "$repo" --keys "$keys" --id default
  mkdir -p "$fixtures/rube-goldberg-provider/bin"
  cp /usr/local/bin/demo-lifecycle "$fixtures/rube-goldberg-provider/bin/lifecycle"
  chmod 0755 "$fixtures/rube-goldberg-provider/bin/lifecycle"
  server publish-provider-artifact --repo "$repo" --keys "$keys" \
    --product demo-enterprise-lifecycle --version 1.0.0 \
    --bundle "$platform=$fixtures/rube-goldberg-provider" --entrypoint bin/lifecycle
  provider_path="products/demo-enterprise-lifecycle/stable/1.0.0/$platform/demo-enterprise-lifecycle"
  provider_sha=$(server target-sha256 --repo "$repo" --name "$provider_path")
  server publish-provider-set --repo "$repo" --keys "$keys" --id rube-goldberg \
    --provider-path "$provider_path" --provider-sha256 "$provider_sha" \
    --provider-timeout-ms 15000
  # Real Magnolia CMS as a managed product — ONLY on linux-x86_64 (the install provider fetches
  # an x86_64 JRE), so an arm64 kind cluster (Apple Silicon Docker) publishes no Magnolia bundle
  # and the demo skips it. Installed at runtime on a plain Ubuntu + agent node — nothing
  # Magnolia-specific is baked into any image; v1 -> v2 is a real rolling restart drained one
  # node at a time.
  if [ "$platform" = "linux-x86_64" ]; then
  for magnolia_version in 1.0.0 2.0.0; do
    source="$fixtures/magnolia-$magnolia_version"
    mkdir -p "$source/bin" "$source/config"
    cp /usr/local/share/magnolia/app.sh "$source/bin/app"
    chmod 0755 "$source/bin/app"
    printf 'version = "%s"\n' "$magnolia_version" >"$source/config/release.toml"
    server publish-app --repo "$repo" --keys "$keys" \
      --product magnolia --channel stable --version "$magnolia_version" --entrypoint bin/app \
      --bundle "$platform=$source"
  done
  # The pre-start install provider — a signed lifecycle artifact the agent downloads and runs
  # to install the JRE + Magnolia into its container at runtime. A generous timeout covers the
  # first-boot download.
  mkdir -p "$fixtures/magnolia-install/bin"
  cp /usr/local/share/magnolia/install.sh "$fixtures/magnolia-install/bin/lifecycle"
  chmod 0755 "$fixtures/magnolia-install/bin/lifecycle"
  server publish-provider-artifact --repo "$repo" --keys "$keys" \
    --product magnolia-install --version 1.0.0 \
    --bundle "$platform=$fixtures/magnolia-install" --entrypoint bin/lifecycle
  magnolia_provider_path="products/magnolia-install/stable/1.0.0/$platform/magnolia-install"
  magnolia_provider_sha=$(server target-sha256 --repo "$repo" --name "$magnolia_provider_path")
  server publish-provider-set --repo "$repo" --keys "$keys" --id magnolia \
    --provider-path "$magnolia_provider_path" --provider-sha256 "$magnolia_provider_sha" \
    --provider-timeout-ms 300000
  fi
  printf '%s\n' "$platform" >/data/platform
  touch /data/ready
fi
# The mock CDN terminates mTLS just like the gateway: cert-manager issues the fleet server cert
# (gateway-tls) into /etc/gateway-tls, and only a client presenting a fleet-CA-signed cert is
# admitted. Agents reach this over https://release-<group>/ under their agent-tls identity.
exec server serve --repo "$repo" --addr 0.0.0.0:8080 \
  --cert /etc/gateway-tls/tls.crt --key /etc/gateway-tls/tls.key --ca /etc/gateway-tls/ca.crt
