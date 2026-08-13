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
      # An unlaunchable entrypoint (not a valid executable): the agent must reject this
      # release at activation and roll back, rather than crash-loop it.
      printf 'intentionally corrupt bundle entrypoint\n' >"$source/bin/app"
      chmod 0755 "$source/bin/app"
    else
      artifact=$(publish_fuzz_artifact "$version")
      case "$artifact" in
        jenkins) cp /usr/local/bin/stateful-like "$source/bin/app" ;;
        sampleapp) cp /usr/local/bin/sampleapp "$source/bin/app" ;;
        *) echo "unknown fuzz artifact: $artifact" >&2; exit 1 ;;
      esac
    fi
    printf 'version = "%s"\n' "$version" >"$source/config/release.toml"
    server publish-app --repo "$repo" --keys "$keys" \
      --product app --channel stable --version "$version" --entrypoint bin/app \
      --bundle "$platform=$source"
  done
  # Every release now carries exactly one signed node reconciler — there is no reconciler-less
  # provider set. The ordinary fleet runs plain, launcher-owned HTTP apps, so its `default` set uses
  # a MINIMAL, stateless reconciler: the launcher owns process lifecycle, so every phase is a no-op
  # except health verification. `verify` (the update gate) and `periodic` (the steady-state liveness
  # signal) confirm the managed app answers `/healthz`; a non-zero exit fails the update and rolls
  # back. It must be stateless — a stateful provider that gates `verify` on a prior `start` marker
  # (like the demo's enterprise reconciler) can never pass a Managed-mode cold install, whose first
  # boot health-gates the freshly installed release without running a transaction's start phase.
  mkdir -p "$fixtures/default-provider/bin"
  cat >"$fixtures/default-provider/bin/lifecycle" <<'RECONCILER'
#!/bin/sh
case "$1" in
  verify|periodic)
    curl -fsS -o /dev/null --max-time 3 http://127.0.0.1:8080/healthz || {
      echo "managed application failed its health check during $1" >&2
      exit 1
    }
    ;;
esac
exit 0
RECONCILER
  chmod 0755 "$fixtures/default-provider/bin/lifecycle"
  server publish-provider-artifact --repo "$repo" --keys "$keys" \
    --product default-reconciler --version 1.0.0 \
    --bundle "$platform=$fixtures/default-provider" --entrypoint bin/lifecycle
  provider_path="products/default-reconciler/stable/1.0.0/$platform/default-reconciler"
  provider_sha=$(server target-sha256 --repo "$repo" --name "$provider_path")
  server publish-provider-set --repo "$repo" --keys "$keys" --id default \
    --provider-path "$provider_path" --provider-sha256 "$provider_sha" \
    --provider-timeout-ms 15000
  # Real Jenkins as a managed product — ONLY on linux-x86_64 (the install provider fetches
  # an x86_64 JRE), so an arm64 kind cluster (Apple Silicon Docker) publishes no Jenkins bundle
  # and the demo skips it. Installed at runtime on a plain Ubuntu + agent node — nothing
  # Jenkins-specific is baked into any image; v1 -> v2 is a real rolling restart drained one
  # node at a time.
  if [ "$platform" = "linux-x86_64" ]; then
  for jenkins_version in 1.0.0 2.0.0; do
    source="$fixtures/jenkins-$jenkins_version"
    mkdir -p "$source/bin" "$source/config"
    cp /usr/local/share/jenkins/app.sh "$source/bin/app"
    chmod 0755 "$source/bin/app"
    printf 'version = "%s"\n' "$jenkins_version" >"$source/config/release.toml"
    server publish-app --repo "$repo" --keys "$keys" \
      --product jenkins --channel stable --version "$jenkins_version" --entrypoint bin/app \
      --bundle "$platform=$source"
  done
  # The pre-start install provider — a signed lifecycle artifact the agent downloads and runs
  # to install the JRE + Jenkins into its container at runtime. A generous timeout covers the
  # first-boot download.
  mkdir -p "$fixtures/jenkins-install/bin"
  cp /usr/local/share/jenkins/install.sh "$fixtures/jenkins-install/bin/lifecycle"
  chmod 0755 "$fixtures/jenkins-install/bin/lifecycle"
  server publish-provider-artifact --repo "$repo" --keys "$keys" \
    --product jenkins-install --version 1.0.0 \
    --bundle "$platform=$fixtures/jenkins-install" --entrypoint bin/lifecycle
  jenkins_provider_path="products/jenkins-install/stable/1.0.0/$platform/jenkins-install"
  jenkins_provider_sha=$(server target-sha256 --repo "$repo" --name "$jenkins_provider_path")
  server publish-provider-set --repo "$repo" --keys "$keys" --id jenkins \
    --provider-path "$jenkins_provider_path" --provider-sha256 "$jenkins_provider_sha" \
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
