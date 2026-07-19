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
  for major in $(seq 1 20); do
    version="${major}.0.0"
    source="$fixtures/$version"
    mkdir -p "$source/bin" "$source/config"
    if [ "$major" -eq 18 ]; then
      # Same unlaunchable-entrypoint fault used by macos-publish-fuzz.sh.
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
  printf '%s\n' "$platform" >/data/platform
  touch /data/ready
fi
exec server serve --repo "$repo" --addr 0.0.0.0:8080
