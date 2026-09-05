#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/updatedc-source-check.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

cd "$ROOT"

printf '\n==> Rust formatting\n'
cargo fmt --all --check

printf '\n==> Agent archive extraction boundary\n'
bash scripts/test-agent-archive.sh

printf '\n==> Fleet fuzz release plan\n'
# shellcheck source=scripts/lib/publish-fuzz-plan.sh
. scripts/lib/publish-fuzz-plan.sh
actual=""
for round in $(seq 1 20); do
  for lane in 0 1 2; do
    version="$(publish_fuzz_generation_version "$round" "$lane")"
    major=${version%%.*}
    if [[ "$major" -ge "$PUBLISH_FUZZ_RESERVED_FIRST_MAJOR" \
      && "$major" -le "$PUBLISH_FUZZ_RESERVED_LAST_MAJOR" ]]; then
      echo "FAIL: ordinary fuzz generation $round/$lane selected reserved release $version" >&2
      exit 1
    fi
    if [[ "$round" -le 6 ]]; then
      actual="${actual}${actual:+ }$version"
    fi
  done
done
expected="4.0.0 5.0.0 6.0.0 7.0.0 8.0.0 9.0.0 10.0.0 11.0.0 12.0.0 13.0.0 14.0.0 15.0.0 16.0.0 17.0.0 22.0.0 23.0.0 24.0.0 25.0.0"
[[ "$actual" == "$expected" ]] || {
  echo "FAIL: ordinary fuzz release plan drifted: $actual" >&2
  exit 1
}
[[ "$(publish_fuzz_max_major 0)" == 22 ]] || {
  echo "FAIL: zero-round fixture no longer publishes the Rust fleet baseline" >&2
  exit 1
}
[[ "$(publish_fuzz_max_major 20)" == 67 ]] || {
  echo "FAIL: the extended 20-round soak is not fully published" >&2
  exit 1
}
echo "ok: ordinary generations skip the rollback corpus and the publisher covers the soak"

printf '\n==> Generated CRDs\n'
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    echo "SKIP: CRD byte comparison runs on Unix to avoid checkout newline conversion"
    ;;
  *)
    generated_crds="$WORK/generated-crds.yaml"
    cargo run -q -p updatec --example crdgen >"$generated_crds"
    if ! diff -u deploy/charts/updatec/crds/updated.dev_crds.yaml "$generated_crds"; then
      echo "FAIL: deploy/charts/updatec/crds/updated.dev_crds.yaml is stale" >&2
      echo "regenerate it with:" >&2
      echo "  cargo run -q -p updatec --example crdgen > deploy/charts/updatec/crds/updated.dev_crds.yaml" >&2
      exit 1
    fi
    ;;
esac
