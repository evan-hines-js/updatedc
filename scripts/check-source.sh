#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/updatedc-source-check.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

cd "$ROOT"

printf '\n==> Rust formatting\n'
cargo fmt --all --check

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
