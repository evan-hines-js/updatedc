#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIFECYCLE="$HERE/lifecycle"
WORK="$(mktemp -d)"
trap 'jobs -p | xargs kill 2>/dev/null || true; rm -rf "$WORK"' EXIT

INSTALL="$WORK/install root"
STATE="$INSTALL/providers/state/haproxy"
mkdir -p "$STATE"

release() {
  local root=$1 version=$2
  mkdir -p "$root/bin" "$root/config"
  cat >"$root/bin/haproxy" <<'SH'
#!/usr/bin/env bash
exit 0
SH
  chmod 0755 "$root/bin/haproxy"
  printf 'global\n  daemon\n' >"$root/config/haproxy.cfg"
  printf '%s\n' "$version" >"$root/VERSION"
}

release "$WORK/v1" 1.0.0
release "$WORK/v2" 2.0.0
mkdir -p "$WORK/bad/bin" "$WORK/bad/config"

invoke() {
  local operation=$1 candidate=$2 predecessor=$3 attempt=$4
  "$LIFECYCLE" "$operation" \
    --protocol 1 \
    --attempt-id "$attempt" \
    --reason update \
    --install-root "$INSTALL" \
    --state-dir "$STATE" \
    --candidate "$candidate" \
    --candidate-version 2.0.0 \
    --predecessor "$predecessor" \
    --predecessor-version 1.0.0
}

invoke preflight "$WORK/v2" "$WORK/v1" preflight
if invoke preflight "$WORK/bad" "$WORK/v1" bad-preflight 2>/dev/null; then
  echo "preflight accepted an invalid candidate" >&2
  exit 1
fi

invoke activate "$WORK/v2" "$WORK/v1" update
test -f "$INSTALL/runtime/haproxy.cfg"

# Replaying the same mutation must converge.
invoke activate "$WORK/v2" "$WORK/v1" update

sleep 60 &
master=$!
printf '%s\n' "$master" >"$INSTALL/runtime/haproxy.pid"
invoke verify "$WORK/v2" "$WORK/v1" update
invoke periodic "$WORK/v2" "$WORK/v1" periodic

invoke rollback "$WORK/v2" "$WORK/v1" rollback
test -f "$INSTALL/runtime/haproxy.cfg"

for operation in prepare pre-drain drain stop pre-start start finalize; do
  invoke "$operation" "$WORK/v2" "$WORK/v1" "noop-$operation"
done

if "$LIFECYCLE" nonsense --protocol 1 --attempt-id x --reason update \
  --install-root "$INSTALL" --state-dir "$STATE" --candidate "$WORK/v2" \
  --candidate-version 2.0.0 --predecessor "$WORK/v1" \
  --predecessor-version 1.0.0 2>/dev/null; then
  echo "unknown operation succeeded" >&2
  exit 1
fi

echo "haproxy reconciler tests passed"
