#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SUITE="${1:-all}"
LINUX_HOST="${UPDATEDC_CI_LINUX_HOST:-root@10.0.0.206}"
LINUX_DIR="${UPDATEDC_CI_LINUX_DIR:-/var/tmp/updatedc-ci}"
FUZZ_ROUNDS="${UPDATEC_FUZZ_ROUNDS:-1}"
LOCK_DIR="${LINUX_DIR}.lock"
LOCKED=0
LOCAL_PID=""
LINUX_PID=""

usage() {
  cat <<'EOF'
usage: scripts/ci-mac-linux.sh [all|rust|charts|semgrep|trivy|haproxy|kind|fleet]

Synchronize the exact local working tree to Linux, then run scripts/ci.sh on
this Mac and Linux concurrently. Configuration:

  UPDATEDC_CI_LINUX_HOST  SSH destination (default: root@10.0.0.206)
  UPDATEDC_CI_LINUX_DIR   dedicated remote mirror (default: /var/tmp/updatedc-ci)
  UPDATEC_FUZZ_ROUNDS     Kind fleet-fuzz rounds on both hosts (default: 1)
EOF
}

case "$SUITE" in
  all|rust|charts|semgrep|trivy|haproxy|kind|fleet) ;;
  --help|-h)
    usage
    exit 0
    ;;
  *)
    echo "FAIL: unknown CI suite '$SUITE'" >&2
    usage >&2
    exit 2
    ;;
esac
[[ $# -le 1 ]] || { echo "FAIL: only one CI suite may be selected" >&2; exit 2; }
[[ "$LINUX_HOST" =~ ^[A-Za-z0-9_.:@-]+$ ]] || {
  echo "FAIL: unsafe SSH destination '$LINUX_HOST'" >&2
  exit 2
}
[[ "$LINUX_DIR" =~ ^/[A-Za-z0-9_./-]+$ ]] || {
  echo "FAIL: remote directory must be an absolute simple path" >&2
  exit 2
}
case "$LINUX_DIR" in
  *'/../'*|*'/./'*)
    echo "FAIL: remote directory may not contain traversal components" >&2
    exit 2
    ;;
esac
case "$LINUX_DIR" in
  /updatedc-ci|/*/updatedc-ci|/*/updatedc-ci-*) ;;
  *)
    echo "FAIL: remote directory must be dedicated and named updatedc-ci or updatedc-ci-*" >&2
    exit 2
    ;;
esac
[[ "$FUZZ_ROUNDS" =~ ^[0-9]+$ ]] || {
  echo "FAIL: UPDATEC_FUZZ_ROUNDS must be a non-negative integer" >&2
  exit 2
}

for command in rsync ssh; do
  command -v "$command" >/dev/null || {
    echo "FAIL: missing required command: $command" >&2
    exit 2
  }
done

release_remote_lock() {
  if (( LOCKED == 1 )); then
    ssh -o BatchMode=yes "$LINUX_HOST" "rmdir -- '$LOCK_DIR'" >/dev/null 2>&1 || true
    LOCKED=0
  fi
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$LOCAL_PID" ]]; then kill "$LOCAL_PID" >/dev/null 2>&1 || true; fi
  if [[ -n "$LINUX_PID" ]]; then kill "$LINUX_PID" >/dev/null 2>&1 || true; fi
  release_remote_lock
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

echo "Acquiring Linux workspace lock on $LINUX_HOST"
if ! ssh -o BatchMode=yes "$LINUX_HOST" "mkdir -- '$LOCK_DIR'"; then
  echo "FAIL: another Linux CI run owns $LOCK_DIR" >&2
  echo "If no run is active, remove that stale directory explicitly and retry." >&2
  exit 1
fi
LOCKED=1

echo "Synchronizing the working tree to $LINUX_HOST:$LINUX_DIR"
ssh -o BatchMode=yes "$LINUX_HOST" \
  "mkdir -p -- '$LINUX_DIR' && touch '$LINUX_DIR/.updatedc-ci-rsync-root'"
rsync -az --delete-delay \
  --filter=':- .gitignore' \
  --exclude '/.git/' \
  --exclude '/.code-review-graph/' \
  --exclude '/.DS_Store' \
  --exclude '/.updatedc-ci-rsync-root' \
  --exclude '/dist/' \
  --exclude '/target/' \
  -e 'ssh -o BatchMode=yes' \
  "$ROOT/" "$LINUX_HOST:$LINUX_DIR/"
ssh -o BatchMode=yes "$LINUX_HOST" \
  "test -f '$LINUX_DIR/.updatedc-ci-rsync-root' && test -x '$LINUX_DIR/scripts/ci.sh'"

prefix_output() {
  local label=$1 line
  while IFS= read -r line || [[ -n "$line" ]]; do
    printf '[%s] %s\n' "$label" "$line"
  done
}

run_local() {
  UPDATEC_FUZZ_ROUNDS="$FUZZ_ROUNDS" "$ROOT/scripts/ci.sh" "$SUITE" 2>&1 \
    | prefix_output mac
}

run_linux() {
  ssh -o BatchMode=yes "$LINUX_HOST" \
    "cd '$LINUX_DIR' && UPDATEC_FUZZ_ROUNDS='$FUZZ_ROUNDS' exec ./scripts/ci.sh '$SUITE'" \
    2>&1 | prefix_output linux
}

echo "Running CI suite '$SUITE' on macOS and Linux in parallel"
run_local &
LOCAL_PID=$!
run_linux &
LINUX_PID=$!

set +e
wait "$LOCAL_PID"
LOCAL_RC=$?
LOCAL_PID=""
wait "$LINUX_PID"
LINUX_RC=$?
LINUX_PID=""
set -e

release_remote_lock
echo "macOS exit=$LOCAL_RC, Linux exit=$LINUX_RC"
if (( LOCAL_RC != 0 || LINUX_RC != 0 )); then
  exit 1
fi
echo "PASS: macOS and Linux CI suite $SUITE"
