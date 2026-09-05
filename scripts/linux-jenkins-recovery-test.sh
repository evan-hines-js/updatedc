#!/usr/bin/env bash
set -euo pipefail
[[ $(uname -s) == Linux ]] || { echo "SKIP: Jenkins process ownership test requires Linux"; exit 0; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK=$(mktemp -d)
export JENKINS_DATA="$WORK/data" JENKINS_BACKUPS="$WORK/backups"
cleanup() {
  if [[ -f $JENKINS_DATA/jenkins.pid ]]; then
    kill "$(cat "$JENKINS_DATA/jenkins.pid")" 2>/dev/null || true
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT
mkdir -p "$JENKINS_DATA/jre/bin" "$JENKINS_DATA/home" "$WORK/old/bin" "$WORK/new/bin"
# A real native process at the runtime path exercises the installer's /proc identity checks.
# Avoid network installation: this test isolates snapshot and compensation ordering.
cp /bin/sleep "$JENKINS_DATA/jre/bin/java"
touch "$JENKINS_DATA/jenkins.war"
printf original >"$JENKINS_DATA/home/value"
cat >"$WORK/old/bin/app" <<'APP'
#!/bin/bash
exec "$JENKINS_DATA/jre/bin/java" 60
APP
cat >"$WORK/new/bin/app" <<'APP'
#!/bin/bash
printf migrated >"$JENKINS_DATA/home/value"
exec "$JENKINS_DATA/jre/bin/java" 60
APP
chmod +x "$WORK/old/bin/app" "$WORK/new/bin/app"
"$WORK/old/bin/app" &
original_pid=$!
printf '%s\n' "$original_pid" >"$JENKINS_DATA/jenkins.pid"
printf '%s\n' "$WORK/old" >"$JENKINS_DATA/payload-path"
printf '1.0.0\n' >"$JENKINS_DATA/installed-version"
wait_controller() {
  for _ in {1..100}; do
    local pid
    pid=$(cat "$JENKINS_DATA/jenkins.pid" 2>/dev/null || true)
    if [[ -n $pid && $(readlink "/proc/$pid/exe" 2>/dev/null || true) == "$JENKINS_DATA/jre/bin/java" ]]; then
      return 0
    fi
    sleep 0.05
  done
  echo "FAIL: test controller did not start" >&2
  return 1
}
wait_controller
invoke() {
  env UPDATED_OPERATION="$1" UPDATED_ATTEMPT_ID="$2" UPDATED_PAYLOAD_VERSION=2.0.0 \
    UPDATED_PAYLOAD_ROOT="$WORK/new" UPDATED_RESULT_FILE="$WORK/result.json" \
    bash "$ROOT/crates/updatec/e2e/jenkins/install.sh"
}
invoke converge transaction
wait "$original_pid" 2>/dev/null || true
wait_controller
[[ $(cat "$JENKINS_DATA/home/value") == migrated ]]
[[ $(tar xOf "$JENKINS_BACKUPS/before-transaction/home.tar.gz" home/value) == original ]]
invoke rollback transactionr
wait_controller
[[ $(cat "$JENKINS_DATA/home/value") == original ]]
[[ $(cat "$JENKINS_DATA/payload-path") == "$WORK/old" ]]
[[ $(cat "$JENKINS_DATA/installed-version") == 1.0.0 ]]
# Repeated compensation must preserve the original backup and restored data.
invoke rollback transactionr
wait_controller
[[ $(cat "$JENKINS_DATA/home/value") == original ]]
echo "PASS: Jenkins snapshot, explicit predecessor restoration, and repeated compensation"
