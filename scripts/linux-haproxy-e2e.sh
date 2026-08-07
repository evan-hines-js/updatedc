#!/usr/bin/env bash
set -euo pipefail

[[ "$(uname -s)" == Linux ]] || { echo "SKIP: real HAProxy test requires Linux"; exit 0; }
for command in haproxy curl pgrep readlink stat; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 1; }
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${UPDATED_HAPROXY_E2E_DIR:-$ROOT/target/haproxy-e2e}"
REPO="$WORK/repo"
KEYS="$WORK/keys"
INSTALL="$WORK/install"
BIN="$WORK/bin"
BOOTSTRAP="$WORK/bootstrap.toml"
RUNTIME="$WORK/runtime.json"
TOWER_LOG="$WORK/tower.log"
REPO_LOG="$WORK/repository.log"
TRAFFIC_LOG="$WORK/traffic.log"
HTTP_PORT="${UPDATED_HAPROXY_HTTP_PORT:-19091}"
REPO_PORT="${UPDATED_HAPROXY_REPO_PORT:-18081}"
REPO_PID=""
TOWER_PID=""
TRAFFIC_PID=""

cleanup() {
  set +e
  # HAProxy is provider-managed: it is detached from the agent tower, so killing the tower does not
  # take it with it and this is the only thing that reclaims the port it is bound to.
  [[ -f "$INSTALL/runtime/haproxy.pid" ]] && kill "$(cat "$INSTALL/runtime/haproxy.pid")" 2>/dev/null
  [[ -n "$TRAFFIC_PID" ]] && kill "$TRAFFIC_PID" 2>/dev/null
  [[ -n "$TOWER_PID" ]] && kill "$TOWER_PID" 2>/dev/null
  [[ -n "$REPO_PID" ]] && kill "$REPO_PID" 2>/dev/null
  [[ -n "$TRAFFIC_PID" ]] && wait "$TRAFFIC_PID" 2>/dev/null
  [[ -n "$TOWER_PID" ]] && wait "$TOWER_PID" 2>/dev/null
  [[ -n "$REPO_PID" ]] && wait "$REPO_PID" 2>/dev/null
}
trap cleanup EXIT INT TERM

fail() {
  echo "FAIL: $*" >&2
  echo "--- tower log ---" >&2
  tail -n 120 "$TOWER_LOG" >&2 2>/dev/null || true
  echo "--- traffic log ---" >&2
  tail -n 40 "$TRAFFIC_LOG" >&2 2>/dev/null || true
  exit 1
}

wait_version() {
  local expected="$1"
  for _ in {1..200}; do
    [[ "$(curl -fsS --max-time 1 "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null || true)" == "$expected" ]] && return
    sleep 0.1
  done
  fail "HAProxy did not converge to $expected"
}

wait_new_worker() {
  local master="$1" old="$2" found
  for _ in {1..100}; do
    found="$(pgrep -P "$master" 2>/dev/null | sort -n | tail -n1 || true)"
    [[ -n "$found" && "$found" != "$old" ]] && { echo "$found"; return; }
    sleep 0.1
  done
  return 1
}

wait_master_loaded_runtime() {
  local master="$1" expected actual
  expected="$(stat -Lc '%d:%i' "$INSTALL/runtime/haproxy")"
  for _ in {1..100}; do
    actual="$(stat -Lc '%d:%i' "/proc/$master/exe" 2>/dev/null || true)"
    [[ "$actual" == "$expected" ]] && return
    sleep 0.1
  done
  return 1
}

make_config() {
  local destination="$1" version="$2" validity="${3:-valid}"
  mkdir -p "$destination/bin" "$destination/config"
  cp "$(command -v haproxy)" "$destination/bin/haproxy"
  # Distinct trailing bytes leave a valid ELF executable but give every candidate a
  # different signed artifact and inode, so the test proves binary re-exec.
  printf '\nUPDATED-HAPROXY-CANDIDATE=%s\n' "$version" >>"$destination/bin/haproxy"
  chmod 0755 "$destination/bin/haproxy"
  if [[ "$validity" == invalid-binary ]]; then
    printf 'not an executable\n' >"$destination/bin/haproxy"
    chmod 0755 "$destination/bin/haproxy"
  fi
  cat >"$destination/config/haproxy.cfg" <<EOF
global
    master-worker
    stats socket $INSTALL/runtime/admin.sock mode 600 level admin expose-fd listeners

defaults
    mode http
    timeout connect 2s
    timeout client 10s
    timeout server 10s

frontend test
    bind 127.0.0.1:$HTTP_PORT
    http-request return status 200 content-type text/plain string $version
EOF
  if [[ "$validity" == valid ]]; then
    haproxy -c -f "$destination/config/haproxy.cfg" >/dev/null
  fi
}

publish() {
  local version="$1" tree="$2"
  "$BIN/server" publish-app --repo "$REPO" --keys "$KEYS" --product app \
    --channel stable --version "$version" --bundle "linux-x86_64=$tree" \
    --entrypoint bin/launch
  assign "$version"
}

target_sha256() { "$BIN/server" target-sha256 --repo "$REPO" --name "$1"; }
assign() {
  local version="$1" app_path="products/app/stable/$1/linux-x86_64/app" set_path="provider-sets/default.json"
  "$BIN/server" publish-assignment --repo "$REPO" --keys "$KEYS" \
    --name assignments/agents/agent.json --deployment "app-$version" \
    --metadata-url "http://127.0.0.1:$REPO_PORT/metadata/" \
    --targets-url "http://127.0.0.1:$REPO_PORT/targets/" \
    --application-path "$app_path" --application-sha256 "$(target_sha256 "$app_path")" \
    --provider-set-path "$set_path" --provider-set-sha256 "$(target_sha256 "$set_path")" \
    --runtime "$RUNTIME"
}

rm -rf "$WORK"
mkdir -p "$BIN" "$WORK/guardian-state"
(cd "$ROOT" && cargo build --release -p server -p bootstrap -p supervisor)
cp "$ROOT/target/release/"{server,bootstrap,supervisor} "$BIN/"
# The lifecycle provider and its helpers are the real, tested bundle scripts under scripts/haproxy/ —
# the same bytes the demo publishes — so this e2e proves the shipped provider, not an inline copy.
cp "$ROOT/scripts/haproxy/lifecycle" "$BIN/lifecycle"
cp "$ROOT/scripts/haproxy/lib.sh" "$BIN/lib.sh"
chmod 0755 "$BIN/lifecycle"

"$BIN/server" init --repo "$REPO" --keys "$KEYS"
mkdir -p "$WORK/adapter/bin"
cp "$ROOT/scripts/haproxy/lifecycle" "$WORK/adapter/bin/lifecycle"
cp "$ROOT/scripts/haproxy/lib.sh" "$WORK/adapter/bin/lib.sh"
chmod 0755 "$WORK/adapter/bin/lifecycle"
"$BIN/server" publish-provider-artifact --repo "$REPO" --keys "$KEYS" \
  --product app-lifecycle --version 1.0.0 \
  --bundle "linux-x86_64=$WORK/adapter" --entrypoint bin/lifecycle
provider_path="products/app-lifecycle/stable/1.0.0/linux-x86_64/app-lifecycle"
"$BIN/server" publish-provider-set --repo "$REPO" --keys "$KEYS" --id default \
  --provider-path "$provider_path" --provider-sha256 "$(target_sha256 "$provider_path")" \
  --provider-timeout-ms 10000
for version in 1.0.0 2.0.0 4.0.0; do make_config "$WORK/bundle-$version" "$version"; done
make_config "$WORK/bundle-3.0.0" 3.0.0 invalid-binary

# The deployment is provider-managed (see $RUNTIME above): the agent starts no application process,
# so the launcher is what the reconciler's `apply` runs when no master is up. It puts HAProxy at a
# stable path; every subsequent upgrade is HAProxy's own SIGUSR2 re-exec of that same master. It is
# the real bundle launcher (scripts/haproxy/launch), the same one the demo ships.
for tree in "$WORK"/bundle-*; do
  cp "$ROOT/scripts/haproxy/launch" "$tree/bin/launch"
  chmod 0755 "$tree/bin/launch"
done

cat >"$RUNTIME" <<EOF
{"mode":"provider-managed","product":"app","channel":"stable","install_root":"$INSTALL","args":[],"repository":{"metadata_limit":1048576,"target_limit":536870912,"transport_timeout_seconds":5},"storage":{"inactive_releases":2,"inactive_providers":2,"inactive_supervisors":1,"inactive_bytes":1073741824,"inactive_repository_caches":2},"timeouts":{"check_interval_seconds":1,"health_grace_seconds":4,"health_successes":1,"health_interval_seconds":1,"retry_after_seconds":60,"refresh_retry_seconds":1,"confirmation_window_seconds":2,"supervisor_check_interval_seconds":3600}}
EOF
publish 1.0.0 "$WORK/bundle-1.0.0"
"$BIN/server" export-enrollment --repo "$REPO" --assignment assignments/agents/agent.json \
  --agent-id agent --routing-base-url "http://127.0.0.1:$REPO_PORT/" \
  --output "$WORK/guardian-state/enrollment.json"
# Enrollment is preplaced (export-enrollment wrote enrollment.json above), so the agent never calls
# /enroll — but the bootstrap config must still be a complete, valid EnrollmentBootstrap. The name
# and cert paths are never read in this offline path; they only satisfy config validation.
cat >"$BOOTSTRAP" <<EOF
[enrollment]
url = "http://127.0.0.1:$REPO_PORT/"
name = "agent"
client_cert = "unused-preplaced.crt"
client_key = "unused-preplaced.key"
ca = "unused-preplaced-ca.crt"
EOF

: >"$TOWER_LOG"; : >"$REPO_LOG"; : >"$TRAFFIC_LOG"
"$BIN/server" serve --repo "$REPO" --addr "127.0.0.1:$REPO_PORT" >>"$REPO_LOG" 2>&1 &
REPO_PID="$!"
"$BIN/bootstrap" --state-dir "$WORK/guardian-state" --supervisor-config "$BOOTSTRAP" \
  --supervisor "$BIN/supervisor" --stop-grace 2 >>"$TOWER_LOG" 2>&1 &
TOWER_PID="$!"
wait_version 1.0.0

# First deployment: nothing but the reconciler can have started this master, because the agent owns
# no application process in provider-managed mode — it says so itself in the log, and the serving
# HAProxy above is the proof that `apply` did the starting.
grep -q 'started provider-managed runtime' "$TOWER_LOG" || fail "the agent did not run this deployment in provider-managed mode"
master_pid="$(cat "$INSTALL/runtime/haproxy.pid")"
[[ "$(readlink "/proc/$master_pid/exe")" == "$INSTALL/runtime/haproxy" ]] || fail "master is not running the stable executable"
initial_exe_inode="$(stat -Lc '%d:%i' "/proc/$master_pid/exe")"

( while true; do
    body="$(curl -fsS --max-time 1 "http://127.0.0.1:$HTTP_PORT/" 2>/dev/null)" || { echo unavailable >>"$TRAFFIC_LOG"; continue; }
    case "$body" in 1.0.0|2.0.0|4.0.0) ;; *) echo "invalid:$body" >>"$TRAFFIC_LOG" ;; esac
  done ) &
TRAFFIC_PID="$!"

old_worker="$(pgrep -P "$master_pid" | head -n1)"
publish 2.0.0 "$WORK/bundle-2.0.0"
wait_version 2.0.0
[[ "$(cat "$INSTALL/runtime/haproxy.pid")" == "$master_pid" ]] || fail "master PID changed on valid upgrade"
new_worker="$(wait_new_worker "$master_pid" "$old_worker")" || fail "HAProxy did not replace its worker"
wait_master_loaded_runtime "$master_pid" || fail "master did not re-exec the runtime binary the upgrade staged"
[[ "$(stat -Lc '%d:%i' "/proc/$master_pid/exe")" != "$initial_exe_inode" ]] || fail "master did not re-exec the candidate binary inode"

# The updater provides at-least-once provider execution across the unavoidable
# action/journal-write crash gap. Prove this real provider converges when the exact same
# activation is replayed, rather than relying only on the purpose-built sample server.
release2="$(find "$INSTALL/versions" -maxdepth 1 -type d -name '2.0.0-*' -print -quit)"
[[ -n "$release2" ]] || fail "could not locate the immutable HAProxy 2.0.0 release"
for _ in 1 2; do
  "$BIN/lifecycle" apply \
    --protocol 1 \
    --attempt-id haproxy-idempotency-replay \
    --reason update \
    --install-root "$INSTALL" \
    --state-dir "$INSTALL/providers/state/haproxy" \
    --candidate "$release2" \
    --candidate-version 2.0.0 \
    --predecessor "$release2" \
    --predecessor-version 2.0.0
done

# Those replays ran `apply` against the live master, which is the provider's in-place upgrade
# path: it stages the release and SIGUSR2s the master. Prove it happened rather than assuming —
# same master PID, a fresh worker, and the master's image is the freshly staged runtime binary.
[[ "$(cat "$INSTALL/runtime/haproxy.pid")" == "$master_pid" ]] || fail "replayed apply restarted the master instead of re-execing it"
preflight_worker="$(wait_new_worker "$master_pid" "$new_worker")" || fail "replayed apply did not turn the worker over"
wait_master_loaded_runtime "$master_pid" || fail "master did not re-exec the runtime binary the replayed apply staged"
preflight_inode="$(stat -Lc '%d:%i' "/proc/$master_pid/exe")"
publish 3.0.0 "$WORK/bundle-3.0.0"
sleep 6
[[ "$(curl -fsS "http://127.0.0.1:$HTTP_PORT/")" == 2.0.0 ]] || fail "invalid binary displaced the healthy release"
grep -q 'failed lifecycle preflight' "$TOWER_LOG" || fail "invalid binary preflight failure was not recorded"
grep -q 'rejected 3.0.0 before activation' "$TOWER_LOG" || fail "invalid binary was not rejected before activation"
[[ "$(cat "$INSTALL/runtime/haproxy.pid")" == "$master_pid" ]] || fail "master PID changed during failed preflight"
[[ "$(stat -Lc '%d:%i' "/proc/$master_pid/exe")" == "$preflight_inode" ]] || fail "failed preflight replaced the live executable"
pgrep -P "$master_pid" | grep -qx "$preflight_worker" || fail "failed preflight replaced the live worker"

publish 4.0.0 "$WORK/bundle-4.0.0"
wait_version 4.0.0
[[ "$(cat "$INSTALL/runtime/haproxy.pid")" == "$master_pid" ]] || fail "master PID changed on recovery upgrade"
kill "$TRAFFIC_PID"; wait "$TRAFFIC_PID" 2>/dev/null || true; TRAFFIC_PID=""
[[ ! -s "$TRAFFIC_LOG" ]] || fail "traffic failed during HAProxy upgrades"

# The other half of the provider's process duty: with the master gone, `apply` STARTS HAProxy — in
# provider-managed mode nothing else will. This is the first-deployment path again, run against an
# already-upgraded node. The traffic probe is stopped first, so the deliberate outage is not counted
# as a dropped request; while it lasts the agent simply reports the node unhealthy (a provider-managed
# liveness failure never tears the tower down, so no restart races this).
release4="$(find "$INSTALL/versions" -maxdepth 1 -type d -name '4.0.0-*' -print -quit)"
[[ -n "$release4" ]] || fail "could not locate the immutable HAProxy 4.0.0 release"
kill "$master_pid"
for _ in {1..100}; do
  kill -0 "$master_pid" 2>/dev/null || break
  sleep 0.1
done
if kill -0 "$master_pid" 2>/dev/null; then fail "the HAProxy master did not exit"; fi
# The workers go with it; wait for the listener to be released so the restart cannot lose a bind.
for _ in {1..100}; do
  curl -fsS --max-time 1 "http://127.0.0.1:$HTTP_PORT/" >/dev/null 2>&1 || break
  sleep 0.1
done
"$BIN/lifecycle" apply \
  --protocol 1 \
  --attempt-id haproxy-start-duty \
  --reason update \
  --install-root "$INSTALL" \
  --state-dir "$INSTALL/providers/state/haproxy" \
  --candidate "$release4" \
  --candidate-version 4.0.0 \
  --predecessor "$release4" \
  --predecessor-version 4.0.0
restarted_pid="$(cat "$INSTALL/runtime/haproxy.pid")"
[[ "$restarted_pid" != "$master_pid" ]] || fail "apply reported a master that is the one we killed"
kill -0 "$restarted_pid" 2>/dev/null || fail "apply returned success without a running master"
[[ "$(readlink "/proc/$restarted_pid/exe")" == "$INSTALL/runtime/haproxy" ]] || fail "the started master is not running the stable executable"
wait_version 4.0.0

echo "PASS: real HAProxy started by the provider, upgraded by SIGUSR2 with stable master PID $master_pid, safe duplicate activation, worker turnover, preflight rejection, and zero failed probes"
