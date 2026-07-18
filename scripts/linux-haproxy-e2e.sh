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
CONFIG="$WORK/config.toml"
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
    http-request return status 200 content-type text/plain hdr X-Updated-Token %[env(UPDATED_HEALTH_TOKEN)] hdr X-Updated-Version $version string $version
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
    --name assignments/nodes/node.json --deployment "app-$version" \
    --metadata-url "http://127.0.0.1:$REPO_PORT/metadata/" \
    --targets-url "http://127.0.0.1:$REPO_PORT/targets/" \
    --application-path "$app_path" --application-sha256 "$(target_sha256 "$app_path")" \
    --provider-set-path "$set_path" --provider-set-sha256 "$(target_sha256 "$set_path")"
}

rm -rf "$WORK"
mkdir -p "$BIN" "$WORK/guardian-state"
(cd "$ROOT" && cargo build --release -p server -p bootstrap -p supervisor)
cp "$ROOT/target/release/"{server,bootstrap,supervisor} "$BIN/"
cp "$ROOT/scripts/haproxy-activate.sh" "$BIN/activate"
chmod 0755 "$BIN/activate"
cat >"$BIN/lifecycle" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
case "${UPDATED_LIFECYCLE_PHASE:?}" in
  preflight)
    exec "$UPDATED_CANDIDATE/bin/haproxy" -c -f "$UPDATED_CANDIDATE/config/haproxy.cfg"
    ;;
  activate)
    exec "$(dirname "$0")/activate" "$UPDATED_CANDIDATE" "$UPDATED_INSTALL_ROOT/runtime" "$UPDATED_CHILD_PID"
    ;;
  drain|prepare|stop|start|verify|finalize|rollback)
    exit 0
    ;;
esac
EOF
chmod 0755 "$BIN/lifecycle"

"$BIN/server" init --repo "$REPO" --keys "$KEYS"
mkdir -p "$WORK/adapter/bin"
cp "$BIN/lifecycle" "$WORK/adapter/bin/lifecycle"
cp "$BIN/activate" "$WORK/adapter/bin/activate"
"$BIN/server" publish-provider-artifact --repo "$REPO" --keys "$KEYS" \
  --product app-lifecycle --version 1.0.0 \
  --bundle "linux-x86_64=$WORK/adapter" --entrypoint bin/lifecycle
provider_path="products/app-lifecycle/stable/1.0.0/linux-x86_64/app-lifecycle"
"$BIN/server" publish-provider-set --repo "$REPO" --keys "$KEYS" --id default \
  --provider-path "$provider_path" --provider-sha256 "$(target_sha256 "$provider_path")" \
  --provider-timeout-ms 10000
for version in 1.0.0 2.0.0 4.0.0; do make_config "$WORK/bundle-$version" "$version"; done
make_config "$WORK/bundle-3.0.0" 3.0.0 invalid-binary

# The launcher is the manifested entrypoint only for first process creation. It puts
# HAProxy at a stable path; subsequent upgrades are HAProxy's own SIGUSR2 re-execs.
for tree in "$WORK"/bundle-*; do
  cat >"$tree/bin/launch" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
runtime="$UPDATED_INSTALL_ROOT/runtime"
mkdir -p "$runtime"
cp "$(dirname "$0")/haproxy" "$runtime/.haproxy.initial"
chmod 0755 "$runtime/.haproxy.initial"
cp "$(dirname "$0")/../config/haproxy.cfg" "$runtime/.haproxy.cfg.initial"
mv -f "$runtime/.haproxy.initial" "$runtime/haproxy"
mv -f "$runtime/.haproxy.cfg.initial" "$runtime/haproxy.cfg"
exec "$runtime/haproxy" -W -db -f "$runtime/haproxy.cfg" -p "$runtime/haproxy.pid"
EOF
  chmod 0755 "$tree/bin/launch"
done

"$BIN/server" install-app --install-root "$INSTALL" --product app --version 1.0.0 \
  --platform linux-x86_64 --bundle "$WORK/bundle-1.0.0" --entrypoint bin/launch
publish 1.0.0 "$WORK/bundle-1.0.0"

cat >"$CONFIG" <<EOF
[routing]
root = "$REPO/metadata/root.json"
base_url = "http://127.0.0.1:$REPO_PORT/"
assignment = "assignments/nodes/node.json"
transport_timeout = "5s"
[repository]
root = "$REPO/metadata/root.json"
transport_timeout = "5s"
[application]
product = "app"
channel = "stable"
install_root = "$INSTALL"
health_url = "http://127.0.0.1:$HTTP_PORT/"
[application.activation]
mode = "reexec"
[timeouts]
check_interval = "1s"
health_grace = "4s"
retry_after = "60s"
refresh_retry = "1s"
confirmation_window = "2s"
EOF

: >"$TOWER_LOG"; : >"$REPO_LOG"; : >"$TRAFFIC_LOG"
"$BIN/server" serve --repo "$REPO" --addr "127.0.0.1:$REPO_PORT" >>"$REPO_LOG" 2>&1 &
REPO_PID="$!"
"$BIN/bootstrap" --state-dir "$WORK/guardian-state" --supervisor-config "$CONFIG" \
  --supervisor "$BIN/supervisor" --stop-grace 2 >>"$TOWER_LOG" 2>&1 &
TOWER_PID="$!"
wait_version 1.0.0

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
[[ "$(stat -Lc '%d:%i' "/proc/$master_pid/exe")" != "$initial_exe_inode" ]] || fail "master did not re-exec the candidate binary inode"

# The updater provides at-least-once provider execution across the unavoidable
# action/journal-write crash gap. Prove this real provider converges when the exact same
# activation is replayed, rather than relying only on the purpose-built sample server.
release2="$(find "$INSTALL/versions" -maxdepth 1 -type d -name '2.0.0-*' -print -quit)"
[[ -n "$release2" ]] || fail "could not locate the immutable HAProxy 2.0.0 release"
replay_worker="$new_worker"
for _ in 1 2; do
  old_worker="$(pgrep -P "$master_pid" | sort -n | tail -n1)"
  UPDATED_LIFECYCLE_PHASE=activate \
  UPDATED_LIFECYCLE_ATTEMPT_ID=haproxy-idempotency-replay \
  UPDATED_CANDIDATE="$release2" \
  UPDATED_INSTALL_ROOT="$INSTALL" \
    UPDATED_CHILD_PID="$master_pid" \
    "$BIN/lifecycle"
  replay_worker="$(wait_new_worker "$master_pid" "$old_worker")" || fail "duplicate activation did not finish worker turnover"
  wait_master_loaded_runtime "$master_pid" || fail "duplicate activation did not finish master re-exec"
  wait_version 2.0.0
done
[[ "$(cat "$INSTALL/runtime/haproxy.pid")" == "$master_pid" ]] || fail "idempotent activation replay changed the HAProxy master PID"

preflight_worker="$replay_worker"
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

echo "PASS: real HAProxy upgraded by SIGUSR2 with stable master PID $master_pid, safe duplicate activation, worker turnover, preflight rejection, and zero failed probes"
