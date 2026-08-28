#!/usr/bin/env bash
set -euo pipefail

[[ "$(uname -s)" == Linux ]] || { echo "SKIP: real HAProxy test requires Linux"; exit 0; }
for command in haproxy curl pgrep readlink stat; do
  command -v "$command" >/dev/null || { echo "missing required command: $command" >&2; exit 1; }
done

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# Fixed beneath the repository because this directory is recursively replaced below. An arbitrary
# environment path makes a typo in a test-only convenience variable a destructive operation.
WORK="$ROOT/target/haproxy-e2e"
ROUTING_REPO="$WORK/routing-repo"
ROUTING_KEYS="$WORK/routing-keys"
RELEASE_REPO="$WORK/release-repo"
RELEASE_KEYS="$WORK/release-keys"
CERTS="$WORK/certs"
INSTALL="$WORK/install"
BIN="$WORK/bin"
CONFIG="$WORK/config.toml"
RUNTIME="$WORK/runtime.json"
STACK_LOG="$WORK/tower.log"
REPO_LOG="$WORK/repository.log"
TRAFFIC_LOG="$WORK/traffic.log"
HTTP_PORT="${UPDATED_HAPROXY_HTTP_PORT:-19091}"
REPO_PORT="${UPDATED_HAPROXY_REPO_PORT:-18081}"
OBJECT_PORT="${UPDATED_HAPROXY_OBJECT_PORT:-18082}"
for port in "$HTTP_PORT" "$REPO_PORT" "$OBJECT_PORT"; do
  if [[ ${#port} -gt 5 || ! "$port" =~ ^[0-9]+$ ]]; then
    echo "FAIL: HAProxy E2E ports must be integers from 1 through 65535, got '$port'" >&2
    exit 2
  fi
  if (( 10#$port < 1 || 10#$port > 65535 )); then
    echo "FAIL: HAProxy E2E ports must be integers from 1 through 65535, got '$port'" >&2
    exit 2
  fi
done
[[ "$HTTP_PORT" != "$REPO_PORT" && "$HTTP_PORT" != "$OBJECT_PORT" \
  && "$REPO_PORT" != "$OBJECT_PORT" ]] || {
  echo "FAIL: HAProxy E2E ports must be distinct" >&2
  exit 2
}
REPO_PID=""
OBJECT_PID=""
STACK_PID=""
TRAFFIC_PID=""
FOREIGN_PID=""

cleanup() {
  set +e
  # The release's reconciler owns HAProxy, so it is detached from the node stack: killing the stack
  # does not take it with it, and this is the only thing that reclaims the port it is bound to.
  [[ -f "$INSTALL/runtime/haproxy.pid" ]] && kill "$(cat "$INSTALL/runtime/haproxy.pid")" 2>/dev/null
  [[ -n "$FOREIGN_PID" ]] && kill "$FOREIGN_PID" 2>/dev/null
  [[ -n "$TRAFFIC_PID" ]] && kill "$TRAFFIC_PID" 2>/dev/null
  [[ -n "$STACK_PID" ]] && kill "$STACK_PID" 2>/dev/null
  [[ -n "$REPO_PID" ]] && kill "$REPO_PID" 2>/dev/null
  [[ -n "$OBJECT_PID" ]] && kill "$OBJECT_PID" 2>/dev/null
  [[ -n "$TRAFFIC_PID" ]] && wait "$TRAFFIC_PID" 2>/dev/null
  [[ -n "$STACK_PID" ]] && wait "$STACK_PID" 2>/dev/null
  [[ -n "$REPO_PID" ]] && wait "$REPO_PID" 2>/dev/null
  [[ -n "$OBJECT_PID" ]] && wait "$OBJECT_PID" 2>/dev/null
}
trap cleanup EXIT INT TERM

fail() {
  echo "FAIL: $*" >&2
  echo "--- tower log ---" >&2
  tail -n 120 "$STACK_LOG" >&2 2>/dev/null || true
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

rejection_count() {
  local ledger="$INSTALL/state/rejected"
  [[ -f "$ledger" ]] || { echo 0; return; }
  wc -l <"$ledger"
}

# A failed activation first records its verdict and rollback journal, then exits so the next boot
# performs the one rollback path. Synchronize on those durable facts: a log line emitted while the
# next boot plans recovery is diagnostic output, not a state-machine boundary.
wait_failed_candidate_recovered() {
  local previous_rejections="$1" expected_version="$2" active="$INSTALL/active-release"
  for _ in {1..200}; do
    if (( $(rejection_count) > previous_rejections )) &&
       [[ -f "$active" ]] && grep -q "\"version\":\"$expected_version\"" "$active" &&
       [[ ! -e "$INSTALL/state/transaction.json" ]]; then
      return
    fi
    sleep 0.1
  done
  fail "failed candidate did not reach a durable rejection and completed rollback"
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
  "$BIN/server" publish-app --repo "$RELEASE_REPO" --keys "$RELEASE_KEYS" --product app \
    --channel stable --version "$version" --bundle "linux-x86_64=$tree" \
    --entrypoint bin/launch
  assign "$version"
}

target_sha256() { "$BIN/server" target-sha256 --repo "$RELEASE_REPO" --name "$1"; }
assign() {
  local version="$1" app_path="products/app/stable/$1/linux-x86_64/app" set_path="provider-sets/default.json"
  "$BIN/server" publish-assignment --repo "$ROUTING_REPO" --keys "$ROUTING_KEYS" \
    --release-root "$RELEASE_REPO/metadata/root.json" \
    --name assignments/agents/agent.json --deployment "app-$version" \
    --metadata-url "https://127.0.0.1:$OBJECT_PORT/metadata/" \
    --targets-url "https://127.0.0.1:$OBJECT_PORT/targets/" \
    --application-path "$app_path" --application-sha256 "$(target_sha256 "$app_path")" \
    --provider-set-path "$set_path" --provider-set-sha256 "$(target_sha256 "$set_path")" \
    --runtime "$RUNTIME"
}

rm -rf "$WORK"
mkdir -p "$BIN" "$WORK/launcher-state"
(cd "$ROOT" && cargo build --release -p server -p launcher -p agent)
cp "$ROOT/target/release/"{server,updated-launcher,updated-agent} "$BIN/"
# The lifecycle provider and its helpers are the real, tested bundle scripts under scripts/haproxy/ —
# the same bytes the fleet e2e publishes — so this proves the shipped provider, not an inline copy.
cp "$ROOT/scripts/haproxy/lifecycle" "$BIN/lifecycle"
cp "$ROOT/scripts/haproxy/lib.sh" "$BIN/lib.sh"
chmod 0755 "$BIN/lifecycle"

"$BIN/server" init --repo "$ROUTING_REPO" --keys "$ROUTING_KEYS"
"$BIN/server" init --repo "$RELEASE_REPO" --keys "$RELEASE_KEYS"
# One TLS hierarchy covers two origins with different duties: the routing listener authenticates
# the node before minting an exact bearer; the release listener never receives the node identity.
"$BIN/server" gen-certs --dir "$CERTS" --san 127.0.0.1 --san localhost
mkdir -p "$WORK/adapter/bin"
cp "$ROOT/scripts/haproxy/lifecycle" "$WORK/adapter/bin/lifecycle"
cp "$ROOT/scripts/haproxy/lib.sh" "$WORK/adapter/bin/lib.sh"
chmod 0755 "$WORK/adapter/bin/lifecycle"
"$BIN/server" publish-provider-artifact --repo "$RELEASE_REPO" --keys "$RELEASE_KEYS" \
  --product app-lifecycle --version 1.0.0 \
  --bundle "linux-x86_64=$WORK/adapter" --entrypoint bin/lifecycle
provider_path="products/app-lifecycle/stable/1.0.0/linux-x86_64/app-lifecycle"
"$BIN/server" publish-provider-set --repo "$RELEASE_REPO" --keys "$RELEASE_KEYS" --id default \
  --provider-path "$provider_path" --provider-sha256 "$(target_sha256 "$provider_path")" \
  --provider-timeout-ms 10000
for version in 1.0.0 2.0.0 4.0.0; do make_config "$WORK/bundle-$version" "$version"; done
make_config "$WORK/bundle-3.0.0" 3.0.0 invalid-binary

# The agent starts no workload process, ever, so the bundle's own launcher is what the reconciler's
# `apply` runs after projecting a release when no master is up. Every subsequent upgrade is
# HAProxy's own SIGUSR2 re-exec of that same master. It is the real bundle launcher
# (scripts/haproxy/launch), the same one the fleet e2e ships.
for tree in "$WORK"/bundle-*; do
  cp "$ROOT/scripts/haproxy/launch" "$tree/bin/launch"
  chmod 0755 "$tree/bin/launch"
done

cat >"$RUNTIME" <<EOF
{"product":"app","channel":"stable","installRoot":"$INSTALL","repository":{"metadataLimit":1048576,"targetLimit":536870912,"transportTimeoutSeconds":5},"storage":{"inactiveReleases":2,"inactiveProviders":2,"inactiveAgents":1,"inactiveBytes":1073741824,"inactiveRepositoryCaches":2},"timeouts":{"checkIntervalSeconds":1,"healthGraceSeconds":4,"healthSuccesses":1,"healthIntervalSeconds":1,"refreshRetrySeconds":1,"confirmationWindowSeconds":2,"agentCheckIntervalSeconds":3600}}
EOF
publish 1.0.0 "$WORK/bundle-1.0.0"
"$BIN/server" export-enrollment --repo "$ROUTING_REPO" --assignment assignments/agents/agent.json \
  --agent-id agent --routing-base-url "https://127.0.0.1:$REPO_PORT/" \
  --output "$WORK/launcher-state/enrollment.json"
# Enrollment is preplaced (export-enrollment wrote enrollment.json above), so the agent never calls
# /enroll — but only because its steady-state identity is preplaced too. A preplaced bundle whose
# routing base URL is remote makes the node mint a per-node leaf at `/enroll` on first boot unless
# `agent.crt`/`agent.key` already exist in the state dir, and that mint reads the config's cert
# paths for real. Seed them with this fixture node's named client leaf, exactly as an offline
# installer would; the repository verifies it against the same CA.
cp "$CERTS/client.crt" "$WORK/launcher-state/agent.crt"
cp "$CERTS/client.key" "$WORK/launcher-state/agent.key"
# The certificate is presented only to the routing capability origin; direct release downloads use
# an anonymous client that trusts the same local CA.
cat >"$CONFIG" <<EOF
[enrollment]
url = "https://127.0.0.1:$REPO_PORT/"
name = "agent"
ca = "$CERTS/ca.crt"
EOF

: >"$STACK_LOG"; : >"$REPO_LOG"; : >"$TRAFFIC_LOG"
"$BIN/server" serve-capability --repo "$ROUTING_REPO" --addr "127.0.0.1:$REPO_PORT" \
  --public-url "https://127.0.0.1:$REPO_PORT" \
  --cert "$CERTS/server.crt" --key "$CERTS/server.key" --ca "$CERTS/ca.crt" >>"$REPO_LOG" 2>&1 &
REPO_PID="$!"
"$BIN/server" serve-object --repo "$RELEASE_REPO" --addr "127.0.0.1:$OBJECT_PORT" \
  --cert "$CERTS/server.crt" --key "$CERTS/server.key" >>"$REPO_LOG" 2>&1 &
OBJECT_PID="$!"
"$BIN/updated-launcher" --state-dir "$WORK/launcher-state" --config "$CONFIG" \
  --agent "$BIN/updated-agent" --stop-grace 2 >>"$STACK_LOG" 2>&1 &
STACK_PID="$!"
wait_version 1.0.0

# First deployment: nothing but the reconciler can have started this master, because the agent owns
# no workload process at all. The serving HAProxy above is the proof that `apply` did the starting,
# and the agent's own log says what it did instead: it ran packages.
grep -q 'running packages in' "$STACK_LOG" || fail "the agent never reported running this deployment's packages"
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
wait_new_worker "$master_pid" "$old_worker" >/dev/null || fail "HAProxy did not replace its worker"
wait_master_loaded_runtime "$master_pid" || fail "master did not re-exec the runtime binary the upgrade staged"
[[ "$(stat -Lc '%d:%i' "/proc/$master_pid/exe")" != "$initial_exe_inode" ]] || fail "master did not re-exec the candidate binary inode"

# The updater provides at-least-once provider execution across the unavoidable
# action/journal-write crash gap. Prove this real provider makes an exact replay a true no-op,
# rather than needlessly reloading a master that already runs the requested immutable release.
release2="$(find "$INSTALL/versions" -maxdepth 1 -type d -name '2.0.0-*' -print -quit)"
[[ -n "$release2" ]] || fail "could not locate the immutable HAProxy 2.0.0 release"
# `wait_version` observes the new worker before the provider necessarily finishes its bounded
# survival checks and commits the live-release receipt. Directly invoking the provider before that
# return would be unsupported concurrent mutation, not at-least-once replay, so wait for the first
# invocation's durable completion boundary.
for _ in {1..100}; do
  [[ "$(cat "$INSTALL/runtime/live-release.path" 2>/dev/null || true)" == "$release2" ]] && break
  sleep 0.1
done
[[ "$(cat "$INSTALL/runtime/live-release.path" 2>/dev/null || true)" == "$release2" ]] || fail "upgrade did not record its live release"
replay_worker="$(pgrep -P "$master_pid" | sort -n | tail -n1)"
replay_inode="$(stat -Lc '%d:%i' "/proc/$master_pid/exe")"
for _ in 1 2; do
  "$BIN/lifecycle" apply \
    --protocol 1 \
    --attempt-id haproxy-idempotency-replay \
    --reason update \
    --install-root "$INSTALL" \
    --state-dir "$INSTALL/providers/state/haproxy" \
    --result-file "$WORK/replay-result.json" \
    --candidate "$release2" \
    --candidate-version 2.0.0 \
    --predecessor "$release2" \
    --predecessor-version 2.0.0
done

# The successful-release receipt, stable projected bytes, and live executable inode are the one
# convergence identity. Replays must preserve all three, including the worker.
[[ "$(cat "$INSTALL/runtime/haproxy.pid")" == "$master_pid" ]] || fail "replayed apply restarted the master"
[[ "$(pgrep -P "$master_pid" | sort -n | tail -n1)" == "$replay_worker" ]] || fail "replayed apply needlessly replaced the live worker"
[[ "$(stat -Lc '%d:%i' "/proc/$master_pid/exe")" == "$replay_inode" ]] || fail "replayed apply needlessly re-execed the live binary"
rejections_before="$(rejection_count)"
publish 3.0.0 "$WORK/bundle-3.0.0"
wait_failed_candidate_recovered "$rejections_before" 2.0.0
[[ "$(curl -fsS "http://127.0.0.1:$HTTP_PORT/")" == 2.0.0 ]] || fail "invalid binary displaced the healthy release"
grep -q 'candidate HAProxy configuration failed validation' "$STACK_LOG" || fail "invalid binary validation failure was not recorded"
[[ "$(cat "$INSTALL/runtime/haproxy.pid")" == "$master_pid" ]] || fail "master PID changed while rejecting the invalid release"
[[ "$(stat -Lc '%d:%i' "/proc/$master_pid/exe")" == "$replay_inode" ]] || fail "rejecting the invalid release replaced the live executable"
pgrep -P "$master_pid" | grep -qx "$replay_worker" || fail "rejecting the invalid release replaced the live worker"

publish 4.0.0 "$WORK/bundle-4.0.0"
wait_version 4.0.0
[[ "$(cat "$INSTALL/runtime/haproxy.pid")" == "$master_pid" ]] || fail "master PID changed on recovery upgrade"
kill "$TRAFFIC_PID"; wait "$TRAFFIC_PID" 2>/dev/null || true; TRAFFIC_PID=""
[[ ! -s "$TRAFFIC_LOG" ]] || fail "traffic failed during HAProxy upgrades"

# The other half of the reconciler's process duty: with the master gone, `apply` STARTS HAProxy —
# nothing else ever will. This is the first-deployment path again, run against an
# already-upgraded node. The traffic probe is stopped first, so the deliberate outage is not counted
# as a dropped request; while it lasts the agent simply reports the node unhealthy (it has no
# workload process to react to, so no restart races this).
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
  --result-file "$WORK/start-duty-result.json" \
  --candidate "$release4" \
  --candidate-version 4.0.0 \
  --predecessor "$release4" \
  --predecessor-version 4.0.0
restarted_pid="$(cat "$INSTALL/runtime/haproxy.pid")"
[[ "$restarted_pid" != "$master_pid" ]] || fail "apply reported a master that is the one we killed"
kill -0 "$restarted_pid" 2>/dev/null || fail "apply returned success without a running master"
[[ "$(readlink "/proc/$restarted_pid/exe")" == "$INSTALL/runtime/haproxy" ]] || fail "the started master is not running the stable executable"
wait_version 4.0.0

# The pid file outlives the master that wrote it, and the kernel recycles pids: the number left in
# it can come to name an unrelated process, which the reload's SIGUSR2 would kill outright. That is
# why `live_master` (scripts/haproxy/lib.sh) demands identity — exec'd from the stable runtime path
# — and not merely liveness. Prove it against a real stranger: the reconciler must leave it running
# and unsignalled, and start a master of its own beside it. The stand-in records SIGUSR2 rather
# than dying of it, so a signal sent in error shows up as this assertion failing rather than as a
# process that is merely gone.
kill "$restarted_pid"
for _ in {1..100}; do
  kill -0 "$restarted_pid" 2>/dev/null || break
  sleep 0.1
done
if kill -0 "$restarted_pid" 2>/dev/null; then fail "the HAProxy master did not exit"; fi
for _ in {1..100}; do
  curl -fsS --max-time 1 "http://127.0.0.1:$HTTP_PORT/" >/dev/null 2>&1 || break
  sleep 0.1
done
FOREIGN_SIGNALS="$WORK/foreign-signals"
: >"$FOREIGN_SIGNALS"
# shellcheck disable=SC2016 # "$0"/"$1" are the stand-in's own positionals, not this script's
bash -c 'trap "printf signalled >>\"$0\"" USR2; : >"$1"; while :; do sleep 0.2; done' \
  "$FOREIGN_SIGNALS" "$WORK/foreign-ready" &
foreign="$!"
FOREIGN_PID="$foreign"
for _ in {1..100}; do
  [[ -e "$WORK/foreign-ready" ]] && break
  sleep 0.1
done
[[ -e "$WORK/foreign-ready" ]] || fail "the stand-in for a recycled pid never started"
printf '%s\n' "$foreign" >"$INSTALL/runtime/haproxy.pid"
"$BIN/lifecycle" apply \
  --protocol 1 \
  --attempt-id haproxy-recycled-pid \
  --reason update \
  --install-root "$INSTALL" \
  --state-dir "$INSTALL/providers/state/haproxy" \
  --result-file "$WORK/recycled-pid-result.json" \
  --candidate "$release4" \
  --candidate-version 4.0.0 \
  --predecessor "$release4" \
  --predecessor-version 4.0.0
kill -0 "$foreign" 2>/dev/null || fail "apply killed the process named by a recycled pid file"
[[ ! -s "$FOREIGN_SIGNALS" ]] || fail "apply signalled the process named by a recycled pid file"
adopted="$(cat "$INSTALL/runtime/haproxy.pid")"
[[ "$adopted" != "$foreign" ]] || fail "apply left an unrelated process standing in for the master"
kill -0 "$adopted" 2>/dev/null || fail "apply did not start a master beside the unrelated process"
[[ "$(readlink "/proc/$adopted/exe")" == "$INSTALL/runtime/haproxy" ]] || fail "the master started over a recycled pid is not running the stable executable"
wait_version 4.0.0
kill "$foreign" 2>/dev/null || true
wait "$foreign" 2>/dev/null || true
FOREIGN_PID=""

echo "PASS: real HAProxy started by the provider, upgraded by SIGUSR2 with stable master PID $master_pid, exact-replay no-op, worker turnover, invalid-release rejection, an unrelated process left untouched under a recycled pid file, and zero failed probes"
