#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIFECYCLE="$HERE/lifecycle"
WORK="$(mktemp -d)"

INSTALL="$WORK/install root"
STATE="$INSTALL/providers/state/haproxy"
RUNTIME="$INSTALL/runtime"
# Every stand-in master a launcher starts records its pid here, so none is left running behind us:
# they are grandchildren of this shell, not jobs of it.
MASTERS="$RUNTIME/masters"
RELOADS="$RUNTIME/reloads"
mkdir -p "$STATE" "$RUNTIME"
trap 'jobs -p | xargs kill 2>/dev/null || true; xargs kill <"$MASTERS" 2>/dev/null || true; rm -rf "$WORK"' EXIT

# An immutable release: the binary and configuration `apply` validates, plus the `bin/launch` the
# provider runs when no master of ours is running.
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
  # Stand-in for the real launcher (scripts/haproxy/launch): the same contract — project this
  # release onto the stable runtime paths and leave a detached master behind under the runtime pid
  # file — with a master that is a copy of bash rather than HAProxy, so that it can be identified
  # (a `#!` script would show its interpreter in /proc/<pid>/exe, not itself) and can record the
  # SIGUSR2s it is sent instead of re-execing on them. What the real launcher does with a real
  # HAProxy is proven by scripts/linux-haproxy-e2e.sh, which runs this same provider.
  cat >"$root/bin/launch" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
release="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
runtime="${UPDATED_INSTALL_ROOT:?UPDATED_INSTALL_ROOT is required}/runtime"
mkdir -p "$runtime"
cp "$(command -v bash)" "$runtime/haproxy"
chmod 0755 "$runtime/haproxy"
cp "$release/config/haproxy.cfg" "$runtime/haproxy.cfg"
rm -f "$runtime/haproxy.pid" "$runtime/started"
# shellcheck disable=SC2016 # "$0"/"$1" are the stand-in master's own positionals, not ours
"$runtime/haproxy" -c 'trap "printf reload >>\"$0\"" USR2; : >"$1"; while :; do sleep 0.2; done' \
  "$runtime/reloads" "$runtime/started" &
master=$!
for _ in $(seq 1 200); do
  [ -e "$runtime/started" ] && break
  sleep 0.05
done
[ -e "$runtime/started" ] || { echo "stand-in master never started" >&2; exit 1; }
printf '%s\n' "$master" >>"$runtime/masters"
printf '%s\n' "$master" >"$runtime/haproxy.pid"
SH
  chmod 0755 "$root/bin/launch"
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

# Block until a stand-in has exec'd and installed its trap: it touches this file last. Writing the
# pid file before that would race the reload against a process that is not yet what it claims.
await() {
  local marker=$1 waited=0
  until [ -e "$marker" ]; do
    waited=$((waited + 1))
    [ "$waited" -lt 200 ] || { echo "stand-in master never started" >&2; exit 1; }
    sleep 0.05
  done
}

# Wait for a pid to be gone, so what follows tests the absent-master case rather than racing it.
reaped() {
  local pid=$1 waited=0
  while kill -0 "$pid" 2>/dev/null; do
    waited=$((waited + 1))
    [ "$waited" -lt 200 ] || { echo "process $pid never exited" >&2; exit 1; }
    sleep 0.05
  done
}

# The deployment is provider-managed: the agent starts nothing, so the first apply on a node has to
# start HAProxy itself rather than stage bytes and wait for a launch that never comes.
invoke apply "$WORK/v2" "$WORK/v1" apply
test -f "$RUNTIME/haproxy.cfg"
master="$(cat "$RUNTIME/haproxy.pid")"
kill -0 "$master" || {
  echo "apply did not start HAProxy when none was running" >&2
  exit 1
}
[ ! -s "$RELOADS" ] || {
  echo "apply signalled the master it had just started" >&2
  exit 1
}

# Health and inspection are meaningful in that started state.
invoke healthcheck "$WORK/v2" "$WORK/v1" update
test -n "$(invoke inspect "$WORK/v2" "$WORK/v1" inspect)"

if invoke apply "$WORK/bad" "$WORK/v1" bad-apply 2>/dev/null; then
  echo "apply accepted an invalid candidate" >&2
  exit 1
fi
[ "$(cat "$RUNTIME/haproxy.pid")" = "$master" ] || {
  echo "a rejected candidate disturbed the running master" >&2
  exit 1
}

# Replaying the same mutation must converge — and against a live master that means an in-place
# re-exec, never a restart.
invoke apply "$WORK/v2" "$WORK/v1" update
[ "$(cat "$RUNTIME/haproxy.pid")" = "$master" ] || {
  echo "apply restarted the master instead of re-execing it" >&2
  exit 1
}
[ "$(cat "$RELOADS")" = reload ] || {
  echo "apply did not signal the running master to re-exec" >&2
  exit 1
}

invoke rollback "$WORK/v2" "$WORK/v1" rollback
test -f "$RUNTIME/haproxy.cfg"
[ "$(cat "$RUNTIME/haproxy.pid")" = "$master" ] || {
  echo "rollback restarted the master instead of re-execing it" >&2
  exit 1
}
[ "$(cat "$RELOADS")" = reloadreload ] || {
  echo "rollback did not signal the running master to re-exec" >&2
  exit 1
}

# A pid file outlives the master that wrote it. Nothing of ours is then running, so healthcheck
# must say so rather than pass on a file, and apply must start HAProxy rather than stage alone.
kill "$master"
reaped "$master"
if invoke healthcheck "$WORK/v2" "$WORK/v1" dead-healthcheck 2>/dev/null; then
  echo "healthcheck passed with no master running" >&2
  exit 1
fi
invoke apply "$WORK/v2" "$WORK/v1" stale-pid
restarted="$(cat "$RUNTIME/haproxy.pid")"
[ "$restarted" != "$master" ] || {
  echo "apply reported the master it was told is gone" >&2
  exit 1
}
kill -0 "$restarted" || {
  echo "apply did not restart HAProxy over a stale pid file" >&2
  exit 1
}
kill "$restarted"
reaped "$restarted"

# The signal is not optional: a master that dies on reload fails the operation. This stand-in is
# hand-rolled rather than launched, because a launcher whose master dies on SIGUSR2 is not a
# release the provider could ever have started.
cp "$BASH" "$RUNTIME/haproxy"
chmod 0755 "$RUNTIME/haproxy"
# shellcheck disable=SC2016 # "$0" is the stand-in master's own positional, not ours
"$RUNTIME/haproxy" -c 'trap "exit 1" USR2; : >"$0"; while :; do sleep 0.2; done' "$WORK/doomed-ready" &
doomed=$!
await "$WORK/doomed-ready"
printf '%s\n' "$doomed" >"$RUNTIME/haproxy.pid"
if invoke apply "$WORK/v2" "$WORK/v1" doomed-reload 2>/dev/null; then
  echo "apply reported success after the master died on re-exec" >&2
  exit 1
fi
reaped "$doomed"

# The kernel recycles pids, so the number in a stale pid file can name an unrelated process, which
# SIGUSR2 would kill outright. Such a pid is not our master: apply leaves the stranger alone and
# starts a master of its own. The stand-in is deliberately not exec'd from the runtime path, and
# records a SIGUSR2 rather than dying of one, so that a signal sent in error is visible as a
# failure here instead of as a killed process.
FOREIGN="$WORK/foreign"
: >"$FOREIGN"
# shellcheck disable=SC2016 # "$0" is the stand-in master's own positional, not ours
bash -c 'trap "printf signalled >>\"$0\"" USR2; : >"$1"; while :; do sleep 0.2; done' "$FOREIGN" "$WORK/foreign-ready" &
foreign=$!
await "$WORK/foreign-ready"
printf '%s\n' "$foreign" >"$RUNTIME/haproxy.pid"
invoke apply "$WORK/v2" "$WORK/v1" foreign-pid
kill -0 "$foreign" 2>/dev/null || {
  echo "apply killed the foreign process named by a recycled pid file" >&2
  exit 1
}
[ ! -s "$FOREIGN" ] || {
  echo "apply signalled the foreign process named by a recycled pid file" >&2
  exit 1
}
adopted="$(cat "$RUNTIME/haproxy.pid")"
[ "$adopted" != "$foreign" ] || {
  echo "apply left the foreign process standing in for the master" >&2
  exit 1
}
kill -0 "$adopted" || {
  echo "apply did not start HAProxy beside the foreign process" >&2
  exit 1
}
test -f "$RUNTIME/haproxy.cfg"
kill "$foreign" 2>/dev/null || true

if "$LIFECYCLE" nonsense --protocol 1 --attempt-id x --reason update \
  --install-root "$INSTALL" --state-dir "$STATE" --candidate "$WORK/v2" \
  --candidate-version 2.0.0 --predecessor "$WORK/v1" \
  --predecessor-version 1.0.0 2>/dev/null; then
  echo "unknown operation succeeded" >&2
  exit 1
fi

echo "haproxy reconciler tests passed"
