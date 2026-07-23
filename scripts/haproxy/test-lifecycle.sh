#!/usr/bin/env bash
set -euo pipefail

# Hermetic test for the HAProxy lifecycle provider and launcher. It stands in a stub `haproxy`
# (config check + a master-worker that turns its worker over on SIGUSR2) so the whole state machine —
# preflight, launch, activate/reload, idempotent replay, verify, finalize, rollback, the no-op
# phases, and the failure paths — is exercised with no real HAProxy and no network. Runs anywhere
# bash, coreutils, and pgrep exist (macOS or Linux); the real-HAProxy proof is linux-haproxy-e2e.sh.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIFECYCLE="$HERE/lifecycle"
LAUNCH="$HERE/launch"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/haproxy-lifecycle-test.XXXXXX")"
INSTALL="$WORK/install"
RUNTIME="$INSTALL/runtime"

cleanup() {
  local master
  master="$(cat "$RUNTIME/haproxy.pid" 2>/dev/null || true)"
  [[ -n "$master" ]] && pkill -P "$master" 2>/dev/null || true
  [[ -n "$master" ]] && kill "$master" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }

# A stub that behaves enough like haproxy for the provider: `-c` validates a config that begins with
# VALID; `-W` runs a master-worker foreground process that replaces its single worker on SIGUSR2, so
# `pgrep -P <master>` turnover is real.
cat >"$WORK/stub-haproxy" <<'STUB'
#!/usr/bin/env bash
cfg=""; pidfile=""; check=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    -c) check=1 ;;
    -f) cfg="${2:-}"; shift ;;
    -p) pidfile="${2:-}"; shift ;;
    -W|-db) ;;
  esac
  shift
done
[[ -n "$cfg" && -f "$cfg" ]] || { echo "stub haproxy: missing config: $cfg" >&2; exit 1; }
grep -q '^VALID' "$cfg" || { echo "stub haproxy: invalid config" >&2; exit 1; }
((check)) && exit 0
: "${pidfile:?stub haproxy: -p pidfile required for -W}"
sleep 300 & worker=$!
echo "$$" >"$pidfile"
reload() { local old=$worker; sleep 300 & worker=$!; kill "$old" 2>/dev/null || true; }
graceful() { kill "$worker" 2>/dev/null || true; exit 0; }
trap reload USR2
trap graceful USR1
while kill -0 "$worker" 2>/dev/null; do wait "$worker" 2>/dev/null || true; done
STUB
chmod +x "$WORK/stub-haproxy"

# A release tree in the bundle layout: bin/haproxy (the stub), bin/launch, config/haproxy.cfg whose
# first line marks validity and which carries a version marker the assertions read back.
make_release() {
  local dir="$1" version="$2" validity="${3:-valid}"
  mkdir -p "$dir/bin" "$dir/config"
  cp "$WORK/stub-haproxy" "$dir/bin/haproxy"; chmod +x "$dir/bin/haproxy"
  cp "$LAUNCH" "$dir/bin/launch"
  if [[ "$validity" == valid ]]; then
    printf 'VALID\nVERSION=%s\n' "$version" >"$dir/config/haproxy.cfg"
  else
    printf 'INVALID\nVERSION=%s\n' "$version" >"$dir/config/haproxy.cfg"
  fi
}

worker_of() { pgrep -P "$1" 2>/dev/null | sort -n | tail -n1; }

make_release "$WORK/v1" 1.0.0
make_release "$WORK/v2" 2.0.0
make_release "$WORK/bad" 3.0.0 invalid

# ── first launch ──────────────────────────────────────────────────────────────
UPDATED_INSTALL_ROOT="$INSTALL" "$WORK/v1/bin/launch" &
for _ in {1..50}; do [[ -f "$RUNTIME/haproxy.pid" ]] && break; sleep 0.1; done
master="$(cat "$RUNTIME/haproxy.pid" 2>/dev/null || true)"
if [[ -z "$master" ]] || ! kill -0 "$master" 2>/dev/null; then
  fail "launch did not bring up a master"
fi
grep -q 'VERSION=1.0.0' "$RUNTIME/haproxy.cfg" || fail "launch did not stage the v1 config"
[[ -x "$RUNTIME/haproxy" ]] || fail "launch did not stage the haproxy binary"
echo "ok: launch staged v1 and started a master ($master)"

# ── preflight: good candidate passes, bad candidate is rejected ─────────────────
UPDATED_LIFECYCLE_PHASE=preflight UPDATED_CANDIDATE="$WORK/v2" UPDATED_INSTALL_ROOT="$INSTALL" \
  UPDATED_LIFECYCLE_ATTEMPT_ID=a-pre "$LIFECYCLE" || fail "preflight rejected a valid candidate"
if UPDATED_LIFECYCLE_PHASE=preflight UPDATED_CANDIDATE="$WORK/bad" UPDATED_INSTALL_ROOT="$INSTALL" \
   UPDATED_LIFECYCLE_ATTEMPT_ID=a-pre "$LIFECYCLE" 2>/dev/null; then
  fail "preflight accepted an invalid candidate"
fi
echo "ok: preflight accepts valid, rejects invalid"

# ── activate: reexec into v2, master PID preserved, worker turns over ────────────
old_worker="$(worker_of "$master")"
UPDATED_LIFECYCLE_PHASE=activate UPDATED_CANDIDATE="$WORK/v2" UPDATED_CHILD_PID="$master" \
  UPDATED_INSTALL_ROOT="$INSTALL" UPDATED_LIFECYCLE_ATTEMPT_ID=a-2 "$LIFECYCLE" \
  || fail "activate to v2 failed"
grep -q 'VERSION=2.0.0' "$RUNTIME/haproxy.cfg" || fail "activate did not stage v2"
[[ "$(cat "$RUNTIME/haproxy.pid")" == "$master" ]] || fail "activate changed the master PID"
new_worker="$(worker_of "$master")"
[[ -n "$new_worker" && "$new_worker" != "$old_worker" ]] || fail "activate did not turn over the worker"
echo "ok: activate reexeced to v2 (master $master kept, worker $old_worker → $new_worker)"

# ── idempotent replay of the same attempt reconverges (no fake-skip) ─────────────
old_worker="$new_worker"
UPDATED_LIFECYCLE_PHASE=activate UPDATED_CANDIDATE="$WORK/v2" UPDATED_CHILD_PID="$master" \
  UPDATED_INSTALL_ROOT="$INSTALL" UPDATED_LIFECYCLE_ATTEMPT_ID=a-2 "$LIFECYCLE" \
  || fail "replayed activate failed"
new_worker="$(worker_of "$master")"
[[ "$new_worker" != "$old_worker" ]] || fail "replayed activate did not reconverge"
echo "ok: replayed activate reconverged"

# ── verify + finalize ───────────────────────────────────────────────────────────
UPDATED_LIFECYCLE_PHASE=verify UPDATED_CANDIDATE="$WORK/v2" UPDATED_INSTALL_ROOT="$INSTALL" \
  UPDATED_LIFECYCLE_ATTEMPT_ID=a-2 "$LIFECYCLE" || fail "verify failed after activation"
UPDATED_LIFECYCLE_PHASE=finalize UPDATED_CANDIDATE="$WORK/v2" UPDATED_INSTALL_ROOT="$INSTALL" \
  UPDATED_LIFECYCLE_ATTEMPT_ID=a-2 "$LIFECYCLE" || fail "finalize failed"
grep -q $'finalize\t' "$INSTALL/haproxy-lifecycle/audit.tsv" || fail "finalize wrote no audit receipt"
echo "ok: verify and finalize passed, receipt audited"

# ── rollback: updated hands the predecessor back as UPDATED_CANDIDATE ────────────
old_worker="$(worker_of "$master")"
UPDATED_LIFECYCLE_PHASE=rollback UPDATED_CANDIDATE="$WORK/v1" UPDATED_CHILD_PID="$master" \
  UPDATED_INSTALL_ROOT="$INSTALL" UPDATED_LIFECYCLE_ATTEMPT_ID=a-rb "$LIFECYCLE" \
  || fail "rollback failed"
grep -q 'VERSION=1.0.0' "$RUNTIME/haproxy.cfg" || fail "rollback did not restore v1"
new_worker="$(worker_of "$master")"
[[ "$new_worker" != "$old_worker" ]] || fail "rollback did not turn over the worker"
echo "ok: rollback reexeced back to v1"

# ── the stop/start-only phases are clean no-ops in reexec mode ───────────────────
for p in prepare pre-drain drain stop pre-start start; do
  UPDATED_LIFECYCLE_PHASE="$p" UPDATED_CANDIDATE="$WORK/v1" UPDATED_INSTALL_ROOT="$INSTALL" \
    UPDATED_LIFECYCLE_ATTEMPT_ID=a-noop "$LIFECYCLE" || fail "no-op phase $p exited nonzero"
done
echo "ok: stop/start-only phases are clean no-ops"

# ── failure paths fail closed ────────────────────────────────────────────────────
if UPDATED_LIFECYCLE_PHASE=activate UPDATED_CANDIDATE="$WORK/v2" UPDATED_INSTALL_ROOT="$INSTALL" \
   UPDATED_LIFECYCLE_ATTEMPT_ID=a-noenv "$LIFECYCLE" 2>/dev/null; then
  fail "activate without UPDATED_CHILD_PID should fail"
fi
if UPDATED_LIFECYCLE_PHASE=activate UPDATED_CANDIDATE="$WORK/v2" UPDATED_CHILD_PID=2147480000 \
   UPDATED_INSTALL_ROOT="$INSTALL" UPDATED_LIFECYCLE_ATTEMPT_ID=a-dead "$LIFECYCLE" 2>/dev/null; then
  fail "activate against a dead master should fail"
fi
if UPDATED_LIFECYCLE_PHASE=nonsense UPDATED_INSTALL_ROOT="$INSTALL" \
   UPDATED_LIFECYCLE_ATTEMPT_ID=a-x "$LIFECYCLE" 2>/dev/null; then
  fail "an unknown phase should fail"
fi
echo "ok: missing PID, dead master, and unknown phase all fail closed"

# ── uninstall / decommission: graceful stop + runtime wiped, idempotent ──────────
worker_before="$(worker_of "$master")"
UPDATED_LIFECYCLE_PHASE=uninstall UPDATED_CHILD_PID="$master" UPDATED_INSTALL_ROOT="$INSTALL" \
  UPDATED_LIFECYCLE_ATTEMPT_ID=a-un "$LIFECYCLE" || fail "uninstall failed"
for _ in {1..50}; do kill -0 "$master" 2>/dev/null || break; sleep 0.1; done
kill -0 "$master" 2>/dev/null && fail "uninstall did not stop the master"
[[ -e "$RUNTIME/haproxy" ]] && fail "uninstall did not wipe the runtime"
if [[ -n "$worker_before" ]] && kill -0 "$worker_before" 2>/dev/null; then
  fail "uninstall left an orphaned worker"
fi
# Idempotent: a replayed wipe (master already gone, runtime already removed) still succeeds.
UPDATED_LIFECYCLE_PHASE=uninstall UPDATED_CHILD_PID="$master" UPDATED_INSTALL_ROOT="$INSTALL" \
  UPDATED_LIFECYCLE_ATTEMPT_ID=a-un "$LIFECYCLE" || fail "replayed uninstall failed"
echo "ok: uninstall gracefully stopped the master and wiped the runtime (idempotent)"

echo "PASS: HAProxy lifecycle provider state machine"
