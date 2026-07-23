# shellcheck shell=bash
# Shared helpers for the updated-managed HAProxy lifecycle provider.
#
# Sourced by `lifecycle`; carries the primitives the phases share. Nothing here daemonizes or
# leaves a background helper, nothing mutates an immutable release directory, and every wait is
# bounded. This file is meant to be sourced, so it sets no shell options of its own.

# Fail a phase with a clear, single-line diagnostic on stderr and a nonzero exit — the only signal
# `updated` reads. Never prints secrets.
die() {
  echo "haproxy-lifecycle: $*" >&2
  exit 1
}

# Value of a required environment variable, or die naming the one that is missing.
require_env() {
  local name="$1" value="${!1:-}"
  [[ -n "$value" ]] || die "missing required environment variable $name"
  printf '%s' "$value"
}

# Append one tab-separated audit line (phase, attempt, event) under the install root, so a
# reexec deployment is as observable as the demo's stop/start one (both read a lifecycle receipt).
# Strictly best-effort: a phase is never failed because its audit line could not be written.
audit() {
  local root="$1" phase="$2" attempt="$3" event="$4" log="$1/haproxy-lifecycle/audit.tsv"
  mkdir -p "$root/haproxy-lifecycle" 2>/dev/null || return 0
  printf '%s\t%s\t%s\n' "$phase" "$attempt" "$event" >>"$log" 2>/dev/null || true
}

# Atomically project a release's HAProxy binary and configuration onto the stable runtime paths the
# master re-execs from on reload. The immutable release directory is only ever read. Idempotent: the
# publish is an atomic rename, so a replayed attempt simply reconverges to the same bytes, and a
# crash between the two renames leaves a valid (if mixed) pair that the next attempt overwrites whole.
stage_runtime() {
  local release="$1" runtime="$2"
  [[ -x "$release/bin/haproxy" ]] || die "release $release has no executable bin/haproxy"
  [[ -f "$release/config/haproxy.cfg" ]] || die "release $release has no config/haproxy.cfg"
  mkdir -p "$runtime"
  local bin_tmp="$runtime/.haproxy.$$" cfg_tmp="$runtime/.haproxy.cfg.$$"
  # shellcheck disable=SC2064
  trap "rm -f '$bin_tmp' '$cfg_tmp'" RETURN
  cp "$release/bin/haproxy" "$bin_tmp" && chmod 0755 "$bin_tmp"
  cp "$release/config/haproxy.cfg" "$cfg_tmp" && chmod 0644 "$cfg_tmp"
  mv -f "$bin_tmp" "$runtime/haproxy"
  mv -f "$cfg_tmp" "$runtime/haproxy.cfg"
}

# The newest current worker PID of an HAProxy master (its direct children). Empty when the master has
# not yet forked one. Used only to detect turnover, never to signal a worker directly.
current_worker() {
  pgrep -P "$1" 2>/dev/null | sort -n | tail -n1
}

# Make a running master seamlessly re-exec into whatever now sits at the stable runtime paths
# (SIGUSR2, the HAProxy master-worker reload), then wait — bounded — until it has brought up a new
# worker, which is the proof the candidate binary and configuration were accepted. Keeps the master
# PID; never replaces it. Dies (nonzero) if the master is gone or no new worker appears in time, so a
# failed reload is never reported as success.
reload_master() {
  local master="$1" timeout_ms="${2:-10000}" before now waited=0
  kill -0 "$master" 2>/dev/null || die "HAProxy master $master is not running; cannot reload it"
  before="$(current_worker "$master")"
  kill -USR2 "$master" || die "signalling reload (SIGUSR2 $master) failed"
  while ((waited < timeout_ms)); do
    now="$(current_worker "$master")"
    [[ -n "$now" && "$now" != "$before" ]] && return 0
    sleep 0.1
    waited=$((waited + 100))
  done
  die "HAProxy master $master did not bring up a new worker within ${timeout_ms}ms of the reload"
}

# Gracefully stop an HAProxy master for decommission: SIGUSR1 lets it finish in-flight requests and
# exit, then SIGTERM is the bounded fallback. Idempotent — a master that is already gone is success,
# so a replayed uninstall never fails on an absent process.
stop_master() {
  local master="$1" timeout_ms="${2:-10000}" waited=0
  kill -0 "$master" 2>/dev/null || return 0
  kill -USR1 "$master" 2>/dev/null || return 0
  while ((waited < timeout_ms)); do
    kill -0 "$master" 2>/dev/null || return 0
    sleep 0.1
    waited=$((waited + 100))
  done
  kill -TERM "$master" 2>/dev/null || true
}
