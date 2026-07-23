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
