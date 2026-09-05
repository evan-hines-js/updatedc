# shellcheck shell=bash
# Shared helpers for the updated-managed HAProxy reconciler.
#
# Sourced by `lifecycle`; carries the primitives the phases share. The only process left behind is
# the HAProxy master itself (started by the release's own launcher — never a background helper of
# this provider's), nothing mutates an immutable release directory, and every wait is bounded. This
# file is meant to be sourced, so it sets no shell options of its own.

# Fail a phase with a clear, single-line diagnostic on stderr and a nonzero exit — the only signal
# `updated` reads. Never prints secrets.
die() {
  echo "haproxy-lifecycle: $*" >&2
  exit 1
}

# Append one tab-separated audit line (phase, attempt, event) under the install root, so a
# reexec deployment is as observable as a stop/start one (both read a lifecycle receipt).
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
  if ! cp "$release/bin/haproxy" "$bin_tmp" ||
     ! chmod 0755 "$bin_tmp" ||
     ! cp "$release/config/haproxy.cfg" "$cfg_tmp" ||
     ! chmod 0644 "$cfg_tmp" ||
     ! mv -f "$bin_tmp" "$runtime/haproxy" ||
     ! mv -f "$cfg_tmp" "$runtime/haproxy.cfg"; then
    rm -f "$bin_tmp" "$cfg_tmp"
    die "could not project HAProxy release $release onto the stable runtime"
  fi
}

# Whether the running master has already loaded this exact immutable release. The receipt is
# written only after a successful start/re-exec, while configuration equality and the Linux
# executable inode prove neither the stable projection nor the live image drifted afterwards. On a
# platform without /proc, `live_master` has already performed its documented basename identity
# check; the receipt plus configuration are the strongest available evidence there.
live_release_matches() {
  local release="$1" runtime="$2" pid="$3" recorded
  command -v cmp >/dev/null 2>&1 || return 1
  [[ -r "$runtime/live-release.path" ]] || return 1
  IFS= read -r recorded <"$runtime/live-release.path" || return 1
  [[ "$recorded" == "$release" ]] || return 1
  cmp -s "$release/config/haproxy.cfg" "$runtime/haproxy.cfg" || return 1
  if [[ -e "/proc/$pid/exe" ]]; then
    [[ "$runtime/haproxy" -ef "/proc/$pid/exe" ]]
  else
    return 0
  fi
}

# Commit the evidence used by `live_release_matches`. A partial write can only cause another
# idempotent convergence: the atomic rename never lets a truncated receipt suppress one.
record_live_release() {
  local release="$1" runtime="$2" temporary="$2/.live-release.$$"
  if ! printf '%s\n' "$release" >"$temporary" ||
     ! mv -f "$temporary" "$runtime/live-release.path"; then
    rm -f "$temporary"
    die "could not record the live HAProxy release"
  fi
}

# Liveness of `pid`, as three distinct answers, because "we could not tell" is not "dead":
#
#   0  running
#   1  gone, or a corpse (zombie) still waiting to be reaped by its parent
#   2  unknown — the process exists (`kill -0` proves that much) but no state probe answered
#
# A master that died still answers `kill -0` until it is reaped, so the process state is consulted
# where the OS exposes it: that is the whole point of the post-reload survival check. But the probe
# itself can be unavailable — a busybox/toybox `ps` that does not implement `-o`/`-p` fails, or
# prints something that is not a state — and reading its silence as "dead" is exactly the silent
# divergence this provider must not have. Unknown is reported as unknown; callers pick the policy.
master_state() {
  local pid="$1" line state
  kill -0 "$pid" 2>/dev/null || return 1
  # Linux and friends: /proc is authoritative and needs no external tool. Field 3 of `stat` is the
  # state code, and it follows the parenthesised comm — which may itself contain spaces or ')'.
  if [[ -r /proc/$pid/stat ]] && read -r line <"/proc/$pid/stat" 2>/dev/null; then
    state=${line##*') '}
    state=${state%% *}
    [[ -n $state ]] || return 2
    [[ $state != Z ]]
    return
  fi
  command -v ps >/dev/null 2>&1 || return 2
  state="$(ps -o state= -p "$pid" 2>/dev/null)" || return 2
  # One process was asked about, so anything but one line means this `ps` ignored `-o`/`-p`.
  [[ $state != *$'\n'* ]] || return 2
  state="${state//[[:space:]]/}"
  [[ $state =~ ^[A-Za-z] ]] || return 2
  [[ ${state:0:1} != Z ]]
}

# Whether `pid` really is the HAProxy master this runtime directory belongs to, so that a recycled
# pid — the pid file outlives a crashed master, and the number is handed to an unrelated process —
# is never sent a SIGUSR2 that would kill it outright. Answers, like `master_state`:
#
#   0  yes    1  no, some foreign process    2  unknown, nothing here can tell
#
# Identity means "was exec'd from the stable runtime path we publish onto" (the same check
# scripts/linux-haproxy-e2e.sh makes). Note that it is a *path*, not an inode, comparison, and
# deliberately so: `stage_runtime` publishes by rename, so a master that has not re-exec'd yet is
# still executing the replaced inode and /proc reports that as "<path> (deleted)". Across such a
# rename the honest statement is that the process was started from our runtime path, so the
# " (deleted)" marker is stripped before comparing. Where /proc is absent (macOS dev runs) only the
# executable's name is available, so the comparison weakens to the basename.
master_identity() {
  local pid="$1" binary="$2" exe comm
  if exe="$(readlink "/proc/$pid/exe" 2>/dev/null)" && [[ -n $exe ]]; then
    [[ "${exe% (deleted)}" == "$binary" ]]
    return
  fi
  command -v ps >/dev/null 2>&1 || return 2
  comm="$(ps -o comm= -p "$pid" 2>/dev/null)" || return 2
  [[ $comm != *$'\n'* ]] || return 2
  comm="${comm#"${comm%%[![:space:]]*}"}"
  comm="${comm%"${comm##*[![:space:]]}"}"
  [[ -n $comm ]] || return 2
  [[ "${comm##*/}" == "${binary##*/}" ]]
}

# The live HAProxy master this runtime directory belongs to, if there is one.
#
# Publishes its pid in `master_pid` and returns 0 when the pid file names a process that is ours and
# has not gone. Returns 1 when nothing of ours is running: no pid file, a stale one, or one whose
# pid the kernel has recycled onto an unrelated process — which is left untouched. Deliberately not
# a value-returning helper: the "cannot tell" case must end the phase, and a `die` inside a command
# substitution would only end the substitution.
#
# One policy for each kind of uncertainty:
#   * unknown liveness is treated as running. `kill -0` has already proved the pid exists, and that
#     is the check that works everywhere; assuming "dead" instead is what would let a reload be
#     skipped, a dead master be reported as reloaded, or a second master be started beside a live
#     one, without anyone hearing about it.
#   * unknown identity fails the phase. The alternatives are landing SIGUSR2 — fatal by default —
#     on a process that is not ours, or starting a competing master beside it; neither is a risk to
#     take silently.
master_pid=
live_master() {
  local runtime="$1" pid state identity
  master_pid=
  [[ -f "$runtime/haproxy.pid" ]] || return 1
  pid="$(<"$runtime/haproxy.pid")"
  pid="${pid//[[:space:]]/}"
  [[ $pid =~ ^[0-9]+$ ]] || die "master pid file does not contain a pid"

  state=0; master_state "$pid" || state=$?
  ((state != 1)) || return 1

  identity=0; master_identity "$pid" "$runtime/haproxy" || identity=$?
  ((identity != 1)) || return 1
  ((identity != 2)) || die "cannot confirm pid $pid is the HAProxy master (no readable /proc and no usable ps); refusing to signal it"

  master_pid="$pid"
}

# Make the running master `pid` pick up the bytes `stage_runtime` just published, in place.
#
# SIGUSR2 is HAProxy's master-worker reload: the master re-execs itself from the stable runtime
# path (keeping its PID and its bound listeners), starts a worker on the new configuration and
# retires the old one. Staging alone is invisible to an already-running master, so this is the
# step that makes an upgrade take effect without a restart.
#
# Fail-closed: if either the signal or the re-exec fails, the operation fails, because the live
# instance is then still serving the previous bytes and the operator must hear about it.
reload_master() {
  local pid="$1" state
  kill -USR2 "$pid" 2>/dev/null || die "could not signal HAProxy master $pid to re-exec"
  # The master keeps its PID across the re-exec; if it is gone, the new bytes are not serving.
  for _ in 1 2 3 4 5; do
    sleep 0.2
    state=0; master_state "$pid" || state=$?
    if ((state == 1)); then
      die "HAProxy master $pid did not survive the SIGUSR2 re-exec"
    fi
  done
}

# Start HAProxy from `release` under install root `root`.
#
# The start line is the application bundle's own `bin/launch` — the single place HAProxy is ever
# started — so this provider owns *when* a master is started, never *how*. Projection remains here,
# in the same `stage_runtime` path reload uses; `launch` only leaves a detached master-worker behind
# under the runtime pid file, which makes the resulting master reloadable in place forever after.
start_master() {
  local release="$1" root="$2" runtime="$2/runtime"
  [[ -x "$release/bin/launch" ]] || die "release $release has no executable bin/launch"
  # Projection has one implementation, `stage_runtime`, for both the absent-master and reload
  # paths. The release launcher only owns how to start the already-projected stable executable.
  stage_runtime "$release" "$runtime"
  UPDATED_INSTALL_ROOT="$root" "$release/bin/launch" >/dev/null \
    || die "launching HAProxy from $release failed"
  live_master "$runtime" || die "launching HAProxy from $release left no running master behind"
}

# Converge the machine onto `release`: the whole of what `converge` and `rollback` do, which differ
# only in the release they name.
#
# A master of ours that is already running takes the new bytes in place — that re-exec is the point
# of this provider. If that master already carries this exact immutable release, convergence is a
# real no-op: at-least-once converge/rollback replay must not manufacture a second reload. Where
# nothing of ours is running the release is started instead: the agent launches no workload
# process, so the first deployment on a node (and any later operation that finds the master gone)
# has no other way into service.
converge_release() {
  local release="$1" root="$2" runtime="$2/runtime"
  if live_master "$runtime"; then
    if live_release_matches "$release" "$runtime" "$master_pid"; then
      return
    fi
    stage_runtime "$release" "$runtime"
    reload_master "$master_pid"
    record_live_release "$release" "$runtime"
  else
    start_master "$release" "$root"
    record_live_release "$release" "$runtime"
  fi
}
