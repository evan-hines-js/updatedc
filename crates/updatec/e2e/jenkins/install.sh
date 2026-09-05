#!/usr/bin/env bash
# Node reconciler for the "jenkins" product on a plain Ubuntu + agent node. This is the
# whole point: the agent does its TUF job (download + verify the signed
# release), then hands everything else to this custom code through the four operations:
#
#   converge    : first boot installs a JRE + real Jenkins LTS onto the node's volume; an
#                 upgrade backs JENKINS_HOME up to another disk as a compressed tar first.
#                 Either way it then (re)starts the controller from the candidate's own
#                 entrypoint — this hook owns the JVM; the agent never touches it.
#   healthcheck : one bounded observation of the controller's /login endpoint.
#   rollback    : stop the candidate, restore the pre-upgrade JENKINS_HOME, and restart
#                 the captured predecessor explicitly.
#   inspect     : report the installed version as fingerprint material.
#
# Idempotent per the protocol's execution contract: every step converges under replay —
# installs skip work already done, the backup is keyed to the transaction, and
# (re)start is kill-then-start against a pidfile.
set -euo pipefail

PHASE=${UPDATED_OPERATION:?}
PAYLOAD_VERSION=${UPDATED_PAYLOAD_VERSION:?}
PAYLOAD=${UPDATED_PAYLOAD_ROOT:?}
RESULT_FILE=${UPDATED_RESULT_FILE:?}
ATTEMPT=${UPDATED_ATTEMPT_ID:?}
DATA="${JENKINS_DATA:-/var/lib/jenkins}"
BACKUPS="${JENKINS_BACKUPS:-/var/lib/jenkins-backups}"
RECOVERY="$BACKUPS/before-${ATTEMPT%r}"
[[ "$DATA" == /* && "$DATA" != / ]] || {
  echo "jenkins-install: JENKINS_DATA must be a non-root absolute path" >&2
  exit 2
}
[[ "$BACKUPS" == /* && "$BACKUPS" != / ]] || {
  echo "jenkins-install: JENKINS_BACKUPS must be a non-root absolute path" >&2
  exit 2
}
JENKINS_VERSION="${JENKINS_VERSION:-2.462.3}"
# Ceiling on waiting for running builds to finish before a restart. A ceiling, not a floor:
# an idle controller restarts immediately. Builds still running when it expires are lost —
# the bound exists so a wedged build cannot hold an upgrade (or worse, a rollback) hostage.
DRAIN_TIMEOUT="${JENKINS_DRAIN_TIMEOUT:-300}"
JRE="$DATA/jre"
WAR="$DATA/jenkins.war"
PIDFILE="$DATA/jenkins.pid"
URL="http://127.0.0.1:8080"

live_controller() {
  [[ -s $PIDFILE ]] || return 1
  local pid state
  pid=$(cat "$PIDFILE")
  [[ $pid =~ ^[1-9][0-9]*$ ]] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  [[ $(readlink "/proc/$pid/exe" 2>/dev/null || true) == "$JRE/bin/java" ]] || return 1
  IFS= read -r state <"/proc/$pid/stat" || return 1
  state=${state##*') '}
  [[ ${state%% *} != Z ]]
}

install_runtime() {
  # A Java runtime — a portable Temurin JRE tarball extracted onto the volume. No apt, no
  # root: exactly how you would drop a runtime into a plain container. Jenkins's WAR is
  # architecture-independent, so the same product publishes for x86_64 and aarch64 alike.
  case "$(uname -m)" in
    aarch64 | arm64) arch=aarch64 ;;
    *) arch=x64 ;;
  esac
  if [ ! -x "$JRE/bin/java" ]; then
    echo "jenkins-install: installing Temurin JRE 17 ($arch)" >&2
    # An interrupted extraction must never look like a usable installed runtime merely
    # because bin/java happened to arrive before its libraries.
    rm -rf "$JRE.tmp"
    mkdir -p "$JRE.tmp"
    curl -fsSL "https://api.adoptium.net/v3/binary/latest/17/ga/linux/$arch/jre/hotspot/normal/eclipse" \
      | tar -xz -C "$JRE.tmp" --strip-components=1
    "$JRE.tmp/bin/java" -version >/dev/null 2>&1
    rm -rf "$JRE"
    mv "$JRE.tmp" "$JRE"
  fi
  # Real Jenkins LTS: one architecture-independent WAR.
  if [ ! -f "$WAR" ]; then
    echo "jenkins-install: downloading Jenkins LTS $JENKINS_VERSION" >&2
    curl -fsSL "https://get.jenkins.io/war-stable/$JENKINS_VERSION/jenkins.war" -o "$WAR.tmp"
    mv "$WAR.tmp" "$WAR"
  fi
  mkdir -p "$DATA/home"
}

# Quiesce the running controller before a restart so no CI build fails for the upgrade's
# sake: /quietDown stops the controller SCHEDULING new builds (queued items persist in
# queue.xml and resume after the restart), then we wait — bounded — for the busy executors
# to finish what they are running. This is the drain the healthproxy cannot do for us:
# pool membership only moves HTTP traffic, while builds live inside the controller.
# Best-effort by construction: a controller that is down or unresponsive has nothing
# running to protect, and a drain that cannot complete must never block a rollback.
drain_controller() {
  if ! live_controller; then
    return 0
  fi
  # Modern Jenkins fronts POSTs with a CSRF crumb even with anonymous control; fetch one and
  # tolerate its absence on configurations that disable the issuer.
  local crumb
  crumb="$(curl -fsS --max-time 10 "$URL/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,\":\",//crumb)" 2>/dev/null || true)"
  if curl -fsS -o /dev/null --max-time 10 -X POST ${crumb:+-H "$crumb"} "$URL/quietDown"; then
    echo "jenkins-install: controller is quieting down; waiting up to ${DRAIN_TIMEOUT}s for running builds" >&2
    local waited=0
    while [ "$waited" -lt "$DRAIN_TIMEOUT" ]; do
      local busy
      busy="$(curl -fsS --max-time 10 "$URL/computer/api/xml?xpath=//busyExecutors/text()" 2>/dev/null || true)"
      if [ "$busy" = "0" ]; then
        echo "jenkins-install: no builds running; the queue is drained" >&2
        return 0
      fi
      sleep 5
      waited=$((waited + 5))
    done
    echo "jenkins-install: drain ceiling reached with builds still running; restarting anyway" >&2
  else
    echo "jenkins-install: controller did not accept quietDown; restarting without a drain" >&2
  fi
}

# Every snapshot and restore requires the same stopped-controller invariant.
stop_controller() {
  if live_controller; then
    drain_controller
    echo "jenkins-install: stopping the running controller (pid $(cat "$PIDFILE"))" >&2
    kill "$(cat "$PIDFILE")" 2>/dev/null || true
    for _ in $(seq 1 30); do
      live_controller || break
      sleep 1
    done
    if live_controller; then kill -9 "$(cat "$PIDFILE")" 2>/dev/null || true; fi
    for _ in $(seq 1 50); do
      live_controller || break
      sleep 0.1
    done
    if live_controller; then
      echo "jenkins-install: controller did not stop; refusing to touch its data" >&2
      exit 1
    fi
  fi
  rm -f "$PIDFILE"
}

start_controller() {
  local release="$1"
  stop_controller
  echo "jenkins-install: starting the controller from $release" >&2
  # The child records its own identity before exec, closing the parent-death/startup gap.
  setsid /bin/bash -c '
    printf "%s\n" "$$" >"$1.tmp"
    mv "$1.tmp" "$1"
    exec "$2/bin/app"
  ' bash "$PIDFILE" "$release" </dev/null >>"$DATA/jenkins.log" 2>&1 &
  printf '%s\n' "$release" > "$DATA/payload-path"
}

case "$PHASE" in
  converge)
    if [[ ! -d $RECOVERY ]]; then
      mkdir -p "$RECOVERY.tmp"
      cat "$DATA/payload-path" 2>/dev/null >"$RECOVERY.tmp/path" || true
      cat "$DATA/installed-version" 2>/dev/null >"$RECOVERY.tmp/version" || true
      if [[ -d $DATA/home ]]; then
        stop_controller
        tar czf "$RECOVERY.tmp/home.tar.gz" -C "$DATA" home
      fi
      mv "$RECOVERY.tmp" "$RECOVERY"
    fi
    install_runtime
    # Upgrade in place over the SAME home directory: Jenkins migrates JENKINS_HOME's data
    # formats forward on the next start, so this is the reuse-in-place step of a genuine
    # in-place upgrade rather than a versioned-directory swap.
    echo "jenkins-install: converging to ${PAYLOAD_VERSION:-?}, reusing JENKINS_HOME at $DATA/home" >&2
    printf '%s\n' "${PAYLOAD_VERSION:-?}" > "$DATA/installed-version"
    start_controller "$PAYLOAD"
    printf '%s' '{"schema":1,"status":"succeeded","changed":true,"hostAction":"none","message":null}' >"$RESULT_FILE"
    ;;

  healthcheck)
    [[ $(cat "$DATA/payload-path" 2>/dev/null || true) == "$PAYLOAD" ]]
    curl -fsS -o /dev/null --max-time 10 "http://127.0.0.1:8080/login"
    ;;

  inspect)
    printf 'jenkins-version=%s\n' "$(cat "$DATA/installed-version" 2>/dev/null || true)"
    ;;

  rollback)
    # Restore the captured data and explicitly restart the previous application.
    stop_controller
    if [[ -f $RECOVERY/home.tar.gz ]]; then
      rm -rf "${DATA:?}/home"
      tar xzf "$RECOVERY/home.tar.gz" -C "$DATA"
    fi
    previous=$(cat "$RECOVERY/path" 2>/dev/null || true)
    if [[ -n $previous ]]; then
      cp "$RECOVERY/version" "$DATA/installed-version"
      start_controller "$previous"
    fi
    printf '%s' '{"schema":1,"status":"succeeded","changed":true,"hostAction":"none","message":null}' >"$RESULT_FILE"
    ;;

  *)
    echo "jenkins-install: unknown operation '$PHASE'" >&2
    exit 2
    ;;
esac
