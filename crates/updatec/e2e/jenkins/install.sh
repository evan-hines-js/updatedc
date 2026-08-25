#!/usr/bin/env bash
# Node reconciler for the "jenkins" product on a plain Ubuntu + agent node. This is the
# whole point: the agent does its TUF job (download + verify the signed
# release), then hands everything else to this custom code through the four operations:
#
#   apply       : first boot installs a JRE + real Jenkins LTS onto the node's volume; an
#                 upgrade backs JENKINS_HOME up to another disk as a compressed tar first.
#                 Either way it then (re)starts the controller from the candidate's own
#                 entrypoint — this hook owns the JVM; the agent never touches it.
#   healthcheck : one bounded observation of the controller's /login endpoint.
#   rollback    : restore the pre-upgrade JENKINS_HOME from that backup and restart the
#                 predecessor, so a failed upgrade reverts the data with the code.
#   inspect     : report the installed version as fingerprint material.
#
# Idempotent per the protocol's execution contract: every step converges under replay —
# installs skip work already done, the backup is keyed to the predecessor version, and
# (re)start is kill-then-start against a pidfile.
set -euo pipefail

PHASE=${1:?missing reconciler operation}
shift
PROTOCOL=
PREDECESSOR_VERSION=
CANDIDATE_VERSION=
CANDIDATE=
RESULT_FILE=
while (($#)); do
  case "$1" in
    --protocol) PROTOCOL=$2; shift 2 ;;
    --predecessor-version) PREDECESSOR_VERSION=$2; shift 2 ;;
    --candidate-version) CANDIDATE_VERSION=$2; shift 2 ;;
    --candidate) CANDIDATE=$2; shift 2 ;;
    --result-file) RESULT_FILE=$2; shift 2 ;;
    --predecessor) shift 2 ;;
    --attempt-id | --reason | --install-root | --state-dir | --input-dir | --output-dir)
      shift 2
      ;;
    --) shift; break ;;
    *) echo "jenkins-install: unknown argument '$1'" >&2; exit 2 ;;
  esac
done
[[ $PROTOCOL == 1 ]] || { echo "jenkins-install: unsupported protocol" >&2; exit 2; }
DATA="${JENKINS_DATA:-/var/lib/jenkins}"
BACKUPS="${JENKINS_BACKUPS:-/var/lib/jenkins-backups}"
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
    mkdir -p "$JRE"
    curl -fsSL "https://api.adoptium.net/v3/binary/latest/17/ga/linux/$arch/jre/hotspot/normal/eclipse" \
      | tar -xz -C "$JRE" --strip-components=1
  fi
  # Real Jenkins LTS: one architecture-independent WAR.
  if [ ! -f "$WAR" ]; then
    echo "jenkins-install: downloading Jenkins LTS $JENKINS_VERSION" >&2
    curl -fsSL "https://get.jenkins.io/war-stable/$JENKINS_VERSION/jenkins.war" -o "$WAR.tmp"
    mv "$WAR.tmp" "$WAR"
  fi
  mkdir -p "$DATA/home"
}

# tar the live JENKINS_HOME to another disk before an in-place change, and remember it for
# rollback. Keyed to the predecessor version, so a replayed apply overwrites its own backup
# rather than stacking a second one.
backup_home() {
  mkdir -p "$BACKUPS"
  local stamp="${PREDECESSOR_VERSION:-baseline}"
  if [ -d "$DATA/home" ]; then
    local archive="home-$stamp.tar.gz"
    echo "jenkins-install: backing up JENKINS_HOME (from $stamp) to $BACKUPS/$archive" >&2
    tar czf "$BACKUPS/$archive" -C "$DATA" home
    printf '%s\n' "$archive" > "$BACKUPS/latest"
  fi
}

# Quiesce the running controller before a restart so no CI build fails for the upgrade's
# sake: /quietDown stops the controller SCHEDULING new builds (queued items persist in
# queue.xml and resume after the restart), then we wait — bounded — for the busy executors
# to finish what they are running. This is the drain the healthproxy cannot do for us:
# pool membership only moves HTTP traffic, while builds live inside the controller.
# Best-effort by construction: a controller that is down or unresponsive has nothing
# running to protect, and a drain that cannot complete must never block a rollback.
drain_controller() {
  if [ ! -f "$PIDFILE" ] || ! kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
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

# Kill-then-start convergence: stop whatever pidfile'd controller is running, then daemonize
# the given release's own entrypoint. This hook is the controller's only process owner.
start_controller() {
  local release="$1"
  if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    drain_controller
    echo "jenkins-install: stopping the running controller (pid $(cat "$PIDFILE"))" >&2
    kill "$(cat "$PIDFILE")" 2>/dev/null || true
    for _ in $(seq 1 30); do
      kill -0 "$(cat "$PIDFILE")" 2>/dev/null || break
      sleep 1
    done
    kill -9 "$(cat "$PIDFILE")" 2>/dev/null || true
  fi
  rm -f "$PIDFILE"
  echo "jenkins-install: starting the controller from $release" >&2
  setsid "$release/bin/app" </dev/null >>"$DATA/jenkins.log" 2>&1 &
  printf '%s\n' "$!" > "$PIDFILE"
}

case "$PHASE" in
  apply)
    install_runtime
    if [ -n "$PREDECESSOR_VERSION" ] && [ "$PREDECESSOR_VERSION" != "$CANDIDATE_VERSION" ]; then
      backup_home
    fi
    # Upgrade in place over the SAME home directory: Jenkins migrates JENKINS_HOME's data
    # formats forward on the next start, so this is the reuse-in-place step of a genuine
    # in-place upgrade rather than a versioned-directory swap.
    echo "jenkins-install: converging to ${CANDIDATE_VERSION:-?}, reusing JENKINS_HOME at $DATA/home" >&2
    printf '%s\n' "${CANDIDATE_VERSION:-?}" > "$DATA/installed-version"
    start_controller "$CANDIDATE"
    printf '%s' '{"schema":1,"status":"succeeded","changed":true,"hostAction":"none","message":null}' >"$RESULT_FILE"
    ;;

  healthcheck)
    curl -fsS -o /dev/null --max-time 10 "http://127.0.0.1:8080/login"
    ;;

  inspect)
    printf 'jenkins-version=%s\n' "$(cat "$DATA/installed-version" 2>/dev/null || true)"
    ;;

  rollback)
    # Restore the pre-upgrade JENKINS_HOME from the backup tar and restart the release being
    # restored, so a failed upgrade reverts the data with the code. On a rollback the agent
    # passes that release as --candidate (the failed one is --predecessor).
    latest="$(cat "$BACKUPS/latest" 2>/dev/null || true)"
    if [ -n "$latest" ] && [ -f "$BACKUPS/$latest" ]; then
      echo "jenkins-install: restoring JENKINS_HOME from $BACKUPS/$latest" >&2
      rm -rf "${DATA:?}/home"
      tar xzf "$BACKUPS/$latest" -C "$DATA"
    else
      echo "jenkins-install: no JENKINS_HOME backup to restore (nothing was upgraded yet)" >&2
    fi
    printf '%s\n' "${CANDIDATE_VERSION:-?}" > "$DATA/installed-version"
    start_controller "$CANDIDATE"
    printf '%s' '{"schema":1,"status":"succeeded","changed":true,"hostAction":"none","message":null}' >"$RESULT_FILE"
    ;;

  *)
    echo "jenkins-install: unknown operation '$PHASE'" >&2
    exit 2
    ;;
esac
