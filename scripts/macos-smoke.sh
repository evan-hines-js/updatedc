#!/usr/bin/env bash
set -euo pipefail

# Production-shaped local smoke test:
# launchd -> bootstrap -> supervisor -> sampleapp

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${UPDATED_SMOKE_DIR:-$ROOT/target/macos-smoke}"
LABEL="com.updated.local-smoke"
DOMAIN="gui/$(id -u)"
SERVICE="$DOMAIN/$LABEL"
REPO="$WORK/repo"
KEYS="$WORK/keys"
STATE="$WORK/state"
BIN="$WORK/bin"
PLIST="$WORK/$LABEL.plist"
CONFIG="$WORK/config.toml"
SERVER_PID="$WORK/server.pid"
REPO_LOG="$WORK/repository.log"
TOWER_LOG="$WORK/tower.log"
PLATFORM="macos-$(case "$(uname -m)" in arm64) echo aarch64;; x86_64) echo x86_64;; *) echo "unsupported Mac architecture: $(uname -m)" >&2; exit 1;; esac)"
CHECK_INTERVAL="${UPDATED_SMOKE_CHECK_INTERVAL:-2s}"
HEALTH_GRACE="${UPDATED_SMOKE_HEALTH_GRACE:-10s}"
CONFIRMATION_WINDOW="${UPDATED_SMOKE_CONFIRMATION_WINDOW:-10s}"
STOP_GRACE_SECONDS="${UPDATED_SMOKE_STOP_GRACE_SECONDS:-10}"
LAUNCHD_THROTTLE_SECONDS="${UPDATED_SMOKE_LAUNCHD_THROTTLE_SECONDS:-10}"

usage() {
  cat <<EOF
Usage: scripts/macos-smoke.sh <command> [argument]

  start [restart|reexec] Build and start version 1.0.0 under a user LaunchAgent
                         (default: restart)
  publish [version]     Publish an update (default: 2.0.0)
  status                Show launchd state and the running application version
  logs                  Follow repository and update-tower logs
  stop                  Unload the LaunchAgent and stop the local repository
  reset                 Stop and delete this smoke test's state under target/

Optional environment: UPDATED_SMOKE_DIR (default: target/macos-smoke)
                      UPDATED_SMOKE_PUBLISH_NO_WAIT=1 returns after publishing
                      UPDATED_SMOKE_REUSE_ARTIFACT=1 reuses an existing version artifact
                      UPDATED_SMOKE_PREPARE_ONLY=1 builds without publishing
                      UPDATED_SMOKE_ALLOW_LOWER_PUBLISH=1 permits downgrade metadata
                      UPDATED_SMOKE_CHECK_INTERVAL (default: 2s)
                      UPDATED_SMOKE_HEALTH_GRACE (default: 10s)
                      UPDATED_SMOKE_CONFIRMATION_WINDOW (default: 10s)
                      UPDATED_SMOKE_STOP_GRACE_SECONDS (default: 10)
                      UPDATED_SMOKE_LAUNCHD_THROTTLE_SECONDS (default: 10)
EOF
}

need_macos() {
  if [[ "$(uname -s)" != Darwin ]]; then
    echo "This smoke test requires macOS/launchd." >&2
    exit 1
  fi
}

is_loaded() {
  launchctl print "$SERVICE" >/dev/null 2>&1
}

stop_all() {
  if is_loaded; then
    launchctl bootout "$DOMAIN" "$PLIST"
  fi
  if [[ -f "$SERVER_PID" ]]; then
    pid="$(<"$SERVER_PID")"
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid"
    fi
    rm -f "$SERVER_PID"
  fi
}

build_app() {
  local version="$1" out="$2"
  echo "Building sampleapp $version..."
  (cd "$ROOT" && APP_VERSION="$version" cargo build --release -p sampleapp)
  cp "$ROOT/target/release/sampleapp" "$out"
  chmod +x "$out"
}

semver_is_lower() {
  local candidate="${1%%+*}" current="${2%%+*}"
  candidate="${candidate%%-*}"
  current="${current%%-*}"
  local c_major c_minor c_patch i_major i_minor i_patch
  IFS=. read -r c_major c_minor c_patch <<<"$candidate"
  IFS=. read -r i_major i_minor i_patch <<<"$current"
  [[ "$c_major" =~ ^[0-9]+$ && "$c_minor" =~ ^[0-9]+$ && "$c_patch" =~ ^[0-9]+$ &&
     "$i_major" =~ ^[0-9]+$ && "$i_minor" =~ ^[0-9]+$ && "$i_patch" =~ ^[0-9]+$ ]] ||
    return 1
  (( 10#$c_major < 10#$i_major )) ||
    (( 10#$c_major == 10#$i_major && 10#$c_minor < 10#$i_minor )) ||
    (( 10#$c_major == 10#$i_major && 10#$c_minor == 10#$i_minor &&
       10#$c_patch < 10#$i_patch ))
}

start() {
  need_macos
  local mode="${1:-restart}"
  case "$mode" in
    restart|reexec) ;;
    *) echo "start mode must be 'restart' or 'reexec'" >&2; exit 2;;
  esac
  if [[ -e "$REPO" || -e "$STATE" ]]; then
    echo "Smoke state already exists at $WORK." >&2
    echo "Run '$0 reset' before starting a fresh test." >&2
    exit 1
  fi

  mkdir -p "$WORK" "$STATE" "$BIN"
  echo "Building updater binaries..."
  (cd "$ROOT" && cargo build --release -p server -p bootstrap -p supervisor)
  cp "$ROOT/target/release/server" "$BIN/server"
  cp "$ROOT/target/release/bootstrap" "$BIN/bootstrap"
  cp "$ROOT/target/release/supervisor" "$BIN/supervisor"
  build_app "1.0.0" "$BIN/app"
  BASELINE_SHA=$(shasum -a 256 "$BIN/app" | awk '{print $1}')

  "$BIN/server" init --repo "$REPO" --keys "$KEYS"
  "$BIN/server" publish --repo "$REPO" --keys "$KEYS" \
    --product app --channel stable --version 1.0.0 \
    --target "$PLATFORM=$BIN/app"

  local command reload_config
  if [[ "$mode" == "reexec" ]]; then
    command="[\"$BIN/app\", \"--addr\", \"127.0.0.1:19090\", \"--reload-mode\", \"reexec\", \"--reload-signal\", \"HUP\"]"
    reload_config='reload_command = "kill -HUP $UPDATED_CHILD_PID"'
  else
    command="[\"$BIN/app\", \"--addr\", \"127.0.0.1:19090\"]"
    reload_config=""
  fi

  cat >"$CONFIG" <<EOF
[repository]
root = "$REPO/metadata/root.json"
metadata_url = "http://127.0.0.1:18080/metadata/"
targets_url = "http://127.0.0.1:18080/targets/"

[application]
product = "app"
channel = "stable"
current_version = "1.0.0"
current_sha256 = "$BASELINE_SHA"
command = $command
health_url = "http://127.0.0.1:19090/healthz"
$reload_config

[timeouts]
check_interval = "$CHECK_INTERVAL"
health_grace = "$HEALTH_GRACE"
confirmation_window = "$CONFIRMATION_WINDOW"
EOF

  : >"$REPO_LOG"
  nohup "$BIN/server" serve --repo "$REPO" --addr 127.0.0.1:18080 \
    >>"$REPO_LOG" 2>&1 &
  echo "$!" >"$SERVER_PID"

  cat >"$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>$LABEL</string>
  <key>ProgramArguments</key><array>
    <string>$BIN/bootstrap</string>
    <string>--state-dir</string><string>$STATE</string>
    <string>--supervisor-config</string><string>$CONFIG</string>
    <string>--supervisor</string><string>$BIN/supervisor</string>
    <string>--ready-timeout</string><string>30</string>
    <string>--stop-grace</string><string>$STOP_GRACE_SECONDS</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>$LAUNCHD_THROTTLE_SECONDS</integer>
  <key>StandardOutPath</key><string>$TOWER_LOG</string>
  <key>StandardErrorPath</key><string>$TOWER_LOG</string>
</dict></plist>
EOF
  plutil -lint "$PLIST" >/dev/null
  launchctl bootstrap "$DOMAIN" "$PLIST"

  echo "Waiting for sampleapp 1.0.0..."
  for _ in {1..40}; do
    if version="$(curl -fsS http://127.0.0.1:19090/version 2>/dev/null)"; then
      echo "Running under launchd: sampleapp $version ($mode mode)"
      echo "Next: $0 publish 2.0.0"
      return
    fi
    sleep 0.25
  done
  echo "Application did not become ready; inspect $TOWER_LOG" >&2
  exit 1
}

publish() {
  local version="${1:-2.0.0}"
  local artifact="$BIN/sampleapp-$version"
  local current
  [[ -x "$BIN/server" && -d "$REPO" ]] || { echo "Run '$0 start' first." >&2; exit 1; }
  current="$(curl -fsS http://127.0.0.1:19090/version 2>/dev/null || true)"
  if [[ -z "$current" ]]; then
    echo "Cannot publish an update: the managed application is unavailable; run '$0 status' and '$0 logs'." >&2
    return 1
  fi
  if [[ "${UPDATED_SMOKE_REUSE_ARTIFACT:-0}" == "1" && -x "$artifact" ]]; then
    : # A stress publisher can reuse bytes prepared for this exact version.
  else
    build_app "$version" "$artifact"
  fi
  if [[ "${UPDATED_SMOKE_PREPARE_ONLY:-0}" == "1" ]]; then
    echo "Prepared sampleapp $version at $artifact; not published."
    return
  fi
  "$BIN/server" publish --repo "$REPO" --keys "$KEYS" \
    --product app --channel stable --version "$version" \
    --target "$PLATFORM=$artifact"
  if semver_is_lower "$version" "$current" &&
      [[ "${UPDATED_SMOKE_ALLOW_LOWER_PUBLISH:-0}" != "1" ]]; then
    echo "Update not selected: $version is below running version $current; downgrades are not supported." >&2
    return 1
  fi
  if [[ "${UPDATED_SMOKE_PUBLISH_NO_WAIT:-0}" == "1" ]]; then
    echo "Published $version; not waiting for the background supervisor."
    return
  fi
  echo "Published $version; waiting for the background supervisor..."
  for _ in {1..60}; do
    if [[ "$(curl -fsS http://127.0.0.1:19090/version 2>/dev/null || true)" == "$version" ]]; then
      echo "Updated successfully: sampleapp $version"
      return
    fi
    if ! is_loaded; then
      echo "Update failed: the LaunchAgent exited; run '$0 logs'." >&2
      return 1
    fi
    sleep 0.5
  done
  current="$(curl -fsS http://127.0.0.1:19090/version 2>/dev/null || echo unavailable)"
  echo "Timed out waiting for $version; application remains at $current. Run '$0 logs' for the update outcome." >&2
  exit 1
}

status() {
  if is_loaded; then
    launchctl print "$SERVICE" | sed -n '1,35p'
  else
    echo "LaunchAgent is not loaded."
  fi
  echo "Application version: $(curl -fsS http://127.0.0.1:19090/version 2>/dev/null || echo unavailable)"
  echo "Health: $(curl -fsS http://127.0.0.1:19090/healthz 2>/dev/null || echo unavailable)"
  echo "Work directory: $WORK"
}

case "${1:-}" in
  start) start "${2:-restart}";;
  publish) publish "${2:-2.0.0}";;
  status) status;;
  logs) touch "$REPO_LOG" "$TOWER_LOG"; tail -n 100 -F "$REPO_LOG" "$TOWER_LOG";;
  stop) stop_all; echo "Stopped; state retained at $WORK";;
  reset) stop_all; rm -rf "$WORK"; echo "Removed $WORK";;
  *) usage; exit 2;;
esac
