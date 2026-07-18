#!/usr/bin/env bash
set -euo pipefail

# Production-shaped local smoke test:
# launchd -> bootstrap guardian -> supervisor -> manifested application bundle.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${UPDATED_SMOKE_DIR:-$ROOT/target/macos-smoke}"
LABEL="com.updated.local-smoke"
DOMAIN="gui/$(id -u)"
SERVICE="$DOMAIN/$LABEL"
REPO="$WORK/repo"
KEYS="$WORK/keys"
INSTALL="$WORK/install"
GUARDIAN_STATE="$WORK/guardian-state"
BIN="$WORK/bin"
PLIST="$WORK/$LABEL.plist"
CONFIG="$WORK/config.toml"
SERVER_PID="$WORK/server.pid"
REPO_LOG="$WORK/repository.log"
TOWER_LOG="$WORK/tower.log"
case "$(uname -m)" in
  arm64) PLATFORM="macos-aarch64" ;;
  x86_64) PLATFORM="macos-x86_64" ;;
  *) echo "unsupported Mac architecture: $(uname -m)" >&2; exit 1 ;;
esac

usage() {
  cat <<EOF
Usage: scripts/macos-smoke.sh <command> [argument]
  start [restart|reexec]  Seed bundle 1.0.0 and run it under a user LaunchAgent
  publish [version]       Publish a bundle update (default: 2.0.0)
  assign [version]        Atomically select an already-published application target
  provider-set [id]       Publish an equivalent provider set under a fresh signed identity
  prepare [version]       Prepare, but do not publish, a versioned bundle tree
  status                  Show launchd and application state
  logs                    Follow repository and tower logs
  stop                     Stop the LaunchAgent and repository
  reset                    Stop and remove target/macos-smoke state
EOF
}

target_path() { printf 'products/app/stable/%s/%s/app' "$1" "$PLATFORM"; }
target_sha256() { "$BIN/server" target-sha256 --repo "$REPO" --name "$1"; }
publish_assignment() {
  local version="$1" app_path set_id="${UPDATED_SMOKE_PROVIDER_SET_ID:-default}" set_path
  set_path="provider-sets/$set_id.json"
  app_path="$(target_path "$version")"
  "$BIN/server" publish-assignment --repo "$REPO" --keys "$KEYS" \
    --name assignments/nodes/node.json --deployment "app-$version" \
    --metadata-url http://127.0.0.1:18080/metadata/ \
    --targets-url http://127.0.0.1:18080/targets/ \
    --application-path "$app_path" --application-sha256 "$(target_sha256 "$app_path")" \
    --provider-set-path "$set_path" --provider-set-sha256 "$(target_sha256 "$set_path")"
}

publish_provider_set() {
  local id="${1:-default}" profile="${UPDATED_SMOKE_LIFECYCLE_PROFILE:-default}"
  local provider_path provider_product source
  provider_product="app-lifecycle-$id"
  if [[ "$profile" == complex ]]; then
    source="$BIN/lifecycle-$id"
    {
      printf '#!/bin/sh\nset -eu\nSTATE=%q\n' "$WORK/deploy-state"
      cat <<'EOF'
phase=${UPDATED_LIFECYCLE_PHASE:?missing lifecycle phase}
attempt=${UPDATED_LIFECYCLE_ATTEMPT_ID:?missing lifecycle attempt ID}
candidate=${UPDATED_CANDIDATE_VERSION:?missing candidate version}
predecessor=${UPDATED_PREDECESSOR_VERSION:?missing predecessor version}
live="$STATE/live"
backup="$STATE/backups/$attempt"
effects="$STATE/effects/$attempt"
mkdir -p "$live" "$STATE/backups" "$effects"
printf '%s\t%s\t%s\t%s\n' "$phase" "$attempt" "$candidate" "$predecessor" >>"$STATE/attempts.log"

require_file() {
  test -s "$1" || { echo "complex lifecycle: missing required state $1" >&2; exit 1; }
}
require_effect() {
  test -e "$effects/$1" || { echo "complex lifecycle: phase $phase requires completed $1" >&2; exit 1; }
}
record_completion() {
  : >"$effects/$phase"
}
atomic_copy() {
  cp "$1" "$2.tmp"
  mv "$2.tmp" "$2"
}
atomic_write() {
  printf '%s\n' "$1" >"$2.tmp"
  mv "$2.tmp" "$2"
}

case "$phase" in
  preflight)
    require_file "$live/app.version"
    require_file "$live/content.db"
    test "$(cat "$live/app.version")" = "$predecessor" || {
      echo "complex lifecycle: live version does not match predecessor $predecessor" >&2
      exit 1
    }
    record_completion
    ;;
  prepare)
    require_effect preflight
    mkdir -p "$backup"
    if test ! -e "$backup/app.version"; then atomic_copy "$live/app.version" "$backup/app.version"; fi
    if test ! -e "$backup/content.db"; then atomic_copy "$live/content.db" "$backup/content.db"; fi
    require_file "$backup/app.version"
    require_file "$backup/content.db"
    record_completion
    ;;
  drain)
    require_effect prepare
    atomic_write "$attempt" "$live/draining"
    record_completion
    ;;
  stop)
    require_effect drain
    test "$(cat "$live/draining")" = "$attempt"
    record_completion
    ;;
  activate)
    require_effect stop
    test "$(cat "$live/draining")" = "$attempt"
    atomic_write "$candidate" "$live/app.version"
    if test -n "${UPDATED_CHILD_PID:-}"; then kill -HUP "$UPDATED_CHILD_PID"; fi
    record_completion
    ;;
  start)
    require_effect activate
    test "$(cat "$live/app.version")" = "$candidate"
    record_completion
    ;;
  verify)
    require_effect start
    test "$(cat "$live/app.version")" = "$candidate"
    observed=$(curl --connect-timeout 1 --max-time 2 -fsS http://127.0.0.1:19090/version)
    test "$observed" = "$candidate"
    record_completion
    ;;
  finalize)
    require_effect verify
    atomic_write "schema=2 version=$candidate" "$live/content.db"
    rm -f "$live/draining"
    record_completion
    ;;
  rollback)
    require_file "$backup/app.version"
    require_file "$backup/content.db"
    atomic_copy "$backup/app.version" "$live/app.version"
    atomic_copy "$backup/content.db" "$live/content.db"
    rm -f "$live/draining"
    record_completion
    ;;
  *)
    echo "complex lifecycle: unsupported phase $phase" >&2
    exit 2
    ;;
esac
EOF
    } >"$source"
    chmod 0755 "$source"
  elif [[ "$profile" != default ]]; then
    echo "UPDATED_SMOKE_LIFECYCLE_PROFILE must be default or complex" >&2
    exit 2
  elif grep -Eq '^mode[[:space:]]*=[[:space:]]*"reexec"' "$CONFIG" 2>/dev/null; then
    source="$BIN/lifecycle"
  else
    source="$BIN/lifecycle-noop"
    printf '#!/bin/sh\nexit 0\n' >"$source"
    chmod 0755 "$source"
  fi
  "$BIN/server" publish-provider-artifact --repo "$REPO" --keys "$KEYS" \
    --product "$provider_product" --version 1.0.0 \
    --bundle "$PLATFORM=$source" --entrypoint bin/lifecycle
  provider_path="products/$provider_product/stable/1.0.0/$PLATFORM/$provider_product"
  "$BIN/server" publish-provider-set --repo "$REPO" --keys "$KEYS" --id "$id" \
    --provider-path "$provider_path" \
    --provider-sha256 "$(target_sha256 "$provider_path")" \
    --provider-timeout-ms 10000
}

need_macos() { [[ "$(uname -s)" == Darwin ]] || { echo "This smoke test requires macOS/launchd." >&2; exit 1; }; }
is_loaded() { launchctl print "$SERVICE" >/dev/null 2>&1; }

stop_all() {
  if is_loaded; then
    # Address the registered job directly. The plist may already have been replaced or
    # removed after a failed run; cleanup must not depend on that mutable input surviving.
    launchctl bootout "$SERVICE" 2>/dev/null || true
  fi
  if [[ -f "$SERVER_PID" ]]; then
    local pid; pid="$(<"$SERVER_PID")"
    if kill -0 "$pid" 2>/dev/null; then kill "$pid"; fi
    rm -f "$SERVER_PID"
  fi
}

prepare_bundle() {
  local version="$1" tree="$BIN/bundle-$1"
  rm -rf "$tree"
  mkdir -p "$tree/bin" "$tree/config"
  cp "$BIN/sampleapp" "$tree/bin/app"
  chmod +x "$tree/bin/app"
  printf 'version = "%s"\n' "$version" >"$tree/config/release.toml"
  echo "$tree"
}

publish() {
  local version="${1:-2.0.0}" tree
  [[ -x "$BIN/server" && -d "$REPO" ]] || { echo "Run '$0 start' first." >&2; exit 1; }
  tree="$BIN/bundle-$version"
  if [[ "${UPDATED_SMOKE_REUSE_BUNDLE:-0}" != 1 || ! -d "$tree" ]]; then
    tree="$(prepare_bundle "$version")"
  fi
  if [[ "${UPDATED_SMOKE_PREPARE_ONLY:-0}" == 1 ]]; then
    echo "Prepared bundle tree $tree"
    return
  fi
  "$BIN/server" publish-app --repo "$REPO" --keys "$KEYS" \
    --product app --channel stable --version "$version" \
    --bundle "$PLATFORM=$tree" --entrypoint bin/app
  if [[ "${UPDATED_SMOKE_PUBLISH_NO_WAIT:-0}" == 1 ]]; then return; fi
  publish_assignment "$version"
  for _ in {1..80}; do
    if [[ "$(curl -fsS http://127.0.0.1:19090/version 2>/dev/null || true)" == "$version" ]]; then
      echo "Updated successfully: sampleapp $version"
      return
    fi
    sleep 0.5
  done
  echo "Timed out waiting for sampleapp $version; inspect $TOWER_LOG" >&2
  return 1
}

start() {
  need_macos
  local mode="${1:-restart}" reload="" baseline provider_path
  local check_interval="${UPDATED_SMOKE_CHECK_INTERVAL:-2s}"
  local health_grace="${UPDATED_SMOKE_HEALTH_GRACE:-10s}"
  local confirmation_window="${UPDATED_SMOKE_CONFIRMATION_WINDOW:-10s}"
  local stop_grace="${UPDATED_SMOKE_STOP_GRACE_SECONDS:-2}"
  local launchd_throttle="${UPDATED_SMOKE_LAUNCHD_THROTTLE_SECONDS:-2}"
  [[ "$stop_grace" =~ ^[0-9]+$ ]] || { echo "UPDATED_SMOKE_STOP_GRACE_SECONDS must be a non-negative integer" >&2; exit 2; }
  [[ "$launchd_throttle" =~ ^[1-9][0-9]*$ ]] || { echo "UPDATED_SMOKE_LAUNCHD_THROTTLE_SECONDS must be a positive integer" >&2; exit 2; }
  [[ "$mode" == restart || "$mode" == reexec ]] || { echo "mode must be restart or reexec" >&2; exit 2; }
  [[ ! -e "$WORK" ]] || { echo "Smoke state exists; run '$0 reset'." >&2; exit 1; }
  mkdir -p "$BIN" "$GUARDIAN_STATE"
  (cd "$ROOT" && cargo build --release -p server -p bootstrap -p supervisor -p sampleapp -p sampleapp-reexec)
  cp "$ROOT/target/release/"{server,bootstrap,supervisor} "$BIN/"
  if [[ "$mode" == reexec ]]; then
    cp "$ROOT/target/release/sampleapp-reexec" "$BIN/sampleapp"
  else
    cp "$ROOT/target/release/sampleapp" "$BIN/sampleapp"
  fi
  "$BIN/server" init --repo "$REPO" --keys "$KEYS"
  baseline="$(prepare_bundle 1.0.0)"
  "$BIN/server" install-app --install-root "$INSTALL" --product app --version 1.0.0 \
    --platform "$PLATFORM" --bundle "$baseline" --entrypoint bin/app
  "$BIN/server" publish-app --repo "$REPO" --keys "$KEYS" --product app \
    --version 1.0.0 --bundle "$PLATFORM=$baseline" --entrypoint bin/app
  "$BIN/server" publish-provider-set --repo "$REPO" --keys "$KEYS" --id default
  if [[ "$mode" == reexec ]]; then
    cat >"$BIN/lifecycle" <<'EOF'
#!/bin/sh
case "$UPDATED_LIFECYCLE_PHASE" in
  activate) exec kill -HUP "$UPDATED_CHILD_PID" ;;
  *) exit 0 ;;
esac
EOF
    chmod 0755 "$BIN/lifecycle"
    "$BIN/server" publish-provider-artifact --repo "$REPO" --keys "$KEYS" \
      --product app-lifecycle --version 1.0.0 \
      --bundle "$PLATFORM=$BIN/lifecycle" --entrypoint bin/lifecycle
    provider_path="products/app-lifecycle/stable/1.0.0/$PLATFORM/app-lifecycle"
    "$BIN/server" publish-provider-set --repo "$REPO" --keys "$KEYS" --id default \
      --provider-path "$provider_path" \
      --provider-sha256 "$(target_sha256 "$provider_path")" \
      --provider-timeout-ms 10000
    reload="$(cat <<EOF

[application.activation]
mode = "reexec"

EOF
)"
  fi
  publish_assignment 1.0.0
  cat >"$CONFIG" <<EOF
[routing]
root = "$REPO/metadata/root.json"
base_url = "http://127.0.0.1:18080/"
assignment = "assignments/nodes/node.json"
[repository]
root = "$REPO/metadata/root.json"
[application]
product = "app"
channel = "stable"
install_root = "$INSTALL"
args = ["--addr", "127.0.0.1:19090", "--reload-mode", "$mode"]
health_url = "http://127.0.0.1:19090/healthz"
$reload
[timeouts]
check_interval = "$check_interval"
health_grace = "$health_grace"
confirmation_window = "$confirmation_window"
EOF
  : >"$REPO_LOG"; : >"$TOWER_LOG"
  nohup "$BIN/server" serve --repo "$REPO" --addr 127.0.0.1:18080 >>"$REPO_LOG" 2>&1 &
  echo "$!" >"$SERVER_PID"
  cat >"$PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>$LABEL</string><key>ProgramArguments</key><array>
<string>$BIN/bootstrap</string><string>--state-dir</string><string>$GUARDIAN_STATE</string>
<string>--supervisor-config</string><string>$CONFIG</string><string>--supervisor</string><string>$BIN/supervisor</string>
<string>--confirm-timeout</string><string>1</string>
<string>--stop-grace</string><string>$stop_grace</string>
</array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>$launchd_throttle</integer>
<key>StandardOutPath</key><string>$TOWER_LOG</string><key>StandardErrorPath</key><string>$TOWER_LOG</string>
</dict></plist>
EOF
  plutil -lint "$PLIST" >/dev/null
  launchctl bootstrap "$DOMAIN" "$PLIST"
  for _ in {1..120}; do
    if [[ "$(curl -fsS http://127.0.0.1:19090/version 2>/dev/null || true)" == 1.0.0 ]]; then
      echo "Running manifested bundle 1.0.0 under launchd ($mode mode)"
      return
    fi
    sleep 0.25
  done
  echo "Application did not become ready within 30s" >&2
  echo "--- tower log ---" >&2
  tail -n 120 "$TOWER_LOG" >&2 2>/dev/null || true
  echo "--- repository log ---" >&2
  tail -n 40 "$REPO_LOG" >&2 2>/dev/null || true
  return 1
}

case "${1:-}" in
  start) start "${2:-restart}" ;;
  publish) publish "${2:-2.0.0}" ;;
  assign) publish_assignment "${2:-2.0.0}" ;;
  provider-set) publish_provider_set "${2:-default}" ;;
  prepare) UPDATED_SMOKE_PREPARE_ONLY=1 publish "${2:-2.0.0}" ;;
  status) launchctl print "$SERVICE" 2>/dev/null | sed -n '1,35p' || true; curl -fsS http://127.0.0.1:19090/version || true; echo ;;
  logs) touch "$REPO_LOG" "$TOWER_LOG"; tail -n 100 -F "$REPO_LOG" "$TOWER_LOG" ;;
  stop) stop_all ;;
  reset) stop_all; rm -rf "$WORK" ;;
  *) usage; exit 2 ;;
esac
