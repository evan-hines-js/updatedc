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
  prepare [version]       Prepare, but do not publish, a versioned bundle tree
  status                  Show launchd and application state
  logs                    Follow repository and tower logs
  stop                     Stop the LaunchAgent and repository
  reset                    Stop and remove target/macos-smoke state
EOF
}

need_macos() { [[ "$(uname -s)" == Darwin ]] || { echo "This smoke test requires macOS/launchd." >&2; exit 1; }; }
is_loaded() { launchctl print "$SERVICE" >/dev/null 2>&1; }

stop_all() {
  if is_loaded; then launchctl bootout "$DOMAIN" "$PLIST"; fi
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
  local mode="${1:-restart}" reload="" baseline
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
  "$BIN/server" publish-assignment --repo "$REPO" --keys "$KEYS" \
    --name assignments/node.json \
    --metadata-url http://127.0.0.1:18080/metadata/ \
    --targets-url http://127.0.0.1:18080/targets/
  if [[ "$mode" == reexec ]]; then
    cat >"$BIN/transition" <<'EOF'
#!/bin/sh
case "$UPDATED_TRANSITION_PHASE" in
  activate) exec kill -HUP "$UPDATED_CHILD_PID" ;;
  *) exit 0 ;;
esac
EOF
    chmod 0755 "$BIN/transition"
    reload=$'\n[application.activation]\nmode = "reexec"\n\n[application.transition]\ncommand = ["'$BIN'/transition"]\ntimeout = "10s"'
  fi
  cat >"$CONFIG" <<EOF
[routing]
root = "$REPO/metadata/root.json"
base_url = "http://127.0.0.1:18080/"
assignment = "assignments/node.json"
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
check_interval = "2s"
health_grace = "10s"
confirmation_window = "10s"
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
</array><key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>StandardOutPath</key><string>$TOWER_LOG</string><key>StandardErrorPath</key><string>$TOWER_LOG</string>
</dict></plist>
EOF
  plutil -lint "$PLIST" >/dev/null
  launchctl bootstrap "$DOMAIN" "$PLIST"
  for _ in {1..60}; do
    if [[ "$(curl -fsS http://127.0.0.1:19090/version 2>/dev/null || true)" == 1.0.0 ]]; then
      echo "Running manifested bundle 1.0.0 under launchd ($mode mode)"
      return
    fi
    sleep 0.25
  done
  echo "Application did not become ready; inspect $TOWER_LOG" >&2; return 1
}

case "${1:-}" in
  start) start "${2:-restart}" ;;
  publish) publish "${2:-2.0.0}" ;;
  prepare) UPDATED_SMOKE_PREPARE_ONLY=1 publish "${2:-2.0.0}" ;;
  status) launchctl print "$SERVICE" 2>/dev/null | sed -n '1,35p' || true; curl -fsS http://127.0.0.1:19090/version || true; echo ;;
  logs) touch "$REPO_LOG" "$TOWER_LOG"; tail -n 100 -F "$REPO_LOG" "$TOWER_LOG" ;;
  stop) stop_all ;;
  reset) stop_all; rm -rf "$WORK" ;;
  *) usage; exit 2 ;;
esac
