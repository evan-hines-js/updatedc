#!/usr/bin/env bash
set -euo pipefail

# Generic reload-command provider for HAProxy master-worker deployments. The signed
# bundle remains immutable; this atomically projects its binary and configuration
# onto the stable paths HAProxy uses when SIGUSR2 makes the master re-exec itself.

release="${1:?candidate release directory is required}"
runtime="${2:?stable runtime directory is required}"
master_pid="${3:?master pid is required}"
mkdir -p "$runtime"

binary_tmp="$runtime/.haproxy.$master_pid"
config_tmp="$runtime/.haproxy.cfg.$master_pid"
cleanup() { rm -f "$binary_tmp" "$config_tmp"; }
trap cleanup EXIT

cp "$release/bin/haproxy" "$binary_tmp"
chmod 0755 "$binary_tmp"
cp "$release/config/haproxy.cfg" "$config_tmp"
chmod 0644 "$config_tmp"
mv -f "$binary_tmp" "$runtime/haproxy"
mv -f "$config_tmp" "$runtime/haproxy.cfg"
kill -USR2 "$master_pid"
