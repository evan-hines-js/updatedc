#!/bin/sh
# Stop the agent only on a real removal, never on the remove half of an upgrade — postinstall
# restarts it there, and stopping it twice needlessly widens the window with no supervisor.
set -e

case "$1" in
  # dpkg: `remove`/`purge` are real removals, `upgrade` is not. rpm: `0` is a real removal, `1` is
  # the remove half of an upgrade.
  remove|purge|0)
    systemctl disable --now updated-agent.service >/dev/null 2>&1 || true
    ;;
esac
