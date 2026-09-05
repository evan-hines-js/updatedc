#!/bin/sh
# Register the unit and, on an upgrade, restart it. A FRESH install is deliberately left stopped:
# the agent cannot enroll until an operator has written this node's enrollment URL, name, and mTLS
# material, and a service that crash-loops on a config skeleton teaches an operator to ignore it.
set -e

systemctl daemon-reload >/dev/null 2>&1 || true

case "$1" in
  # dpkg passes `configure <old-version>`; rpm passes `2` on upgrade, `1` on fresh install.
  configure|2)
    upgrade=0
    [ "$1" = "2" ] && upgrade=1
    [ "$1" = "configure" ] && [ -n "$2" ] && upgrade=1
    if [ "$upgrade" = "1" ]; then
      # Restarting the agent never disturbs a host-managed workload: workload processes belong to each
      # release's own reconciler hooks and their own units, not to this one.
      systemctl try-restart updated-agent.service >/dev/null 2>&1 || true
      exit 0
    fi
    ;;
esac

cat <<'EOF'

updated-agent is installed but NOT started. Bootstrap this node:

  1. Edit /etc/updated/config.toml — the gateway URL and this node's name.
  2. Place its mTLS identity in /etc/updated/agent-tls/{tls.crt,tls.key,ca.crt}
     (mode 0600, owned by root).
  3. systemctl enable --now updated-agent

Use the host package manager to upgrade this agent. Workload releases continue to arrive through
the fleet's signed TUF channel.
EOF
