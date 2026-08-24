#!/bin/sh
# Deliberately leaves /var/lib/updated and /etc/updated/agent-tls in place. That directory holds
# the node's enrollment, its committed agent pointer, and its installed releases; deleting it on a
# package removal would silently destroy a running deployment's only record of what it is running.
# Removing the fleet's software and removing a node's identity are separate decisions.
set -e

systemctl daemon-reload >/dev/null 2>&1 || true

case "$1" in
  purge)
    cat <<'EOF'
The node's state was NOT removed. It holds this node's enrollment identity, its committed agent
pointer, and its installed releases. To decommission the node completely:

  rm -rf /var/lib/updated /etc/updated

Then delete its UpdateAgent object in the control plane.
EOF
    ;;
esac
