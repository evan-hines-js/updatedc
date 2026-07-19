#!/usr/bin/env bash
# The managed application for the "magnolia" product. The container is plain Ubuntu + our
# agent — nothing Magnolia-specific is baked in. The pre-start install provider downloaded a
# JRE and real Magnolia CE onto the persistent volume at runtime; this launcher just runs it
# in the foreground so the supervisor/guardian own the JVM directly. The guardian's SIGTERM
# reaches Tomcat, which drains its connector and shuts the instance down gracefully.
set -euo pipefail

DATA="${MAGNOLIA_DATA:-/var/lib/magnolia}"
export JAVA_HOME="$DATA/jre"
export CATALINA_HOME="$DATA/tomcat" CATALINA_BASE="$DATA/tomcat"

# The JCR repositories live on the persistent volume, so a restart reuses the installed
# repository — Magnolia sees it is already installed and boots in ~30-60s instead of running
# the multi-minute first install again.
export JAVA_OPTS="${JAVA_OPTS:-} -Xms256m -Xmx768m \
  -Dmagnolia.update.auto=true \
  -Dmagnolia.repositories.home=$DATA/repositories"

if [ ! -x "$CATALINA_HOME/bin/catalina.sh" ]; then
  echo "magnolia-app: Magnolia is not installed at $CATALINA_HOME (pre-start install provider must run first)" >&2
  exit 1
fi

echo "magnolia-app: starting Magnolia (release ${UPDATED_CANDIDATE_VERSION:-?})" >&2
# exec: the JVM inherits our PID so the tower manages it directly.
exec "$CATALINA_HOME/bin/catalina.sh" run
