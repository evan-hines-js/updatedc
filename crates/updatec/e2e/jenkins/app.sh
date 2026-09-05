#!/usr/bin/env bash
# The "jenkins" product's entrypoint: run Jenkins in the foreground. The release's own
# reconciler (install.sh) daemonizes this script and owns the process — the agent never
# touches it. The controller state lives on the persistent volume, so a restart reuses the
# installed JENKINS_HOME and boots in seconds instead of re-running the first-boot setup.
set -euo pipefail

DATA="${JENKINS_DATA:-/var/lib/jenkins}"
export JENKINS_HOME="$DATA/home"
JAVA="$DATA/jre/bin/java"
WAR="$DATA/jenkins.war"

if [ ! -x "$JAVA" ] || [ ! -f "$WAR" ]; then
  echo "jenkins-app: Jenkins is not installed under $DATA (the reconciler's converge must run first)" >&2
  exit 1
fi

echo "jenkins-app: starting Jenkins" >&2
# The e2e fleet is headless: skip the interactive setup wizard so /login answers as soon
# as the controller is up, which is what the reconciler's healthcheck probes.
exec "$JAVA" -Djenkins.install.runSetupWizard=false -jar "$WAR" --httpPort=8080
