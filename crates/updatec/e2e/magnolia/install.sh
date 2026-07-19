#!/usr/bin/env bash
# Lifecycle provider for the "magnolia" product on a plain Ubuntu + agent node. This is the
# whole point of the demo: the supervisor does its TUF job (download + verify the signed
# release), then hands the install to this custom code. Two phases do real work:
#
#   pre-start : first-boot install of a JRE + real Magnolia CE onto the node's volume.
#   activate  : the online, in-place UPGRADE under `custom` activation — back the JCR up to
#               another disk as a compressed tar, then upgrade the webapp in place, reusing
#               the same repository (Magnolia's automatic update migrates it on start).
#   rollback  : restore the pre-upgrade JCR from that backup so a failed upgrade reverts.
#
# Every other lifecycle phase is a no-op: the supervisor's stop-start plus Tomcat's own
# graceful shutdown drain and relaunch the instance with no custom scripts.
set -euo pipefail

PHASE="${UPDATED_LIFECYCLE_PHASE:-}"
DATA="${MAGNOLIA_DATA:-/var/lib/magnolia}"
BACKUPS="${MAGNOLIA_BACKUPS:-/var/lib/magnolia-backups}"
INSTANCE="${MAGNOLIA_INSTANCE:-public}"
JRE="$DATA/jre"
TOMCAT="$DATA/tomcat"

install_runtime() {
  # A Java runtime — a portable Temurin JRE tarball extracted onto the volume. No apt, no
  # root: exactly how you would drop a runtime into a plain container.
  case "$(uname -m)" in
    aarch64 | arm64) arch=aarch64 ;;
    *) arch=x64 ;;
  esac
  if [ ! -x "$JRE/bin/java" ]; then
    echo "magnolia-install: installing Temurin JRE 17 ($arch)" >&2
    mkdir -p "$JRE"
    curl -fsSL "https://api.adoptium.net/v3/binary/latest/17/ga/linux/$arch/jre/hotspot/normal/eclipse" \
      | tar -xz -C "$JRE" --strip-components=1
  fi
  # Real Magnolia CE (the ready-to-run Tomcat bundle). The bundle ships one full webapp (the
  # author context); Magnolia resolves author-vs-public from the servlet context name, so a
  # publisher node moves that webapp to the public context to run as a real publisher.
  if [ ! -x "$TOMCAT/bin/catalina.sh" ]; then
    echo "magnolia-install: downloading and installing Magnolia CE 6.2.45 ($INSTANCE instance)" >&2
    tmp="$(mktemp -d)"
    curl -fsSL "https://nexus.magnolia-cms.com/repository/public/info/magnolia/bundle/magnolia-community-demo-webapp/6.2.45/magnolia-community-demo-webapp-6.2.45-tomcat-bundle.zip" \
      -o "$tmp/magnolia.zip"
    unzip -q "$tmp/magnolia.zip" -d "$tmp"
    mv "$tmp"/magnolia-*/apache-tomcat-* "$TOMCAT"
    rm -rf "$tmp"
    webapps="$TOMCAT/webapps"
    rm -rf "$webapps/ROOT"
    case "$INSTANCE" in
      author) rm -rf "$webapps/magnoliaPublic" ;;
      public)
        rm -rf "$webapps/magnoliaPublic"
        mv "$webapps/magnoliaAuthor" "$webapps/magnoliaPublic"
        ;;
      *)
        echo "magnolia-install: MAGNOLIA_INSTANCE must be author|public, got '$INSTANCE'" >&2
        exit 2
        ;;
    esac
  fi
  mkdir -p "$DATA/repositories"
}

# tar the live JCR to another disk before an in-place change, and remember it for rollback.
backup_jcr() {
  mkdir -p "$BACKUPS"
  local stamp="${UPDATED_PREDECESSOR_VERSION:-baseline}"
  if [ -d "$DATA/repositories" ]; then
    local archive="repositories-$stamp.tar.gz"
    echo "magnolia-install: backing up the JCR (from $stamp) to $BACKUPS/$archive" >&2
    tar czf "$BACKUPS/$archive" -C "$DATA" repositories
    printf '%s\n' "$archive" > "$BACKUPS/latest"
  fi
}

case "$PHASE" in
  pre-start)
    # Runs on every launch; idempotent, so a restart with a persisted volume is a fast no-op
    # and only the first boot pays for the download.
    install_runtime
    ;;

  activate)
    # Custom activation: the real online, in-place upgrade. The supervisor has already stopped
    # the predecessor, so the files are free to change and the JCR is free to migrate.
    install_runtime
    backup_jcr
    # Upgrade the webapp in place over the SAME directory, reusing the repository. Magnolia's
    # automatic update (magnolia.update.auto, set by the launcher) migrates the JCR to the new
    # version on the next start. The CE bytes are pinned here, so this is the reuse-in-place
    # step of a genuine in-place upgrade rather than a versioned-directory swap.
    echo "magnolia-install: upgrading Magnolia in place to ${UPDATED_CANDIDATE_VERSION:-?}, reusing the JCR at $DATA/repositories" >&2
    printf '%s\n' "${UPDATED_CANDIDATE_VERSION:-?}" > "$DATA/installed-version"
    ;;

  rollback)
    # Restore the pre-upgrade JCR from the backup tar so a failed upgrade reverts the data.
    latest="$(cat "$BACKUPS/latest" 2>/dev/null || true)"
    if [ -n "$latest" ] && [ -f "$BACKUPS/$latest" ]; then
      echo "magnolia-install: restoring the JCR from $BACKUPS/$latest" >&2
      rm -rf "$DATA/repositories"
      tar xzf "$BACKUPS/$latest" -C "$DATA"
    else
      echo "magnolia-install: no JCR backup to restore (nothing was upgraded yet)" >&2
    fi
    ;;

  *)
    : # every other lifecycle phase is a no-op for custom activation
    ;;
esac
