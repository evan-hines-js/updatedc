#!/usr/bin/env bash
# Bootstrap a node onto an `updated` fleet.
#
# Download this script from an immutable `build-<commit>` release and verify its GitHub provenance
# before running it as root. The exact bootstrap commands are in docs/agent-install.md.
#
# This script places the installer-owned agent, the
# service definition, and the node's enrollment config. The host installer owns agent upgrades;
# signed TUF assignments manage workloads. Native crypto dependencies travel with the agent.
#
# What it downloads is the immutable, attested build CI published: a per-platform archive plus
# SHA256SUMS, both verified before anything is written outside the work directory.
set -euo pipefail

# Shared by bootstrap and the artifact regression tests. Sourcing this file only exposes the
# validator; it never prepares identity, downloads files, or touches a host installation.
fail() { printf '[updated] error: %s\n' "$*" >&2; exit 1; }
validate_archive() {
  local archive="$1" platform="$2" unit="$3"
  local archive_members archive_headers archive_header member required_members
  native_libraries=()
  archive_members="$(tar -tzf "$archive")" \
    || fail "could not list $archive"
  [ "$(printf '%s\n' "$archive_members" | sort | uniq -d)" = "" ] \
    || fail "$archive contains duplicate paths"
  required_members=0
  while IFS= read -r member; do
    case "$member" in
      updated-agent|"$unit") required_members=$((required_members + 1)) ;;
      libaws_lc_fips_*_crypto.dylib|libaws_lc_fips_*_rust_wrapper.dylib)
        [ "$platform" = Darwin ] || fail "unexpected native library in $archive"
        case "$member" in *[!a-zA-Z0-9_.-]*) fail "unsafe native library path in $archive" ;; esac
        native_libraries+=("$member")
        [ "${#native_libraries[@]}" -le 8 ] || fail "too many native libraries in $archive"
        ;;
      *) fail "$archive contains unexpected paths; refusing to extract it as root" ;;
    esac
  done <<<"$archive_members"
  [ "$required_members" -eq 2 ] || fail "$archive is missing its agent or service definition"
  archive_headers="$(tar -tvzf "$archive")" \
    || fail "could not inspect $archive member types"
  while IFS= read -r archive_header; do
    case "$archive_header" in
      -*) ;;
      *) fail "$archive contains a non-regular member; refusing to extract it as root" ;;
    esac
  done <<<"$archive_headers"
}
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then return; fi

DEFAULT_REPO="evan-hines-js/updatedc"

REPO="${UPDATED_INSTALL_REPO:-$DEFAULT_REPO}"
TAG="${UPDATED_INSTALL_TAG:-}"
METHOD="${UPDATED_INSTALL_METHOD:-auto}"
GATEWAY_URL="${UPDATED_INSTALL_GATEWAY_URL:-}"
NODE_NAME="${UPDATED_INSTALL_NODE_NAME:-}"
BOOTSTRAP_CERT="${UPDATED_INSTALL_BOOTSTRAP_CERT:-}"
BOOTSTRAP_KEY="${UPDATED_INSTALL_BOOTSTRAP_KEY:-}"
CA_CERT="${UPDATED_INSTALL_CA:-}"
LOCAL_DIR="${UPDATED_INSTALL_LOCAL_DIR:-}"
NO_START="${UPDATED_INSTALL_NO_START:-0}"
DRY_RUN="${UPDATED_INSTALL_DRY_RUN:-0}"
VERIFY_ATTESTATION="${UPDATED_INSTALL_VERIFY_ATTESTATION:-0}"
WORK=""

usage() {
  cat <<'EOF'
Bootstrap a node onto an `updated` fleet. Run once, as root.

Usage:
  install.sh --gateway-url URL [options]

Required:
  --gateway-url URL      the control plane's gateway, as nodes resolve it. Must match the
                         `publicUrl` the control plane was installed with.

Identity (mutual TLS — there is no shared enrollment secret):
  --bootstrap-cert PATH  fleet certificate used only for the first /enroll handshake
  --bootstrap-key PATH   private key for --bootstrap-cert
  --ca PATH              the fleet CA certificate
  --node-name NAME       how the control plane addresses this node (default: hostname).
                         Pre-create a `reserved` UpdateAgent for this name so no other
                         machine can claim it — see docs/agent-install.md.

Source:
  --tag BUILD_TAG        immutable `build-<40-hex-commit>` release to install. Required when
                         downloading; unnecessary with --local-dir.
  --repo OWNER/REPO      release repository (default: evan-hines-js/updatedc)
  --local-dir DIR        install from already-downloaded artifacts in DIR instead of
                         fetching (air-gapped installs). DIR must contain SHA256SUMS.
  --method METHOD        auto | package | archive. `auto` uses the .deb/.rpm on systems that
                         have dpkg or rpm, and the archive elsewhere.

Behavior:
  --no-start             install and configure, but do not start the service
  --verify-attestation   verify provenance for local artifacts too (requires --tag and `gh`).
                         Network downloads are always provenance-verified.
  --dry-run              print the plan; change nothing
  -h, --help             this text

Every option has a UPDATED_INSTALL_* environment equivalent, e.g.
UPDATED_INSTALL_GATEWAY_URL, UPDATED_INSTALL_TAG, UPDATED_INSTALL_NO_START=1.
EOF
}

log()  { printf '[updated] %s\n' "$*"; }
warn() { printf '[updated] warning: %s\n' "$*" >&2; }

cleanup() {
  local status=$?
  trap - EXIT
  if [ -n "$WORK" ] && [ -d "$WORK" ]; then
    rm -rf -- "$WORK"
  fi
  exit "$status"
}
trap cleanup EXIT

need_value() { [ -n "${2:-}" ] || fail "$1 requires a value"; }

while (( $# > 0 )); do
  case "$1" in
    --gateway-url) need_value "$1" "${2:-}"; GATEWAY_URL="$2"; shift 2 ;;
    --node-name) need_value "$1" "${2:-}"; NODE_NAME="$2"; shift 2 ;;
    --bootstrap-cert) need_value "$1" "${2:-}"; BOOTSTRAP_CERT="$2"; shift 2 ;;
    --bootstrap-key) need_value "$1" "${2:-}"; BOOTSTRAP_KEY="$2"; shift 2 ;;
    --ca) need_value "$1" "${2:-}"; CA_CERT="$2"; shift 2 ;;
    --tag) need_value "$1" "${2:-}"; TAG="$2"; shift 2 ;;
    --repo) need_value "$1" "${2:-}"; REPO="$2"; shift 2 ;;
    --local-dir) need_value "$1" "${2:-}"; LOCAL_DIR="$2"; shift 2 ;;
    --method) need_value "$1" "${2:-}"; METHOD="$2"; shift 2 ;;
    --no-start) NO_START=1; shift ;;
    --verify-attestation) VERIFY_ATTESTATION=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf '[updated] error: unknown argument %s\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

case "$METHOD" in auto|package|archive) ;; *) fail "--method must be auto, package, or archive" ;; esac

# ── Platform ──────────────────────────────────────────────────────────────────
OS="$(uname -s)"
MACHINE="$(uname -m)"
case "$OS" in
  Linux) ;;
  Darwin) ;;
  *) fail "unsupported operating system: $OS. Windows nodes install through install-updated-agent.bat, shipped inside updated-windows-x86_64.zip." ;;
esac
case "$MACHINE" in
  x86_64|amd64) ARCH=x86_64; PKG_ARCH=amd64 ;;
  aarch64|arm64) ARCH=aarch64; PKG_ARCH=arm64 ;;
  *) fail "unsupported architecture: $MACHINE" ;;
esac
if [ "$OS" = Linux ]; then
  PLATFORM="linux-$ARCH"
else
  # The published macOS archives are named for the arch they were built on.
  [ "$ARCH" = x86_64 ] && PLATFORM="macos-x86_64" || PLATFORM="macos-aarch64"
fi
ARCHIVE="updated-${PLATFORM}.tar.gz"

# `auto` prefers the OS package: it owns the root-only directory modes, the unit, and
# config-file merge semantics on upgrade — all things this script would otherwise reimplement.
PACKAGE_KIND=""
if [ "$OS" = Linux ] && [ "$METHOD" != archive ]; then
  if command -v dpkg >/dev/null 2>&1; then
    PACKAGE_KIND=deb
  elif command -v rpm >/dev/null 2>&1; then
    PACKAGE_KIND=rpm
  fi
fi
if [ "$METHOD" = package ] && [ -z "$PACKAGE_KIND" ]; then
  fail "--method package: neither dpkg nor rpm is available on this host"
fi
if [ -n "$PACKAGE_KIND" ]; then
  PACKAGE_FILE="updated-agent_${PKG_ARCH}.${PACKAGE_KIND}"
  INSTALL_KIND="$PACKAGE_KIND package"
else
  PACKAGE_FILE=""
  INSTALL_KIND="archive"
fi

# ── Layout, per platform's own convention ────────────────────────────────────
if [ "$OS" = Linux ]; then
  BIN_DIR=/usr/lib/updated
  STATE_DIR=/var/lib/updated
  UNIT_FILE=updated-agent.service
  SERVICE_LABEL=updated-agent
else
  BIN_DIR=/etc/updated
  STATE_DIR=/usr/local/var/updated
  UNIT_FILE=dev.updated.agent.plist
  SERVICE_LABEL=dev.updated.agent
fi
CONFIG_DIR=/etc/updated
TLS_DIR="$CONFIG_DIR/agent-tls"

[ -n "$NODE_NAME" ] || NODE_NAME="$(hostname -s 2>/dev/null || hostname)"

# The control plane accepts exactly this DNS-safe node identity grammar. Refuse a value that would
# either fail enrollment or turn the TOML line below into syntax/data rather than one string.
case "$NODE_NAME" in
  ""|*[!a-z0-9-]*|-*|*-) fail "--node-name must contain only lowercase letters, digits, and interior hyphens" ;;
  fleet) fail "--node-name fleet is reserved for the fleet telemetry index" ;;
esac
[ "${#NODE_NAME}" -le 253 ] || fail "--node-name must be at most 253 bytes"

# ── Validate before touching anything ────────────────────────────────────────
CONFIGURE=1
if [ -z "$GATEWAY_URL" ]; then
  # An existing config means a node being re-bootstrapped; leaving it alone is right, because
  # rewriting a node's enrollment name would orphan its rollout history under a new identity.
  if [ -f "$CONFIG_DIR/config.toml" ]; then
    warn "--gateway-url not given; keeping the existing $CONFIG_DIR/config.toml"
    CONFIGURE=0
  else
    fail "--gateway-url is required (the URL nodes reach the gateway at). See --help."
  fi
fi
case "$GATEWAY_URL" in
  ""|https://*) ;;
  http://*) fail "--gateway-url must be https: enrollment is mutual TLS, and the pinned trust root is worthless over plaintext" ;;
  *) fail "--gateway-url must be an https URL, got: $GATEWAY_URL" ;;
esac

# A moving `latest` pointer is useful for discovery, never for trust. Resolve it before invoking
# this script, then bind both the release URL and the attestation's source digest to the immutable
# build tag. Local artifacts may omit the tag because their trust was established while staging;
# `--verify-attestation` opts back into the same online provenance check.
if [ -z "$LOCAL_DIR" ] || [ "$VERIFY_ATTESTATION" = 1 ]; then
  [[ "$TAG" =~ ^build-[0-9a-f]{40}$ ]] \
    || fail "--tag must be an immutable build-<40-hex-commit> release (and is required for downloads)"
fi
if [ -z "$LOCAL_DIR" ]; then
  VERIFY_ATTESTATION=1
fi
# These characters are not needed literally in an HTTPS URL (they may be percent-encoded), but
# they can escape the basic TOML string written below or inject another line into the config.
case "$GATEWAY_URL" in
  *\"*|*\\*|*$'\n'*|*$'\r'*) fail "--gateway-url contains a character that cannot be written safely to config.toml" ;;
esac

IDENTITY_GIVEN=0
if [ -n "$BOOTSTRAP_CERT$BOOTSTRAP_KEY$CA_CERT" ]; then
  [ -n "$BOOTSTRAP_CERT" ] && [ -n "$BOOTSTRAP_KEY" ] && [ -n "$CA_CERT" ] \
    || fail "--bootstrap-cert, --bootstrap-key, and --ca must be given together"
  for path in "$BOOTSTRAP_CERT" "$BOOTSTRAP_KEY" "$CA_CERT"; do
    [ -r "$path" ] || fail "cannot read $path"
  done
  IDENTITY_GIVEN=1
fi

if [ "$DRY_RUN" != 1 ] && [ "$(id -u)" != 0 ]; then
  fail "must run as root (it installs a system service). Re-run with sudo."
fi

for command in curl tar; do
  command -v "$command" >/dev/null || fail "missing required command: $command"
done
if command -v sha256sum >/dev/null 2>&1; then
  verify_digests() { sha256sum --ignore-missing --check "$1"; }
elif command -v shasum >/dev/null 2>&1; then
  # macOS ships shasum, not coreutils. It has no --ignore-missing, so the caller trims SHA256SUMS
  # to the lines it actually downloaded before calling this.
  verify_digests() { shasum -a 256 --check "$1"; }
else
  fail "missing required command: sha256sum (or shasum)"
fi

log "node:      $NODE_NAME"
log "platform:  $PLATFORM"
log "install:   $INSTALL_KIND"
[ "$CONFIGURE" = 1 ] && log "gateway:   $GATEWAY_URL"
if [ "$IDENTITY_GIVEN" = 1 ]; then
  log "bootstrap: $BOOTSTRAP_CERT (enrollment only)"
else
  warn "no --bootstrap-cert/--bootstrap-key/--ca given: place the enrollment bootstrap pair and CA in $TLS_DIR before starting the service"
fi

if [ "$DRY_RUN" = 1 ]; then
  log "dry run: nothing was changed"
  exit 0
fi

# ── Fetch and verify ─────────────────────────────────────────────────────────
WORK="$(mktemp -d)"
if [ -n "$LOCAL_DIR" ]; then
  LOCAL_DIR="$(cd "$LOCAL_DIR" && pwd)"
  log "installing from local artifacts in $LOCAL_DIR"
  [ -f "$LOCAL_DIR/SHA256SUMS" ] || fail "$LOCAL_DIR/SHA256SUMS is missing; it is what makes an offline install verifiable"
  cp "$LOCAL_DIR/SHA256SUMS" "$WORK/"
  wanted="${PACKAGE_FILE:-$ARCHIVE}"
  [ -f "$LOCAL_DIR/$wanted" ] || fail "$LOCAL_DIR/$wanted is missing"
  cp "$LOCAL_DIR/$wanted" "$WORK/"
else
  BASE="https://github.com/$REPO/releases/download/$TAG"
  log "downloading from $BASE"
  curl -fsSL --proto '=https' --tlsv1.2 -o "$WORK/SHA256SUMS" "$BASE/SHA256SUMS" \
    || fail "could not download SHA256SUMS from $BASE"
  wanted="${PACKAGE_FILE:-$ARCHIVE}"
  curl -fsSL --proto '=https' --tlsv1.2 -o "$WORK/$wanted" "$BASE/$wanted" \
    || fail "could not download $wanted from $BASE"
fi

# Verify provenance before parsing the checksum manifest or handing the archive to `tar`. The
# source digest ties an otherwise-valid attestation from this repository to the exact immutable
# build tag the operator selected; the signer workflow prevents a second, less-trusted workflow in
# the same repository from attesting bootstrap bytes.
if [ "$VERIFY_ATTESTATION" = 1 ]; then
  command -v gh >/dev/null || fail "provenance verification needs the gh CLI"
  source_digest="${TAG#build-}"
  for artifact in SHA256SUMS "${PACKAGE_FILE:-$ARCHIVE}"; do
    log "verifying build provenance for $artifact"
    gh attestation verify "$WORK/$artifact" \
      --repo "$REPO" \
      --signer-workflow "$REPO/.github/workflows/ci.yml" \
      --source-ref refs/heads/main \
      --source-digest "$source_digest" \
      --deny-self-hosted-runners \
      || fail "provenance verification failed for $artifact"
  done
fi

# Verify only the lines for what was actually downloaded, so a release carrying other platforms'
# artifacts does not fail the check for files this host never asked for.
# Matched on the whole filename field, not as a substring: `updated-agent_amd64.deb` must not be
# satisfied by a line for `updated-agent_amd64.deb.sig`.
awk -v want="${PACKAGE_FILE:-$ARCHIVE}" '$2 == want' "$WORK/SHA256SUMS" >"$WORK/SHA256SUMS.wanted"
[ -s "$WORK/SHA256SUMS.wanted" ] \
  || fail "SHA256SUMS does not list ${PACKAGE_FILE:-$ARCHIVE}; refusing to install an unlisted artifact"
( cd "$WORK" && verify_digests SHA256SUMS.wanted >/dev/null ) \
  || fail "checksum mismatch on ${PACKAGE_FILE:-$ARCHIVE}; refusing to install"
log "verified ${PACKAGE_FILE:-$ARCHIVE} against SHA256SUMS"

native_libraries=()
if [ -z "$PACKAGE_KIND" ]; then
  validate_archive "$WORK/$ARCHIVE" "$OS" "$UNIT_FILE"
fi

# ── Install ──────────────────────────────────────────────────────────────────
install_package() {
  case "$PACKAGE_KIND" in
    deb)
      log "installing $PACKAGE_FILE with apt"
      if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -y "$WORK/$PACKAGE_FILE"
      else
        dpkg --install "$WORK/$PACKAGE_FILE"
      fi
      ;;
    rpm)
      log "installing $PACKAGE_FILE"
      if command -v dnf >/dev/null 2>&1; then
        dnf install -y "$WORK/$PACKAGE_FILE"
      elif command -v yum >/dev/null 2>&1; then
        yum install -y "$WORK/$PACKAGE_FILE"
      else
        rpm --upgrade --force "$WORK/$PACKAGE_FILE"
      fi
      ;;
  esac
}

# The archive carries the service definition alongside the binaries — the same
# deploy/systemd/updated-agent.service the package installs, and the same
# deploy/launchd/dev.updated.agent.plist documented for a manual setup. This installer never
# writes its own copy: one definition, so a node bootstrapped here and one set up by hand or by
# package cannot drift into running subtly different services.
install_archive() {
  log "unpacking $ARCHIVE into $BIN_DIR"
  mkdir -p "$BIN_DIR" "$STATE_DIR"
  local extract="$WORK/archive"
  mkdir -p "$extract"
  tar -C "$extract" -xzf "$WORK/$ARCHIVE"
  # Install dependencies before the executable that needs them on its very first launch.
  for binary in "${native_libraries[@]}" updated-agent; do
    [ -f "$extract/$binary" ] && [ ! -L "$extract/$binary" ] \
      || fail "$ARCHIVE did not contain a regular $binary"
    install -m 0755 "$extract/$binary" "$BIN_DIR/$binary"
  done
  [ -f "$extract/$UNIT_FILE" ] && [ ! -L "$extract/$UNIT_FILE" ] \
    || fail "$ARCHIVE did not contain a regular $UNIT_FILE"
  if [ "$OS" = Linux ]; then
    install -m 0644 "$extract/$UNIT_FILE" "/etc/systemd/system/$UNIT_FILE"
  else
    install -m 0644 "$extract/$UNIT_FILE" "/Library/LaunchDaemons/$UNIT_FILE"
  fi
  chown -R root "$STATE_DIR"
  chmod 0700 "$STATE_DIR"
}

if [ -n "$PACKAGE_KIND" ]; then
  install_package
else
  install_archive
fi

# ── Configure ────────────────────────────────────────────────────────────────
# Unlike the service definition above, this file cannot be shipped and placed verbatim: it carries
# this node's gateway URL and name, substituted here under the TOML-safety checks at the top. The
# commented reference version — same keys, same mTLS paths, placeholder values — is
# packaging/etc/config.toml, the conffile the .deb/.rpm install and the file docs point operators
# at; the Ansible role templates the same document from its own variables. Keep the key set and the
# /etc/updated/agent-tls layout below in step with that file. A key that drifts does not fail
# quietly: the agent's enrollment config is strict and refuses to parse an unknown or missing
# one at first boot.
mkdir -p "$CONFIG_DIR" "$TLS_DIR"
if [ "$CONFIGURE" = 1 ]; then
  log "writing $CONFIG_DIR/config.toml"
  cat >"$CONFIG_DIR/config.toml" <<EOF
# Written by install.sh. The agent reads this canonical path; it holds only paths and a name.
# The annotated reference copy of this document is packaging/etc/config.toml.
# Enrollment happens once — after enrollment.json exists in agent state it is never retried.
[enrollment]
url = "$GATEWAY_URL"
name = "$NODE_NAME"
ca = "$TLS_DIR/ca.crt"

[enrollment.bootstrap]
client_cert = "$TLS_DIR/tls.crt"
client_key = "$TLS_DIR/tls.key"
EOF
  chmod 0600 "$CONFIG_DIR/config.toml"
fi

if [ "$IDENTITY_GIVEN" = 1 ]; then
  log "installing the enrollment bootstrap identity into $TLS_DIR"
  install -m 0600 "$BOOTSTRAP_CERT" "$TLS_DIR/tls.crt"
  install -m 0600 "$BOOTSTRAP_KEY" "$TLS_DIR/tls.key"
  install -m 0600 "$CA_CERT" "$TLS_DIR/ca.crt"
fi
chmod 0700 "$TLS_DIR"
chown -R root "$TLS_DIR" "$CONFIG_DIR/config.toml"

# ── Register the service ─────────────────────────────────────────────────────
# The definition itself was already placed — by the package, or by install_archive from the copy
# inside the release archive. All that is left is to make the init system aware of it.
SERVICE_READY=0
if [ "$OS" = Linux ]; then
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    SERVICE_READY=1
  else
    warn "systemd is not present; register $BIN_DIR/updated-agent with this host's init system and set UPDATED_STATE_DIR=$STATE_DIR"
  fi
else
  SERVICE_READY=1
fi

# ── Start ────────────────────────────────────────────────────────────────────
START_BLOCKED=0
for file in tls.crt tls.key ca.crt; do
  [ -f "$TLS_DIR/$file" ] || START_BLOCKED=1
done

if [ "$NO_START" = 1 ]; then
  log "not starting the service (--no-start)"
elif [ "$START_BLOCKED" = 1 ]; then
  warn "not starting: this node has no mTLS identity yet. Place tls.crt, tls.key, and ca.crt in $TLS_DIR, then start the service."
elif [ "$SERVICE_READY" = 1 ]; then
  log "starting $SERVICE_LABEL"
  if [ "$OS" = Linux ]; then
    systemctl enable --now "$UNIT_FILE"
  else
    launchctl bootstrap system "/Library/LaunchDaemons/$UNIT_FILE" 2>/dev/null \
      || launchctl kickstart -k "system/$SERVICE_LABEL"
  fi
fi

cat <<EOF

[updated] bootstrap complete.

  binaries   $BIN_DIR
  state      $STATE_DIR
  config     $CONFIG_DIR/config.toml
  identity   $TLS_DIR

The node enrolls with $GATEWAY_URL. Signed TUF assignments manage workloads; upgrade the agent
and its bundled native dependencies through this installer or the host's package manager.
EOF
