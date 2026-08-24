#!/usr/bin/env bash
# Build the node bootstrap packages (.deb and .rpm) from one nfpm description.
#
# By default it compiles the binaries from this checkout. Pass --bindir to package binaries that
# already exist — which is what CI does, so the package ships the exact attested artifacts that were
# tested and published, rather than a second, separately-compiled build of the same source.
#
#   packaging/build.sh                             # compile, then package for the host arch
#   packaging/build.sh --bindir target/release     # package existing binaries
#   packaging/build.sh --version 1.4.0 --arch arm64
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BINDIR=""
VERSION=""
ARCH=""
OUT="$ROOT/dist"

usage() {
  cat <<'EOF'
usage: packaging/build.sh [--bindir DIR] [--version V] [--arch amd64|arm64] [--out DIR]

  --bindir   package existing updated-launcher/updated-agent binaries instead of compiling
  --version  package version (default: the workspace version from Cargo.toml)
  --arch     target package architecture (default: the host's)
  --out      where the packages land (default: dist/)
EOF
}

while (( $# > 0 )); do
  case "$1" in
    --bindir) [[ $# -ge 2 ]] || { echo "--bindir needs a value" >&2; exit 2; }; BINDIR="$2"; shift 2 ;;
    --version) [[ $# -ge 2 ]] || { echo "--version needs a value" >&2; exit 2; }; VERSION="$2"; shift 2 ;;
    --arch) [[ $# -ge 2 ]] || { echo "--arch needs a value" >&2; exit 2; }; ARCH="$2"; shift 2 ;;
    --out) [[ $# -ge 2 ]] || { echo "--out needs a value" >&2; exit 2; }; OUT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

command -v nfpm >/dev/null || {
  echo "FAIL: nfpm is not installed. Install it with:" >&2
  echo "  go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.47.0" >&2
  echo "  # or: brew install nfpm" >&2
  exit 2
}

if [[ -z "$VERSION" ]]; then
  # The workspace version, read from the one place it is declared.
  VERSION="$(awk '/^\[workspace\.package\]/{p=1;next} /^\[/{p=0} p && /^version *=/{gsub(/[",]/,"");print $3;exit}' "$ROOT/Cargo.toml")"
  [[ -n "$VERSION" ]] || { echo "FAIL: could not read the workspace version from Cargo.toml" >&2; exit 1; }
fi

if [[ -z "$ARCH" ]]; then
  case "$(uname -m)" in
    x86_64|amd64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) echo "FAIL: unsupported host architecture $(uname -m); pass --arch" >&2; exit 2 ;;
  esac
fi

if [[ -z "$BINDIR" ]]; then
  echo "==> building updated-launcher and updated-agent"
  (cd "$ROOT" && cargo build --release -p launcher -p agent)
  BINDIR="$ROOT/target/release"
fi
BINDIR="$(cd "$BINDIR" && pwd)"
for binary in updated-launcher updated-agent; do
  [[ -x "$BINDIR/$binary" ]] || { echo "FAIL: missing binary $BINDIR/$binary" >&2; exit 1; }
done

mkdir -p "$OUT"
export PKG_VERSION="$VERSION" PKG_ARCH="$ARCH" PKG_BINDIR="$BINDIR"
# Explicit, version-free target names. nfpm's default naming embeds the version, but the installer
# and Ansible role select an immutable release before choosing its platform artifact, so the
# filename must be derivable without parsing package metadata first. The version remains inside
# that metadata, where the package manager reads it.
for format in deb rpm; do
  target="$OUT/updated-agent_${ARCH}.${format}"
  echo "==> packaging updated-agent $VERSION ($ARCH) as $target"
  (cd "$ROOT/packaging" && nfpm package --config nfpm.yaml --packager "$format" --target "$target")
done

echo
echo "packages in $OUT:"
for artifact in "$OUT"/*; do
  [[ -e "$artifact" ]] || continue
  printf '  %s\n' "${artifact##*/}"
done
