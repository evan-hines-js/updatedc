#!/usr/bin/env bash
# Exercise the installer's actual extraction boundary without root or machine-wide writes.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
source "$ROOT/install.sh"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/updated-archive-test.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
mkdir "$scratch/files"
unit=dev.updated.agent.plist
library=libaws_lc_fips_0_14_1_crypto.dylib
printf agent > "$scratch/files/updated-agent"
printf unit > "$scratch/files/$unit"
printf library > "$scratch/files/$library"
printf foreign > "$scratch/files/foreign.dylib"
tar -czf "$scratch/plain.tar.gz" -C "$scratch/files" updated-agent "$unit"
validate_archive "$scratch/plain.tar.gz" Darwin "$unit"
[[ ${#native_libraries[@]} == 0 ]]
tar -czf "$scratch/fips.tar.gz" -C "$scratch/files" updated-agent "$unit" "$library"
validate_archive "$scratch/fips.tar.gz" Darwin "$unit"
[[ ${#native_libraries[@]} == 1 && ${native_libraries[0]} == "$library" ]]
refuse() {
  if (validate_archive "$1" "${2:-Darwin}" "$unit") >/dev/null 2>&1; then
    echo "FAIL: accepted unsafe agent archive $1" >&2
    exit 1
  fi
}
refuse "$scratch/fips.tar.gz" Linux
tar -czf "$scratch/duplicate.tar.gz" -C "$scratch/files" updated-agent "$unit" updated-agent
refuse "$scratch/duplicate.tar.gz"
tar -czf "$scratch/foreign.tar.gz" -C "$scratch/files" updated-agent "$unit" foreign.dylib
refuse "$scratch/foreign.tar.gz"
tar -czf "$scratch/missing.tar.gz" -C "$scratch/files" "$unit" "$library"
refuse "$scratch/missing.tar.gz"
# Write link headers directly: Git Bash can implement `ln -s` by copying the target,
# which silently turns this attack fixture into a valid archive of regular files.
python3 - "$scratch" "$library" <<'PY'
import pathlib
import sys
import tarfile

scratch = pathlib.Path(sys.argv[1])
library = sys.argv[2]
for name, kind in (("link", tarfile.SYMTYPE), ("hardlink", tarfile.LNKTYPE)):
    with tarfile.open(scratch / "fips.tar.gz", "r:gz") as source:
        with tarfile.open(scratch / f"{name}.tar.gz", "w:gz") as target:
            for member in source:
                if member.name == library:
                    member.type = kind
                    member.linkname = "updated-agent"
                    member.size = 0
                    target.addfile(member)
                else:
                    target.addfile(member, source.extractfile(member))
PY
refuse "$scratch/link.tar.gz"
refuse "$scratch/hardlink.tar.gz"
echo 'ok: bootstrap accepts bundled FIPS modules and refuses foreign, duplicate, missing, and linked members'
