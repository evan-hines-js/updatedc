#!/bin/sh

# Shared release classification for the two fuzzing environments: the Kind fleet
# fuzzer (scripts/kind-updatec-e2e.sh) and the container release server
# (crates/updatec/e2e/release-server.sh). Keep artifact selection and
# corrupt-candidate construction here so both exercise the same update sequence.
#
# The names are the identities the workloads themselves serve on `/artifact`
# (`sampleapp` and the `stateful-like` binary's `stateful`), so an update is proven to have
# replaced the executable rather than merely rewritten the version file beside it.

# Majors 18 through 21 are the fixed rollback campaign: corrupt 18, valid recovery 19/20, then a
# second corrupt head at 21. Ordinary generations must never consume one of those identities or
# their exact-convergence oracle would demand that a deliberately unlaunchable release become
# healthy. Version 22 is also always published because the larger Rust fleet fixture seeds from it.
PUBLISH_FUZZ_PRIMARY_CORRUPT_VERSION=18.0.0
PUBLISH_FUZZ_SECONDARY_CORRUPT_VERSION=21.0.0
PUBLISH_FUZZ_RESERVED_FIRST_MAJOR=${PUBLISH_FUZZ_PRIMARY_CORRUPT_VERSION%%.*}
PUBLISH_FUZZ_RESERVED_LAST_MAJOR=${PUBLISH_FUZZ_SECONDARY_CORRUPT_VERSION%%.*}
PUBLISH_FUZZ_REQUIRED_MAX_MAJOR=22

publish_fuzz_generation_version() {
  round=${1:?missing fuzz round}
  lane=${2:?missing fuzz lane}
  case $round in
    *[!0-9]*|0) echo "invalid fuzz round: $round" >&2; return 2 ;;
  esac
  case $lane in
    0|1|2) ;;
    *) echo "invalid fuzz lane: $lane" >&2; return 2 ;;
  esac

  major=$((4 + (round - 1) * 3 + lane))
  if [ "$major" -ge "$PUBLISH_FUZZ_RESERVED_FIRST_MAJOR" ]; then
    major=$((major + PUBLISH_FUZZ_RESERVED_LAST_MAJOR - PUBLISH_FUZZ_RESERVED_FIRST_MAJOR + 1))
  fi
  printf '%s.0.0\n' "$major"
}

publish_fuzz_max_major() {
  rounds=${1:?missing fuzz round count}
  case $rounds in
    *[!0-9]*) echo "invalid fuzz round count: $rounds" >&2; return 2 ;;
  esac

  major=$PUBLISH_FUZZ_REQUIRED_MAX_MAJOR
  if [ "$rounds" -gt 0 ]; then
    last=$(publish_fuzz_generation_version "$rounds" 2) || return
    last=${last%%.*}
    if [ "$last" -gt "$major" ]; then
      major=$last
    fi
  fi
  printf '%s\n' "$major"
}

publish_fuzz_recovery_versions() {
  printf '%s\n' 19.0.0 20.0.0
}

publish_fuzz_artifact() {
  version=$1
  checksum=$(printf '%s\n' "$version" | awk -F. '{
    sum = 0
    for (component = 1; component <= NF; component++) {
      sum += $component
    }
    print sum
  }')
  if [ $((checksum % 2)) -eq 0 ]; then
    printf '%s\n' stateful
  else
    printf '%s\n' sampleapp
  fi
}

# The fixed corrupt corpus is one shared declaration. Publishers, resident campaigns, and
# assertions consume this function instead of carrying their own lists that can drift.
publish_fuzz_is_corrupt() {
  version=${1:?missing release version}
  [ "$version" = "$PUBLISH_FUZZ_PRIMARY_CORRUPT_VERSION" ] \
    || [ "$version" = "$PUBLISH_FUZZ_SECONDARY_CORRUPT_VERSION" ]
}

# Canonical expected observation emitted by every harness and verifier.
publish_fuzz_expectation() {
  version=$1
  printf '%s,%s\n' "$version" "$(publish_fuzz_artifact "$version")"
}
