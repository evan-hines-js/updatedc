#!/bin/sh

# Shared release classification for the two fuzzing environments: the Kind fleet
# fuzzer (scripts/kind-updatec-e2e.sh) and the container release server
# (crates/updatec/e2e/release-server.sh). Keep artifact selection and
# corrupt-candidate construction here so both exercise the same update sequence.
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
    printf '%s\n' jenkins
  else
    printf '%s\n' sampleapp
  fi
}

# Canonical expected observation emitted by every harness and verifier.
publish_fuzz_expectation() {
  version=$1
  printf '%s,%s\n' "$version" "$(publish_fuzz_artifact "$version")"
}
