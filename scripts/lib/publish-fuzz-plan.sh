#!/bin/sh

# Shared release classification for the macOS publisher fuzzer and Kind fleet
# fuzzer. Keep artifact selection and corrupt-candidate construction here so the
# two environments exercise the same update sequence.
publish_fuzz_artifact() {
  version=$1
  old_ifs=$IFS
  IFS=.
  set -- $version
  IFS=$old_ifs
  checksum=0
  for component in "$@"; do checksum=$((checksum + component)); done
  if [ $((checksum % 2)) -eq 0 ]; then
    printf '%s\n' magnolia
  else
    printf '%s\n' sampleapp
  fi
}

publish_fuzz_corrupt_version() {
  round=$1
  batch_size=$2
  printf '999.%s.%s\n' "$round" "$((batch_size + 1))"
}
