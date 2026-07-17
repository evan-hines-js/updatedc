#!/usr/bin/env bash
set -euo pipefail

# Exercise bursty control-plane publication: publish a large initial set, allow the
# node one quiet convergence window, then repeat with small sets of fresh versions.

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SMOKE="$ROOT/scripts/macos-smoke.sh"
WORK="${UPDATED_SMOKE_DIR:-$ROOT/target/macos-smoke}"
BIN="$WORK/bin"
DURATION="${UPDATED_SMOKE_FUZZ_SECONDS:-600}"
INTERVAL="${UPDATED_SMOKE_FUZZ_INTERVAL_SECONDS:-30}"
BATCH_MIN="${UPDATED_SMOKE_FUZZ_BATCH_MIN:-3}"
BATCH_MAX="${UPDATED_SMOKE_FUZZ_BATCH_MAX:-4}"
VERSION_MAJOR="${UPDATED_SMOKE_FUZZ_VERSION_MAJOR:-999}"
MAX_UNAVAILABLE="${UPDATED_SMOKE_FUZZ_MAX_UNAVAILABLE:-30}"
RESULTS="$WORK/publish-fuzz-results"

positive_integer() { [[ "$1" =~ ^[1-9][0-9]*$ ]]; }

semver_greater() {
  local left_major left_minor left_patch right_major right_minor right_patch
  IFS=. read -r left_major left_minor left_patch <<<"$1"
  IFS=. read -r right_major right_minor right_patch <<<"$2"
  (( 10#$left_major > 10#$right_major )) ||
    (( 10#$left_major == 10#$right_major && 10#$left_minor > 10#$right_minor )) ||
    (( 10#$left_major == 10#$right_major && 10#$left_minor == 10#$right_minor &&
       10#$left_patch > 10#$right_patch ))
}

new_version() {
  local candidate existing floor floor_major floor_minor candidate_major
  floor="${generation_floor%%+*}"
  floor="${floor%%-*}"
  IFS=. read -r floor_major floor_minor _ <<<"$floor"
  if (( 10#$VERSION_MAJOR > 10#$floor_major )); then
    candidate_major="$VERSION_MAJOR"
    floor_minor=0
  else
    candidate_major="$floor_major"
  fi
  while :; do
    # Every candidate clears the maximum from the preceding burst, while the
    # random increments leave publication order unrelated to version order.
    candidate="$candidate_major.$((10#$floor_minor + RANDOM + 1)).$((RANDOM * 2 + RANDOM + 1))"
    existing=0
    for version in "${all_versions[@]:-}"; do
      if [[ "$version" == "$candidate" ]]; then
        existing=1
        break
      fi
    done
    if (( existing == 0 )); then
      all_versions+=("$candidate")
      NEW_VERSION="$candidate"
      return
    fi
  done
}

publish_batch() {
  local count="$1" batch="$2" version pid corrupt_version artifact failed=0
  local batch_max="$expected"
  local versions=() publish_versions=() pids=()

  echo "Preparing batch $batch ($count fresh random versions)..."
  generation_floor="$expected"
  for ((index = 0; index < count; index++)); do
    new_version
    version="$NEW_VERSION"
    versions+=("$version")
    UPDATED_SMOKE_PREPARE_ONLY=1 "$SMOKE" publish "$version"
    if semver_greater "$version" "$batch_max"; then
      batch_max="$version"
    fi
  done

  # Make a genuinely corrupt executable the newest candidate in this burst. The
  # guardian must restart the tower, recovery must reject its bytes and roll back,
  # then the supervisor must select the greatest valid release.
  generation_floor="$batch_max"
  new_version
  corrupt_version="$NEW_VERSION"
  artifact="$BIN/sampleapp-$corrupt_version"
  printf 'intentionally corrupt sample application for fuzz batch %s\n' "$batch" >"$artifact"
  chmod +x "$artifact"
  publish_versions=("${versions[@]}" "$corrupt_version")

  echo "Publishing batch $batch concurrently: ${versions[*]} (corrupt: $corrupt_version)"
  for version in "${publish_versions[@]}"; do
    (
      UPDATED_SMOKE_PUBLISH_NO_WAIT=1 UPDATED_SMOKE_REUSE_ARTIFACT=1 \
        UPDATED_SMOKE_ALLOW_LOWER_PUBLISH=1 \
        "$SMOKE" publish "$version" >"$RESULTS/$version.log" 2>&1
    ) &
    pids+=("$!")
  done

  for pid in "${pids[@]}"; do
    if ! wait "$pid"; then
      failed=$((failed + 1))
    fi
  done
  if (( failed != 0 )); then
    echo "FAIL: $failed publications failed in batch $batch; inspect $RESULTS." >&2
    return 1
  fi

  expected="$batch_max"
  echo "$expected" >"$RESULTS/expected-version"
}

check_convergence() {
  local batch="$1" current started timeout_at elapsed unavailable_streak=0
  started=$SECONDS
  timeout_at=$((started + INTERVAL))
  echo "Waiting up to ${INTERVAL}s for batch $batch to converge to $expected..."
  while (( SECONDS < timeout_at )); do
    current="$(curl -fsS http://127.0.0.1:19090/version 2>/dev/null || true)"
    if [[ -z "$current" ]]; then
      unavailable_streak=$((unavailable_streak + 1))
      if (( unavailable_streak > MAX_UNAVAILABLE )); then
        echo "FAIL: application was unavailable for $unavailable_streak consecutive probes in batch $batch." >&2
        echo "Inspect $WORK/tower.log and $RESULTS." >&2
        return 1
      fi
    else
      unavailable_streak=0
    fi
    if [[ "$current" == "$expected" ]]; then
      elapsed=$((SECONDS - started))
      echo "Batch $batch converged correctly to $current in ${elapsed}s."
      return
    fi
    sleep 0.25
  done

  current="$(curl -fsS http://127.0.0.1:19090/version 2>/dev/null || echo unavailable)"
  echo "FAIL: batch $batch did not converge to $expected within ${INTERVAL}s; found $current." >&2
  echo "Inspect $WORK/tower.log and $RESULTS." >&2
  return 1
}

if [[ "$(uname -s)" != Darwin ]]; then
  echo "This fuzzer requires macOS." >&2
  exit 1
fi
for value in "$DURATION" "$INTERVAL" "$BATCH_MIN" "$BATCH_MAX" \
    "$VERSION_MAJOR" "$MAX_UNAVAILABLE"; do
  if ! positive_integer "$value"; then
    echo "Fuzz parameters must be positive integers." >&2
    exit 2
  fi
done
if (( BATCH_MIN > BATCH_MAX )); then
  echo "UPDATED_SMOKE_FUZZ_BATCH_MIN cannot exceed UPDATED_SMOKE_FUZZ_BATCH_MAX." >&2
  exit 2
fi
expected="$(curl -fsS http://127.0.0.1:19090/version 2>/dev/null || true)"
if [[ -z "$expected" ]]; then
  echo "Start the smoke tower first with: $SMOKE start" >&2
  exit 1
fi

rm -rf "$RESULTS"
mkdir -p "$RESULTS"
all_versions=()
started=$SECONDS
stop_at=$((started + DURATION))
batch=1
completed=0

while (( batch == 1 || SECONDS < stop_at )); do
  count=$((BATCH_MIN + RANDOM % (BATCH_MAX - BATCH_MIN + 1)))
  publish_batch "$count" "$batch"
  check_convergence "$batch"
  completed="$batch"
  batch=$((batch + 1))
done

elapsed=$((SECONDS - started))
echo "PASS: $completed bursts completed in ${elapsed}s and converged after every burst; final version $expected."
