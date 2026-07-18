#!/usr/bin/env bash
set -euo pipefail

# Publish concurrent bundles and require convergence to the greatest valid version.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SMOKE="$ROOT/scripts/macos-smoke.sh"
WORK="${UPDATED_SMOKE_DIR:-$ROOT/target/macos-smoke}"
RESULTS="$WORK/publish-fuzz-results"
DURATION="${UPDATED_SMOKE_FUZZ_SECONDS:-60}"
INTERVAL="${UPDATED_SMOKE_FUZZ_INTERVAL_SECONDS:-60}"
BATCH="${UPDATED_SMOKE_FUZZ_BATCH_SIZE:-4}"
probe_version() {
  curl --connect-timeout 1 --max-time 1 -fsS http://127.0.0.1:19090/version 2>/dev/null || true
}
if grep -Eq '^mode[[:space:]]*=[[:space:]]*"reexec"' "$WORK/config.toml"; then
  MODE=reexec
else
  MODE=restart
fi
CORRUPT="${UPDATED_SMOKE_FUZZ_CORRUPT:-auto}"
if [[ "$CORRUPT" == auto ]]; then
  [[ "$MODE" == restart ]] && CORRUPT=1 || CORRUPT=0
fi
if [[ "$CORRUPT" != 0 && "$CORRUPT" != 1 ]]; then
  echo "UPDATED_SMOKE_FUZZ_CORRUPT must be 0, 1, or auto" >&2
  exit 2
fi
pids=()
monitor_pid=""
monitor_stop=""
cleanup_children() {
  if [[ -n "$monitor_stop" ]]; then touch "$monitor_stop" 2>/dev/null || true; fi
  if [[ -n "$monitor_pid" ]]; then kill "$monitor_pid" 2>/dev/null || true; fi
  for pid in "${pids[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${pids[@]:-}"; do wait "$pid" 2>/dev/null || true; done
  if [[ -n "$monitor_pid" ]]; then wait "$monitor_pid" 2>/dev/null || true; fi
}
trap cleanup_children EXIT
trap 'echo "Interrupted; stopping fuzz publisher and monitor children" >&2; exit 130' INT TERM

[[ "$(uname -s)" == Darwin ]] || { echo "This fuzzer requires macOS." >&2; exit 1; }
current="$(probe_version)"
[[ -n "$current" ]] || { echo "Start the smoke tower first: $SMOKE start" >&2; exit 1; }
rm -rf "$RESULTS"
mkdir -p "$RESULTS"
echo "Fuzzing bundle publication for ${DURATION}s from running version $current ($MODE mode)"
if [[ "$CORRUPT" == 1 ]]; then
  echo "Fault injection: enabled (an unlaunchable newest release will test rollback; restart recovery may be briefly unavailable)"
elif [[ "$MODE" == reexec ]]; then
  echo "Fault injection: disabled (every candidate is executable; reexec requires zero observed downtime)"
else
  echo "Fault injection: disabled (every candidate is executable; restart must converge within ${INTERVAL}s)"
fi
echo "Per-release publisher logs: $RESULTS"
started=$SECONDS
round=0
while (( round == 0 || SECONDS - started < DURATION )); do
  round=$((round + 1)); pids=(); versions=()
  batch_started=$SECONDS
  samples="$RESULTS/batch-$round-availability.log"
  monitor_stop="$RESULTS/batch-$round-monitor.stop"
  rm -f "$monitor_stop"
  (
    while [[ ! -e "$monitor_stop" ]]; do
      observed="$(probe_version)"
      printf '%s %s\n' "$(date '+%H:%M:%S')" "${observed:-unavailable}" >>"$samples"
      sleep 0.1
    done
  ) & monitor_pid=$!
  echo
  echo "== batch $round: preparing $BATCH valid bundles =="
  for ((i=1; i<=BATCH; i++)); do
    version="999.$round.$i"; versions+=("$version")
    UPDATED_SMOKE_PREPARE_ONLY=1 "$SMOKE" publish "$version" >/dev/null
  done
  expected="999.$round.$BATCH"
  corrupt=""
  if [[ "$CORRUPT" == 1 ]]; then
    corrupt="999.$round.$((BATCH + 1))"
    UPDATED_SMOKE_PREPARE_ONLY=1 "$SMOKE" publish "$corrupt" >/dev/null
    printf 'intentionally corrupt bundle entrypoint\n' >"$WORK/bin/bundle-$corrupt/bin/app"
    chmod +x "$WORK/bin/bundle-$corrupt/bin/app"
    versions+=("$corrupt")
  fi
  printf '%s\n' "$expected" >"$RESULTS/expected-version"
  echo "Publishing concurrently: ${versions[*]}"
  if [[ -n "$corrupt" ]]; then
    echo "Expected recovery target: $expected (newest $corrupt is intentionally unlaunchable)"
  else
    echo "Expected convergence target: $expected"
  fi
  for version in "${versions[@]}"; do
    (
      UPDATED_SMOKE_PUBLISH_NO_WAIT=1 UPDATED_SMOKE_REUSE_BUNDLE=1 \
        "$SMOKE" publish "$version" >"$RESULTS/$version.log" 2>&1
    ) & pids+=("$!")
  done
  failed=0
  for pid in "${pids[@]}"; do
    if ! wait "$pid"; then failed=$((failed + 1)); fi
  done
  if (( failed != 0 )); then
    touch "$monitor_stop"; wait "$monitor_pid" || true
    echo "FAIL: $failed publisher process(es) failed; logs:" >&2
    for version in "${versions[@]}"; do
      echo "--- $version ---" >&2
      tail -n 20 "$RESULTS/$version.log" >&2
    done
    exit 1
  fi
  if [[ -n "$corrupt" ]]; then
    "$SMOKE" assign "$corrupt" >/dev/null
    reject_deadline=$((SECONDS + 30))
    while (( SECONDS < reject_deadline )) && ! grep -q "rejected $corrupt" "$WORK/tower.log"; do
      sleep 0.25
    done
    grep -q "rejected $corrupt" "$WORK/tower.log" || {
      echo "FAIL: desired corrupt release $corrupt was not rejected" >&2
      exit 1
    }
  fi
  # The control plane, not the node, chooses the fallback. Publishing this exact
  # assignment last also makes concurrent artifact publication ordering irrelevant.
  "$SMOKE" assign "$expected" >/dev/null
  echo "All ${#versions[@]} signed publications completed; waiting up to ${INTERVAL}s for recovery and convergence..."
  recovery_started=$SECONDS
  deadline=$((recovery_started + INTERVAL)); probes=0; next_progress=$recovery_started
  while (( SECONDS < deadline )); do
    probes=$((probes + 1))
    current="$(probe_version)"
    [[ "$current" == "$expected" ]] && break
    if (( SECONDS >= next_progress )); then
      echo "  recovery $((SECONDS - recovery_started))s/${INTERVAL}s: ${current:-unavailable}"
      next_progress=$((SECONDS + 2))
    fi
    sleep 0.25
  done
  if [[ "$current" != "$expected" ]]; then
    touch "$monitor_stop"; wait "$monitor_pid" || true
    echo "FAIL: batch $round expected $expected, found ${current:-unavailable} after $probes probes" >&2
    echo "Tower log tail ($WORK/tower.log):" >&2
    tail -n 80 "$WORK/tower.log" >&2
    exit 1
  fi
  touch "$monitor_stop"; wait "$monitor_pid" || true
  monitor_pid=""
  monitor_stop=""
  pids=()
  unavailable_total="$(grep -c ' unavailable$' "$samples" || true)"
  unavailable_streak="$(awk '$2 == "unavailable" { run++; if (run > max) max = run; next } { run = 0 } END { print max + 0 }' "$samples")"
  if [[ "$MODE" == reexec && "$CORRUPT" == 0 && "$unavailable_total" != 0 ]]; then
    echo "FAIL: reexec batch observed $unavailable_total unavailable samples; complete timeline:" >&2
    cat "$samples" >&2
    exit 1
  fi
  if [[ -n "$corrupt" ]]; then
    echo "PASS batch $round: rejected $corrupt and recovered to $expected in $((SECONDS - batch_started))s ($probes probes, $unavailable_total unavailable samples, longest streak $unavailable_streak)"
  elif [[ "$MODE" == reexec ]]; then
    echo "PASS batch $round: converged to $expected with no observed downtime in $((SECONDS - batch_started))s ($probes probes, availability log: $samples)"
  else
    echo "PASS batch $round: converged to $expected in $((SECONDS - batch_started))s ($probes probes, $unavailable_total unavailable samples, longest streak $unavailable_streak)"
  fi
done
echo
echo "PASS: $round concurrent bundle batches converged in $((SECONDS - started))s"
echo "Publisher logs retained at $RESULTS"
