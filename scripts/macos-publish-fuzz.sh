#!/usr/bin/env bash
set -euo pipefail

# Publish concurrent bundles and require convergence to the greatest valid version.
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SMOKE="$ROOT/scripts/macos-smoke.sh"
WORK="${UPDATED_SMOKE_DIR:-$ROOT/target/macos-smoke}"
RESULTS="$WORK/publish-fuzz-results"
DEPLOY_STATE="$WORK/deploy-state"
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
mkdir -p "$DEPLOY_STATE/live" "$DEPLOY_STATE/backups" "$DEPLOY_STATE/effects"
if [[ ! -e "$DEPLOY_STATE/live/app.version" ]]; then
  printf '%s\n' "$current" >"$DEPLOY_STATE/live/app.version"
  printf 'schema=1 version=%s\n' "$current" >"$DEPLOY_STATE/live/content.db"
elif [[ "$(<"$DEPLOY_STATE/live/app.version")" != "$current" ]]; then
  echo "FAIL: complex deployment state does not match the running release; reset the smoke tower" >&2
  exit 1
fi
[[ -s "$DEPLOY_STATE/live/content.db" ]] || {
  echo "FAIL: complex deployment content state is missing or empty" >&2
  exit 1
}
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
  round_predecessor="$current"
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
  provider_set="fuzz-$round"
  previous_content="$(<"$DEPLOY_STATE/live/content.db")"
  if [[ -e "$DEPLOY_STATE/attempts.log" ]]; then
    attempts_before="$(wc -l <"$DEPLOY_STATE/attempts.log")"
  else
    attempts_before=0
  fi
  UPDATED_SMOKE_LIFECYCLE_PROFILE=complex "$SMOKE" provider-set "$provider_set" >/dev/null
  # Provider sets are independently deployable. Rotate only that half of the signed
  # assignment first and prove it does not manufacture a same-release app transaction.
  same_before="$(grep -c "applying update $current -> $current" "$WORK/tower.log" || true)"
  UPDATED_SMOKE_PROVIDER_SET_ID="$provider_set" "$SMOKE" assign "$current" >/dev/null
  sleep 2
  same_after="$(grep -c "applying update $current -> $current" "$WORK/tower.log" || true)"
  if [[ "$same_after" != "$same_before" || "$(probe_version)" != "$current" ]]; then
    echo "FAIL: provider-only assignment created an application transaction" >&2
    tail -n 80 "$WORK/tower.log" >&2
    exit 1
  fi
  if [[ -e "$DEPLOY_STATE/attempts.log" ]]; then
    attempts_after="$(wc -l <"$DEPLOY_STATE/attempts.log")"
  else
    attempts_after=0
  fi
  if [[ "$attempts_after" != "$attempts_before" ]]; then
    echo "FAIL: provider-only assignment ran application lifecycle phases" >&2
    exit 1
  fi
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
    UPDATED_SMOKE_PROVIDER_SET_ID="$provider_set" "$SMOKE" assign "$corrupt" >/dev/null
    reject_deadline=$((SECONDS + 30))
    while (( SECONDS < reject_deadline )) && ! grep -q "rejected $corrupt" "$WORK/tower.log"; do
      sleep 0.25
    done
    grep -q "rejected $corrupt" "$WORK/tower.log" || {
      echo "FAIL: desired corrupt release $corrupt was not rejected" >&2
      exit 1
    }
    corrupt_attempt="$(awk -F '\t' -v version="$corrupt" '$1 == "preflight" && $3 == version { id=$2 } END { print id }' "$DEPLOY_STATE/attempts.log")"
    rollback_deadline=$((SECONDS + 15))
    while (( SECONDS < rollback_deadline )); do
      if [[ -n "$corrupt_attempt" ]] && awk -F '\t' -v id="$corrupt_attempt" '$1 == "rollback" && $2 == id { found=1 } END { exit !found }' "$DEPLOY_STATE/attempts.log"; then
        break
      fi
      sleep 0.25
      corrupt_attempt="$(awk -F '\t' -v version="$corrupt" '$1 == "preflight" && $3 == version { id=$2 } END { print id }' "$DEPLOY_STATE/attempts.log")"
    done
    if [[ -z "$corrupt_attempt" ]] || ! awk -F '\t' -v id="$corrupt_attempt" '$1 == "rollback" && $2 == id { found=1 } END { exit !found }' "$DEPLOY_STATE/attempts.log"; then
      echo "FAIL: corrupt release was rejected without completing the complex deployment rollback" >&2
      exit 1
    fi
    if [[ "$(<"$DEPLOY_STATE/live/app.version")" != "$current" || "$(<"$DEPLOY_STATE/live/content.db")" != "$previous_content" || -e "$DEPLOY_STATE/live/draining" ]]; then
      echo "FAIL: complex rollback did not restore the predecessor's exact deployment state" >&2
      exit 1
    fi
  fi
  # The control plane, not the node, chooses the fallback. Publishing this exact
  # assignment last also makes concurrent artifact publication ordering irrelevant.
  UPDATED_SMOKE_PROVIDER_SET_ID="$provider_set" "$SMOKE" assign "$expected" >/dev/null
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
  lifecycle_deadline=$((SECONDS + 15))
  attempt_id=""
  while (( SECONDS < lifecycle_deadline )); do
    attempt_id="$(awk -F '\t' -v version="$expected" '$1 == "finalize" && $3 == version { id=$2 } END { print id }' "$DEPLOY_STATE/attempts.log")"
    [[ -n "$attempt_id" ]] && break
    sleep 0.25
  done
  if [[ -z "$attempt_id" ]]; then
    echo "FAIL: application converged without a completed complex deployment" >&2
    exit 1
  fi
  phases="$(awk -F '\t' -v id="$attempt_id" '$2 == id { print $1 }' "$DEPLOY_STATE/attempts.log" | paste -sd, -)"
  if [[ "$phases" != preflight,prepare,drain,stop,activate,start,verify,finalize ]]; then
    echo "FAIL: complex deployment phases for $attempt_id were '$phases'" >&2
    exit 1
  fi
  for phase in preflight prepare drain stop activate start verify finalize; do
    if [[ ! -e "$DEPLOY_STATE/effects/$attempt_id/$phase" ]]; then
      echo "FAIL: complex deployment did not durably record $phase for $attempt_id" >&2
      exit 1
    fi
  done
  if [[ "$(<"$DEPLOY_STATE/backups/$attempt_id/app.version")" != "$round_predecessor" ]]; then
    echo "FAIL: complex deployment backup did not capture the immediate predecessor" >&2
    exit 1
  fi
  if [[ "$(<"$DEPLOY_STATE/backups/$attempt_id/content.db")" != "$previous_content" ]]; then
    echo "FAIL: complex deployment backup did not capture predecessor content" >&2
    exit 1
  fi
  if [[ "$(<"$DEPLOY_STATE/live/app.version")" != "$expected" || "$(<"$DEPLOY_STATE/live/content.db")" != "schema=2 version=$expected" || -e "$DEPLOY_STATE/live/draining" ]]; then
    echo "FAIL: complex deployment did not finish with migrated, undrained live state" >&2
    exit 1
  fi
  assignment="$WORK/install/state/repository-assignment.json"
  if ! grep -q "provider-sets/$provider_set.json" "$assignment" 2>/dev/null; then
    echo "FAIL: app converged without retaining the assigned provider set $provider_set" >&2
    cat "$assignment" >&2 2>/dev/null || true
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
sleep 3
release_dirs="$(find "$WORK/install/versions" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
repository_caches="$(find "$WORK/install/state/tuf" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
provider_dirs="$(find "$WORK/install/providers/versions" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')"
if (( release_dirs > 3 )); then
  echo "FAIL: immutable release GC retained $release_dirs directories (expected active + at most 2 inactive)" >&2
  exit 1
fi
if (( repository_caches > 3 )); then
  echo "FAIL: repository cache GC retained $repository_caches assignments (expected active + at most 2 inactive)" >&2
  exit 1
fi
if (( provider_dirs > 3 )); then
  echo "FAIL: provider GC retained $provider_dirs directories (expected active + at most 2 inactive)" >&2
  exit 1
fi
echo
echo "PASS: $round concurrent bundle/provider-set batches converged in $((SECONDS - started))s; bounded storage retained $release_dirs releases, $provider_dirs providers, and $repository_caches repository caches"
echo "Publisher logs retained at $RESULTS"
