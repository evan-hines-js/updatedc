#!/bin/sh
set -eu
# Installed into the image at runtime; there is no source-tree path at this location for
# ShellCheck to follow.
# shellcheck source=/dev/null
. /usr/local/lib/publish-fuzz-plan.sh

repo=/data/repository
keys=/data/keys
fixtures=/data/fixtures
case $(uname -m) in
  aarch64|arm64) platform=linux-aarch64 ;;
  x86_64|amd64) platform=linux-x86_64 ;;
  *) echo "unsupported E2E architecture: $(uname -m)" >&2; exit 1 ;;
esac
if [ ! -f /data/ready ]; then
  rm -rf "$repo" "$keys" "$fixtures"
  server init --repo "$repo" --keys "$keys"
  # Every release carries exactly one signed node reconciler, and the reconciler OWNS the
  # workload: the agent runs packages and never starts, stops, or holds a PID of one. The ordinary
  # fleet runs a plain HTTP application, so its `default` set uses the smallest hook that owns a
  # process honestly — `converge` selects the supplied payload (kill-then-start
  # against a pidfile, detached with `setsid` so it escapes the invocation's contained tree),
  # `healthcheck` observes `/healthz`, `inspect` reports the running release. Convergence, not
  # restart: an already-correct running workload is left alone, so its PID is stable across agent
  # boots and restarts.
  mkdir -p "$fixtures/entrypoint/bin"
  cat >"$fixtures/entrypoint/bin/lifecycle" <<'RECONCILER'
#!/bin/sh
set -eu

operation=${UPDATED_OPERATION:?}
payload=${UPDATED_PAYLOAD_ROOT:?}
state_dir=${UPDATED_STATE_DIR:?}
result_file=${UPDATED_RESULT_FILE:?}
attempt=${UPDATED_ATTEMPT_ID:?}
backup="$state_dir/before-${attempt%r}"

# The service address every peer in the fleet reaches this node's workload on.
address=0.0.0.0:8080
# The workload record is shared by every release of this node, not scoped to this reconciler: the
# next release may ship a DIFFERENT reconciler, and that one has to be able to stop the process
# this one started. It therefore sits beside the per-provider state directories — the same path
# the enterprise lifecycle reconciler derives from its own --state-dir (crates/demo-lifecycle).
record_dir=$(dirname "$state_dir")
pidfile="$record_dir/workload.pid"
releasefile="$record_dir/workload.release"

# Whether the recorded workload is still serving. A detached workload is reparented to whatever
# runs as pid 1, which reaps its own children and nothing else, so a crashed one lingers as a
# zombie that answers `kill -0` and serves nothing: the process state, not its mere existence, is
# what says the workload is still there.
running() {
  [ -f "$pidfile" ] || return 1
  pid=$(cat "$pidfile")
  kill -0 "$pid" 2>/dev/null || return 1
  # Container restarts recycle PIDs while these records persist. Never treat an unrelated
  # process as our workload or signal it during convergence.
  recorded_release=$(cat "$releasefile" 2>/dev/null || true)
  [ -n "$recorded_release" ] || return 1
  [ "$(readlink "/proc/$pid/exe" 2>/dev/null || true)" = "$recorded_release/bin/app" ] || return 1
  [ "$(sed 's/.*) //' "/proc/$pid/stat" 2>/dev/null | cut -d' ' -f1)" != Z ]
}

# Converge the workload onto $payload: leave it alone when it already runs these bytes,
# otherwise stop what is running and start the payload's executable.
converge() {
  if running && [ "$(cat "$releasefile" 2>/dev/null || true)" = "$payload" ]; then
    return 0
  fi
  if running; then
    pid=$(cat "$pidfile")
    kill "$pid" 2>/dev/null || true
    for _ in 1 2 3 4 5; do
      running || break
      sleep 1
    done
    kill -9 "$pid" 2>/dev/null || true
  fi
  rm -f "$pidfile" "$releasefile"
  # The workload is started by a shell that records its OWN pid before exec'ing the entrypoint,
  # and the entrypoint refuses to serve until the pidfile names it: this hook can be killed at any
  # instant, and a workload nothing can name is a workload nothing can stop. `setsid` moves it out
  # of this invocation's contained tree, which the agent tears down when the hook returns.
  setsid /bin/sh -c '
    cd "$1" || exit 1
    printf "%s\n" "$1" >"$4.tmp"
    mv "$4.tmp" "$4"
    printf "%s\n" "$$" >"$2.tmp"
    mv "$2.tmp" "$2"
    exec ./bin/app --addr "$3" --await-record "$2"
  ' sh "$payload" "$pidfile" "$address" "$releasefile" </dev/null >>"$state_dir/workload.log" 2>&1 &
  # A release whose entrypoint cannot run at all fails its own activation here, rather than
  # leaving the agent to infer it from a health observation.
  waited=0
  while [ ! -f "$pidfile" ] && [ "$waited" -lt 3 ]; do
    sleep 1
    waited=$((waited + 1))
  done
  sleep 1
  running || {
    echo "default-reconciler: the workload from $payload did not stay up" >&2
    tail -n 20 "$state_dir/workload.log" >&2 || true
    exit 1
  }
  printf '%s\n' "$payload" >"$releasefile"
}

case "$operation" in
  converge)
    if [ ! -f "$backup" ]; then
      cat "$releasefile" 2>/dev/null >"$backup.tmp" || true
      mv "$backup.tmp" "$backup"
    fi
    changed=true
    if running && [ "$(cat "$releasefile" 2>/dev/null || true)" = "$payload" ]; then changed=false; fi
    converge
    printf '{"schema":1,"status":"succeeded","changed":%s,"hostAction":"none","message":null}' "$changed" >"$result_file"
    ;;
  rollback)
    previous=$(cat "$backup" 2>/dev/null || true)
    if [ -n "$previous" ]; then payload=$previous; converge; fi
    printf '%s' '{"schema":1,"status":"succeeded","changed":true,"hostAction":"none","message":null}' >"$result_file"
    ;;
  healthcheck) [ "$(cat "$releasefile" 2>/dev/null || true)" = "$payload" ]; curl -fsS -o /dev/null --max-time 3 http://127.0.0.1:8080/healthz ;;
  inspect) printf 'release=%s\n' "$(cat "$releasefile" 2>/dev/null || true)" ;;
  *) echo "default-reconciler: unknown operation '$operation'" >&2; exit 2 ;;
esac
RECONCILER
  chmod 0755 "$fixtures/entrypoint/bin/lifecycle"
  max_major=$(publish_fuzz_max_major "${UPDATEC_FUZZ_ROUNDS:-0}")
  for major in $(seq 1 "$max_major"); do
    version="${major}.0.0"
    source="$fixtures/$version"
    mkdir -p "$source/bin" "$source/config"
    if publish_fuzz_is_corrupt "$version"; then
      # An unlaunchable entrypoint (not a valid executable): the agent must reject this
      # release at activation and roll back, rather than crash-loop it.
      printf 'intentionally corrupt bundle entrypoint\n' >"$source/bin/app"
      chmod 0755 "$source/bin/app"
    else
      artifact=$(publish_fuzz_artifact "$version")
      case "$artifact" in
        stateful) cp /usr/local/bin/stateful-like "$source/bin/app" ;;
        sampleapp) cp /usr/local/bin/sampleapp "$source/bin/app" ;;
        *) echo "unknown fuzz artifact: $artifact" >&2; exit 1 ;;
      esac
    fi
    printf 'version = "%s"\n' "$version" >"$source/config/release.toml"
    cp "$fixtures/entrypoint/bin/lifecycle" "$source/bin/lifecycle"
    printf '%s\n' '{"schema":1,"deploy":{"argv":["./bin/lifecycle"],"timeoutSeconds":15},"inspect":{"argv":["./bin/lifecycle"],"timeoutSeconds":10},"replay":{"policy":"safe"},"recovery":{"policy":"command","command":{"argv":["./bin/lifecycle"],"timeoutSeconds":15},"replay":{"policy":"safe"}},"health":{"argv":["./bin/lifecycle"],"timeoutSeconds":10}}' >"$source/.updated-execution.json"
    server publish-app --repo "$repo" --keys "$keys" \
      --product app --channel stable --version "$version" \
      --bundle "$platform=$source"
  done
  # Real Jenkins as a managed product, on every architecture: the WAR is architecture-independent
  # and the reconciler fetches the JRE matching the node's own `uname -m`. Installed at runtime on
  # a plain Ubuntu + agent node — nothing Jenkins-specific is baked into any image; v1 -> v2 is a
  # real rolling restart, drained one node at a time by the reconciler's quiet-down.
  for jenkins_version in 1.0.0 2.0.0; do
    source="$fixtures/jenkins-$jenkins_version"
    mkdir -p "$source/bin" "$source/config"
    cp /usr/local/share/jenkins/app.sh "$source/bin/app"
    chmod 0755 "$source/bin/app"
    printf 'version = "%s"\n' "$jenkins_version" >"$source/config/release.toml"
    cp /usr/local/share/jenkins/install.sh "$source/bin/lifecycle"
    chmod 0755 "$source/bin/lifecycle"
    printf '%s\n' '{"schema":1,"deploy":{"argv":["./bin/lifecycle"],"timeoutSeconds":300},"inspect":{"argv":["./bin/lifecycle"],"timeoutSeconds":10},"replay":{"policy":"safe"},"recovery":{"policy":"command","command":{"argv":["./bin/lifecycle"],"timeoutSeconds":300},"replay":{"policy":"safe"}},"health":{"argv":["./bin/lifecycle"],"timeoutSeconds":10}}' >"$source/.updated-execution.json"
    server publish-app --repo "$repo" --keys "$keys" \
      --product jenkins --channel stable --version "$jenkins_version" \
      --bundle "$platform=$source"
  done
  printf '%s\n' "$platform" >/data/platform
  touch /data/ready
fi
# These indexes are derived from the one release-classification function on every start. This also
# upgrades an existing persistent repository created before the resident campaign was installed.
valid_tmp=/data/.valid-versions.tmp
corrupt_tmp=/data/.corrupt-versions.tmp
: >"$valid_tmp"
: >"$corrupt_tmp"
max_major=$(publish_fuzz_max_major "${UPDATEC_FUZZ_ROUNDS:-0}")
for major in $(seq 1 "$max_major"); do
  version="${major}.0.0"
  if publish_fuzz_is_corrupt "$version"; then
    printf '%s\n' "$version" >>"$corrupt_tmp"
  else
    printf '%s\n' "$version" >>"$valid_tmp"
  fi
done
mv "$valid_tmp" /data/valid-versions
mv "$corrupt_tmp" /data/corrupt-versions
# Releases are the object plane: agents fetch them anonymously over HTTPS and never offer their
# control-plane certificate. The real routing gateway is exercised separately and redirects its
# authorized requests to signed MinIO URLs.
exec server serve-object --repo "$repo" --addr 0.0.0.0:8080 \
  --cert /etc/gateway-tls/tls.crt --key /etc/gateway-tls/tls.key
