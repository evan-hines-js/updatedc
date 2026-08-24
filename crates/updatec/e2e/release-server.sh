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
  for major in $(seq 1 22); do
    version="${major}.0.0"
    source="$fixtures/$version"
    mkdir -p "$source/bin" "$source/config"
    if [ "$major" -eq 18 ] || [ "$major" -eq 21 ]; then
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
    server publish-app --repo "$repo" --keys "$keys" \
      --product app --channel stable --version "$version" --entrypoint bin/app \
      --bundle "$platform=$source"
  done
  # Every release carries exactly one signed node reconciler, and the reconciler OWNS the
  # workload: the agent runs packages and never starts, stops, or holds a PID of one. The ordinary
  # fleet runs a plain HTTP application, so its `default` set uses the smallest hook that owns a
  # process honestly — `apply`/`rollback` converge the workload onto `--candidate` (kill-then-start
  # against a pidfile, detached with `setsid` so it escapes the invocation's contained tree),
  # `healthcheck` observes `/healthz`, `inspect` reports the running release. Convergence, not
  # restart: an already-correct running workload is left alone, so its PID is stable across agent
  # boots, restarts and self-updates.
  mkdir -p "$fixtures/default-provider/bin"
  cat >"$fixtures/default-provider/bin/lifecycle" <<'RECONCILER'
#!/bin/sh
set -eu

operation=${1:?missing reconciler operation}
shift
protocol= candidate= state_dir= result_file=
while [ $# -gt 0 ]; do
  case $1 in
    --protocol) protocol=$2; shift 2 ;;
    --candidate) candidate=$2; shift 2 ;;
    --state-dir) state_dir=$2; shift 2 ;;
    --result-file) result_file=$2; shift 2 ;;
    --attempt-id|--reason|--install-root|--candidate-version|--predecessor|\
--predecessor-version|--input-dir|--output-dir) shift 2 ;;
    --) shift; break ;;
    *) echo "default-reconciler: unknown argument '$1'" >&2; exit 2 ;;
  esac
done
[ "$protocol" = 1 ] || { echo "default-reconciler: unsupported protocol" >&2; exit 2; }

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
  [ "$(sed 's/.*) //' "/proc/$pid/stat" 2>/dev/null | cut -d' ' -f1)" != Z ]
}

# Converge the workload onto $candidate: leave it alone when it already runs these bytes,
# otherwise stop what is running and start the candidate's own entrypoint.
converge() {
  if running && [ "$(cat "$releasefile" 2>/dev/null || true)" = "$candidate" ]; then
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
    printf "%s\n" "$$" >"$2.tmp"
    mv "$2.tmp" "$2"
    exec ./bin/app --addr "$3" --await-record "$2"
  ' sh "$candidate" "$pidfile" "$address" </dev/null >>"$state_dir/workload.log" 2>&1 &
  # A release whose entrypoint cannot run at all fails its own activation here, rather than
  # leaving the agent to infer it from a health observation.
  waited=0
  while [ ! -f "$pidfile" ] && [ "$waited" -lt 3 ]; do
    sleep 1
    waited=$((waited + 1))
  done
  sleep 1
  running || {
    echo "default-reconciler: the workload from $candidate did not stay up" >&2
    tail -n 20 "$state_dir/workload.log" >&2 || true
    exit 1
  }
  printf '%s\n' "$candidate" >"$releasefile"
}

case "$operation" in
  # On a rollback --candidate IS the release being restored, so both directions converge the
  # same way onto the same argument.
  apply|rollback)
    changed=true
    if running && [ "$(cat "$releasefile" 2>/dev/null || true)" = "$candidate" ]; then changed=false; fi
    converge
    printf '{"schema":1,"status":"succeeded","changed":%s,"hostAction":"none","retryAfterSeconds":null,"message":null}' "$changed" >"$result_file"
    ;;
  healthcheck) curl -fsS -o /dev/null --max-time 3 http://127.0.0.1:8080/healthz ;;
  inspect) printf 'release=%s\n' "$(cat "$releasefile" 2>/dev/null || true)" ;;
  *) echo "default-reconciler: unknown operation '$operation'" >&2; exit 2 ;;
esac
RECONCILER
  chmod 0755 "$fixtures/default-provider/bin/lifecycle"
  server publish-provider-artifact --repo "$repo" --keys "$keys" \
    --product default-reconciler --version 1.0.0 \
    --bundle "$platform=$fixtures/default-provider" --entrypoint bin/lifecycle
  provider_path="products/default-reconciler/stable/1.0.0/$platform/default-reconciler"
  provider_sha=$(server target-sha256 --repo "$repo" --name "$provider_path")
  server publish-provider-set --repo "$repo" --keys "$keys" --id default \
    --provider-path "$provider_path" --provider-sha256 "$provider_sha" \
    --provider-timeout-ms 15000
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
    server publish-app --repo "$repo" --keys "$keys" \
      --product jenkins --channel stable --version "$jenkins_version" --entrypoint bin/app \
      --bundle "$platform=$source"
  done
  # The pre-start install provider — a signed lifecycle artifact the agent downloads and runs
  # to install the JRE + Jenkins into its container at runtime. A generous timeout covers the
  # first-boot download.
  mkdir -p "$fixtures/jenkins-install/bin"
  cp /usr/local/share/jenkins/install.sh "$fixtures/jenkins-install/bin/lifecycle"
  chmod 0755 "$fixtures/jenkins-install/bin/lifecycle"
  server publish-provider-artifact --repo "$repo" --keys "$keys" \
    --product jenkins-install --version 1.0.0 \
    --bundle "$platform=$fixtures/jenkins-install" --entrypoint bin/lifecycle
  jenkins_provider_path="products/jenkins-install/stable/1.0.0/$platform/jenkins-install"
  jenkins_provider_sha=$(server target-sha256 --repo "$repo" --name "$jenkins_provider_path")
  server publish-provider-set --repo "$repo" --keys "$keys" --id jenkins \
    --provider-path "$jenkins_provider_path" --provider-sha256 "$jenkins_provider_sha" \
    --provider-timeout-ms 300000
  printf '%s\n' "$platform" >/data/platform
  touch /data/ready
fi
# Releases are the object plane: agents fetch them anonymously over HTTPS and never offer their
# control-plane certificate. The real routing gateway is exercised separately and redirects its
# authorized requests to signed MinIO URLs.
exec server serve-object --repo "$repo" --addr 0.0.0.0:8080 \
  --cert /etc/gateway-tls/tls.crt --key /etc/gateway-tls/tls.key
