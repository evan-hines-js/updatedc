#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SUITE="${1:-all}"
BACKGROUND_PID=""

usage() {
  cat <<'EOF'
usage: scripts/ci.sh [all|rust|coverage|charts|semgrep|trivy|haproxy|kind|fleet]

With no argument, run every CI check supported by this host. The named suites
exist so GitHub Actions can call this same implementation while retaining
independent jobs and failure reporting.
EOF
}

case "$SUITE" in
  all|rust|coverage|charts|semgrep|trivy|haproxy|kind|fleet) ;;
  --help|-h)
    usage
    exit 0
    ;;
  *)
    echo "FAIL: unknown CI suite '$SUITE'" >&2
    usage >&2
    exit 2
    ;;
esac
[[ $# -le 1 ]] || { echo "FAIL: only one CI suite may be selected" >&2; exit 2; }

cd "$ROOT"
[[ -f Cargo.toml && -d scripts ]] || {
  echo "FAIL: could not resolve the updatedc repository root" >&2
  exit 2
}

require_commands() {
  local missing="" command
  for command in "$@"; do
    if ! command -v "$command" >/dev/null 2>&1; then
      missing="$missing $command"
    fi
  done
  if [[ -n "$missing" ]]; then
    echo "FAIL: missing required commands:$missing" >&2
    exit 2
  fi
}

preflight() {
  local selected=$1
  case "$selected" in
    rust)
      require_commands cargo cmake diff go mktemp uname
      ;;
    coverage)
      require_commands cargo cmake go
      local coverage_toolchain=${RUST_COVERAGE_TOOLCHAIN:-nightly}
      cargo +"$coverage_toolchain" --version >/dev/null 2>&1 || {
        echo "FAIL: the coverage suite requires Rust toolchain $coverage_toolchain" >&2
        exit 2
      }
      cargo +"$coverage_toolchain" llvm-cov --version >/dev/null 2>&1 || {
        echo "FAIL: the coverage suite requires cargo-llvm-cov" >&2
        exit 2
      }
      ;;
    charts)
      require_commands grep helm kubeconform mktemp python3
      python3 -c 'import yaml' >/dev/null 2>&1 || {
        echo "FAIL: the charts suite requires the Python yaml module" >&2
        exit 2
      }
      ;;
    semgrep)
      require_commands semgrep
      ;;
    trivy)
      require_commands cp helm mkdir trivy
      ;;
    haproxy)
      if [[ "$(uname -s)" == Linux ]]; then
        require_commands cargo curl haproxy pgrep readlink stat
      fi
      ;;
    kind|fleet)
      require_commands awk cargo curl docker helm kind kubectl openssl sha256sum
      ;;
    all)
      preflight rust
      preflight coverage
      preflight charts
      preflight semgrep
      preflight trivy
      preflight haproxy
      preflight kind
      ;;
  esac
}

run_coverage() {
  local coverage_toolchain=${RUST_COVERAGE_TOOLCHAIN:-nightly}
  local -a excluded=(
    e2e
    updatec-e2e
    killfuzz
    demo-lifecycle
    sampleapp
    server
    windows-service
  )
  local -a report_scope=()
  local package
  for package in "${excluded[@]}"; do
    report_scope+=(--exclude-from-report "$package")
  done
  section "Shipped Rust code coverage (test and harness code excluded)"
  # This function is the one report scope: it still RUNS every workspace test, while excluding test
  # harnesses, demos, fixture servers, and platform wrappers from the report. Inline
  # `cfg(test)` modules carry nightly's `coverage(off)`, so test bodies cannot inflate either the
  # numerator or denominator. This initial floor is deliberately below the measured baseline; it
  # makes coverage regression a build failure without encouraging low-value tests for a round
  # number. Raise it when production-path tests improve the baseline.
  #
  # A source edit can leave an older instrumented object beside its replacement. llvm-cov unions
  # both source maps if they survive into a later report, duplicating that file's denominator. The
  # explicit clean is therefore part of correctness, not build hygiene.
  cargo +"$coverage_toolchain" llvm-cov clean --workspace
  cargo +"$coverage_toolchain" llvm-cov --workspace \
    "${report_scope[@]}" \
    --all-features --all-targets --fail-under-lines 70
}

section() {
  printf '\n==> %s\n' "$1"
}

run_rust() {
  local e2e_rc killfuzz_pid="" killfuzz_rc=0
  local killfuzz_log="$WORK/killfuzz.log"

  section "Installer guardrails"
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
      echo "SKIP: install.sh supports Unix service managers"
      ;;
    *)
      ./install.sh --dry-run --method archive \
        --tag build-0000000000000000000000000000000000000000 \
        --gateway-url https://updates.example --node-name node-1 >/dev/null
      if ./install.sh --dry-run --method archive \
        --tag build-0000000000000000000000000000000000000000 \
        --gateway-url https://updates.example --node-name fleet >/dev/null 2>&1; then
        echo "FAIL: install.sh accepted the reserved fleet node name" >&2
        return 1
      fi
      if ./install.sh --dry-run --method archive \
        --tag build-0000000000000000000000000000000000000000 \
        --gateway-url 'https://updates.example/"injected' --node-name node-1 >/dev/null 2>&1; then
        echo "FAIL: install.sh accepted a TOML-breaking gateway URL" >&2
        return 1
      fi
      if ./install.sh --dry-run --method archive \
        --gateway-url https://updates.example --node-name node-1 >/dev/null 2>&1; then
        echo "FAIL: install.sh accepted a network install with no immutable tag" >&2
        return 1
      fi
      if ./install.sh --dry-run --method archive --tag latest \
        --gateway-url https://updates.example --node-name node-1 >/dev/null 2>&1; then
        echo "FAIL: install.sh accepted the mutable latest release" >&2
        return 1
      fi
      ;;
  esac

  ./scripts/check-source.sh

  section "Rust tests"
  cargo test --workspace --all-targets --all-features

  section "Rust lint"
  cargo clippy --workspace --all-targets --all-features --no-deps -- -D warnings

  # The `#[cfg(windows)]` paths compile nowhere else, so on a Unix developer machine they are
  # linted by nothing until the Windows runner picks them up — and by then it is a red build on a
  # branch. Cross-lint them here when the target is installed. Only these crates can: everything
  # else in the workspace reaches `zstd-sys`, which needs a Windows C toolchain to cross-compile,
  # while `cargo clippy` alone needs no linker.
  #
  # This is not hypothetical. `foundation::file` built `map_err(|error| error)` on Windows — the
  # `ELOOP` branch inside it is `#[cfg(unix)]` — and an identity closure is exactly what
  # `-D warnings` rejects. It sat there failing the Windows job for anyone who ran the full matrix.
  section "Windows cross-lint"
  if rustup target list --installed 2>/dev/null | grep -q '^x86_64-pc-windows-msvc$'; then
    cargo clippy --target x86_64-pc-windows-msvc \
      -p foundation -p windows-service \
      --all-targets --all-features --no-deps -- -D warnings
    echo "ok: the Windows-only paths lint clean"
  else
    echo "SKIP: x86_64-pc-windows-msvc is not installed (rustup target add x86_64-pc-windows-msvc)"
  fi

  section "Portable updater E2E and kill fuzzer"
  if [[ "$(uname -s)" == Linux || "$(uname -s)" == Darwin ]]; then
    # These suites run concurrently, but their output must not interleave: an immediate E2E
    # startup failure used to disappear beneath several minutes of kill-fuzzer output. Keep the
    # foreground E2E live and replay the background suite as one labelled block when it finishes.
    cargo run -p killfuzz >"$killfuzz_log" 2>&1 &
    killfuzz_pid=$!
    BACKGROUND_PID=$killfuzz_pid
  fi
  set +e
  cargo run -p e2e
  e2e_rc=$?
  if (( e2e_rc != 0 )); then
    echo "FAIL: portable E2E exited with status $e2e_rc" >&2
  fi
  if [[ -n "$killfuzz_pid" ]]; then
    wait "$killfuzz_pid"
    killfuzz_rc=$?
    BACKGROUND_PID=""
    section "Kill fuzzer output"
    cat "$killfuzz_log"
  fi
  set -e
  echo "e2e exit=$e2e_rc, killfuzz exit=$killfuzz_rc"
  (( e2e_rc == 0 && killfuzz_rc == 0 ))
}

must_refuse_chart() {
  local description=$1
  shift
  if "$@" >/dev/null 2>&1; then
    echo "FAIL: $description rendered successfully but must be refused" >&2
    return 1
  fi
  echo "ok: refused $description"
}

# The cert-manager templates carry three independent `create` toggles, and a Certificate whose
# issuerRef names an issuer no combination of them rendered is not a render error — it is a
# gateway stuck in ContainerCreating on a Secret cert-manager will never write. Check the
# references resolve, by name AND kind, in the document the operator would actually apply.
assert_issuer_refs_resolve() {
  local description=$1 manifests="$WORK/certmanager.yaml"
  shift
  "$@" >"$manifests"
  python3 - "$description" "$manifests" <<'PY'
import sys, yaml
description, path = sys.argv[1], sys.argv[2]
issuers, certificates = set(), []
for doc in yaml.safe_load_all(open(path, encoding="utf-8")):
    if not doc:
        continue
    if doc["kind"] in ("Issuer", "ClusterIssuer"):
        issuers.add((doc["kind"], doc["metadata"]["name"]))
    elif doc["kind"] == "Certificate":
        ref = doc["spec"]["issuerRef"]
        certificates.append((doc["metadata"]["name"], (ref.get("kind", "Issuer"), ref["name"])))
assert certificates, f"{description}: rendered no Certificates, so nothing was checked"
for name, ref in certificates:
    assert ref in issuers, (
        f"{description}: Certificate {name} references {ref[0]}/{ref[1]}, "
        f"which this release does not create (it creates {sorted(issuers)})"
    )
print(f"ok: every Certificate issuerRef resolves — {description}")
PY
}

render_valid_charts() {
  local output_dir=$1
  mkdir -p "$output_dir"
  helm template updatec deploy/charts/updatec -n updated-system \
    --set publicUrl=https://updates.example >"$output_dir/updatec.yaml"
  helm template updatec deploy/charts/updatec -n updated-system \
    --set publicUrl=https://updates.example \
    --set controller.replicaCount=3 \
    --set 'controller.persistence.accessModes={ReadWriteMany}' \
    --set controller.podDisruptionBudget.enabled=true \
    --set gateway.replicaCount=2 \
    --set gateway.podDisruptionBudget.enabled=true >>"$output_dir/updatec.yaml"
}

run_charts() {
  local rendered_dir="$WORK/rendered-charts"
  local updatec_manifests="$rendered_dir/updatec.yaml"
  local pinned_manifests="$WORK/pinned.yaml"
  local digest_manifests="$WORK/digest.yaml"
  local default_manifests="$WORK/default.yaml"
  local soak_manifests="$WORK/soak.yaml"
  local runtime_uid e2e_runtime_uid healthproxy_runtime_uid backend_runtime_uid

  local dockerfile
  for dockerfile in \
    crates/updatec/Dockerfile \
    crates/updatec/Dockerfile.e2e \
    crates/updated-healthproxy/Dockerfile; do
    grep -Fq \
      'COPY --chmod=0755 scripts/install-ubi-build-dependencies.sh /usr/local/bin/install-ubi-build-dependencies' \
      "$dockerfile" && \
      grep -Fq 'RUN /usr/local/bin/install-ubi-build-dependencies' "$dockerfile" || {
      echo "FAIL: $dockerfile bypasses the shared UBI build-dependency installer" >&2
      return 1
    }
  done

  runtime_uid="$(awk '$1 == "USER" {value = $2} END {print value}' crates/updatec/Dockerfile)"
  e2e_runtime_uid="$(awk '$1 == "USER" {value = $2} END {print value}' crates/updatec/Dockerfile.e2e)"
  healthproxy_runtime_uid="$(awk '$1 == "USER" {value = $2} END {print value}' crates/updated-healthproxy/Dockerfile)"
  backend_runtime_uid="$(grep -oE 'HEALTHPROXY_RUNTIME_UID: i64 = [0-9_]+' \
    crates/updatec/src/runtime/backend.rs | grep -oE '[0-9_]+$' | tr -d '_')"
  [[ "$runtime_uid" =~ ^[0-9]+$ && "$runtime_uid" == "$e2e_runtime_uid" && "$runtime_uid" == "$healthproxy_runtime_uid" && "$runtime_uid" == "$backend_runtime_uid" ]] || {
    echo "FAIL: updatec, E2E, healthproxy, and generated backend workloads do not share one numeric runtime UID" >&2
    return 1
  }

  section "Helm lint"
  helm lint deploy/charts/updatec --set publicUrl=https://updates.example
  helm lint lab/chaos/infrastructure/soak

  helm template updatec-soak lab/chaos/infrastructure/soak -n updated-system \
    >"$soak_manifests"
  python3 - "$soak_manifests" crates/updated-tuf/src/repo.rs "$runtime_uid" \
    crates/updatec-e2e/src/fixture.rs <<'PY'
import re, sys, yaml
documents = [doc for doc in yaml.safe_load_all(open(sys.argv[1], encoding="utf-8")) if doc]
source = open(sys.argv[2], encoding="utf-8").read()
runtime_uid = int(sys.argv[3])
fixture_source = open(sys.argv[4], encoding="utf-8").read()
body = re.search(r"pub const KEY_FILE_NAMES: \[&str; \d+\] = \[(.*?)\];", source, re.S)
assert body, "the canonical signing-key list is missing"
signing_keys = set(re.findall(r'"([^"]+)"', body.group(1)))

restricted = {
    "allowPrivilegeEscalation": False,
    "capabilities": {"drop": ["ALL"]},
    "readOnlyRootFilesystem": True,
    "runAsNonRoot": True,
}
workloads = []
for doc in documents:
    pod = None
    if doc["kind"] in ("Deployment", "StatefulSet"):
        pod = doc["spec"]["template"]["spec"]
    elif doc["kind"] == "Job":
        pod = doc["spec"]["template"]["spec"]
    if not pod:
        continue
    name = doc["metadata"]["name"]
    uid = 1000 if name in ("minio", "minio-initialize") else runtime_uid
    if name == "agent":
        assert "fsGroup" not in pod["securityContext"], pod["securityContext"]
    else:
        assert pod["securityContext"]["fsGroup"] == uid, name
        assert pod["securityContext"]["fsGroupChangePolicy"] == "OnRootMismatch", name
    for container in pod.get("containers", []) + pod.get("initContainers", []):
        if container["name"] == "prepare-private-state":
            continue
        expected = {**restricted, "runAsUser": uid, "runAsGroup": uid}
        assert container["securityContext"] == expected, (name, container["name"], container["securityContext"])
    workloads.append(name)
assert set(workloads) == {"agent", "minio", "minio-initialize", "release-server", "updatec-soak"}, workloads
campaign = next(doc for doc in documents if doc["kind"] == "Deployment" and doc["metadata"]["name"] == "updatec-soak")
assert campaign["spec"]["template"]["spec"]["terminationGracePeriodSeconds"] == 420

agents = next(doc for doc in documents if doc["kind"] == "StatefulSet" and doc["metadata"]["name"] == "agent")
pod = agents["spec"]["template"]["spec"]
runtime = next(container for container in pod["containers"] if container["name"] == "agent")
prepare = next(container for container in pod["initContainers"] if container["name"] == "prepare-private-state")
runtime_uid = runtime["securityContext"]["runAsUser"]
assert f"uid={runtime_uid}" in prepare["args"][0], prepare["args"]
assert 'chown -R "$uid:$uid" /var/lib/updated' in prepare["args"][0], prepare["args"]
assert "chmod 0600 /var/lib/updated/state/agent.key" in prepare["args"][0], prepare["args"]
assert "chmod 0400 /prepared-tls/ca.crt /prepared-tls/tls.crt /prepared-tls/tls.key" in prepare["args"][0], prepare["args"]
volumes = {volume["name"]: volume for volume in pod["volumes"]}
assert volumes["agent-tls-source"]["secret"]["secretName"] == "agent-tls", volumes
assert volumes["agent-tls"]["emptyDir"]["medium"] == "Memory", volumes
assert volumes["chaos-mount-workspace"]["emptyDir"]["sizeLimit"] == "16Mi", volumes
mounts = {mount["name"]: mount["mountPath"] for mount in runtime["volumeMounts"]}
assert mounts["chaos-mount-workspace"] == "/var/lib", mounts
assert mounts["state"] == "/var/lib/updated", mounts
assert runtime["livenessProbe"] == {
    "exec": {"command": ["/usr/bin/mountpoint", "-q", "/var/lib/updated"]},
    "periodSeconds": 5,
    "failureThreshold": 4,
}, runtime["livenessProbe"]

minio = next(doc for doc in documents if doc["kind"] == "StatefulSet" and doc["metadata"]["name"] == "minio")
minio_pod = minio["spec"]["template"]["spec"]
minio_server = next(container for container in minio_pod["containers"] if container["name"] == "minio")
assert any(env == {"name": "HOME", "value": "/tmp"} for env in minio_server["env"]), minio_server["env"]
assert any(mount == {"name": "minio-tmp", "mountPath": "/tmp"} for mount in minio_server["volumeMounts"])
initializer = next(doc for doc in documents if doc["kind"] == "Job" and doc["metadata"]["name"] == "minio-initialize")
assert "helm.sh/hook" not in initializer["metadata"].get("annotations", {}), initializer["metadata"]

role = next(doc for doc in documents if doc["kind"] == "Role" and doc["metadata"]["name"] == "updatec-soak")
owned = {
    tuple(rule["resources"]): tuple(rule.get("resourceNames", []))
    for rule in role["rules"]
    if rule["apiGroups"] == ["updated.dev"] and "resourceNames" in rule
}
assert owned == {
    ("updaterepositories",): ("default",),
    ("updategroups",): ("soak-a", "soak-b", "soak-c"),
    ("updategroupsets",): ("soak-fleet",),
}, owned
creates = [
    rule for rule in role["rules"]
    if rule["apiGroups"] == ["updated.dev"] and rule.get("verbs") == ["create"]
]
assert creates == [{
    "apiGroups": ["updated.dev"],
    "resources": ["updaterepositories", "updategroups", "updategroupsets"],
    "verbs": ["create"],
}], creates

policies = {doc["metadata"]["name"]: str(doc["spec"]) for doc in documents if doc["kind"] == "ValidatingAdmissionPolicy"}
signing = next(text for name, text in policies.items() if name.endswith("signing-secret"))
assert set(re.findall(r"'([^']+\.pk8)'", signing)) == signing_keys, (signing_keys, signing)
for boundary in [
    "app.kubernetes.io/part-of", "metadata.annotations.size() == 0",
    "metadata.finalizers.size() == 0", "metadata.ownerReferences.size() == 0",
]:
    assert boundary in signing, boundary
labels = next(text for name, text in policies.items() if name.endswith("agent-labels"))
for boundary in ["labels.size() == 2", "soak.updated.dev/cohort", "soak.updated.dev/node", "^agent-[0-9]+$"]:
    assert boundary in labels, boundary
control = next(text for name, text in policies.items() if name.endswith("control-boundary"))
for boundary in [
    "'operations': ['CREATE', 'UPDATE']", "tuf-signing-keys", "s3-credentials",
    "http://minio:9000", "https://minio-direct.updated-system.svc", "assignmentPrefix",
    "stateMaxShards", "repositoryRef", "selector", "dependsOn", "inputs",
    "maxUnavailable", "emergencyCorrection", "maxConcurrent", "maxRegressions",
    "onRegression", "stuckAfterSeconds", "metadata.annotations.size() == 0",
    "metadata.finalizers.size() == 0", "metadata.ownerReferences.size() == 0",
]:
    assert boundary in control, boundary
chaos = next(text for name, text in policies.items() if name.endswith("chaos-boundary"))
for boundary in [
    "'operations': ['CREATE', 'DELETE']", "request.operation == 'DELETE' ? oldObject : object",
    "^soak-round-[1-9][0-9]*$", "networkchaos", "iochaos", "podchaos", "partition",
    "pod-kill", "volumePath", "/var/lib/updated/*", "updated.dev/chaos-target",
    "metadata.annotations.size() == 0", "metadata.finalizers.size() == 0",
    "metadata.ownerReferences.size() == 0",
]:
    assert boundary in chaos, boundary

def rust_string(name):
    match = re.search(rf'const {name}: &str = "([^"]+)";', fixture_source)
    assert match, name
    return match.group(1)

def rust_number(name):
    match = re.search(rf'const {name}: (?:u8|u32|u64|usize) = ([0-9_]+);', fixture_source)
    assert match, name
    return int(match.group(1).replace("_", ""))

for name in [
    "REPOSITORY_NAME", "RELEASE_ENDPOINT", "RELEASE_PUBLIC_ENDPOINT", "RELEASE_BUCKET",
    "RELEASE_REGION", "SIGNING_SECRET", "STORAGE_SECRET", "ASSIGNMENT_PREFIX",
    "SOAK_FLEET_LABEL", "SOAK_FLEET_VALUE", "SOAK_COHORT_LABEL", "SOAK_GROUP_SET",
]:
    assert rust_string(name) in control, name
for name in ["SOAK_CHAOS_LABEL", "SOAK_CHAOS_VALUE", "SOAK_CHAOS_NAME_PREFIX"]:
    assert rust_string(name) in chaos, name
for name, field in {
    "STATE_MAX_SHARDS": "stateMaxShards",
    "SOAK_MAX_UNAVAILABLE": "maxUnavailable",
    "SOAK_MAX_CONCURRENT": "maxConcurrent",
    "SOAK_MAX_REGRESSIONS": "maxRegressions",
    "SOAK_STUCK_AFTER_SECONDS": "stuckAfterSeconds",
}.items():
    assert f"object.spec.{field} == {rust_number(name)}" in control, name
groups_body = re.search(r'const SOAK_GROUPS: \[&str; \d+\] = \[(.*?)\];', fixture_source, re.S)
assert groups_body, "SOAK_GROUPS"
fixture_groups = set(re.findall(r'"([^"]+)"', groups_body.group(1)))
policy_groups = re.search(r"object.metadata.name in \[([^]]+)\]", control)
assert policy_groups, control
assert set(re.findall(r"'([^']+)'", policy_groups.group(1))) == fixture_groups
print("ok: every lab workload shares one restricted context and every campaign write is bounded")
PY

  section "Helm safety guardrails"
  must_refuse_chart "a control plane with no publicUrl" \
    helm template updatec deploy/charts/updatec
  must_refuse_chart "an ingress that terminates TLS" \
    helm template updatec deploy/charts/updatec --set publicUrl=https://u.example \
      --set gateway.ingress.enabled=true --set gateway.ingress.host=u.example \
      --set gateway.ingress.passthrough=false
  # Both halves of the one-identity collapse: an unnamed bring-your-own pair (which used to fall
  # back to the namespace `default` account for BOTH workloads), and two names spelled the same.
  must_refuse_chart "bring-your-own ServiceAccounts with no names" \
    helm template updatec deploy/charts/updatec --set publicUrl=https://u.example \
      --set serviceAccount.create=false
  must_refuse_chart "one ServiceAccount name for both workloads" \
    helm template updatec deploy/charts/updatec --set publicUrl=https://u.example \
      --set serviceAccount.controllerName=updatec --set serviceAccount.gatewayName=updatec
  must_refuse_chart "a bootstrap issuer kind the chart does not create" \
    helm template updatec deploy/charts/updatec --set publicUrl=https://u.example \
      --set certManager.enabled=true --set certManager.bootstrapIssuer.kind=ClusterIssuer
  must_refuse_chart "a bootstrap certificate whose CN the gateway will not admit" \
    helm template updatec deploy/charts/updatec --set publicUrl=https://u.example \
      --set certManager.enabled=true --set certManager.agentCertificate.create=true \
      --set certManager.agentCertificate.commonName=wrong
  must_refuse_chart "requireDigest with no digest" \
    helm template updatec deploy/charts/updatec --set publicUrl=https://u.example \
      --set image.requireDigest=true
  must_refuse_chart "a malformed digest" \
    helm template updatec deploy/charts/updatec --set publicUrl=https://u.example \
      --set image.digest=sha256:deadbeef
  must_refuse_chart "a tag and a digest together" \
    helm template updatec deploy/charts/updatec --set publicUrl=https://u.example \
      --set image.tag=v1 \
      --set image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000
  must_refuse_chart "a healthproxy requiring a digest it was not given" \
    helm template updatec deploy/charts/updatec --set publicUrl=https://u.example \
      --set healthproxy.image.requireDigest=true
  must_refuse_chart "controller replicas on a ReadWriteOnce volume" \
    helm template updatec deploy/charts/updatec --set publicUrl=https://u.example \
      --set controller.replicaCount=3
  # 232 characters: one past what `updatec-admitted-<repository>` can spell inside the 248 bytes
  # the shard suffix leaves. The chart must refuse rather than hash the name down — a second
  # spelling of `bounded_child_name` here would drift from the controller's and surface as a
  # Forbidden on every durable admitted-state write instead of an error anyone can see.
  must_refuse_chart "a repository name too long to grant by exact ConfigMap name" \
    helm template updatec deploy/charts/updatec --set publicUrl=https://u.example \
      --set "repository=$(printf 'r%.0s' $(seq 232))"

  # `gateway.fleetReportMaxShards` is bounded by MAX_FLEET_REPORT_SHARDS, which is private to
  # crates/updated-contracts so no Rust caller can re-implement the range test. Helm cannot read a
  # Rust constant, so the chart carries a copy of the ceiling — and this is what stops the copy
  # from drifting: read the constant, then assert the chart accepts exactly it and refuses one
  # past it. Lower the constant and the chart fails here, not as a gateway crash-loop.
  # The gateway's ValidatingAdmissionPolicy is the LAST boundary on what may be written into a
  # node's identity, and it is CEL: it carries its own copy of the canonical-digest and P-256
  # pin grammars because it cannot call Rust. Both copies are exported from beside the Rust
  # predicates that own them, and each has a test proving the exported pattern and the predicate
  # accept the same spellings — so pinning the chart to the exported strings here closes the loop.
  # Drift either way is a real outage: a shape Rust accepts and the policy refuses fails enrolment
  # at the API server for keys the gateway believes are valid, and the reverse quietly widens the
  # boundary.
  section "Admission-policy grammars pinned to the contract"
  local sha_pattern key_pattern policy_manifest
  sha_pattern="$(grep -oE 'CANONICAL_SHA256_PATTERN: &str = "[^"]+"' \
    crates/foundation/src/digest.rs | sed -E 's/.*"([^"]+)".*/\1/')"
  key_pattern="$(grep -oE 'P256_POINT_HEX_PATTERN: &str = "[^"]+"' \
    crates/updated-contracts/src/key.rs | sed -E 's/.*"([^"]+)".*/\1/')"
  [[ -n "$sha_pattern" && -n "$key_pattern" ]] || {
    echo "FAIL: could not read the exported admission grammars from the Rust contracts" >&2
    return 1
  }
  policy_manifest="$(mktemp)"
  helm template updatec deploy/charts/updatec --set publicUrl=https://u.example \
    >"$policy_manifest"
  for pattern in "$sha_pattern" "$key_pattern"; do
    grep -qF "$pattern" "$policy_manifest" || {
      echo "FAIL: the rendered admission policy does not enforce $pattern, which the Rust contract exports" >&2
      rm -f "$policy_manifest"
      return 1
    }
  done
  rm -f "$policy_manifest"
  echo "ok: the admission policy spells the contract's digest and pin grammars"

  # The two shard-name boundaries in the write policies are CEL range regexes, and CEL cannot read
  # a Rust constant either. RBAC cannot resourceName-restrict CREATE — authorization runs before a
  # create request has a name — so these regexes ARE the object-level boundary on what the
  # controller may bring into existence. Pinned behaviourally rather than by string match: the
  # rendered pattern must admit the contract's last shard and refuse the one past it. The inventory
  # boundary was eight times wider than `BACKEND_INVENTORY_SHARDS` when this check was written,
  # permitting 56 object names the controller can never legitimately create.
  section "Shard-name boundaries pinned to the contract"
  local inventory_shards durable_shards boundary_manifest
  inventory_shards="$(grep -oE 'BACKEND_INVENTORY_SHARDS: usize = [0-9]+' \
    crates/updated-contracts/src/backend.rs | grep -oE '[0-9]+$')"
  durable_shards="$(grep -oE 'MAX_ADMITTED_STATE_SHARDS: usize = [0-9]+' \
    crates/updatec/src/runtime/mod.rs | grep -oE '[0-9]+$')"
  [[ -n "$inventory_shards" && -n "$durable_shards" ]] || {
    echo "FAIL: could not read the shard ceilings from the Rust contracts" >&2
    return 1
  }
  boundary_manifest="$(mktemp)"
  helm template updatec deploy/charts/updatec --set publicUrl=https://u.example \
    >"$boundary_manifest"
  python3 scripts/check-shard-boundaries.py \
    "$boundary_manifest" "$inventory_shards" "$durable_shards" || {
    rm -f "$boundary_manifest"
    return 1
  }
  rm -f "$boundary_manifest"

  section "Chart bounds pinned to the contract"
  local contract_shards
  contract_shards="$(grep -oE 'MAX_FLEET_REPORT_SHARDS: usize = [0-9]+' \
    crates/updated-contracts/src/telemetry.rs | grep -oE '[0-9]+$')"
  [[ -n "$contract_shards" ]] || {
    echo "FAIL: could not read MAX_FLEET_REPORT_SHARDS from crates/updated-contracts/src/telemetry.rs" >&2
    return 1
  }
  helm template updatec deploy/charts/updatec --set publicUrl=https://u.example \
    --set "gateway.fleetReportMaxShards=$contract_shards" >/dev/null || {
    echo "FAIL: the chart refuses $contract_shards fleet-report shards, which the contract accepts" >&2
    return 1
  }
  must_refuse_chart "a fleet report shard ceiling one past the contract's $contract_shards" \
    helm template updatec deploy/charts/updatec --set publicUrl=https://u.example \
      --set "gateway.fleetReportMaxShards=$((contract_shards + 1))"
  must_refuse_chart "a fleet report shard ceiling of zero" \
    helm template updatec deploy/charts/updatec --set publicUrl=https://u.example \
      --set gateway.fleetReportMaxShards=0
  grep -Fq "Valid range: 1..$contract_shards." deploy/charts/updatec/values.yaml || {
    echo "FAIL: values.yaml documents a fleetReportMaxShards range other than 1..$contract_shards" >&2
    return 1
  }
  grep -Fq "Range 1–$contract_shards;" deploy/charts/updatec/README.md || {
    echo "FAIL: the chart README documents a fleetReportMaxShards range other than 1–$contract_shards" >&2
    return 1
  }
  echo "ok: the chart's fleet-report shard ceiling matches the contract's $contract_shards"

  section "cert-manager issuer references"
  assert_issuer_refs_resolve "the chart issues the whole chain" \
    helm template updatec deploy/charts/updatec -n updated-system \
      --set publicUrl=https://updates.example --set certManager.enabled=true \
      --set certManager.agentCertificate.create=true
  assert_issuer_refs_resolve "the operator supplies the fleet CA Secret" \
    helm template updatec deploy/charts/updatec -n updated-system \
      --set publicUrl=https://updates.example --set certManager.enabled=true \
      --set certManager.fleetCA.create=false --set certManager.agentCertificate.create=true

  section "Rendered Kubernetes schemas and permissions"
  render_valid_charts "$rendered_dir"
  helm template updatec deploy/charts/updatec -n updated-system \
    --set publicUrl=https://updates.example >"$default_manifests"
  python3 - "$default_manifests" <<'PY'
import sys, yaml
documents = [doc for doc in yaml.safe_load_all(open(sys.argv[1], encoding="utf-8")) if doc]
locks = [doc["metadata"]["name"] for doc in documents if doc["kind"] == "Lease"]
assert len(locks) == 1, locks
gateway_policies = [
    doc for doc in documents
    if doc["kind"] == "ValidatingAdmissionPolicy"
    and [resource for rule in doc["spec"]["matchConstraints"]["resourceRules"] for resource in rule["resources"]] == ["updateagents"]
]
assert len(gateway_policies) == 1, gateway_policies
gateway_policy = gateway_policies[0]
policy_text = str(gateway_policy["spec"])
for required in ["reserved", "enrolled", "registrationSha256", "publicKey", "repositoryRef", "metadataPreserved", "params.spec.enrollment.mode", "open"]:
    assert required in policy_text, required
gateway = next(
    doc for doc in documents
    if doc["kind"] == "Deployment" and doc["metadata"]["name"].endswith("gateway")
)
gateway_pod = gateway["spec"]["template"]["spec"]
gateway_container = next(container for container in gateway_pod["containers"] if container["name"] == "updatec")
gateway_env = {entry["name"]: entry["value"] for entry in gateway_container["env"] if "value" in entry}
assert gateway_env["UPDATED_GATEWAY_CLIENT_CA"] == "/etc/client-ca/ca.crt", gateway_env
gateway_mounts = {mount["name"]: mount["mountPath"] for mount in gateway_container["volumeMounts"]}
assert gateway_mounts["gateway-tls"] == "/etc/gateway-tls", gateway_mounts
assert gateway_mounts["client-ca"] == "/etc/client-ca", gateway_mounts
gateway_volumes = {volume["name"]: volume for volume in gateway_pod["volumes"]}
assert gateway_volumes["client-ca"]["secret"] == {
    "secretName": "gateway-tls",
    "defaultMode": 0o440,
    "items": [{"key": "ca.crt", "path": "ca.crt"}],
}, gateway_volumes["client-ca"]
for doc in documents:
    if doc["kind"] != "Role" or not doc["metadata"]["name"].endswith("gateway"):
        continue
    agents = False
    lease = False
    for rule in doc["rules"]:
        assert "secrets" not in rule.get("resources", []), rule
        if "updateagents" in rule.get("resources", []):
            assert rule["verbs"] == ["get", "list", "create", "update"], rule
            agents = True
        if "leases" in rule.get("resources", []):
            assert rule.get("resourceNames") == locks, rule
            assert rule["verbs"] == ["get", "update"], rule
            lease = True
    assert agents and lease
    print("ok: default gateway has no Secret authority and enrollment uses one exact CAS Lease")
    break
else:
    raise AssertionError("the rendered release has no gateway Role")
PY
  helm template updatec deploy/charts/updatec -n updated-system \
    --set publicUrl=https://updates.example \
    --set controller.alerting.url=https://alerts.example \
    --set controller.alerting.tokenSecret=alert-token \
    --set podSecurityContext.fsGroup=123 \
    --set podSecurityContext.fsGroupChangePolicy=Always \
    --set podSecurityContext.seccompProfile.type=Unconfined \
    --set securityContext.runAsUser=123 \
    --set securityContext.runAsGroup=456 \
    --set securityContext.allowPrivilegeEscalation=true \
    --set securityContext.readOnlyRootFilesystem=false \
    --set 'gateway.secretResourceNames={updatedc-store}' >"$pinned_manifests"
  # The RBAC below grants the durable admitted-state ConfigMaps BY EXACT NAME, so the chart has to
  # spell out every shard the controller could ever write. That count is `MAX_ADMITTED_STATE_SHARDS`
  # in crates/updatec, and Helm cannot read a Rust constant — so read it here and drive the expected
  # list from it, exactly as the fleet-report ceiling above is pinned. Without this the constant, the
  # chart's `until 64`, and this check's own copy were three independent spellings of one rule:
  # raising the constant left the chart granting the old range and surfaced as a Forbidden on every
  # durable write, which is precisely what naming these ConfigMaps exhaustively was meant to avoid.
  local admitted_shards
  admitted_shards="$(grep -oE 'MAX_ADMITTED_STATE_SHARDS: usize = [0-9]+' \
    crates/updatec/src/runtime/mod.rs | grep -oE '[0-9]+$')"
  [[ -n "$admitted_shards" ]] || {
    echo "FAIL: could not read MAX_ADMITTED_STATE_SHARDS from crates/updatec/src/runtime/mod.rs" >&2
    return 1
  }
  python3 - "$pinned_manifests" "$admitted_shards" "$runtime_uid" <<'PY'
import sys, yaml
admitted_shards = int(sys.argv[2])
runtime_uid = int(sys.argv[3])
gateway_pinned = False
backend_controller = False
admitted_configmap_pinned = False
configmap_mutations = set()
configmap_boundary = False
controller_slice_denied = False
gateway_agent_boundary = False
gateway_agent_binding = False
role_binding_subjects = {}
credential_projections = 0
for doc in yaml.safe_load_all(open(sys.argv[1], encoding="utf-8")):
    if not doc:
      continue
    if doc["kind"] == "RoleBinding":
      role_binding_subjects[doc["metadata"]["name"]] = tuple(
          (subject["kind"], subject.get("namespace"), subject["name"])
          for subject in doc["subjects"]
      )
      continue
    if doc["kind"] == "ValidatingAdmissionPolicy":
      resources = [resource for rule in doc["spec"]["matchConstraints"]["resourceRules"] for resource in rule["resources"]]
      assert doc["spec"]["failurePolicy"] == "Fail"
      if resources == ["configmaps"]:
        expressions = "\n".join(variable["expression"] for variable in doc["spec"].get("variables", []))
        assert "-[ab]-" in expressions and ".size()" in expressions, doc
        configmap_boundary = True
      elif resources == ["endpointslices"]:
        assert doc["spec"]["validations"] == [{"expression": "false", "message": "updatec's controller may delegate EndpointSlice access but may not mutate traffic itself"}], doc
        controller_slice_denied = True
      elif resources == ["updateagents"]:
        text = str(doc["spec"])
        assert doc["spec"]["paramKind"] == {
            "apiVersion": "updated.dev/v1alpha1",
            "kind": "UpdateRepository",
        }, doc
        for required in ["reserved", "enrolled", "registrationSha256", "publicKey", "repositoryRef", "metadataPreserved", "params.spec.enrollment.mode", "open", "params.spec.enrollment.labels", "ownerReferences"]:
            assert required in text, (required, doc)
        gateway_agent_boundary = True
      else:
        raise AssertionError(resources)
      continue
    if doc["kind"] == "ValidatingAdmissionPolicyBinding":
      if doc["spec"]["policyName"].endswith("gateway-updateagents"):
        assert doc["spec"]["paramRef"] == {
            "name": "default",
            "namespace": "updated-system",
            "parameterNotFoundAction": "Deny",
        }, doc
        gateway_agent_binding = True
      continue
    if doc["kind"] == "Deployment":
      pod = doc["spec"]["template"]["spec"]
      containers = pod["containers"]
      assert len(containers) == 1, doc["metadata"]["name"]
      context = containers[0]["securityContext"]
      assert context == {
          "allowPrivilegeEscalation": False,
          "capabilities": {"drop": ["ALL"]},
          "readOnlyRootFilesystem": True,
          "runAsNonRoot": True,
          "runAsUser": runtime_uid,
          "runAsGroup": runtime_uid,
      }, context
      run_as = context["runAsUser"]
      assert pod["securityContext"] == {
          "fsGroup": run_as,
          "fsGroupChangePolicy": "OnRootMismatch",
          "seccompProfile": {"type": "RuntimeDefault"},
      }, pod["securityContext"]
      for volume in pod.get("volumes", []):
        if "secret" not in volume:
          continue
        # Every explicit Secret volume contains credential material. Its projection must be
        # readable by the workload's one group, never by every process in the container.
        assert volume["secret"].get("defaultMode") == 0o440, volume
        credential_projections += 1
      continue
    if doc["kind"] != "Role":
      continue
    if doc["metadata"]["name"].endswith("gateway"):
      for rule in doc["rules"]:
            if "secrets" in rule.get("resources", []):
                assert rule.get("resourceNames") == ["updatedc-store"], rule
                assert rule["verbs"] == ["get"], rule
                gateway_pinned = True
    if doc["metadata"]["name"].endswith("controller"):
      for rule in doc["rules"]:
        if "endpointslices" in rule.get("resources", []):
            # The controller creates per-backend Roles. Kubernetes' anti-escalation check
            # therefore requires it to hold every verb those Roles delegate, including the
            # unconstrained CREATE needed for a missing slice. The admission policy checked
            # above is the boundary that prevents the controller identity from exercising the
            # mutating verbs itself.
            assert rule["verbs"] == ["get", "create", "patch", "delete"], rule
            backend_controller = True
        if "configmaps" in rule.get("resources", []):
            if rule.get("resourceNames"):
                expected = ["updatec-admitted-default"] + [
                    f"updatec-admitted-default-{slot}-{index:02}"
                    for index in range(admitted_shards)
                    for slot in ("a", "b")
                ]
                assert rule["resourceNames"] == expected, rule
                assert rule["verbs"] == ["get", "update", "delete"], rule
                admitted_configmap_pinned = True
            else:
                configmap_mutations.update(rule["verbs"])
# Every RoleBinding in this release grants a DIFFERENT Role, so two of them sharing a subject
# means one workload silently holds another's permissions. The gateway is the only externally
# exposed listener and the controller reconciles the whole namespace: collapsing those two onto
# one identity is the specific outcome this asserts can never render.
assert len(role_binding_subjects) >= 2, role_binding_subjects
assert len(set(role_binding_subjects.values())) == len(role_binding_subjects), role_binding_subjects
assert gateway_pinned, "the gateway Role has no pinned secrets rule"
assert backend_controller, "the controller cannot delegate dynamic EndpointSlice access"
assert admitted_configmap_pinned, "durable ConfigMap reads are not resourceName-pinned"
assert configmap_mutations == {"create", "patch", "delete"}, configmap_mutations
assert configmap_boundary, "dynamic ConfigMap writes have no fail-closed admission boundary"
assert controller_slice_denied, "the controller can exercise its delegation-only EndpointSlice verb"
assert gateway_agent_boundary, "gateway UpdateAgent writes have no fail-closed field boundary"
assert gateway_agent_binding, "gateway UpdateAgent boundary is not pinned to its repository parameter"
assert credential_projections == 4, credential_projections
print("ok: separate identities, one-time volume ownership, owner-group-only credentials, and Secret, UpdateAgent, ConfigMap, and EndpointSlice authority explicitly bounded")
PY
  helm template updatec deploy/charts/updatec -n updated-system \
    --set publicUrl=https://updates.example \
    --set image.requireDigest=true \
    --set image.digest=sha256:0000000000000000000000000000000000000000000000000000000000000000 \
    >"$digest_manifests"
  grep -q 'image: ghcr.io/evan-hines-js/updatec@sha256:0\{64\}' "$digest_manifests" || {
    echo "FAIL: a digest-pinned render did not produce a repository@digest reference" >&2
    return 1
  }
  kubeconform -strict -summary -schema-location default "$updatec_manifests"
}

run_semgrep() {
  section "Semgrep static analysis"
  # Review the working tree, not just Git's index. This matters locally while a refactor's new
  # files are still untracked; `target` and the chaos lab's ignored `.state` directory contain
  # generated credentials and are never source. Keep `--no-git-ignore` so other ignored files do
  # not silently disappear from a local review.
  # The policy is checked in: remote auto-configuration is mutable, requires network access, and
  # can disclose repository metadata. Metrics stay off even if a local Semgrep default changes.
  semgrep scan --config .semgrep.yml --metrics=off --disable-version-check --error \
    --no-git-ignore --exclude target --exclude .git \
    --exclude lab/chaos/infrastructure/.state .
}

run_trivy() {
  local rendered_dir="$WORK/trivy-rendered-charts"
  section "Trivy filesystem scan"
  trivy fs --scanners vuln,secret,misconfig --severity HIGH,CRITICAL \
    --ignore-unfixed --exit-code 1 \
    --skip-dirs "$ROOT/.git" --skip-dirs "$ROOT/deploy/charts" \
    --skip-dirs "$ROOT/dist" --skip-dirs "$ROOT/target" .

  section "Trivy rendered Helm scan"
  render_valid_charts "$rendered_dir"
  cp deploy/charts/updatec/crds/updated.dev_crds.yaml "$rendered_dir/"
  trivy fs --scanners secret,misconfig --severity HIGH,CRITICAL \
    --ignorefile "$ROOT/.trivyignore.yaml" --exit-code 1 "$rendered_dir"
}

run_haproxy() {
  section "Linux real HAProxy binary reload"
  if [[ "$(uname -s)" != Linux ]]; then
    echo "SKIP: the real HAProxy lifecycle suite requires Linux"
    return
  fi
  ./scripts/linux-haproxy-e2e.sh
  section "Linux Jenkins snapshot and recovery ordering"
  bash ./scripts/linux-jenkins-recovery-test.sh
}

run_kind() {
  section "updatec Kind and MinIO E2E"
  ./scripts/kind-updatec-e2e.sh --fuzz-rounds "${UPDATEC_FUZZ_ROUNDS:-1}"
}

run_fleet() {
  section "updatec fleet lifecycle E2E"
  cargo run -p updatec-e2e
}

preflight "$SUITE"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/updatedc-ci.XXXXXX")"
cleanup() {
  local status=$?
  trap - EXIT
  if [[ -n "$BACKGROUND_PID" ]]; then
    kill "$BACKGROUND_PID" >/dev/null 2>&1 || true
    wait "$BACKGROUND_PID" >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

case "$SUITE" in
  rust) run_rust ;;
  coverage) run_coverage ;;
  charts) run_charts ;;
  semgrep) run_semgrep ;;
  trivy) run_trivy ;;
  haproxy) run_haproxy ;;
  kind) run_kind ;;
  fleet) run_fleet ;;
  all)
    run_semgrep
    run_trivy
    run_rust
    run_coverage
    run_charts
    run_haproxy
    run_kind
    run_fleet
    ;;
esac

printf '\nPASS: updatedc CI suite %s\n' "$SUITE"
