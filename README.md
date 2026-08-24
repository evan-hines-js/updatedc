# updatedc — signed, transactional configuration management for fleets of machines

[![CI](https://github.com/evan-hines-js/updatedc/actions/workflows/ci.yml/badge.svg)](https://github.com/evan-hines-js/updatedc/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)

<p align="center">
  <img src="assets/fleet-cube.svg" width="700"
       alt="updatedc: the updatec control plane distributes signed releases to a fleet of updated-agent nodes." />
</p>

**updatedc** is a pull-based configuration-management and software-delivery system for arbitrary
machines. You publish a directory of files — configuration, packages, certificates, scripts,
binaries, assets, or a whole application tree — together with one executable that converges the
host onto that desired state. A fleet pulls it, verifies every byte against signed metadata,
applies it transactionally, gates the result on health, and rolls back to the exact predecessor
when health does not arrive. Publishing a second bundle of the same shape is an update; wrapping an
existing installer or operations script makes it a reconciler.

The executable is the whole learning curve, and it is a Bash script, a PowerShell script, or any
other program. It answers four operations — `apply`, `healthcheck`, `rollback`, `inspect` — in
whatever terms the environment already uses: `systemctl restart`, `sc.exe`, a container runtime, a
config reload, a package manager, a firmware tool, or an existing installer. Everything that must
always happen belongs to the agent: delivery, signature and digest verification, single-writer
locking, bounded retries and deadlines, process containment, durable transactions and crash
recovery, health gating, rollback, reboot orchestration, rejection-by-hash so proven-bad bytes are
never retried, continuous desired-state convergence, drift measurement, and signed reconciliation
reporting.

The system is split into deliberately narrow components:

- **`updated-agent`** runs on Linux, macOS, and Windows. It authenticates bundles through TUF,
  materializes immutable content-addressed releases, drives the transaction, survives interruption
  at every durable boundary, and reports signed health and output evidence.
- **`updated-launcher`** supervises only the agent. It readiness-gates agent self-updates and
  reverts a bad candidate without owning or disturbing the deployed workload.
- **`updatec`** is the reference Kubernetes control plane and mTLS gateway. It resolves fleet
  policy, signs and publishes per-node assignments, enrolls nodes, brokers bounded object
  capabilities, accepts signed reports, and reconciles rollout state.
- **`updated-healthproxy`** turns the control plane's pinned inventory and signed node health into
  EndpointSlice or HAProxy membership; it is not in the application data path.
- **`updatectl`** is the operator CLI for key management, publication, deployment, and reconciler
  conformance checks.

The control plane can never connect to a node. Everything flows through signed artifacts in shared
storage: `updatec` publishes what each group *should* run, and each `updated` agent pulls,
verifies, activates, and reports back. Compromising the distribution path cannot forge a release,
and a node that cannot reach the repository keeps running the last verified bundle.

## What a deployment is

A deployment names two immutable, signed, manifested bundles:

- the **payload** — any directory tree, published as a canonical archive with a strict per-file
  manifest, plus a declared entrypoint. The publisher also accepts a lone executable and wraps it
  into that shape.
- the **node reconciler** — one executable the agent invokes, and the only thing in the system that
  touches a workload process. Starting, stopping, draining, and restarting whatever the release
  runs is its domain behavior, typically by driving the operator's own init system.

The agent supplies delivery, verification of bytes, durable ordering, retries, deadlines,
containment, cancellation, rollback journaling, scheduling, and telemetry. The reconciler supplies
every application-specific desired-state decision. The installed system service has machine
authority so a reconciler can manage users, packages, services, mounts, networking, and boot state;
signed provider artifacts are the authorization boundary, and a reconciler may drop privileges for
the workload it starts. Hooks are invoked with argv only — never shell text — under a
cleared environment, a null stdin, and a contained process tree the agent reaps when the hook
returns. Assigned configuration, including secrets, reaches hooks only as ordinary files in the
fresh private `--input-dir`; it never enters argv, the environment, manifests, telemetry, or logs.

`healthcheck` is the one readiness gate. It makes a single observation and exits zero only when the
observed release is acceptable; the agent retries it to the signed success threshold within the
signed grace window, and runs it on the signed cadence for steady state. At every release-check
cycle the agent also re-runs the installed release's idempotent `apply`, even when no new bundle is
available, then requires the same bounded readiness gate. That platform-owned loop repairs drift;
the script only has to describe how to converge its domain correctly. `inspect` is the bounded
steady-state measurement: it runs after each deploy or rollback once the periodic `healthcheck`
reports healthy, then hourly with stable per-node ±10% jitter — agent policy rather than deployment
configuration, so expensive collection cannot drift into every health check. On exit zero the agent
SHA-256 hashes the exact non-empty stdout bytes, without trimming or decoding them, and places that
digest plus the signed reconciler artifact digest in the node's DSSE report. Stdout is fingerprint
data; diagnostics belong on stderr. Empty output, non-zero exit, cancellation, exceeding the
five-minute agent ceiling, or output beyond 64 KiB omits the fingerprint rather than attesting
incomplete state.

Every invocation carries `--attempt-id`: a transaction's own token when it gates that transaction's
candidate, or one of the reserved `boot`/`converge`/`periodic`/`fingerprint` identities for an operation
belonging to no transaction. A transaction's compensating direction carries that token with `r`
appended. Because intent is journaled before every invocation, every operation is invoked *at least
once* and must tolerate replay.

Successful `apply` and `rollback` operations publish a small structured result declaring whether
state changed, whether the same attempt should be retried, and whether the host must reboot. The
agent validates and durably records that result, owns the retry ceiling and delay, performs reboot
through a fixed OS command, and includes the latest reconciliation evidence in the node's signed
report. Health after a requested reboot is judged only after the next boot, with the predecessor
retained until confirmation.

The argv contract, the output-manifest document, and a copyable Bash template are in the
[node reconciler protocol](docs/node-reconciler-protocol.md). Before publishing, run the
conformance harness against the hook:

```sh
updatectl reconciler-check ./reconciler
```

It builds a scratch install root, drives the hook through the same argv grammar the agent emits,
and replays every operation the way crash recovery does — checking structured results, replay
tolerance, observation purity, fingerprint stability, output-snapshot bounds, and the refusals for an unknown operation
and an unimplemented protocol. It needs no repository, keys, or Kubernetes access.

## Architecture

Every node runs two small processes; workloads belong to the releases themselves, and the control
plane lives outside the node entirely.

```text
                    updatec (Kubernetes controller + mTLS gateway)
                      │  signs & publishes desired deployments per group
                      │  manages updated-healthproxy; never connects into a node
        ┌─────────────┴───────── signed TUF metadata + bundles ──────────────┐
        ▼  (object storage / CDN)                                            ▲
  per node:                                                       signed health reports
    outer lifecycle owner (systemd, launchd, Windows SCM)
      └── updated-launcher (which agent binary runs; readiness-gated pointer flips)
            └── updated-agent (TUF, selection, transactions, health, rollback)
                  └── invokes the release's own reconciler hooks
                        └── workload processes (owned by the hooks, never the agent)
```

The agent never launches, holds, or stops a workload process, so an agent restart, crash, or
self-update cannot disturb one. A workload the reconciler starts must be detached from the
invocation that started it; it then belongs to the release rather than to the agent attempt. The
launcher owns only which agent binary runs: a new agent proves readiness before its pointer is
committed, and a bad one is reverted and rejected by content hash.

Activation follows one durable path:

```text
authenticate the archive through TUF
  → hand the verified filepath to the provider (the default provider extracts and
    verifies the manifested bundle into an immutable release)
  → write the transaction journal
  → atomically switch active-release
  → the release's reconciler `apply` brings the candidate into service
  → honor a requested host reboot, otherwise require health immediately
  → after reboot, reapply and require health before confirmation
  → commit, or reactivate the predecessor and reject the candidate
```

## Fleet management with `updatec`

`updatec` maps nodes' control-plane labels to signed, opaque bundle references published through
TUF; agents never learn *why* their assignment changed. Seven custom resources (`updated.dev`)
describe a fleet:

| Resource | Role |
| --- | --- |
| `UpdateRepository` | The object-store/CDN destination, signing keys, and enrollment policy for one fleet. |
| `UpdateAgent` | One enrolled or manually provisioned node, including identity, labels, assignment, and observed status. |
| `UpdateGroup` | A set of nodes (by label selector) and the exact deployment they should run. |
| `UpdateGroupSet` | A throttle + schedule spanning several groups: `maxConcurrent`, rollout windows, and dated maintenance calendars. |
| `UpdateBackend` | A label-selected, health-driven EndpointSlice or HAProxy projection with operator-owned runtime and RBAC. |
| `UpdateAdmissionPolicy` | A repository-scoped external admission gate that can allow or block release movement. |
| `UpdateSubscription` | At-least-once webhook delivery of repository publication generations with durable cursors. |

Publication is a single consistent generation. The operator resolves every group's selector against
the enrolled agents, builds one plan, signs it, and uploads it with `timestamp.json` last — the TUF
commit point — so a CDN can lag but never mix generations. A single malformed resource is
quarantined (its own status fails) rather than aborting the whole repository.

**Enrollment** has one path: mutual-TLS `POST /enroll` on the gateway data listener. Every node
receives the same fleet enrollment certificate and a unique configured name, generates its durable
private key locally, and sends only a CSR. The control plane ignores the CSR subject, sets the
certificate identity from that validated name, pins the public key on the `UpdateAgent`, and
returns the per-node certificate plus the signed enrollment bundle. The shared credential is used
only to enroll; all routing, repository, secrets, and telemetry requests use the minted per-node
identity.

**Throttled rollouts.** An `UpdateGroupSet` never advances more than `maxConcurrent` members at
once (default `members − 1`), holding the rest until the in-flight ones settle. Settlement is
proven by the node itself: each agent writes a small signed `NodeReport` to shared storage stating
the exact assignment it acted on, the application archive and provider set it is *actually*
running, its latest platform-owned reconciliation record, and whether that running release is
healthy. The control plane reads those back — it never probes the app — and settles a node only
when all desired identities match and no rejection stands. Health remains independent: a restored
predecessor can rejoin service while its rejected assignment remains visibly unconverged. A forged,
missing, stale, or mismatched report fails closed and keeps the slot. Rollout windows and dated
calendars gate *when* a set may admit new rollouts; members already rolling always finish.

**Health-driven load balancing** (`UpdateBackend`). The same signed `NodeReport`s drive backend
membership. The operator derives a pinned inventory from matching `UpdateAgent`s and owns an
`updated-healthproxy` workload for that projection. The proxy programs either a Kubernetes
EndpointSlice (kube-proxy forwards; it adds no data-path hop of its own) or HAProxy runtime members.
A node leaves rotation when its report becomes unhealthy or stale and rejoins when it recovers.
Only a fresh, healthy, correctly attributed report keeps a backend in service. Adding or removing
agent labels changes membership; deleting the CR drains members before generated RBAC is removed.

Control-plane authors targeting a different orchestrator should start with the normative
[JSON Schemas](schemas) — the wire contract integrators write against. The control plane and its
operator-owned backend workloads install from the single [`updatec` Helm chart](deploy/charts/updatec); see the
[Kubernetes install guide](docs/kubernetes-install.md). Nodes are bootstrapped by a package,
`install.sh`, or Ansible — see the [agent install guide](docs/agent-install.md).

## Guarantees

- A bundle cannot execute until TUF authenticates its metadata, platform, length, and digest, and
  every extracted file matches its strict manifest.
- Activation changes one atomic `active-release` record; immutable predecessor and candidate
  directories are never rewritten in place.
- Startup reconciles interrupted transactions before selection or launch.
- Failed activation or health reactivates the predecessor and rejects the candidate archive.
- Reconciler-requested retries and host reboots are bounded, journaled, and executed by the agent.
- Every accepted state-changing reconciliation is durably recorded and signed into node telemetry.
- A post-commit crash inside the confirmation window also reverts the release.
- Agent crashes and agent self-update do not disturb the reconciler-owned workload.
- An unavailable repository does not prevent a verified installed bundle from starting.
- A throttled rollout completes only on the nodes' own signed health reports; a forged, missing, or
  stale report fails closed rather than releasing a slot or a load-balancer backend.
- Unknown configuration and durable-state fields are rejected rather than ignored or migrated
  implicitly.

Trust is anchored by [TUF](https://theupdateframework.io/) through the `tough` crate:
pinned-root rotation, threshold roles, expiry/freeze resistance, metadata rollback protection, and
target hash/length verification are not reimplemented here.

## Node configuration and enrollment

A node's entire local configuration is one `config.toml`, at one canonical path —
`/etc/updated/config.toml` (`C:\Program Files\updated\config.toml` on Windows). It carries the
gateway URL, the fleet CA, the shared fleet enrollment credential, and the node's unique configured
name:

```toml
[enrollment]
url = "https://updates.example.com"
ca  = "/etc/updated/fleet-ca.crt"
name = "node-001"

[enrollment.bootstrap]
client_cert = "/etc/updated/enrollment/tls.crt"
client_key  = "/etc/updated/enrollment/tls.key"
```

Enrollment returns the pinned routing root plus the complete TUF-signed runtime and repository
configuration. An installer places the launcher and the initial agent, provisions permissions, and
registers the platform lifecycle owner; otherwise the first agent enrolls and cold-installs online.
For a network-free first start against a remote gateway, that installer must preplace both
`enrollment.json` and the already-minted `agent.crt` / `agent.key`, and may preplace a verified
bundle; a bundle alone still requires `/enroll` to establish the per-node identity. Loose
preinstalled files are never trusted — every artifact is admitted only through signature and digest
verification.

For an offline-provisioned agent (`identity.kind: manual`), the operator generates the node key
first and places its canonical public half in the `UpdateAgent`. The node never calls `/enroll` and
never receives the shared bootstrap private key; the operator copies both the signed enrollment
object and a fleet-CA-signed leaf for that exact key to the machine. Once running, manual and online
nodes use the same key-pinned authorization, certificate renewal, direct S3 capabilities, and
end-to-end signed telemetry. Only the bootstrap delivery path differs. A reserved identity instead
allows any holder of the shared bootstrap certificate to claim that pre-approved name first; it is
inventory approval, not per-node bootstrap authority.

The controller publishes every node's small, immutable, content-addressed enrollment bootstrap in
the repository's private S3 prefix and records its repository-relative key in
`UpdateAgent.status.enrollmentObjectKey`. Live enrollment receives only a short-lived exact-object
capability and the expected SHA-256 over mTLS, then downloads and verifies those bytes anonymously
from S3. An offline provisioning tool reads the same object with operator S3 credentials and copies
it to the machine as `enrollment.json`; Kubernetes Secrets and gateway response bodies are never a
second bootstrap transport. The object changes only when its actual inputs change (desired
configuration, pinned root, or public repository location), not during routine TUF timestamp
renewal.

The same signed deployment accepts HTTPS release origins, `file:` URLs, or absolute local
repository directories, so an operator can repair a deployment fully offline without permitting a
plaintext network transport. Raw edits inside an immutable installed release remain untrusted and
are rejected. See [packaging/etc/config.toml](packaging/etc/config.toml).

Run the launcher — not the agent — under the chosen lifecycle owner:

```sh
target/release/updated-launcher \
  --state-dir /var/lib/example-app/launcher-state \
  --agent /usr/lib/example-app/updated-agent \
  --ready-timeout 60 \
  --confirm-timeout 30 \
  --stop-grace 10
```

The launcher manages only which agent binary runs, and touches no workload. The config is not named
on the command line: it reads the canonical path above. `--config` overrides it for a deployment
that deliberately keeps the file elsewhere.

Platform templates (systemd, launchd, Windows service) live under [deploy/](deploy).

## Durable layout

```text
install_root/
  active-release
  versions/<version-manifest-id>/
    manifest.json
    bin/application
    config/...
  staging/
  work/<version-manifest-id>/
  providers/
    versions/<version-manifest-id>/
    staging/
    work/<version-manifest-id>/
    state/<product>/          # the reconciler's --state-dir, preserved across replays and boots
    outputs/<archive-id>.json # internal snapshot of the last successful output directory
  state/
    installed.json
    transaction.json
    rejected
    tuf/
```

`work/<version-manifest-id>` is the release's writable working directory, and
`providers/work/<version-manifest-id>` is the equivalent for a reconciler bundle. Each is a
*sibling* of the matching `versions/` tree and deliberately not the tree itself: `versions/<id>` is
content-addressed and re-hashed by release verification on every check tick, so a single log,
lockfile or cache an ordinary program writes into its own `cwd` would make the agent condemn a
perfectly good release and re-download it forever. So that a program still finds its own bundled
configuration, templates and assets where it expects them, the workspace is seeded on resolve with
a private copy of every file the release manifest declares — a copy, not a link, so a program
rewriting one of those files changes only its own workspace and never the content-addressed tree. A
workspace is created on resolve and reaped once its release directory has stayed gone across
collection passes, so it never outlives what it belongs to and scratch survives restarts and
rollbacks onto a release the node has run before.

The launcher has a separate state root containing `desired-agent`, lifecycle markers, and
content-addressed agent candidates.

## Rejected releases and break glass

A release that fails activation or health is rejected by repository lineage and artifact digest.
That rejection does not expire: repeatedly launching unchanged, proven-bad bytes would turn a safe
rollback into an availability loop. The normal fix is to publish a new release containing corrected
bytes; its new digest is eligible without clearing anything.

To deliberately retry the exact rejected bytes, copy its complete key from
`<install-root>/state/rejected` into `<install-root>/state/rejected.allow`, one key per line, and
restart the runtime. This local file is an intentionally inconvenient break-glass mechanism:
malformed or partial keys fail startup closed, overrides are read only at startup, and the file
should be removed after the controlled retry. Application keys are
`repository-lineage-sha256:artifact-sha256`; agent keys are a single artifact SHA-256.

## Try it

Run every CI check supported by the current host through the same entrypoint GitHub Actions uses:

```sh
./scripts/ci.sh
```

To test the exact current working tree on this Mac and the Linux test machine concurrently, use:

```sh
./scripts/ci-mac-linux.sh
```

The coordinator rsyncs source and untracked working-tree changes, but never `.git`, `target`,
`dist`, or ignored files. It preserves the remote `target` cache, locks the dedicated mirror
against concurrent runs, prefixes both output streams, and fails if either host fails. Its defaults
are `root@10.0.0.206` and `/var/tmp/updatedc-ci`; `UPDATEDC_CI_LINUX_HOST` and
`UPDATEDC_CI_LINUX_DIR` override them.

For a focused rerun, both entrypoints accept the same suite name:

```sh
./scripts/ci.sh rust
./scripts/ci-mac-linux.sh charts
```

Available suites are `rust`, `charts`, `semgrep`, `trivy`, `haproxy`, `kind`, and `fleet`.
The default `all` suite fails during preflight when a supported check is missing a dependency;
it never silently reduces coverage. The Kind suites require Docker, Kind, kubectl, Helm,
OpenSSL, and GNU `sha256sum`.

The E2E harness creates a real signed repository and disposable node installations under
`target/e2e-work/`. It covers deploy and rollback, a tampered trust root, offline launch, rejection
persistence, transaction-boundary crashes, locking, agent restart, agent self-update, assigned
secrets, and the reconciler-hook lifecycle — including a Jenkins-shaped enterprise upgrade whose
`apply` backs up state and migrates it, whose `healthcheck` gates the result, and which rolls back
on failure. Its signed chaotic-application fixture separately proves fail-closed behavior for a
workload that exits before it binds, a `healthcheck` that never returns a healthy verdict, a
`healthcheck` held past its deadline, a verdict that flaps between healthy and unhealthy, and one
that degrades only after first reporting healthy.

CI additionally runs:

- the E2E system on Linux, Intel/ARM macOS, and Windows;
- the full Kind operator E2E (`updatec` publishing across groups, enrollment, throttled rollout, and
  rollback);
- the Kind fleet E2E (`./scripts/ci.sh fleet`): a 32-node fleet in eight sets, a Jenkins tier, an
  out-of-cluster slice fronted by the real `updated-healthproxy`, and an `updated`-managed HAProxy
  pair — asserting the ordered red-to-green lifecycle transaction, per-set isolation,
  reconciler-programmed endpoints, a zero-downtime HAProxy upgrade, and a seeded chaos generation
  in which half the cohorts roll back to their exact predecessors while the other half advance,
  before every cohort converges onto one version;
- native Windows Service Control Manager lifecycle testing;
- concurrent macOS publication fuzzing; and
- real HAProxy master-worker binary upgrades on Linux.

## Development publisher

The `server` crate creates real signed TUF repositories for development. Routing and releases are
separate trust domains: routing is private behind the mTLS capability gateway, while release bytes
are fetched directly from an HTTPS object origin. Production keeps the same boundary with private
S3 routing objects, short-lived signed reads, and direct release downloads.

```sh
cargo build --release -p server -p launcher -p agent

target/release/server init --repo ./release-repo --keys ./release-keys
target/release/server init --repo ./routing-repo --keys ./routing-keys
target/release/server gen-certs --dir ./certs --san 127.0.0.1 --san localhost

target/release/server publish-app --repo ./release-repo --keys ./release-keys \
  --product app --channel stable --version 1.0.0 \
  --entrypoint bin/app \
  --bundle linux-x86_64=./release-linux-x86_64 \
  --bundle macos-aarch64=./release-macos-aarch64

target/release/server serve-object --repo ./release-repo --addr 127.0.0.1:8081 \
  --cert ./certs/server.crt --key ./certs/server.key
target/release/server serve-capability --repo ./routing-repo --addr 127.0.0.1:8080 \
  --public-url https://127.0.0.1:8080 \
  --cert ./certs/server.crt --key ./certs/server.key --ca ./certs/ca.crt
```

Publish immutable payload and reconciler artifacts first, then a provider set, and finally the
desired deployment assignment. Every reference includes its exact TUF target path and SHA-256, so
CDN lag can delay a deployment but cannot mix generations:

```sh
target/release/server publish-assignment --repo ./routing-repo --keys ./routing-keys \
  --release-root ./release-repo/metadata/root.json \
  --name assignments/agents/agent-123.json \
  --deployment deploy-42 \
  --metadata-url https://cdn.example.com/groups/canary/metadata/ \
  --targets-url https://cdn.example.com/groups/canary/targets/ \
  --application-path products/app/stable/2.0.0/linux-x86_64/app \
  --application-sha256 '<64 hex characters>' \
  --provider-set-path provider-sets/web-7.json \
  --provider-set-sha256 '<64 hex characters>' \
  --runtime ./signed-runtime.json
```

In a real fleet, `updatec` performs this publication for every group automatically; the CLI is for
development and for control planes built on other orchestrators.

## Scope and limitations

- The launcher is installer-owned and updated out of band; trust roots arrive inside the signed
  enrollment artifact.
- Local state is not hardware-backed monotonic storage; a local administrator is inside the host
  trust boundary and can reseed an installation.
- Node service templates run the agent with machine authority so signed reconcilers can manage the
  whole host. A reconciler should launch an untrusted workload under a separate account or sandbox.
- Activation requires a cooperative lifecycle the reconciler can drive (a master/worker reload, a
  systemd unit, an external launcher). Windows uses stop/activate/start.
- The included publisher and HTTP server are development components, not production signing or
  distribution infrastructure.
- Production desktop deployment still requires platform packaging, macOS signing and notarization,
  Windows Authenticode as appropriate, shortcuts/protocol integration, and a product-specific
  shutdown/readiness contract.

## Documentation

- [JSON Schemas](schemas) — the normative wire contract
- [Node reconciler protocol](docs/node-reconciler-protocol.md) — the argv, structured-result, and output-snapshot
  contract a release's own reconciler is written against
- [Package-runner design](docs/package-runner-design.md) — why the agent owns no workload process
- [Kubernetes install guide](docs/kubernetes-install.md) — the Helm chart, CRDs, and Secrets
- [Agent install guide](docs/agent-install.md) — packages, `install.sh`, Ansible, and the
  bootstrap-then-self-update boundary
- [Reference node config](packaging/etc/config.toml) — the file the package installs
- Design notes for the shipped controls: [observability](docs/observability-design.md),
  [regression response](docs/regression-response-design.md),
  [alerting](docs/alerting-design.md),
  [node controls](docs/node-controls-design.md),
- Node decommission: delete the node's `UpdateAgent` object. There is no tombstone artifact, and
  revocation has two explicit bounds. Enrollment, renewal, and bundle authorization stop on their
  next live membership check. Input/output/report capabilities may be minted from a successful
  authorization memo for up to 30 seconds, and an already minted exact-object capability remains
  usable for at most another 60 seconds. Repository metadata and release-target reads are still
  authorized by the mTLS leaf itself and remain readable until that leaf expires; assignment
  removal is published on the next controller generation. Treat repository bytes reachable by a
  compromised leaf as disclosed until certificate expiry.

## License

GNU Affero General Public License v3.0 only (`AGPL-3.0-only`). See [LICENSE](LICENSE).
