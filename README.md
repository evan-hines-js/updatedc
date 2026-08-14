# updatedc — a signed, transactional deployment channel for fleets of machines

[![CI](https://github.com/evan-hines-js/updatedc/actions/workflows/ci.yml/badge.svg)](https://github.com/evan-hines-js/updatedc/actions/workflows/ci.yml)
[![License: PolyForm Small Business 1.0.0](https://img.shields.io/badge/License-PolyForm%20Small%20Business%201.0.0-blue.svg)](LICENSE)

<p align="center">
  <img src="assets/fleet-cube.svg" width="700"
       alt="updatedc: the updatec control plane distributes signed releases to a fleet of updated node agents." />
</p>

**updatedc** delivers arbitrary content to arbitrary machines under one signed, transactional
contract. You publish a directory of files — binaries, configuration, certificates, scripts,
assets, a whole application tree — together with one executable that knows how to put it into
service. A fleet of machines pulls it, verifies every byte against signed metadata, activates it
transactionally, gates the result on health, and rolls back to the exact predecessor when health
does not arrive. Publishing a second bundle of the same shape is an update; the mechanism does not
distinguish the two.

The executable is the whole learning curve, and it is a Bash script, a PowerShell script, or any
other program. It answers four operations — `apply`, `healthcheck`, `rollback`, `inspect` — in
whatever terms the environment already uses: `systemctl restart`, `sc.exe`, a container runtime, a
config reload, a firmware tool, an existing installer. Everything hard around it belongs to the
agent: delivery, signature and digest verification, durable transactions, health gating, rollback,
rejection-by-hash so proven-bad bytes are never retried, and signed fleet reporting.

Two cooperating halves:

- **`updated`** — the per-node agent, on Linux, macOS, and Windows. It authenticates bundles
  through TUF, materializes them as immutable content-addressed releases, drives the transaction,
  survives interruption at every durable boundary, and can replace its own binary without
  disturbing the workload.
- **`updatec`** — the reference Kubernetes control plane. It groups nodes into fleets, publishes
  each group's desired deployment as signed TUF metadata to object storage or a CDN, throttles how
  fast a change ripples through a group, gates completion on the nodes' own signed health reports,
  and drives load-balancer membership from that same health.

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
every application-specific decision. Hooks are invoked with argv only — never shell text — under a
cleared environment, a null stdin, and a contained process tree the agent reaps when the hook
returns. Assigned secret values reach the hooks through that environment and never touch the
agent's disk, manifests, or logs.

`healthcheck` is the one readiness gate. It makes a single observation and exits zero only when the
observed release is acceptable; the agent retries it to the signed success threshold within the
signed grace window, and runs it on the signed cadence for steady state. `inspect` is the bounded
steady-state measurement: it runs after each deploy or rollback once the periodic `healthcheck`
reports healthy, then hourly with stable per-node ±10% jitter — agent policy rather than deployment
configuration, so expensive collection cannot drift into every health check. On exit zero the agent
SHA-256 hashes the exact non-empty stdout bytes, without trimming or decoding them, and places that
digest plus the signed reconciler artifact digest in the node's DSSE report. Stdout is fingerprint
data; diagnostics belong on stderr. Empty output, non-zero exit, cancellation, exceeding the
five-minute agent ceiling, or output beyond 64 KiB omits the fingerprint rather than attesting
incomplete state.

Every invocation carries `--attempt-id`: a transaction's own token when it gates that transaction's
candidate, or one of the reserved `boot`/`periodic`/`fingerprint` identities for an operation
belonging to no transaction. A transaction's compensating direction carries that token with `r`
appended. Because intent is journaled before every invocation, every operation is invoked *at least
once* and must tolerate replay.

The argv contract, the output-manifest document, and a copyable Bash template are in the
[node reconciler protocol](docs/node-reconciler-protocol.md). Before publishing, run the
conformance harness against the hook:

```sh
updatectl reconciler-check ./reconciler
```

It builds a scratch install root, drives the hook through the same argv grammar the agent emits,
and replays every operation the way crash recovery does — checking replay tolerance, observation
purity, fingerprint stability, output-manifest bounds, and the refusals for an unknown operation
and an unimplemented protocol. It needs no repository, keys, or Kubernetes access.

## Architecture

Every node runs two small processes; workloads belong to the releases themselves, and the control
plane lives outside the node entirely.

```text
                    updatec (Kubernetes operator + gateway + healthproxy)
                      │  signs & publishes desired deployments per group
                      │  never connects into a node
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
  → require health
  → commit, or reactivate and reject the predecessor
```

## Fleet management with `updatec`

`updatec` maps nodes' control-plane labels to signed, opaque bundle references published through
TUF; agents never learn *why* their assignment changed. Four custom resources (`updated.dev`)
describe a fleet:

| Resource | Role |
| --- | --- |
| `UpdateRepository` | The object-store/CDN destination, signing keys, and enrollment policy for one fleet. |
| `UpdateGroup` | A set of nodes (by label selector) and the exact deployment they should run. |
| `UpdateGroupSet` | A throttle + schedule spanning several groups: `maxConcurrent`, rollout windows, and dated maintenance calendars. |
| `UpdateAgent` | One enrolled node: its identity, resolved group, assignment path, and last self-reported running version/health. |

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
the version it is *actually* running, the digest of the archive that version was installed from,
and whether it is healthy. The control plane reads those back — it never probes the app — so a
rollout completes only on real, node-attested health, and a missing or stale report fails closed
(keeps the slot). Rollout windows and dated calendars gate *when* a set may admit new rollouts;
members already rolling always finish.

**Health-driven load balancing** (`updated-healthproxy`). The same signed `NodeReport`s drive
backend membership. `updated-healthproxy` reads each node's report and programs a Kubernetes
EndpointSlice (kube-proxy forwards; it adds no data-path hop of its own), so a node drops out of
rotation the instant its report goes unhealthy or stale and rejoins when it recovers. It fails
closed — only a fresh, healthy, correctly-attributed report keeps a backend in service — and the
backend is pluggable (EndpointSlices today, DNS or HAProxy later) behind one health→membership
core.

Control-plane authors targeting a different orchestrator should start with the normative
[JSON Schemas](schemas) — the wire contract integrators write against. Installation manifests live
under [deploy/kubernetes](deploy/kubernetes); the CRDs, namespace, and Secrets they presuppose are
in the [Kubernetes install guide](docs/kubernetes-install.md).

## Guarantees

- A bundle cannot execute until TUF authenticates its metadata, platform, length, and digest, and
  every extracted file matches its strict manifest.
- Activation changes one atomic `active-release` record; immutable predecessor and candidate
  directories are never rewritten in place.
- Startup reconciles interrupted transactions before selection or launch.
- Failed activation or health reactivates the predecessor and rejects the candidate archive.
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

An offline-provisioned agent (`identity.kind: manual`) is the exception, and deliberately so: it
never talks to `/enroll`, so no public key is ever pinned to its name, and the control plane can
never verify anything it reports. It is staged **blind** — on what was published to it rather than
on evidence — so its group stays throttled and stays updatable without any unverifiable report
being believed. The gateway consequently refuses that node's report writes (`403`), and the node's
agent treats the refusal as the standing verdict it is: it warns once and drops reporting to the
agent-check cadence rather than re-PUTting a report no reader could accept on every cycle.
Reporting resumes at full cadence by itself if the identity is ever completed. An operator who
wants a node observed enrolls it (`kind: reserved` reserves the name for a specific machine to
claim); manual provisioning trades visibility for needing no inbound enrollment at all.

The same signed deployment accepts HTTP(S), `file:` URLs, or absolute local repository directories,
so an operator can repair a deployment fully offline. Raw edits inside an immutable installed
release remain untrusted and are rejected. See [deploy/config.toml](deploy/config.toml).

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

Run the cross-platform end-to-end system:

```sh
cargo run -p e2e
```

Run the Kubernetes operator suites against a disposable Kind cluster (Docker, Kind, kubectl, and
curl required; each builds its own cluster and tears it down):

```sh
./scripts/kind-updatec-e2e.sh     # operator, enrollment, throttled rollout, rollback
cargo run -p updatec-e2e          # the full fleet: lifecycle transaction, rollback, HAProxy
```

Run the complete workspace suite:

```sh
cargo test --workspace
cargo clippy --workspace --all-targets --no-deps -- -D warnings
```

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
- the Kind fleet E2E (`cargo run -p updatec-e2e`): a 32-node fleet in eight sets, a Jenkins tier, an
  out-of-cluster slice fronted by the real `updated-healthproxy`, and an `updated`-managed HAProxy
  pair — asserting the ordered red-to-green lifecycle transaction, per-set isolation,
  reconciler-programmed endpoints, a zero-downtime HAProxy upgrade, and a seeded chaos generation
  in which half the cohorts roll back to their exact predecessors while the other half advance,
  before every cohort converges onto one version;
- native Windows Service Control Manager lifecycle testing;
- concurrent macOS publication fuzzing; and
- real HAProxy master-worker binary upgrades on Linux.

## Development publisher

The `server` crate creates a real signed TUF repository for development. Production deployments
should publish immutable targets and signed metadata to object storage or a CDN and keep role keys
offline or in controlled CI/KMS infrastructure.

```sh
cargo build --release -p server -p launcher -p agent

target/release/server init --repo ./repo --keys ./keys

target/release/server publish-app --repo ./repo --keys ./keys \
  --product app --channel stable --version 1.0.0 \
  --entrypoint bin/app \
  --bundle linux-x86_64=./release-linux-x86_64 \
  --bundle macos-aarch64=./release-macos-aarch64

target/release/server serve --repo ./repo --addr 127.0.0.1:8080
```

Publish immutable payload and reconciler artifacts first, then a provider set, and finally the
desired deployment assignment. Every reference includes its exact TUF target path and SHA-256, so
CDN lag can delay a deployment but cannot mix generations:

```sh
target/release/server publish-assignment --repo ./routing-repo --keys ./routing-keys \
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
- The reference deployment runs the agent and the workload under one restricted OS identity.
  Containing a hostile workload requires a separate account or sandbox.
- Activation requires a cooperative lifecycle the reconciler can drive (a master/worker reload, a
  systemd unit, an external launcher). Windows uses stop/activate/start.
- The included publisher and HTTP server are development components, not production signing or
  distribution infrastructure.
- Production desktop deployment still requires platform packaging, macOS signing and notarization,
  Windows Authenticode as appropriate, shortcuts/protocol integration, and a product-specific
  shutdown/readiness contract.

## Documentation

- [JSON Schemas](schemas) — the normative wire contract
- [Node reconciler protocol](docs/node-reconciler-protocol.md) — the argv and output-manifest
  contract a release's own reconciler is written against
- [Package-runner design](docs/package-runner-design.md) — why the agent owns no workload process
- [Kubernetes install guide](docs/kubernetes-install.md) — CRDs, namespace, and Secrets
- [Reference node config](deploy/config.toml)
- Design notes for the shipped controls: [observability](docs/observability-design.md),
  [regression response](docs/regression-response-design.md),
  [alerting](docs/alerting-design.md),
  [node controls](docs/node-controls-design.md),
  [wire compatibility](docs/wire-compatibility-design.md)
- Node decommission: delete the node's `UpdateAgent` object. The gateway checks enrolled membership
  on every request, so a deleted or re-homed agent stops being served bundles, secrets, and routing
  immediately — even while its unexpired leaf certificate still authenticates. There is no
  tombstone artifact.

## License

PolyForm Small Business License 1.0.0. See [LICENSE](LICENSE).
