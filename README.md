# updatedc — signed, transactional deployment procedures for fleets of machines

[![CI](https://github.com/evan-hines-js/updatedc/actions/workflows/ci.yml/badge.svg)](https://github.com/evan-hines-js/updatedc/actions/workflows/ci.yml)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](LICENSE)

<p align="center">
  <img src="assets/fleet-cube.svg" width="700"
       alt="updatedc: the updatec control plane distributes signed releases to a fleet of updated-agent nodes." />
</p>

**updatedc** safely executes deployment procedures across fleets of machines. Publish a signed
payload and choose how to deploy it. Nodes verify the artifacts, execute under durable transactions
and deadlines, check health, and report authenticated outcomes. Recovery follows the integration's
explicit capabilities; restoring old files alone does not undo a database migration.

Build and publish your custom software from CI:

```sh
updatectl publish --source ./package --entrypoint install.sh \
  --product my-app --version 4.0.0
```

With the release repository configured, this packages, signs, and publishes the code, returning its
immutable target path and digest. Select that reference in your `UpdateGroup` YAML to roll it out.
CI does not need Kubernetes credentials. Add
`--interpreter python3` or `--interpreter pwsh` when needed. The platform supplies execution metadata,
protocol handling, durable receipts, deadlines, and process containment. No wrapper script or
separate reconciler publication is required. The native runtime upgrades with the agent.

Health checks and recovery commands are optional. By default, an uncertain execution pauses for
an operator; `--replay safe` explicitly permits repetition. Without a health check, success means
successful command completion. Application compatibility and external effect safety remain with
the code author. See [running a package entrypoint](docs/command-adapter.md), or validate locally
with `updatectl check ./package --entrypoint install.sh`.

The system is split into deliberately narrow components:

- **`updated-agent`** runs on Linux, macOS, and Windows. It authenticates bundles through TUF,
  materializes immutable content-addressed releases, drives the transaction, survives interruption
  at every durable boundary, and reports signed health and output evidence.
- **`updatec`** is the reference Kubernetes control plane and mTLS gateway. It resolves fleet
  policy, signs and publishes per-node assignments, enrolls nodes, brokers bounded object
  capabilities, accepts signed reports, and reconciles rollout state.
- **`updated-healthproxy`** turns the control plane's pinned inventory and signed node health into
  EndpointSlice or HAProxy membership; it is not in the application data path.
- **`updatectl`** is the CI tool for package validation and publication: `check` and `publish`.
  Operators manage desired deployments and rollout policy through Kubernetes YAML. See the
  [CI publication workflow](docs/ci-publication.md).

The control plane can never connect to a node. Everything flows through signed artifacts in shared
storage: `updatec` publishes what each group *should* run, and each `updated` agent pulls,
verifies, activates, and reports back. Compromising the distribution path cannot forge a release,
and a node that cannot reach the repository keeps running the last verified bundle.

## What a deployment is

A deployment names one immutable signed package. `updatectl publish` places the selected entrypoint,
arguments, timeout, and optional health, inspection, replay, and recovery procedures inside it.

The agent owns verification, durable ordering, retries, deadlines, containment, cancellation,
health gates, rollback journals, and authenticated reports. Your entrypoint owns application state
and can invoke any language, service manager, database client, or infrastructure tool available on
the machine. Assigned configuration and secrets are provided as files. An optional native helper
is automatically available through `UPDATED_RECONCILER_HELPER`; it upgrades with the agent.

The default replay and recovery policy pauses uncertain work for an operator. Declare safe replay
only when your operation can tolerate interruption. A configured recovery command must restore the
previous application, including any data it changed. The platform verifies predecessor health and
never implicitly reruns its deployment script. Version numbers do not prove compatibility; inspect
actual machine state in your code before changing it.

Install and upgrade procedures may be different scripts selected by your entrypoint. For required
intermediate upgrades, the native helper can execute an ordered sequence of checked steps. See
[installation and ordered upgrades](docs/install-and-upgrade.md) for the Kubernetes example and the
boundary between application compatibility and platform execution guarantees.

With `--healthcheck`, routine convergence checks actual health and can rerun the entrypoint to repair
drift. Without it, readiness means the entrypoint completed successfully. Optional `--inspect`
stdout supplies application-specific fingerprint material; generic scripts have no inferred plan
or resource diff.

Validate locally, without a repository or cluster:

```sh
updatectl check ./package --entrypoint install.sh
```

The checker uses the same runtime and helper as a node. It exercises repetition, observation purity,
results, and output bounds. Add integration assertions for clean install, same-version convergence,
drift repair, supported and refused transitions, interruptions, and explicit recovery. The
[internal reconciler protocol](docs/node-reconciler-protocol.md) is implemented by the platform.

## Architecture

Every node runs one agent under the platform's service manager; workloads belong to reconcilers, and the control
plane lives outside the node entirely.

```text
                    updatec (Kubernetes controller + mTLS gateway)
                      │  signs & publishes desired deployments per group
                      │  manages updated-healthproxy; never connects into a node
        ┌─────────────┴───────── signed TUF metadata + bundles ──────────────┐
        ▼  (object storage / CDN)                                            ▲
  per node:                                                       signed health reports
    lifecycle owner (systemd, launchd, Windows SCM, Kubernetes)
      └── updated-agent (TUF, selection, transactions, health, rollback)
            └── native runtime invokes the package entrypoint
                  └── workload processes (owned by the hooks, never the agent)
```

The agent does not supervise workload processes. A persistent workload must be detached from its
invocation or managed by the machine's service manager. It can survive an agent-only restart;
restarting its container or machine still requires the entrypoint to restore it under the declared
replay policy. Agent binary upgrades use the
platform's normal package, image, or service rollout and its rollback mechanism.

Activation follows one durable path:

```text
authenticate the archive through TUF
  → stage the immutable candidate package
  → journal Prepared
  → verify candidate bytes and atomically switch active-release
  → journal Activated
  → candidate reconciler converge(payload=candidate)
  → journal Converged
  → require health immediately and journal Verified
  → commit with the exact predecessor rollback guard and journal Committed
  → clear the journal

On failure, recovery journals RollbackPlanned, invokes candidate
`rollback(payload=failed candidate)`, restores the predecessor pointer, invokes predecessor
`converge(payload=predecessor)`, health-gates it, commits it, and clears the same journal.
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
the exact assignment it acted on, the package and execution definition it is *actually*
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
- Agent crashes do not disturb a reconciler-owned workload.
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
configuration. An installer places the agent, provisions permissions, and
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

Run the agent directly under the chosen lifecycle owner:

```sh
UPDATED_STATE_DIR=/var/lib/example-app/state \
  target/release/updated-agent --config /etc/updated/config.toml
```

Configure the service manager to restart the agent after any exit. The shipped templates do this;
the agent deliberately exits when a fresh process is required, such as after certificate renewal.

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

## Rejected releases

A release that fails activation or health is rejected by repository lineage and artifact digest.
That rejection does not expire: repeatedly launching unchanged, proven-bad bytes would turn a safe
rollback into an availability loop. The normal fix is to publish a new release containing corrected
bytes; its new digest is eligible without clearing anything.
Rejection records are append-only: there is no local deletion or override path that can make the
same proven-bad bytes eligible again.

## Try it

Install the repository-owned pre-commit hook once per clone:

```sh
./scripts/install-git-hooks.sh
```

The hook rejects staged whitespace errors, unformatted Rust, and stale generated CRDs. It checks
the exact staged tree (so partially staged files cannot hide a failure) and calls the same
`scripts/check-source.sh` entrypoint as CI, so local and remote source checks cannot drift.

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
persistence, transaction-boundary crashes, locking, agent restart, assigned
secrets, and the reconciler-hook lifecycle — including a Jenkins-shaped enterprise upgrade whose
`converge` backs up state and migrates it, whose `healthcheck` gates the result, and which rolls back
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
cargo build --release -p server -p agent

target/release/server init --repo ./release-repo --keys ./release-keys
target/release/server init --repo ./routing-repo --keys ./routing-keys
target/release/server gen-certs --dir ./certs --san 127.0.0.1 --san localhost

target/release/server publish-app --repo ./release-repo --keys ./release-keys \
  --product app --channel stable --version 1.0.0 \
  --bundle linux-x86_64=./release-linux-x86_64 \
  --bundle macos-aarch64=./release-macos-aarch64

target/release/server serve-object --repo ./release-repo --addr 127.0.0.1:8081 \
  --cert ./certs/server.crt --key ./certs/server.key
target/release/server serve-capability --repo ./routing-repo --addr 127.0.0.1:8080 \
  --public-url https://127.0.0.1:8080 \
  --cert ./certs/server.crt --key ./certs/server.key --ca ./certs/ca.crt
```

Publish an immutable package first, then its desired deployment assignment. Every reference includes its exact TUF target path and SHA-256, so
CDN lag can delay a deployment but cannot mix generations:

```sh
target/release/server publish-assignment --repo ./routing-repo --keys ./routing-keys \
  --release-root ./release-repo/metadata/root.json \
  --name assignments/agents/agent-123.json \
  --deployment deploy-42 \
  --metadata-url https://cdn.example.com/groups/canary/metadata/ \
  --targets-url https://cdn.example.com/groups/canary/targets/ \
  --application ./release-graph.json \
  --runtime ./signed-runtime.json
```

In a real fleet, `updatec` publishes assignments from the Kubernetes resources automatically.
`server` is a development fixture. Operators declare the [release graph](docs/install-and-upgrade.md)
in YAML and apply it with kubectl or GitOps; `updatectl` only checks and publishes CI packages.

## Scope and limitations

- The agent is upgraded through the platform's package, image, or service deployment mechanism;
  trust roots arrive inside the signed enrollment artifact.
- Local state is not hardware-backed monotonic storage; a local administrator is inside the host
  trust boundary and can reseed an installation.
- Node service templates run the agent with machine authority so signed reconcilers can manage the
  whole host. A reconciler should launch an untrusted workload under a separate account or sandbox.
- Activation requires a cooperative workload lifecycle the reconciler can drive (a master/worker reload, a
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
  platform service-manager boundary
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
