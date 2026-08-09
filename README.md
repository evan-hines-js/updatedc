# updatedc — reliable upgrades across fleets of applications

[![CI](https://github.com/evan-hines-js/updatedc/actions/workflows/ci.yml/badge.svg)](https://github.com/evan-hines-js/updatedc/actions/workflows/ci.yml)
[![License: PolyForm Small Business 1.0.0](https://img.shields.io/badge/License-PolyForm%20Small%20Business%201.0.0-blue.svg)](LICENSE)

<p align="center">
  <img src="assets/fleet-cube.svg" width="700"
       alt="updatedc: the updatec control plane distributes signed releases to a fleet of updated node agents." />
</p>

**updatedc** is two cooperating halves that together roll signed application updates
across a whole fleet:

- **`updated`** — the per-node agent. It securely installs and activates signed
  application bundles on Linux, macOS, and Windows, works with update-unaware
  applications, survives interruption at every durable boundary, rolls back unhealthy
  releases, and can replace its own supervisor without stopping the managed application.
- **`updatec`** — the Kubernetes control plane. It groups nodes into fleets, publishes
  each group's desired release as signed TUF metadata to object storage/CDN, throttles
  how fast a change ripples through a group, gates completion on the nodes' own signed
  health reports, and drives load-balancer membership from that same health — all without
  ever reaching *into* a node.

The control plane can never connect to a node. Everything flows through signed artifacts
in shared storage: `updatec` publishes what each group *should* run, and each `updated`
agent pulls, verifies, activates, and reports back. Compromising the distribution path
cannot forge a release, and a node that cannot reach the repository keeps running the
last verified bundle.

Application releases are immutable directory bundles — not loose executables. A release
may carry its entrypoint, configuration, assets, helpers, and libraries under one signed,
verified, rollback-safe identity.

> `updated` is update infrastructure, not the first installer. An installer places the
> bootstrap and initial supervisor, provisions permissions, and registers the platform
> lifecycle owner. It may also preplace a signed enrollment artifact, the node's minted
> identity, and a verified application bundle for a network-free first start. Otherwise
> the first supervisor enrolls and cold-installs online. Loose preinstalled files are
> never trusted.

## One-command operator demo

With Docker, Kind, kubectl, Cargo, and curl installed, run:

```sh
./scripts/demo-local.sh
```

That runs `updatec-demo start`, which builds the Kind environment, applies the demo layer,
and port-forwards the in-cluster demo service to
[http://127.0.0.1:8088](http://127.0.0.1:8088) (override the port with
`UPDATEC_DEMO_PORT`); it opens the browser for you. The first run takes a few minutes.
Keep the script running while using the page.

`scripts/demo.sh` is the other, Ansible-driven path. It takes no subcommands — its single
optional argument is an SSH host:

```sh
./scripts/demo.sh                  # run deploy/ansible/demo.yml on this machine (Linux;
                                   # needs ansible) — UI at http://localhost/ via nginx
./scripts/demo.sh root@10.0.0.206  # rsync the workspace to that host, run the same
                                   # playbook there, tunnel its port 80 to 127.0.0.1:8088
```

This opens a local page with a red managed application and a small typed `release.json`.
Publishing it creates the update through the real Kubernetes operator. The demo service
holds no signing keys or bucket credentials: `updatec` signs and uploads the new routing
generation to MinIO, then the real agent downloads, verifies, and activates it.

The green release also selects a signed Rust lifecycle-provider executable that models an
intentionally elaborate enterprise deployment: compatibility preflight, mutable-state
backup, generated configuration, load-balancer drain, process stop, artifact activation,
cache warmup, health verification, schema migration, traffic restoration, rollback, and an
audit receipt. The page turns green only after that transaction finishes and the managed
application reports the new version.

Below the release transaction, the page renders the operator's groups and an 80-service
fleet. "Run seeded fleet chaos" keeps agents in sixteen permanent five-service cohorts and
selects two whole groups per seeded generation. One receives a signed but unlaunchable
release while the other receives the valid release. The failed group rolls every member
back to its exact predecessor while the successful group advances. The demo verifies that
exact mixed result, holds it for ten seconds, increments the seed, and repeats. CI runs
one bounded generation; the interactive demo runs continuously.

Delete the demo cluster with:

```sh
./scripts/demo-local.sh reset
```

The same browser-button path is an executable E2E test:

```sh
cargo run -p updatec-demo -- e2e --exit    # or: ./scripts/demo-local.sh e2e --exit
```

CI (`.github/workflows/ci.yml`) runs `cargo run -p updatec-demo -- e2e --exit` in its own
Kind job and blocks release publication unless the red-to-green lifecycle transaction and
the complete failure/rollback/recovery scenario both pass.

`updatec-demo` accepts `start`, `setup`, `e2e [--exit]`, `exercise [passes]`, `serve`, and
`reset`; `scripts/demo-local.sh` passes its arguments straight through and defaults to
`start`.

## Architecture

Every node runs a small tower; the control plane lives outside the node entirely.

```text
                    updatec (Kubernetes operator + gateway + healthproxy)
                      │  signs & publishes desired releases per group
                      │  never connects into a node
        ┌─────────────┴───────── signed TUF metadata + bundles ──────────────┐
        ▼  (object storage / CDN)                                            ▲
  per node:                                                       signed health reports
    outer lifecycle owner (systemd, launchd, Windows SCM, login item, launcher)
      └── bootstrap (small permanent process guardian; no network or release policy)
            ├── supervisor (TUF, selection, transactions, health, rollback)
            └── application (launched from the active immutable bundle)
```

On the node, the supervisor authenticates releases through TUF and hands the verified
bytes to a provider; the bootstrap owns process lifetime. That separation lets a new
supervisor prove readiness before its pointer is committed, while the application keeps
running under the bootstrap. The supervisor carries no knowledge of what it downloads: it
proves the bytes are the exact selected target and hands the provider a filepath. The
built-in default provider extracts and verifies the signed bundle into an immutable
release and resolves its entrypoint — a linked shared library, not a runtime plugin, so it
can evolve independently of the trust/transaction/health/rollback core.

Application activation follows one durable path:

```text
authenticate the archive through TUF
  → hand the verified filepath to the provider (the default provider extracts and
    verifies the manifested bundle into an immutable release)
  → write the transaction journal
  → atomically switch active-release
  → start the candidate (or let the provider-managed reconciler bring it into service)
  → require health
  → commit, or reactivate and reject the predecessor
```

## Fleet management with `updatec`

`updatec` is the reference Kubernetes control plane. It maps nodes' control-plane labels
to signed, opaque config-bundle references published through TUF; agents never learn *why*
their config changed. Four custom resources (`updated.dev`) describe a fleet:

| Resource | Role |
| --- | --- |
| `UpdateRepository` | The object-store/CDN destination, signing keys, and enrollment policy for one fleet. |
| `UpdateGroup` | A set of nodes (by label selector) and the exact deployment they should run. |
| `UpdateGroupSet` | A throttle + schedule spanning several groups: `maxConcurrent`, rollout windows, and dated maintenance calendars. |
| `UpdateAgent` | One enrolled node: its identity, resolved group, assignment path, and last self-reported running version/health. |

Publication is a single consistent generation. The operator resolves every group's
selector against the enrolled agents, builds one plan, signs it, and uploads it with
`timestamp.json` last — the TUF commit point — so a CDN can lag but never mix generations.
A single malformed resource is quarantined (its own status fails) rather than aborting the
whole repository.

**Enrollment** has one path: mutual-TLS `POST /enroll` on the gateway data listener.
Every node receives the same fleet enrollment certificate and a unique configured name,
generates its durable private key locally, and sends only a CSR. The control plane ignores
the CSR subject, sets the certificate identity from that validated name, pins the public
key on the `UpdateAgent`, and returns the per-node certificate plus the signed enrollment
bundle. The shared credential is used only to enroll; all routing, repository, secrets,
and telemetry requests use the minted per-node identity.

**Throttled rollouts.** An `UpdateGroupSet` never advances more than
`maxConcurrent` members at once (default `members − 1`), holding the rest until the
in-flight ones settle. Settlement is proven by the node itself: each agent writes a small
signed `NodeReport` to shared storage stating the version it is *actually* running, the
digest of the archive that version was installed from, and whether it is healthy. The control plane reads those back — it never probes the app — so a
rollout completes only on real, node-attested health, and a missing or stale report fails
closed (keeps the slot). Rollout windows and dated calendars gate *when* a set may admit
new rollouts; members already rolling always finish.

**Health-driven load balancing** (`updated-healthproxy`). The same signed `NodeReport`s
drive backend membership. `updated-healthproxy` reads each node's report and programs a
Kubernetes EndpointSlice (kube-proxy forwards; it adds no data-path hop of its own), so a
node drops out of rotation the instant its report goes unhealthy or stale and rejoins when
it recovers. It fails closed — only a fresh, healthy, correctly-attributed report keeps a
backend in service — and the load-balancer backend is pluggable (EndpointSlices today, DNS
or HAProxy later) behind one health→membership core.

Control-plane authors targeting a different orchestrator should start with the normative
[JSON Schemas](schemas) — the wire contract integrators write against. Installation
manifests live under [deploy/kubernetes](deploy/kubernetes); the CRDs, namespace, and
Secrets they presuppose are in the [Kubernetes install guide](docs/kubernetes-install.md).

## Guarantees

- A release cannot execute until TUF authenticates its metadata, platform, length, and
  digest, and every extracted file matches its strict manifest.
- Activation changes one atomic `active-release` record; immutable predecessor and
  candidate directories are never rewritten in place.
- Startup reconciles interrupted transactions before selection or launch.
- Failed activation or health reactivates the predecessor and rejects the candidate
  archive for a bounded retry period.
- A post-commit crash inside the confirmation window also reverts the release.
- Supervisor crashes and self-updates do not stop the guardian-owned application.
- An unavailable repository does not prevent a verified installed bundle from starting.
- A throttled rollout completes only on the nodes' own signed health reports; a forged,
  missing, or stale report fails closed rather than releasing a slot or a load-balancer
  backend.
- Unknown configuration and durable-state fields are rejected rather than ignored or
  migrated implicitly.

Trust is anchored by [TUF](https://theupdateframework.io/) through the `tough` crate:
pinned-root rotation, threshold roles, expiry/freeze resistance, metadata rollback
protection, and target hash/length verification are not reimplemented here.

## Runtime modes

The signed runtime has two ownership modes:

- `managed` (the default): the guardian launches one contained application child, observes
  exit, adopts it across supervisor replacement, and owns stop and process-tree cleanup.
- `provider-managed`: the agent launches and manages no application process. The signed node
  reconciler performs every external effect, including calls to systemd, launchd, Windows SCM,
  a container runtime, firmware tooling, or a remote control plane.

There is no partially managed mode and no PID-discovery contract. Either the guardian owns
the process, or the reconciler owns the external runtime.

Every deployment carries an immutable, signed node-reconciler bundle. The agent supplies
delivery, verification of bytes, durable ordering, retries, deadlines, containment,
cancellation, rollback journaling, scheduling, and telemetry. The bundle supplies all
application-specific behavior through one executable accepting exactly four operations:
`apply`, `healthcheck`, `rollback`, and `inspect`. The argv contract, the output-manifest
document, and a copyable Bash template are in the
[node reconciler protocol](docs/node-reconciler-protocol.md).

`healthcheck` is the one readiness gate. It performs one observation and exits zero only when the
observed release is acceptable; the agent retries it to the signed success threshold within the
signed grace window, and runs the same operation on the signed cadence for steady state. Each
invocation carries `--attempt-id`: a transaction's own token when it gates that transaction's
candidate, or the reserved `boot`/`periodic` identity for an observation that belongs to no
transaction. Managed child exit remains an immediate reliability event independent of any
reconciler observation.

`inspect` is the bounded steady-state measurement operation. It runs after each deploy or
rollback once the periodic `healthcheck` reports healthy, then hourly with stable per-node ±10% jitter. This
cadence is agent policy rather than deployment configuration, so expensive collection can never
drift into every health check. Fingerprinting runs in its own worker; the single deployment
boundary cancels and reaps its complete process tree before any rollout hook begins, then schedules
a fresh post-deployment measurement. On exit zero, the agent SHA-256 hashes the exact non-empty
stdout bytes (without trimming, decoding, or canonicalizing them) and places that digest plus the
signed reconciler artifact digest in the node's DSSE report. The reconciler owns the meaning and
stability of those bytes; stdout is fingerprint data and diagnostics belong on stderr. Empty
output, non-zero exit, cancellation, exceeding the five-minute agent ceiling, or output beyond 64
KiB omits the fingerprint rather than attesting incomplete state.

## Bootstrap and enrollment

A node's entire local configuration is one `bootstrap.toml`, at one canonical path —
`/etc/updated/bootstrap.toml` (`C:\Program Files\updated\bootstrap.toml` on Windows). It
carries the gateway URL, the fleet CA, the shared fleet enrollment credential, and the
node's unique configured name:

```toml
[enrollment]
url = "https://updates.example.com"
ca  = "/etc/updated/fleet-ca.crt"
name = "node-001"
client_cert = "/etc/updated/enrollment/tls.crt"
client_key  = "/etc/updated/enrollment/tls.key"
```

Enrollment returns the pinned routing root plus the complete TUF-signed runtime and
repository configuration. For a network-free first boot against a remote gateway, an
installer must preplace both `enrollment.json` and the already-minted `agent.crt` /
`agent.key`; a bundle alone still requires `/enroll` to establish the per-node identity.
The same signed deployment accepts HTTP(S), `file:` URLs, or absolute local repository
directories, so an operator can repair a deployment fully offline. Raw edits inside an
immutable installed release remain untrusted and are rejected. See
[deploy/bootstrap.toml](deploy/bootstrap.toml).

Run the bootstrap — not the supervisor — under the chosen lifecycle owner:

```sh
target/release/bootstrap \
  --state-dir /var/lib/example-app/guardian-state \
  --supervisor /usr/lib/example-app/supervisor \
  --ready-timeout 60 \
  --confirm-timeout 30 \
  --probe-address 127.0.0.1:9090
```

The config is not named on the command line: the bootstrap reads the canonical path above.
`--supervisor-config` overrides it for a deployment that deliberately keeps the file
elsewhere.

### Guardian health state machine

The optional probe listener belongs to the permanent guardian, not to a particular
supervisor or application release. It gives Kubernetes, service managers, load balancers,
and local diagnostics one stable lifecycle surface:

| State | `/startupz` | `/readyz` | `/livez` | Meaning |
| --- | --- | --- | --- | --- |
| Starting | 503 | 503 | 200 | Tower is alive; no application has been accepted yet |
| Serving | 200 | 200 | 200 | The committed application is healthy and may receive traffic |
| Draining | 200 | 503 | 200 | Planned update or rollback; remove traffic without restarting |
| Failed | latched value | 503 | 503 | Provider verification or managed-process liveness failed |

```text
Starting --first healthy application--> Serving
Serving  --planned drain-------------> Draining
Draining --commit or restored rollback-> Serving
any live state --application failure--> Failed
```

Readiness is withdrawn before stop begins and restored only after the candidate commits or
the predecessor is restored. Liveness remains successful throughout an intentional drain.
Startup is a one-way latch, matching Kubernetes startup-probe semantics. In managed mode a
child crash is observed directly by the guardian and rolls up the tower immediately. All
application-specific acceptance and steady-state evidence comes from the signed reconciler's
`healthcheck` operation; the node configuration contains no HTTP health language.

Platform templates (systemd, launchd, Windows service) live under [deploy/](deploy).

## Durable application layout

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

`work/<version-manifest-id>` is the managed application's launch working directory, and
`providers/work/<version-manifest-id>` is the equivalent for a lifecycle provider. Each is a
*sibling* of the matching `versions/` tree and deliberately not the tree itself: `versions/<id>`
is content-addressed and re-hashed by release verification on every check tick, so a single log,
lockfile or cache an ordinary application writes into its own `cwd` would make the supervisor
condemn a perfectly good release and re-download it forever. So that a program still finds its own
bundled configuration, templates and assets where it expects them, the workspace is seeded on
resolve with a private copy of every file the release manifest declares — a copy, not a link, so an
application rewriting one of those files changes only its own workspace and never the
content-addressed tree. A workspace is created on resolve and reaped once its release directory has
stayed gone across collection passes, so it never outlives what it belongs to and scratch survives
restarts and rollbacks onto a release the node has run before.

The bootstrap has a separate state root containing `desired-supervisor`, lifecycle markers,
and content-addressed supervisor candidates.

## Try it

Run the cross-platform end-to-end system:

```sh
cargo run -p e2e
```

Run the complete workspace suite:

```sh
cargo test --workspace
cargo clippy --workspace --all-targets --no-deps -- -D warnings
```

The E2E harness creates a real signed repository and disposable towers under
`target/e2e-work/`. It covers application upgrade and rollback, a tampered trust root,
offline launch, rejection persistence, transaction-boundary crashes, locking, supervisor
adoption/self-update, one-shot launch, and the provider-managed lifecycle (including a
Magnolia-shaped enterprise upgrade whose `apply` backs up state and migrates it, whose
`healthcheck` gates the result, and which rolls back on failure). Its signed chaotic-application
fixture separately proves fail-closed behavior for an exit before bind, persistent 503, a
health request held for five minutes, flapping readiness, a crash during probing, and
health that degrades only after initially becoming ready.

### Rejected releases and break glass

A release that fails activation or health is rejected by repository lineage and artifact
digest. That rejection does not expire: repeatedly launching unchanged, proven-bad bytes
would turn a safe rollback into an availability loop. The normal fix is to publish a new
release containing corrected bytes; its new digest is eligible without clearing anything.

To deliberately retry the exact rejected bytes, copy its complete key from
`<install-root>/state/rejected` into `<install-root>/state/rejected.allow`, one key per
line, and restart the runtime. This local file is an intentionally inconvenient break-glass
mechanism: malformed or partial keys fail startup closed, overrides are read only at
startup, and the file should be removed after the controlled retry. Application keys are
`repository-lineage-sha256:artifact-sha256`; supervisor keys are a single artifact SHA-256.

CI additionally runs:

- the E2E system on Linux, Intel/ARM macOS, and Windows;
- the full Kind operator E2E (`updatec` publishing across groups, enrollment, throttled
  rollout, and rollback);
- native Windows Service Control Manager lifecycle testing;
- concurrent macOS publication fuzzing; and
- real HAProxy master-worker binary upgrades on Linux.

## Development publisher

The `server` crate creates a real signed TUF repository for development. Production
deployments should publish immutable targets and signed metadata to object storage or a CDN
and keep role keys offline or in controlled CI/KMS infrastructure.

```sh
cargo build --release -p server -p bootstrap -p supervisor

target/release/server init --repo ./repo --keys ./keys

target/release/server publish-app --repo ./repo --keys ./keys \
  --product app --channel stable --version 1.0.0 \
  --entrypoint bin/app \
  --bundle linux-x86_64=./release-linux-x86_64 \
  --bundle macos-aarch64=./release-macos-aarch64

target/release/server serve --repo ./repo --addr 127.0.0.1:8080
```

Publish immutable application/provider artifacts first, then a provider set, and finally the
desired deployment assignment. Every reference includes its exact TUF target path and
SHA-256, so CDN lag can delay a deployment but cannot mix generations:

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

In a real fleet, `updatec` performs this publication for every group automatically; the CLI
is for development and for control planes built on other orchestrators.

## Scope and limitations

- The bootstrap is installer-owned and updated out of band; trust roots arrive inside the
  signed enrollment artifact.
- Local state is not hardware-backed monotonic storage; a local administrator is inside the
  host trust boundary and can reseed an installation.
- The reference deployment runs the updater and application under one restricted OS
  identity. Containing a hostile managed program requires a separate account or sandbox.
- Custom-provider activation requires a cooperative lifecycle (a master/worker reload, a
  systemd unit, an external launcher). Windows uses stop/activate/start for application
  updates.
- The included publisher and HTTP server are development components, not production signing
  or distribution infrastructure.
- Production desktop deployment still requires platform packaging, macOS signing and
  notarization, Windows Authenticode as appropriate, shortcuts/protocol integration, and a
  product-specific shutdown/readiness contract.

## Documentation

- [JSON Schemas](schemas) — the normative wire contract
- [Node reconciler protocol](docs/node-reconciler-protocol.md) — the argv and output-manifest
  contract a release's own reconciler is written against
- [Kubernetes install guide](docs/kubernetes-install.md) — CRDs, namespace, and Secrets
- [Reference bootstrap](deploy/bootstrap.toml)
- Design notes for the shipped controls: [observability](docs/observability-design.md),
  [regression response](docs/regression-response-design.md),
  [alerting](docs/alerting-design.md),
  [node controls](docs/node-controls-design.md),
  [wire compatibility](docs/wire-compatibility-design.md)
- Node decommission: delete the node's `UpdateAgent` object. The gateway checks enrolled
  membership on every request, so a deleted or re-homed agent stops being served bundles,
  secrets, and routing immediately — even while its unexpired leaf certificate still
  authenticates. There is no tombstone artifact.

## License

PolyForm Small Business License 1.0.0. See [LICENSE](LICENSE).
