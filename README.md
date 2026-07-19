# updated + updatec — reliable upgrades across fleets of applications

[![CI](https://github.com/evan-hines-js/updated/actions/workflows/ci.yml/badge.svg)](https://github.com/evan-hines-js/updated/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

<p align="center">
  <img src="assets/fleet-cube.svg" width="700"
       alt="An isometric lattice of green fleet nodes as a series of cubes and towers, each updating at its own pace — the taller the tower, the slower it changes colour. Most pulse amber and settle back to green; some fail (holding red), turn purple as they roll back, and settle on a different green: the previous version." />
</p>

This project is two cooperating halves that together roll signed application updates
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
> lifecycle owner. It may also preplace a signed enrollment artifact and verified
> application bundle for a network-free first start. Otherwise the first supervisor
> enrolls and cold-installs online. Loose preinstalled files are never trusted.

## One-command operator demo

With Docker, Kind, kubectl, Cargo, and curl installed, run:

```sh
./scripts/demo.sh
```

Open [http://127.0.0.1:8088](http://127.0.0.1:8088) if the browser does not open
automatically. The first run builds the local Kind environment and can take a few
minutes. Keep the script running while using the page.

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

Delete the demo with:

```sh
./scripts/demo.sh reset
```

The same browser-button path is an executable E2E test:

```sh
./scripts/demo.sh e2e --exit
```

CI runs that command in its own Kind job and blocks release publication unless the
red-to-green lifecycle transaction and the complete failure/rollback/recovery scenario
both pass.

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
  → start the candidate (or let a custom provider bring it into service)
  → require health
  → commit, or reactivate and reject the predecessor
```

See [WALKTHROUGH.md](WALKTHROUGH.md) for a five-minute code tour.

## Fleet management with `updatec`

`updatec` is the reference Kubernetes control plane. It maps nodes' control-plane labels
to signed, opaque config-bundle references published through TUF; agents never learn *why*
their config changed. Four custom resources (`updated.dev`) describe a fleet:

| Resource | Role |
| --- | --- |
| `UpdateRepository` | The object-store/CDN destination, signing keys, and enrollment policy for one fleet. |
| `UpdateGroup` | A set of nodes (by label selector) and the exact deployment they should run. Mints a group join token. |
| `UpdateGroupSet` | A throttle + schedule spanning several groups: `maxConcurrent`, rollout windows, and dated maintenance calendars. |
| `UpdateAgent` | One enrolled node: its identity, resolved group, assignment path, and last self-reported running version/health. |

Publication is a single consistent generation. The operator resolves every group's
selector against the enrolled agents, builds one plan, signs it, and uploads it with
`timestamp.json` last — the TUF commit point — so a CDN can lag but never mix generations.
A single malformed resource is quarantined (its own status fails) rather than aborting the
whole repository.

**Enrollment** happens over the gateway's TLS listeners and comes in two modes (a node
picks one by which fields its bootstrap carries):

- **Mount mode** (Kubernetes / cert-manager): a client certificate and key are
  pre-provisioned; the agent presents them as mTLS to `/enroll`. The mutual TLS *is* the
  authentication.
- **Join mode** (immutable infra / VM userdata): the bootstrap carries only a `groupId`
  and a shared `nonce` join token. The agent generates a keypair locally, gets its CSR
  signed at `/join` (server-authenticated TLS, no client cert), and uses the minted
  certificate thereafter. The control plane sets the certificate identity itself and
  certifies only the CSR's public key, so a shared token can never mint an arbitrary
  identity, and two nodes sharing one token get two distinct, individually-revocable
  identities. Deleting the group deletes its token; rotate it with `spec.rotateNonce`.

The join listener is unauthenticated at the transport layer, so it runs on its own
connection budget and exposes nothing but `/join` — never `/enroll`, telemetry, or
repository content. See [group join design](docs/group-enrollment-design.md).

**Throttled rollouts.** An `UpdateGroupSet` never advances more than
`maxConcurrent` members at once (default `members − 1`), holding the rest until the
in-flight ones settle. Settlement is proven by the node itself: each agent writes a small
signed `NodeReport` to shared storage stating the version it is *actually* running and
whether it is healthy. The control plane reads those back — it never probes the app — so a
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
[control-plane API contract](CONTROLPLANE_API_CONTRACT.md) and its [JSON Schemas](schemas).
Installation, CRD examples, trust bootstrapping, verification, and recovery are documented
in the authoritative [Kubernetes operator guide](deploy/kubernetes/README.md).

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

## Activation modes

### Portable restart (default)

`mode = "stop-start"` is the default: stop → activate → start. It works on Linux, macOS,
and Windows and needs no update-specific application behavior. Health gates and the
confirmation window bound the rollback decision.

### Custom provider lifecycle

For deployments the updater should not stop and start itself — a systemd unit, a
launcher, a master/worker service that reloads in place — a signed lifecycle provider
drives activation instead:

```toml
[application.activation]
mode = "custom"
```

The supervisor contains the built-in `default` provider (its version *is* the supervisor
version). A desired deployment may reference an immutable, separately-signed provider-set
document that pins a capability override, argv, and timeout. Built-in and external
providers receive the same phases; external loading is an override, not a second update
path. The manifested entrypoint receives one of `preflight`, `prepare`, `drain`, `stop`,
`activate`, `start`, `verify`, `finalize`, or `rollback` in `UPDATED_LIFECYCLE_PHASE`,
plus a stable `UPDATED_LIFECYCLE_ATTEMPT_ID` and candidate/predecessor paths. It must be
idempotent. In custom mode an external process provider owns the real process and reports
its PID back for health and crash watching; the supervisor commits only once authenticated
health confirms the expected version.

See [LIFECYCLE_PROVIDER.md](LIFECYCLE_PROVIDER.md) for copy/paste AI prompts that map an
existing deployment runbook or script set onto this protocol. Operators configure only the
generated dispatcher; it can delegate internally to existing site scripts.

### Update on launch

`updated-oneshot` uses the same bundle store, verification, journal, recovery, and
activation code before `exec`ing the active entrypoint. This fits CLIs, batch jobs, and
Discord-style desktop launchers that update before the GUI starts. Network failure falls
back to the verified committed bundle.

Always-running desktop or tray applications can instead place the bootstrap under a login
item or small startup host. The updater requires an outer start/relaunch/stop contract,
not specifically a server init system.

## Bootstrap and enrollment

A node's entire local configuration is one `bootstrap.toml`. It always carries the gateway
`url` and the fleet `ca` it trusts for the gateway's server certificate, plus exactly one
credential set — mount **or** join:

```toml
[enrollment]
url = "https://updates.example.com"
ca  = "/etc/updated/fleet-ca.crt"

# Mount mode: pre-provisioned client identity (no secret in this file).
client_cert = "/etc/updated/tls/tls.crt"
client_key  = "/etc/updated/tls/tls.key"

# — or — Join mode: a shared group join token (this file then holds a secret).
# group_id = "…"
# nonce    = "…"
```

Cert paths win when present (mount mode); otherwise the join token is used. Enrollment
returns the pinned routing root plus the complete TUF-signed runtime and repository
configuration. An installer may preplace `enrollment.json` in guardian state, in which case
HTTP enrollment is never attempted. The same signed deployment accepts HTTP(S), `file:`
URLs, or absolute local repository directories, so an operator can repair a deployment
fully offline. Raw edits inside an immutable installed release remain untrusted and are
rejected. See [deploy/bootstrap.toml](deploy/bootstrap.toml).

Run the bootstrap — not the supervisor — under the chosen lifecycle owner:

```sh
target/release/bootstrap \
  --state-dir /var/lib/example-app/guardian-state \
  --supervisor-config /etc/example-app/bootstrap.toml \
  --supervisor /usr/lib/example-app/supervisor \
  --ready-timeout 60 \
  --confirm-timeout 30 \
  --probe-address 127.0.0.1:9090
```

### Guardian health state machine

The optional probe listener belongs to the permanent guardian, not to a particular
supervisor or application release. It gives Kubernetes, service managers, load balancers,
and local diagnostics one stable lifecycle surface:

| State | `/startupz` | `/readyz` | `/livez` | Meaning |
| --- | --- | --- | --- | --- |
| Starting | 503 | 503 | 200 | Tower is alive; no application has been accepted yet |
| Serving | 200 | 200 | 200 | The committed application is healthy and may receive traffic |
| Draining | 200 | 503 | 200 | Planned update or rollback; remove traffic without restarting |
| Failed | latched value | 503 | 503 | Application/process health failed; replace the tower |

```text
Starting --first healthy application--> Serving
Serving  --planned drain-------------> Draining
Draining --commit or restored rollback-> Serving
any live state --application failure--> Failed
```

Readiness is withdrawn before stop begins and restored only after the candidate commits or
the predecessor is restored. Liveness remains successful throughout an intentional drain.
Startup is a one-way latch, matching Kubernetes startup-probe semantics. A process crash is
observed directly by the guardian and rolls up the tower immediately; three consecutive
failures from a tagged application liveness check produce the same `Failed` transition.

Signed managed configuration preserves distinct application health semantics:

```json
{
  "healthChecks": [
    {"kind": "startup", "url": "http://127.0.0.1:8080/startup"},
    {"kind": "readiness", "url": "http://127.0.0.1:8080/ready"},
    {"kind": "liveness", "url": "http://127.0.0.1:8080/live"}
  ]
}
```

Each kind may occur at most once and uses a numeric-loopback HTTP(S) URL. An update-unaware
application may omit all three: surviving the configured startup grace supplies readiness,
while a real process exit is still detected immediately.

Platform templates and permission guidance are in [deploy/README.md](deploy/README.md).

## Durable application layout

```text
install_root/
  active-release
  versions/<version-manifest-id>/
    manifest.json
    bin/application
    config/...
  staging/
  state/
    installed.json
    transaction.json
    rejected
    tuf/
```

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
adoption/self-update, one-shot launch, and the custom provider lifecycle (including a
Magnolia-shaped enterprise upgrade that backs up state, drains, activates a new artifact,
verifies health, finalizes, and rolls back on failure). Its signed chaotic-application
fixture separately proves fail-closed behavior for an exit before bind, persistent 503, a
health request held for five minutes, missing or forged health identity, flapping
readiness, a crash during probing, and health that degrades only after initially becoming
ready.

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

- [System walkthrough](WALKTHROUGH.md)
- [Control-plane API contract](CONTROLPLANE_API_CONTRACT.md)
- [Kubernetes operator guide](deploy/kubernetes/README.md)
- [Group join tokens + CSR enrollment](docs/group-enrollment-design.md)
- [Deployment adapters](deploy/README.md)
- [Reference bootstrap](deploy/bootstrap.toml)

## License

MIT. See [LICENSE](LICENSE).
