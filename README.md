# updated — reliable application updates

[![CI](https://github.com/evan-hines-js/updated/actions/workflows/ci.yml/badge.svg)](https://github.com/evan-hines-js/updated/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

`updated` securely installs and activates signed application bundles on Linux, macOS,
and Windows. It works with update-unaware applications, survives interruption at every
durable update boundary, rolls back unhealthy releases, and can replace its own
supervisor without stopping the managed application.

Application releases are immutable directory bundles—not loose executables. A release
may contain its entrypoint, configuration, assets, helpers, and libraries under one
signed, verified, rollback-safe identity.

> `updated` is update infrastructure, not the first installer. An installer must place
> the bootstrap and initial supervisor, pin the TUF root, seed the initial verified
> application bundle, provision permissions, and register the platform lifecycle owner.

## Architecture

```text
outer lifecycle owner (systemd, launchd, Windows SCM, login item, desktop launcher)
    └── bootstrap (small permanent process guardian; no network or release policy)
          ├── supervisor (TUF, selection, transactions, health, rollback)
          └── application (launched from the active immutable bundle)
```

The supervisor verifies and stages releases, but the bootstrap owns process lifetime.
That separation lets a new supervisor prove readiness before its pointer is committed,
while the application continues running under the bootstrap.

Application activation follows one durable path:

```text
authenticate archive
  → safely extract and verify every manifested file
  → publish an immutable release directory
  → write the transaction journal
  → atomically switch active-release
  → start or reexec the candidate
  → require health (plus exact-version proof for reexec)
  → commit, or reactivate and reject the predecessor
```

See [WALKTHROUGH.md](WALKTHROUGH.md) for a five-minute code tour and
[BUNDLE_SUPPORT.md](BUNDLE_SUPPORT.md) for the complete release model.

## Guarantees

- A release cannot execute until TUF authenticates its metadata, platform, length,
  and digest, and every extracted file matches its strict manifest.
- Activation changes one atomic `active-release` record; immutable predecessor and
  candidate directories are never rewritten in place.
- Startup reconciles interrupted transactions before selection or launch.
- Failed activation or health reactivates the predecessor and rejects the candidate
  archive for a bounded retry period.
- A post-commit crash inside the confirmation window also reverts the release.
- Supervisor crashes and self-updates do not stop the guardian-owned application.
- An unavailable repository does not prevent a verified installed bundle from starting.
- Unknown configuration and durable-state fields are rejected rather than ignored or
  migrated implicitly.

Trust is anchored by [TUF](https://theupdateframework.io/) through the `tough` crate:
pinned-root rotation, threshold roles, expiry/freeze resistance, metadata rollback
protection, and target hash/length verification are not reimplemented here.

## Activation modes

### Portable restart

The default is stop → activate → start. It works on Linux, macOS, and Windows and needs
no update-specific application behavior. Health gates and the confirmation window bound
the rollback decision.

### Unix reexec

A HAProxy-like master/worker service can keep its guardian-owned master PID while an
operator-defined command adopts the active candidate:

```toml
[application.activation]
mode = "reexec"
[application.transition]
command = ["/usr/local/libexec/transition-app"]
timeout = "5m"
```

The command is direct argv, never shell text, and receives one of `preflight`, `drain`,
`prepare`, `activate`, `finalize`, or `rollback` in `UPDATED_TRANSITION_PHASE`, plus a
stable `UPDATED_TRANSITION_ID` and candidate/predecessor paths. It must be idempotent.
The same API also supports site work around portable restarts; only reexec requires it.
The supervisor commits only if the master PID is unchanged and authenticated health
reports the exact expected version.

See [TRANSITION_WRAPPERS.md](TRANSITION_WRAPPERS.md) for copy/paste AI prompts that map
an existing deployment runbook or script set onto this protocol. Operators configure
only the generated dispatcher; it can delegate internally to existing site scripts.

CI exercises both the socket-preserving sample fixture and real HAProxy master-worker
binary reload with `SIGUSR2`.

### Update on launch

`updated-oneshot` uses the same bundle store, verification, journal, recovery, and
activation code before `exec`ing the active entrypoint. This fits CLIs, batch jobs, and
Discord-style desktop launchers that update before the GUI starts. Network failure falls
back to the verified committed bundle.

Always-running desktop or tray applications can instead place the bootstrap under a
login item or small startup host. The updater requires an outer start/relaunch/stop
contract, not specifically a server init system.

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
`target/e2e-work/`. It covers application upgrade and rollback, first-install and
on-disk tampering, offline launch, rejection persistence, transaction-boundary crashes,
locking, supervisor adoption/self-update, one-shot launch, and Unix zero-downtime reexec.

CI additionally runs:

- the E2E system on Linux, Intel/ARM macOS, and Windows;
- native Windows Service Control Manager lifecycle testing;
- concurrent macOS publication fuzzing in restart and reexec modes; and
- real HAProxy master-worker binary upgrades on Linux.

## Development publisher

The `server` crate creates a real signed TUF repository for development. Production
deployments should publish immutable targets and signed metadata to object storage or a
CDN and keep role keys offline or in controlled CI/KMS infrastructure.

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

Publish each node's small routing assignment into the routing TUF repository. In
production the control plane writes these targets and the CDN serves them:

```sh
target/release/server publish-assignment --repo ./routing-repo --keys ./routing-keys \
  --name assignments/node-123.json \
  --metadata-url https://cdn.example.com/groups/canary/metadata/ \
  --targets-url https://cdn.example.com/groups/canary/targets/
```

An installer seeds the initial bundle before starting the tower:

```sh
target/release/server install-app \
  --install-root /var/lib/example-app \
  --bundle ./release-linux-x86_64 \
  --product app --version 1.0.0 --platform linux-x86_64 \
  --entrypoint bin/app
```

## Configuration

```toml
[routing]
root = "/etc/example-app/routing-root.json"
base_url = "https://updates.example.com/routing/"
assignment = "assignments/node-123.json"

[repository]
root = "/etc/example-app/releases-root.json"

[application]
product = "app"
channel = "stable"
install_root = "/var/lib/example-app"
args = ["--config", "/etc/example-app/app.toml"]
health_url = "http://127.0.0.1:9090/healthz" # omit for liveness-only

[timeouts]
check_interval = "60s"
health_grace = "10s"
confirmation_window = "2m"
```

All application-owned release paths resolve beneath `install_root`; mutable operator
configuration and application data belong outside immutable `versions/` directories.

`routing.base_url` is the node's only configured repository URL. The updater derives
its `metadata/` and `targets/` endpoints, verifies the exact assignment target through
TUF, then uses the two release-repository URLs in that strict document. It resolves the
assignment on every update check, so a control-plane group change takes effect without
restarting the node. The release root remains pinned locally: routing selects a repository,
not a new trust authority.
See [deploy/config.toml](deploy/config.toml) for every option.

Run the bootstrap—not the supervisor—under the chosen lifecycle owner:

```sh
target/release/bootstrap \
  --state-dir /var/lib/example-app/guardian-state \
  --supervisor-config /etc/example-app/updated.toml \
  --supervisor /usr/lib/example-app/supervisor \
  --ready-timeout 60
```

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

The bootstrap has a separate state root containing `desired-supervisor`, lifecycle
markers, and content-addressed supervisor candidates.

## Scope and limitations

- The bootstrap and pinned TUF root are installer-owned and updated out of band.
- Local state is not hardware-backed monotonic storage; a local administrator is inside
  the host trust boundary and can reseed an installation.
- The reference deployment runs the updater and application under one restricted OS
  identity. Containing a hostile managed program requires a separate account or sandbox.
- Unix reexec requires a cooperative HAProxy-like master/worker lifecycle. Windows uses
  stop/activate/start for application updates.
- Automatic old-release garbage collection is not yet implemented.
- The included publisher and HTTP server are development components, not production
  signing or distribution infrastructure.
- Production desktop deployment still requires platform packaging, macOS signing and
  notarization, Windows Authenticode as appropriate, shortcuts/protocol integration, and
  a product-specific shutdown/readiness contract.

## Documentation

- [System walkthrough](WALKTHROUGH.md)
- [Bundle-only architecture](BUNDLE_SUPPORT.md)
- [Deployment adapters](deploy/README.md)
- [Reference configuration](deploy/config.toml)

## License

MIT. See [LICENSE](LICENSE).
