# System Walkthrough

This is the shortest path through the system. The implementation is intentionally
broader than a single `download → replace → restart` function because the interesting
part of self-update is preserving a runnable, trusted version when a process, machine,
network request, or candidate fails at the worst possible time.

> **This is not an installer or package manager.** An installer must first place the
> bootstrap, supervisor or one-shot launcher, initial application binary, read-only
> configuration, and pinned TUF root; record the baseline version and SHA-256; create
> the restricted service identity and writable state directory; and register any
> systemd, launchd, Windows SCM, shortcut, or file-association integration. `updated`
> takes responsibility only after that trust and filesystem boundary exists: it keeps
> the provisioned application current, verifies every replacement, and recovers or
> rolls back failed updates. Replacing the bootstrap, changing machine-wide packaging,
> or repairing a broken initial installation remains the installer's responsibility.

## Five-minute overview

The system updates an arbitrary, update-unaware application on Linux, macOS, and
Windows. A signed TUF repository describes releases. A supervisor selects and
downloads the correct target, then performs a journaled, health-gated replacement.
A tiny, network-free bootstrap owns the processes and safely replaces the supervisor
itself.

```text
OS init system
    └── bootstrap (permanent guardian; no network or release policy)
          ├── supervisor (TUF, selection, transactions, health, rollback)
          └── managed application (does not know about the updater)
```

The hierarchy deliberately stops at the bootstrap. Updating that final trust anchor
is an installer/package-manager operation. This avoids an infinite chain of programs
trying to update themselves and gives Windows a process that can activate a new
supervisor after the old executable exits.

The main guarantees are:

- A release cannot execute until its TUF metadata chain, platform attributes,
  length, and digest have been verified.
- An interrupted application replacement converges on startup to either the last
  committed version or the fully verified candidate; it does not trust partial state.
- An unhealthy candidate is rolled back and rejected by content hash.
- A supervisor candidate is staged at a new content-addressed path and committed by
  the bootstrap only after it signals readiness.
- Updating or crashing the supervisor does not stop the managed application.

## Run it

The quickest way to see the complete system is the end-to-end harness. It creates a
real signed repository and disposable processes under `target/e2e-work/`:

```sh
cargo run -p e2e
```

For the complete unit and integration suite:

```sh
cargo test --workspace
```

CI runs the end-to-end system on Linux, Intel and ARM macOS, and Windows. Windows CI
also installs and controls the program through the native Service Control Manager.

On macOS, `scripts/macos-smoke.sh` provides a production-shaped local deployment using
a real user LaunchAgent (`launchd → bootstrap → supervisor → sampleapp`) rather than
starting the processes directly. It builds and provisions version 1.0.0, creates and
serves a signed local repository, then lets the background supervisor discover and
install a newly published release:

```sh
scripts/macos-smoke.sh start
scripts/macos-smoke.sh publish 2.0.0
scripts/macos-smoke.sh status
scripts/macos-smoke.sh logs       # optional: follow repository and tower logs
scripts/macos-smoke.sh reset      # unload and remove the disposable state
```

The default `start` uses portable stop/swap/start behavior. On macOS, start the
sample app in its same-PID, socket-preserving reexec mode to validate a zero-downtime
update instead:

```sh
scripts/macos-smoke.sh reset
scripts/macos-smoke.sh start reexec
scripts/macos-smoke.sh publish 2.0.0
```

After `start`, the managed sample server is available on port `19090`:

```sh
curl -fsS http://127.0.0.1:19090/version
curl -fsS http://127.0.0.1:19090/healthz
```

To watch availability during an update, leave this running in another terminal and
then run `scripts/macos-smoke.sh publish 2.0.0`:

```sh
while true; do
  version=$(curl -fsS http://127.0.0.1:19090/version 2>/dev/null || echo unavailable)
  printf '%s  %s\n' "$(date +%H:%M:%S)" "$version"
  sleep 0.25
done
```

The two smoke paths demonstrate different availability guarantees:

- `start` uses portable stop/swap/start. At a 250 ms polling interval, expect roughly
  0–5 `unavailable` samples during the bounded replacement window. While this is portable, slow starting apps will see a downtime window equal to their startup time. From experience, this would be from 5 seconds to minutes depending on the type of application. For slow starting apps, it is recommended to handle HUP if lower downtime is needed.

- `start reexec` sends the configured HUP signal. The process reexecs in place while
  preserving its PID and listener; expect 0 unavailable samples.

In both cases the loop switches from the old version to the new one after the health
gate succeeds. Exact portable-mode timing depends on the machine and scheduler.

`publish` waits for the requested version while checking that the LaunchAgent remains
active. A requested version below the live version fails immediately because
downgrades are not supported; this check uses the live endpoint, not supervisor log
text. Other failures report the version that remained active and point to
`scripts/macos-smoke.sh logs`. Files are isolated under `target/macos-smoke/` by default.

## Suggested code tour

### 1. Authenticate and select a release

Start in `crates/updated-tuf/src/lib.rs` and `crates/updated-tuf/src/select.rs`.
`TrustedRepository` loads the installer-pinned root, lets `tough` verify and rotate
the TUF metadata chain, exposes only verified targets, and streams the chosen target
under configured size and transport-time limits. `crates/updated-tuf/src/policy.rs`
then applies product, channel, OS, architecture, SemVer, and downgrade policy to
authenticated metadata.

This ordering matters: unsigned repository input never gets to choose an executable
path or bypass platform and downgrade rules.

### 2. Apply an application update

Follow `check_application` in `crates/supervisor/src/selection.rs` into
`apply_update` in `crates/supervisor/src/update.rs`. The transaction is:

```text
verify candidate
  → persist journal
  → preserve rollback image
  → atomically replace executable
  → start/reload candidate
  → require consecutive authenticated health successes
  → commit installed state
  → retain rollback intent for a confirmation window
```

Any pre-commit health or activation failure restores the predecessor and durably
rejects the failed bytes. `crates/updated/src/apply.rs` contains the filesystem
operations; `crates/updated/src/transaction.rs` classifies on-disk state after an
interruption; `crates/supervisor/src/boot.rs` turns that classification into a
recovery plan.

The invariant to look for is: **the durable record never claims a binary is committed
unless the bytes at the application path match that record's digest**. Where a write
cannot be completed, the journal or rollback image is retained so the next start can
finish recovery.

### 3. Update the updater

Read `stage_and_handoff` in `crates/supervisor/src/self_update.rs`, then
`run_supervisor`, `serve`, and `dispatch` in `crates/bootstrap/src/guardian.rs`.

The supervisor downloads its successor into a directory named by SHA-256. It never
overwrites its running image. It asks the bootstrap to activate that path and exits.
The bootstrap launches the candidate under a readiness deadline and advances the
durable desired-supervisor pointer only after the candidate proves ready. Failure to
launch, early exit, or readiness timeout leaves the previous pointer committed.

The bootstrap owns the application across this handoff. The new supervisor adopts
the existing PID instead of launching a duplicate, which is why supervisor replacement
does not interrupt the application.

### 4. Inspect the hostile paths

The most representative tests are:

- `crates/e2e/src/scenarios/security.rs` — tampered trust roots and fail-closed behavior.
- `crates/e2e/src/scenarios/chaos.rs` — interruption at transaction boundaries.
- `crates/e2e/src/scenarios/application.rs` — update, failed health, crash, and rollback.
- `crates/e2e/src/scenarios/self_update.rs` — successful and rejected supervisor replacement.
- `crates/e2e/src/scenarios/locking.rs` — competing updater instances.
- `crates/supervisor/src/tests.rs` — deterministic transaction fault injection and
  state-machine invariants.

## Reliability design rationale

**Why TUF instead of a signed JSON manifest?** TUF already defines root rotation,
role separation, thresholds, expiration/freeze resistance, metadata rollback
protection, and target length/hash verification. The implementation delegates those
security-sensitive rules to `tough` rather than recreating them.

**Why an external supervisor?** A running process cannot reliably replace and recover
itself on every supported OS. Keeping update policy outside the application also works
for arbitrary existing binaries.

**Why a second guardian process?** The supervisor has the same self-replacement
problem one level up. The bootstrap is intentionally small and installer-owned; it
contains no network, cryptography, or release selection, so its change rate and attack
surface remain low.

**What does seamless mean here?** The default is a brief stop/swap/start protected by
a health gate. Cooperative Unix services can use the reload path for same-PID,
zero-downtime replacement. Windows uses stop/swap/start. Supervisor replacement keeps
the application running on every platform.

**What happens when the repository is unavailable?** The installed application keeps
running. Transport failures back off and retry; trust failures fail closed and are not
reclassified as ordinary network errors.

## Native desktop applications

The system was initially designed for long-running daemons, but the same verified
replacement primitives can support conventional native desktop applications such as
Discord-style clients. The natural integration is for the application's installer to
place `updated-oneshot` as its launcher:

```text
user opens application
  → launcher acquires the update lock
  → reconcile any interrupted replacement
  → refresh and verify signed metadata
  → atomically install an eligible update, if available
  → verify the executable against committed state
  → exec the desktop application
```

Network unavailability does not prevent launch: the wrapper verifies and runs the
currently committed binary. Because replacement happens before the GUI process starts,
there is no need to overwrite a running executable or keep a permanent supervisor
alive. Concurrent launches serialize on the same installation lock.

An application with an always-running tray process or background agent can instead use
the bootstrap/supervisor model: request a clean application shutdown, replace the
verified files, start the candidate, and commit only after an application-specific
readiness check succeeds. Multi-process desktop applications need a launcher-owned
shutdown contract so every process releases the installation before replacement.

Production desktop packaging still needs platform integration outside this project:
preserve macOS code signing/notarization and Windows Authenticode packaging, update an
application bundle or installation directory as one release unit, respect per-user vs.
machine-wide permissions, and integrate shortcuts/protocol handlers with the launcher.
TUF authenticates the published release, but it does not replace those OS packaging
and identity requirements.

## Scope and deliberate limitations

- The included publisher and HTTP server are development components. Production
  deployment should publish signed metadata and immutable targets to object storage
  or a CDN, with signing keys kept offline or in CI/KMS infrastructure.
- The bootstrap and pinned root are installer-owned and updated out of band.
- Local state is not monotonic hardware-backed storage. A local administrator is
  inside the trust boundary and can reset the installation to its provisioned baseline.
- Unix can fsync directory entries; Windows has a narrower sudden-power-loss guarantee.
  Atomic replacement still prevents execution of a torn file, and digest checks make
  inconsistent surviving state fail closed.
- The reference deployment runs the updater and managed program under one restricted
  OS identity. A hostile managed program would require a separate account or sandbox.
- Production packaging and signing-key operations are described but intentionally not
  presented as finished infrastructure.

The longer rationale, deployment templates, trust model, on-disk state model, and
configuration reference are in `README.md`, `deploy/README.md`, and
`deploy/config.toml`.
