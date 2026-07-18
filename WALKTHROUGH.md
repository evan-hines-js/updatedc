# System Walkthrough

This is the shortest path through the system. The implementation is intentionally
broader than a single `download → replace → restart` function because the interesting
part of self-update is preserving a runnable, trusted version when a process, machine,
network request, or candidate fails at the worst possible time.

> **This is not an installer or package manager.** An installer must first place the
> bootstrap, supervisor or one-shot launcher, initial application bundle, read-only
> configuration, and pinned routing/release TUF roots; seed strict installed and `active-release`
> records; create the restricted service identity and writable state directory; and register any
> systemd, launchd, Windows SCM, shortcut, or file-association integration. `updated`
> takes responsibility only after that trust and filesystem boundary exists: it keeps
> the provisioned application current, verifies every candidate bundle, and recovers or
> rolls back failed updates. Replacing the bootstrap, changing machine-wide packaging,
> or repairing a broken initial installation remains the installer's responsibility.

## Five-minute overview

The system updates an arbitrary, update-unaware application on Linux, macOS, and
Windows. A small signed routing repository assigns the node to a signed release
repository. A supervisor resolves that assignment, selects and downloads the correct
target, then performs journaled, health-gated release activation.
A tiny, network-free bootstrap owns the processes and safely replaces the supervisor
itself.

```text
outer lifecycle owner (service manager, login item, or desktop launcher)
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
- An interrupted application activation converges on startup to either the last
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

The E2E harness covers both portable stop/activate/start and Unix reexec activation.
The reexec scenario continuously probes availability and asserts that the managed master
PID survives while the application adopts the newly active bundle. A real HAProxy
master-worker test independently proves the contract against an unmodified third-party
service rather than relying only on the sample fixture.

## Suggested code tour

### 1. Authenticate and select a release

Start in `crates/updated-tuf/src/lib.rs` and `crates/updated-tuf/src/select.rs`.
`TrustedRepository::assigned` derives `metadata/` and `targets/` from the one configured
routing base URL, verifies the node's exact assignment target, and loads the assigned
release repository under a separately pinned root. It repeats assignment resolution on
each check so control-plane group changes are live. `tough` verifies and rotates each
TUF metadata chain, exposes only verified targets, and streams the chosen target
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
  → run read-only preflight
  → persist a phase journal
  → drain → quiesce → prepare
  → atomically activate the immutable release directory
  → re-verify its manifested bytes
  → start/reload candidate
  → require consecutive authenticated health successes
  → finalize
  → commit installed state
  → retain rollback intent for a confirmation window
```

Any pre-commit health or activation failure restores the predecessor and durably
rejects the failed archive. `crates/updated/src/bundle.rs` owns strict bundle creation,
extraction, verification, immutable release storage, and `active-release` operations;
`crates/updated/src/transaction.rs` records the last completed boundary and classifies
durable state after an interruption;
`crates/supervisor/src/boot.rs` turns that classification into a recovery plan.

The invariant to look for is: **the durable record never claims a release is committed
unless every manifested file in that immutable release verifies and `active-release`
names it**. Where a durable transition cannot be completed, the journal and predecessor
release remain available so the next start can finish recovery.

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
- `crates/supervisor/src/update.rs` unit tests — deterministic transaction fault injection.
- `crates/updated/src/transaction.rs` unit tests — phase and recovery invariants.

The chaos suite enumerates its forward and rollback injection points from the chaos-built
supervisor itself. It crashes both after an action and after the matching durable phase,
then uses a cross-platform transition fixture to assert the exact phase/transaction-ID
sequence. A replay in the action/journal gap must keep one logical effect; already
journaled phases must not be invoked again. These cases run on Windows, macOS, and Linux.

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

**What does seamless mean here?** The default is a brief stop/activate/start protected
by a health gate. Cooperative Unix services can use a configurable HAProxy-style reexec
command: the supervisor preflights the candidate, switches `active-release`, invokes the
command, and requires the same guardian-owned PID plus exact candidate-version health
before committing. Socket continuity is the managed program's master/worker contract,
not hidden updater behavior. Windows uses stop/activate/start. Supervisor replacement
keeps the application running on every platform.

**What happens when the repository is unavailable?** The installed application keeps
running. Transport failures back off and retry; trust failures fail closed and are not
reclassified as ordinary network errors.

## Native desktop applications

The same verified bundle primitives support conventional native desktop applications
such as Discord-style clients. For an update-on-launch product, the application's
installer can place `updated-oneshot` behind its shortcut or login item:

```text
user opens application
  → launcher acquires the update lock
  → reconcile any interrupted replacement
  → refresh and verify signed metadata
  → stage and atomically activate an eligible bundle, if available
  → verify the complete active release against committed state
  → exec the desktop application
```

Network unavailability does not prevent launch: the wrapper verifies and runs the
currently committed bundle. Because activation happens before the GUI process starts,
there is no need to overwrite a running executable or keep a permanent supervisor
alive. Concurrent launches serialize on the same installation lock.

An application with an always-running tray process or background agent can instead use
the bootstrap/supervisor model under a login item, desktop startup host, launchd, or SCM:
request a clean shutdown, activate the verified candidate bundle, start it, and commit
only after an application-specific readiness check succeeds. Multi-process desktop
applications need a launcher-owned shutdown contract so every process releases the
installation before activation.

Production desktop packaging still needs platform integration outside this project:
preserve macOS code signing/notarization and Windows Authenticode packaging, respect
per-user vs. machine-wide permissions, and integrate shortcuts/protocol handlers with the launcher.
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
  Atomic pointer replacement prevents selection of a torn release, and digest checks make
  inconsistent surviving state fail closed.
- The reference deployment runs the updater and managed program under one restricted
  OS identity. A hostile managed program would require a separate account or sandbox.
- Production packaging and signing-key operations are described but intentionally not
  presented as finished infrastructure.

The longer rationale, deployment templates, trust model, on-disk state model, and
configuration reference are in `README.md`, `deploy/README.md`, and
`deploy/config.toml`.
