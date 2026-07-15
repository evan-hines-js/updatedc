# Artifact Bundle Support Plan

## Summary

Bundle support can be added without replacing the updater architecture. The existing
TUF trust chain, release selection, durable journal, boot reconciliation, guardian,
health gate, confirmation window, rejection list, and supervisor self-update all
remain useful.

The fundamental change is to make an immutable **release directory**, rather than one
application binary, the unit of installation and rollback.

The recommended first implementation publishes one archive per supported
OS/architecture, extracts it into an immutable version directory, and atomically
switches a small `active-release` record. If a bundle contains multiple Rust agent
binaries, a small Rust bundle runner can present them to the existing guardian as one
managed application.

## Estimated size and effort

These estimates include production-style error handling and tests consistent with the
current repository.

| Area | Production code | Test code | Notes |
|---|---:|---:|---|
| Bundle manifest and validation | 250-400 lines | 200-300 lines | Schema, hashes, paths, entrypoint, limits |
| Safe archive extraction | 250-450 lines | 250-400 lines | Traversal, links, duplicates, permissions, limits |
| Immutable release-directory store | 350-550 lines | 300-450 lines | Stage, verify, activate, restore, cleanup |
| Generalized state and transaction types | 150-250 lines | 150-250 lines | Release IDs instead of only binary hashes |
| Supervisor and boot integration | 200-350 lines | 250-400 lines | Selection, activation, reconciliation, drift |
| Configuration and publishing changes | 150-250 lines | 100-200 lines | Bundle layout, TUF custom metadata, CLI |
| Bundle runner | 300-500 lines | 250-400 lines | Process group, shutdown, aggregate readiness |
| End-to-end scenarios and fixtures | 50-100 lines | 400-700 lines | Update, crash, rollback, tampering, cleanup |
| **Total** | **1,700-2,850 lines** | **1,900-3,100 lines** | **Approximately 3,600-5,950 lines overall** |

A narrow proof of concept could be around 1,000-1,500 total lines by supporting only
one archive format, stop/start activation, one entrypoint, and minimal cleanup. That
would demonstrate the design.

Expected focused implementation time:

- 3-5 engineering days for a working cross-platform MVP with unit tests.
- 1-2 weeks for repository-quality implementation, failure injection, end-to-end
  coverage, documentation, and real Windows/macOS/Linux validation.
- Additional time for signing/notarization, installer changes, and production soak
  testing. Those are release-engineering tasks rather than core bundle mechanics.

## Proposed on-disk layout

```text
install/
  bootstrap                         # installer-owned and immutable
  guardian-state/
    desired-supervisor
    supervisors/
  application/
    active-release                  # atomically replaced text/JSON record
    versions/
      2.3.0-a31c9f.../
        manifest.json
        bin/
          node-agent
          telemetry-agent
      2.4.0-91be72.../
        manifest.json
        bin/
          node-agent
          telemetry-agent
    staging/
    state/
      installed.json
      transaction.json
      rejected.json
  config/                           # mutable, not part of a release
  data/                             # mutable, not part of a release
```

`active-release` should contain a content-bound release ID, not an arbitrary path. For
example:

```json
{
  "version": "2.4.0",
  "manifest_sha256": "91be72..."
}
```

An ordinary file is preferable to a symlink/junction because the existing durable
atomic-write implementation works consistently across Windows, macOS, and Linux.
Version directories are immutable after staging. Activation never overwrites their
contents.

## Release artifact format

Publish one `.tar.zst` (or ZIP, if preferred for tooling) per platform as a single TUF
target:

```text
agent-suite-2.4.0-linux-x86_64.tar.zst
agent-suite-2.4.0-linux-aarch64.tar.zst
agent-suite-2.4.0-macos-aarch64.tar.zst
agent-suite-2.4.0-windows-x86_64.tar.zst
```

Using one archive avoids a partially acquired multi-target release. TUF already
authenticates the archive's name, length, and SHA-256. The internal manifest provides
defense in depth and describes how to run the bundle.

Example `manifest.json`:

```json
{
  "schema": 1,
  "product": "agent-suite",
  "version": "2.4.0",
  "platform": "windows-x86_64",
  "entrypoint": "bin/bundle-runner.exe",
  "files": [
    {
      "path": "bin/bundle-runner.exe",
      "sha256": "...",
      "size": 1810432,
      "executable": true
    },
    {
      "path": "bin/rust-agent.exe",
      "sha256": "...",
      "size": 5242880,
      "executable": true
    },
    {
      "path": "bin/node-agent.exe",
      "sha256": "...",
      "size": 5242880,
      "executable": true
    }
  ]
}
```

TUF custom metadata should add a release kind and manifest schema while retaining the
current product, channel, OS, architecture, and version policy fields:

```json
{
  "kind": "bundle",
  "manifest_schema": 1
}
```

Single-binary targets remain valid with `kind = "binary"` (or by treating a missing
kind as binary), which gives a backward-compatible migration path.

## Required code changes

### 1. Add bundle domain types to `updated`

Add modules such as:

```text
crates/updated/src/bundle.rs
crates/updated/src/release.rs
```

Core types:

```rust
pub struct ReleaseId {
    pub version: String,
    pub manifest_sha256: String,
}

pub struct BundleManifest {
    pub schema: u32,
    pub product: String,
    pub version: String,
    pub platform: String,
    pub entrypoint: PathBuf,
    pub files: Vec<ManifestFile>,
}

pub struct ManifestFile {
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub executable: bool,
}
```

Responsibilities:

- Parse with a documented schema and reject unknown incompatible schema versions.
- Validate product, version, platform, and entrypoint.
- Enforce maximum archive size, expanded size, file count, and individual file size.
- Calculate a stable manifest digest and derive the release directory name.
- Verify that the extracted tree exactly matches the manifest.
- Reject missing, duplicate, and unexpected files.

### 2. Implement safe staging and extraction

Add a staging API to `updated`, near the existing `apply` functionality:

```rust
pub fn stage_bundle(
    archive: &Path,
    staging_root: &Path,
    expected: &ExpectedRelease,
    limits: &BundleLimits,
) -> io::Result<StagedRelease>;
```

It must:

1. Create a unique staging directory on the same filesystem as `versions/`.
2. Parse and validate the manifest before activation.
3. Stream extraction rather than loading the archive into memory.
4. Reject absolute paths, `..`, platform prefixes, and path escape after joining.
5. Reject symlinks, hard links, devices, FIFOs, and other non-regular entries for v1.
6. Reject duplicate paths and case-fold collisions relevant to Windows/macOS.
7. Enforce compressed and expanded byte limits and file-count limits.
8. Create files without following links and with restrictive initial permissions.
9. Verify every file's size and SHA-256 while extracting.
10. Set executable permissions from the manifest on Unix.
11. Reject undeclared archive members and missing declared members.
12. Flush files and directories where supported.
13. Atomically rename the complete staging directory into `versions/<release-id>`.
14. Remove incomplete staging directories on ordinary errors; leave enough journaled
    evidence for recovery once activation begins.

Archive parsing is the main new dependency. Prefer a small, actively maintained Rust
implementation with streaming support and no external system library requirement.

### 3. Generalize application paths

`Config::resolve_paths` currently derives `download`, state, and rollback locations
from `application.command[0]`. Add a configured application installation root:

```toml
[application]
kind = "bundle"
install_root = "/var/lib/agent-suite/application"
command = ["bin/bundle-runner"]
```

Extend `Paths` with:

```rust
pub install_root: PathBuf,
pub versions: PathBuf,
pub staging: PathBuf,
pub active_release: PathBuf,
pub download: PathBuf,
```

For bundle applications, `command[0]` is relative to the active version directory.
Arguments remain configuration and are not interpolated from untrusted manifest data.

The existing binary path resolution remains unchanged when `kind = "binary"`.

### 4. Generalize installed state and the transaction journal

The current state records one SHA-256 and `Transaction` records `old_sha256` and
`new_sha256`. Introduce an artifact identity while preserving deserialization of old
records:

```rust
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArtifactId {
    Binary { sha256: String },
    Bundle { release: ReleaseId },
}

pub struct Transaction {
    pub old: Option<ArtifactId>,
    pub new: ArtifactId,
    pub from_version: Option<String>,
    pub to_version: String,
}
```

`InstalledState` and `Pending` receive the corresponding artifact IDs. Old JSON with a
top-level `sha256` must continue to decode as `ArtifactId::Binary` so existing clients
can upgrade their supervisor before receiving a bundle.

The journal does not need a detailed phase field if recovery remains derived from
durable disk facts, as it is today. For bundles those facts are:

- The active-release record.
- Presence and validity of the old release directory.
- Presence and validity of the new release directory.
- The installed state.
- The transaction journal.

### 5. Extend the `Store` port rather than bypassing it

The current `Store` trait is the right seam, but its binary-specific methods need
artifact-level equivalents. One possible shape is:

```rust
trait Store {
    fn installed(&self) -> Installed;
    fn journal(&self) -> io::Result<Option<Transaction>>;
    fn active_artifact(&self) -> io::Result<Option<ArtifactId>>;
    fn rollback_artifact(&self) -> io::Result<Option<ArtifactId>>;
    fn is_rejected(&self, digest: &str) -> bool;

    fn commit_installed(&mut self, state: &InstalledState) -> io::Result<()>;
    fn write_journal(&mut self, tx: &Transaction) -> io::Result<()>;
    fn clear_journal(&mut self) -> io::Result<()>;
    fn reject(&mut self, digest: &str) -> io::Result<()>;
    fn clear_rejection(&mut self, digest: &str) -> io::Result<()>;

    fn verify_active(&self, expected: &ArtifactId) -> io::Result<()>;
    fn activate_staged(&mut self, expected: &ArtifactId) -> io::Result<()>;
    fn restore_committed(&mut self, expected: &ArtifactId) -> io::Result<()>;
    fn drop_rollback(&mut self);
}
```

Implementation options:

- Keep one `FileStore` that dispatches on `ArtifactId`. This minimizes call-site churn.
- Split it into `BinaryStore` and `BundleStore` behind the same trait. This gives
  cleaner internals and is preferable once bundle behavior stabilizes.

`MemStore` must model both variants so the existing state-machine and fault-injection
tests continue to operate without filesystem setup.

For a bundle:

- `active_artifact` reads and validates `active-release`.
- `verify_active` verifies the manifest and complete immutable directory.
- `activate_staged` atomically writes `active-release` to the candidate ID.
- `restore_committed` atomically writes it back to the predecessor ID and verifies it.
- `drop_rollback` marks the predecessor eligible for garbage collection; it need not
  synchronously delete a large directory on the confirmation path.

### 6. Reuse `apply_update`

`supervisor::update::apply_update` is already expressed mostly in terms of the `Store`,
`Control`, and `Health` ports. Change its SHA argument to an artifact identity:

```rust
pub(crate) async fn apply_update<T: Control + Health>(
    tower: &mut T,
    store: &mut dyn Store,
    candidate: &ArtifactId,
    to_version: &str,
    from_version: Option<&str>,
) -> io::Result<Outcome>;
```

The sequence remains:

1. Refuse to start if an old journal is unreconciled.
2. Write the old/new transaction.
3. Stop or quiesce the application.
4. Activate the staged artifact.
5. Re-verify the active artifact.
6. Start the application.
7. Require health and version proof.
8. Commit installed state with pending rollback intent.
9. Clear the journal.
10. Retain the predecessor until the confirmation window passes.

The chaos boundaries can retain their meaning. Rename `BINARY_SWAPPED` to an
artifact-neutral name such as `ARTIFACT_ACTIVATED`, while accepting the old environment
name temporarily if external tests use it.

### 7. Adapt boot planning and reconciliation

`Situation`, `BinaryFix`, and the boot planner currently reason about live and rollback
binary hashes. Generalize them to artifact IDs and artifact actions:

```rust
pub enum ArtifactFix {
    None,
    RestoreCommitted { artifact: ArtifactId },
}
```

The decision table remains the same:

| Journal | Active artifact | Installed artifact | Result |
|---|---|---|---|
| None | Matches installed | Same | Normal boot |
| None | Differs | Same | Restore predecessor if valid, otherwise fail closed |
| Present | Old | Old | Activation did not commit; discard candidate/journal |
| Present | New | Old | Interrupted before state commit; restore old |
| Present | New | New | State committed; clear spent journal |
| Any | Unverifiable | Any | Fail closed unless verified predecessor can be restored |

A pending bundle that crashes within its confirmation window switches
`active-release` back, records the candidate archive/manifest digest as rejected, and
restarts the predecessor exactly as the current binary rollback does.

### 8. Extend TUF selection and publication

`VerifiedTarget.custom` already carries the metadata needed to distinguish artifacts.
Extend `SelectedRelease`:

```rust
pub enum ReleaseKind {
    Binary,
    Bundle { manifest_schema: u32 },
}

pub struct SelectedRelease {
    pub target: VerifiedTarget,
    pub version: String,
    pub sha256: String,
    pub kind: ReleaseKind,
}
```

`stage_release` should continue downloading to a durable temporary path. Bundle
extraction happens only after the TUF-authenticated archive finishes downloading.

Extend the repository publisher/server CLI to accept bundle targets and populate the
custom metadata. No new online server service is required: the existing static TUF
metadata and target origins remain sufficient.

Reject a target when:

- Its `kind` is unsupported.
- Its manifest schema is unsupported.
- Its custom metadata disagrees with the internal manifest.
- Its platform selection does not match the client.

Continue keying rejections by authenticated target digest. A corrected republish of
the same semantic version with new bytes can therefore be selected, preserving current
behavior.

### 9. Resolve the active entrypoint at launch time

The guardian ultimately needs an absolute program path. For a bundle, the supervisor
resolves:

```text
versions/<active-release>/<configured relative command>
```

It must canonicalize the version directory and entrypoint and prove that both remain
inside the expected immutable release directory. The command must identify a file
declared executable in the verified manifest.

Pass that path through the existing guardian launch/replace control boundary. If the
control request already transports an arbitrary program path, only the supervisor's
path resolution changes. Otherwise, extend the protocol with a backward-compatible
optional bundle-relative command or a new capability-negotiated request version.

Do not make the guardian parse archives or trust manifests. Its job remains process
custody; the supervisor supplies an already verified absolute entrypoint.

### 10. Add a bundle runner

For the initial implementation, ship a small Rust executable as the bundle entrypoint:

```text
guardian
  -> bundle-runner
       -> node-agent
       -> telemetry-agent
```

The bundle runner should:

- Read a declarative component list from the verified manifest or a separate verified
  bundle configuration.
- Start each required child without a shell.
- Pass only configured environment variables and external config/data paths.
- Put children into the appropriate Unix process group or Windows Job Object.
- Forward graceful shutdown and enforce a bounded forced-stop timeout.
- Treat an unexpected required-child exit as bundle failure.
- Expose aggregate readiness/health and the release version expected by the supervisor.
- Emit component-qualified logs.
- Avoid restarting a permanently failing child forever inside the confirmation window;
  surface failure so the existing updater rollback policy can act.

This keeps the guardian and supervisor responsible for one managed process. A future
version can extend the control protocol for independently managed components if the
product needs partial restarts or per-agent rollout policy.

### 11. Garbage collection

Garbage collection must never remove:

- The active release.
- The pending rollback predecessor.
- Any release named by an active transaction journal.
- A directory currently being staged.

After confirmation, retain the active release and a configurable number of previously
confirmed releases, subject to a disk budget. Run deletion asynchronously or during a
later maintenance tick so confirmation does not block on deleting a large release
tree.

On startup, safely remove abandoned staging directories older than a configured age,
provided no journal references them.

### 12. Preserve the oneshot mode

`updated-oneshot` can support bundles with the same store and release abstractions:

1. Acquire the existing instance lock.
2. Reconcile any transaction.
3. Download and stage a bundle.
4. Write the journal.
5. Change `active-release`.
6. Verify and commit installed state.
7. Execute the resolved bundle entrypoint.

As today, oneshot cannot health-monitor a candidate after replacing itself unless it
remains as a parent process. Document that limitation or initially restrict bundle
health-confirmation support to supervised mode.

## Compatibility and rollout sequence

Bundle support should be deployed in two releases:

### Phase 1: bundle-capable infrastructure, still publishing binaries

- Deploy a supervisor that can deserialize both old and new state/journal formats.
- Add artifact-neutral store and boot-planning behavior.
- Retain the existing binary installation path as the default.
- Add bundle configuration validation but do not enable it for clients.

### Phase 2: publish bundle targets

- Publish `kind = "bundle"` targets only after the installed supervisor reports a
  bundle-capable control/state schema.
- Configure an `install_root` and relative bundle entrypoint.
- Let the first bundle update transition from `ArtifactId::Binary` to
  `ArtifactId::Bundle` while retaining the old binary as the pending predecessor.
- Confirm and garbage-collect the old binary only after the normal health window.

If mixed binary-to-bundle rollback makes the first implementation too risky, require
the installer to provision an initial bundle directory and make bundle mode a fresh
installation boundary. That reduces migration code but is less seamless.

## Required tests

### Manifest and extraction unit tests

- Valid archive stages to the expected release ID.
- Absolute and parent-traversal paths are rejected.
- Symlinks, hard links, device files, and duplicate paths are rejected.
- Case-fold path collisions are rejected.
- Missing, extra, truncated, oversized, and hash-mismatched files are rejected.
- Unsupported schema/product/platform is rejected.
- Executable permissions are applied on Unix.
- Extraction failure never creates an activatable version directory.

### Store and transaction tests

- Activation atomically changes only `active-release`.
- Old and new release directories remain immutable.
- Rollback switches back to the exact predecessor.
- Active-record corruption fails closed.
- Missing/corrupt active directory restores a verified predecessor when possible.
- Garbage collection preserves all live transaction references.
- Old binary state and journal JSON remain readable.

### Existing state-machine tests

Run the current planner and transaction tests against both binary and bundle artifact
fixtures. Preserve fault injection at every existing chaos boundary and add failures
during extraction and active-record replacement.

### End-to-end scenarios

- Bundle update starts every configured Rust agent binary.
- Both report the expected release version.
- A bad child causes aggregate health failure and rollback.
- A crash during the confirmation window rolls back on boot.
- A tampered archive is rejected by TUF before extraction.
- A valid archive with malicious paths is rejected locally.
- A valid archive with a bad internal file hash is rejected locally.
- Killing the supervisor at every transaction boundary converges safely.
- Supervisor self-update still works while managing a bundle.
- Windows SCM, launchd, and systemd stop/restart behavior remains clean.
- A bundle remains usable when the update origin is unavailable.

## Security and operational decisions

The following decisions should be explicit before implementation:

1. **Archive format:** assume `tar.zst` for streaming and cross-platform consistency.
2. **Rust linkage:** prefer self-contained binaries and explicitly package any required
   dynamic libraries or external assets in the manifest.
3. **Code signing:** TUF authenticates distribution, but macOS notarization and Windows
   Authenticode may still be required by deployment policy.
4. **Migrations:** require backward-compatible data migrations during the rollback
   window; irreversible migrations need a separate coordinated mechanism.
5. **Mutable data:** prohibit writes inside immutable version directories.
6. **Configuration:** keep operator configuration outside the signed bundle unless the
   release owns a separate default configuration that is copied, never edited in place.
7. **Disk budget:** set archive, expanded-tree, staging, and retained-release limits.
8. **Bundle identity:** use the authenticated archive digest for rejection and the
   manifest digest for the installed directory identity; persist both if operational
   diagnostics need the mapping.

## Non-goals for the first version

- Delta or peer-to-peer downloads.
- Updating individual files in an active bundle.
- Independent rollout channels for components within one bundle.
- Hot reload of arbitrary multi-process bundles.
- Automatic rollback of irreversible database migrations.
- Arbitrary lifecycle scripts executed as a shell.
- Sharing files between immutable release directories through links.

These can be added later without changing the immutable-directory and active-record
model.

## Definition of done

Bundle support is ready when:

- A TUF-authenticated archive can be selected, bounded, downloaded, safely extracted,
  and completely verified on all supported platforms.
- Activation changes one durable active-release record rather than mutating live files.
- Every existing transaction interruption point converges to either the verified old or
  verified new release.
- A failed health check and a crash within the confirmation window restore the complete
  predecessor bundle.
- All configured Rust agents are launched and stopped as one process tree.
- The old single-binary configuration and state remain supported through the migration
  release.
- Unit, fault-injection, cross-platform E2E, Windows SCM, launchd, and systemd tests pass.
- The deployment documentation covers directory ownership, disk limits, code signing,
  external config/data, and migration compatibility.
