# Bundle-Only Installation Design

## Decision

`updated` installs exactly one artifact type: a signed application bundle.

A bundle is a platform-specific archive containing an immutable release directory,
including its executable entrypoint and any release-owned configuration or assets.
Installation stages and verifies the complete directory, then atomically changes one
`active-release` record. Rollback changes that record back to the verified predecessor.

There is deliberately no single-binary mode, artifact-kind enum, compatibility decoder,
binary-to-bundle migration, or mixed rollback. This project is pre-launch: existing state
may be deleted and installations reseeded with an initial bundle.

The existing TUF trust chain, release selection, guardian, health gate, confirmation
window, rejection list, durable journal, boot planner, supervisor self-update, and chaos
testing remain. Their application artifact vocabulary changes from a mutable executable
to an immutable release directory.

## Why this is the only installation model

An executable rarely remains the complete product forever. It eventually acquires
templates, schemas, web assets, helper programs, default policy, or dynamic libraries.
Treating the directory as the release unit gives all of those files the same trust,
activation, confirmation, and rollback boundary.

The model also improves a one-executable application:

- activation is a small atomic pointer write rather than replacement of live bytes;
- old and new releases coexist and remain independently verifiable;
- rollback never reconstructs a directory file by file;
- Windows executable locks do not affect application activation;
- a crash cannot expose a partially populated active release;
- the state machine has one artifact identity and one recovery path.

## Scope

The first implementation supports:

- one `.tar.zst` archive per OS and architecture;
- one strict manifest schema;
- regular files and directories only;
- one application entrypoint;
- portable stop/start activation and opt-in Unix HUP/re-exec activation with the
  existing same-PID, socket-preserving zero-downtime guarantee;
- immutable release-owned files;
- external mutable operator configuration and application data;
- health-gated commit and confirmation-window rollback;
- bounded retention and garbage collection.

The first implementation does not support:

- legacy binary targets or state;
- multiple archive formats;
- symlinks, hard links, devices, FIFOs, or sockets in bundles;
- lifecycle shell scripts;
- delta updates;
- mutation inside an installed release;
- independent component rollout channels;
- irreversible data migrations;
- arbitrary multi-process orchestration.

A bundle runner should be added only when a real product requires multiple coordinated
processes. It is not part of the initial bundle mechanism.

## On-disk layout

```text
install/
  bootstrap                         # installer-owned, permanent guardian
  guardian-state/
    desired-supervisor
    supervisors/
  application/
    active-release                  # atomically replaced ReleaseId record
    versions/
      2.3.0-a31c9f.../
        manifest.json
        bin/
          application
        config/
          release.toml
      2.4.0-91be72.../
        manifest.json
        bin/
          application
        config/
          release.toml
    staging/
    state/
      installed.json
      transaction.json
      rejected
  config/                            # mutable operator configuration
  data/                              # mutable application data
```

`versions/` and `staging/` must be on the same filesystem so a completely verified
staging directory can be renamed into place atomically. Release directories become
read-only after staging and are never edited or reused.

`active-release` is an ordinary strict JSON record rather than a symlink or junction, so
the existing durable atomic-write primitive works consistently across supported systems:

```json
{
  "version": "2.4.0",
  "manifest_sha256": "91be72..."
}
```

The directory name is derived from this content-bound identity. It is never accepted as
an arbitrary path.

## Release-owned and operator-owned configuration

The distinction is explicit:

- Release-owned configuration is part of the signed bundle, immutable, and rolls back
  with the release. Examples include embedded schema versions, default rules, or the
  sample application's release identity.
- Operator configuration lives outside `versions/`, remains mutable, and is never
  overwritten by an update. Examples include listen addresses, credentials, and local
  policy.
- Application data also lives outside `versions/`.

The supervisor launches the entrypoint with the active release directory as its working
directory. Relative release-owned paths therefore resolve within that immutable tree.
Any external operator-config or data paths are passed explicitly as absolute arguments or
environment variables.

## Same-PID zero-downtime activation

Stop/start remains the portable default. A Unix service with a HAProxy-like master/worker
interface uses the single structured reexec path:

```toml
[application.activation]
mode = "reexec"
preflight_command = ["{candidate}/bin/app", "--check"] # optional
command = ["kill", "-HUP", "{pid}"]
```

Preflight happens before any durable or live mutation. The activation command is arbitrary
argv and is applied symmetrically on upgrade and rollback; health, expected-version proof,
unchanged guardian ownership, and durable rejection constrain its outcome.

The immutable-directory model changes one detail: a running process cannot re-exec its
original `argv[0]`, because that path still names the predecessor release. A reload-capable
application must instead know the stable application install root. On HUP it:

1. stops accepting new work while retaining its listening socket;
2. drains in-flight requests;
3. reads the stable `active-release` record;
4. resolves the candidate manifest and entrypoint beneath `versions/<release-id>`;
5. changes its working directory to that candidate release directory;
6. `exec`s the candidate entrypoint in the same PID while preserving the listener;
7. starts serving with release-owned files, including `config/release.toml`, from the
   candidate directory.

The supervisor remains the authority that validates and activates the candidate before
signalling HUP. The application's pointer read is a cooperative handoff mechanism, not a
second installation policy: it accepts only the exact current `active-release` and fails
closed if it cannot resolve it. The stable install-root path is supplied at initial launch
through a dedicated argument or non-secret environment variable and remains unchanged
across releases.

Forward activation is:

1. stage and completely verify the candidate bundle;
2. write the transaction journal;
3. atomically switch `active-release` to the candidate;
4. execute the configured reload command, normally HUP;
5. require health to report the candidate version read from the candidate's bundled config;
6. commit installed state only after that proof.

If reload execution or candidate health fails, the supervisor atomically switches
`active-release` back to the predecessor, sends HUP again, and requires the same PID to
report the predecessor's bundled-config version before recording rollback. Thus rollback
is zero-downtime as well. A reload-capable app that exits instead of completing either
handoff falls into the existing guardian crash and boot-recovery path.

The supervisor must never treat PID continuity, a successful `kill`, or generic health as
version proof. Reload health must include the exact expected release version because the
launch token does not change during a same-PID re-exec.

## End-to-end sample application

The E2E application must demonstrate a real directory release rather than a binary
wrapped in an archive.

Each published sample bundle contains:

```text
manifest.json
bin/sampleapp[.exe]
config/release.toml
```

`config/release.toml` contains the release version:

```toml
version = "2.0.0"
```

The sample application reads `config/release.toml` at startup and reports that value from
its health/version endpoint. Its reported version must not come from a compile-time
constant, command-line version flag, environment variable, executable filename, or TUF
metadata.

On Unix, the sample's re-exec mode also receives the stable application install root. Its
HUP handler re-reads `active-release`, resolves the newly active sample entrypoint, changes
to that release directory, and re-execs it while preserving the listening socket. It must
not reuse the executable path or working directory captured at the predecessor's startup.

Prefer using the same sample-app executable bytes across multiple fixture releases while
changing only `config/release.toml`. This proves that selection, activation, health
verification, confirmation, and rollback operate on the bundle identity and its assets,
not accidentally on an executable hash.

The current E2E scenarios retain their behavioral assertions with bundle facts:

- initial provisioning activates the installer-seeded bundle;
- unattended update switches the active release and the app reports the new config value;
- failed health restores the predecessor directory and its config value;
- a post-health crash within the confirmation window restores the predecessor;
- rejection is keyed by authenticated archive digest;
- drift/tampering of any manifested file fails closed;
- transaction-boundary chaos converges to one complete verified release;
- supervisor crash and self-update preserve the running application;
- locking prevents concurrent activation;
- one-shot execution resolves the entrypoint from the active bundle.

## Archive and manifest

Publish one `.tar.zst` target per platform:

```text
products/app/stable/2.4.0/linux-x86_64/bundle.tar.zst
products/app/stable/2.4.0/linux-aarch64/bundle.tar.zst
products/app/stable/2.4.0/macos-aarch64/bundle.tar.zst
products/app/stable/2.4.0/windows-x86_64/bundle.tar.zst
```

TUF authenticates the archive name, size, digest, version, product, channel, OS, and
architecture. There is no `kind` field because every application release is a bundle.

The archive contains a strict `manifest.json`:

```json
{
  "schema": 1,
  "product": "app",
  "version": "2.4.0",
  "platform": "linux-x86_64",
  "entrypoint": "bin/application",
  "files": [
    {
      "path": "bin/application",
      "sha256": "...",
      "size": 5242880,
      "executable": true
    },
    {
      "path": "config/release.toml",
      "sha256": "...",
      "size": 18,
      "executable": false
    }
  ]
}
```

The schema rejects unknown fields and any schema number other than the one implemented.
The manifest itself is not listed as a file; its canonical bytes are hashed to form the
`manifest_sha256` in `ReleaseId`.

The manifest must agree with authenticated TUF metadata for product, version, and
platform. The entrypoint must name exactly one declared executable regular file.

## Core domain model

The shared `updated` crate owns the only application artifact vocabulary:

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
    pub entrypoint: RelativePath,
    pub files: Vec<ManifestFile>,
}

pub struct ManifestFile {
    pub path: RelativePath,
    pub sha256: String,
    pub size: u64,
    pub executable: bool,
}
```

`RelativePath` is validated at construction and cannot represent an absolute path,
prefix, empty component, `.` component, or `..` component.

There is no `ArtifactId`, `ReleaseKind`, `Binary` variant, or dispatch by installation
kind. `ReleaseId` is used directly everywhere.

## Strict durable state

All durable records have one current schema and reject missing or unknown fields.

```rust
pub struct InstalledState {
    pub release: ReleaseId,
    pub archive_sha256: String,
    pub pending: Option<Pending>, // field required; value may be null
}

pub struct Pending {
    pub previous_release: ReleaseId,
    pub previous_archive_sha256: String,
    pub committed_at: u64,
}

pub struct Transaction {
    pub previous_release: ReleaseId,
    pub candidate_release: ReleaseId,
    pub candidate_archive_sha256: String,
}
```

State from the binary implementation is invalid by design. Development and test state is
deleted; installers seed a complete initial bundle and current records.

The archive digest is the rejection identity because it is authenticated before local
parsing. The manifest digest identifies the immutable installed tree. Persisting both
makes their relationship explicit and diagnosable.

## Safe staging and extraction

`updated` exposes one staging operation:

```rust
pub fn stage_bundle(
    archive: &Path,
    roots: &ReleaseRoots,
    expected: &ExpectedRelease,
    limits: &BundleLimits,
) -> io::Result<StagedRelease>;
```

It must:

1. Create a uniquely named, owner-only staging directory beneath `staging/`.
2. Stream decompression and extraction without loading the archive into memory.
3. Enforce compressed size, expanded size, file count, path length, and per-file limits.
4. Reject absolute paths, platform prefixes, empty components, `.`, `..`, and escapes.
5. Reject symlinks, hard links, devices, FIFOs, sockets, sparse files, and unknown types.
6. Reject duplicate paths and Unicode/case-fold collisions relevant to supported filesystems.
7. Create new files without following links and with restrictive initial permissions.
8. Require `manifest.json` exactly once and parse its strict schema.
9. Verify manifest identity against TUF-authenticated product, version, and platform.
10. Hash and size-check every declared file while extracting.
11. Reject missing, undeclared, reordered-conflicting, or trailing archive members.
12. Apply executable permissions from the manifest on Unix; ignore archive mode bits.
13. Verify the entrypoint is a declared executable regular file within the release.
14. Flush files and directories where supported.
15. Atomically rename the complete staging directory to `versions/<release-id>`.
16. Treat an existing destination as valid only after complete re-verification.

No extraction code may canonicalize through attacker-controlled links. Validation and
creation operate component by component beneath an already-open trusted staging root.

## Store and activation

The supervisor store becomes release-specific rather than artifact-generic:

```rust
trait Store {
    fn installed(&self) -> Installed;
    fn journal(&self) -> io::Result<Option<Transaction>>;
    fn active_release(&self) -> io::Result<Option<ReleaseId>>;
    fn is_rejected(&self, archive_sha256: &str) -> bool;

    fn verify_release(&self, release: &ReleaseId) -> io::Result<()>;
    fn activate(&mut self, release: &ReleaseId) -> io::Result<()>;
    fn commit_installed(&mut self, state: &InstalledState) -> io::Result<()>;
    fn write_journal(&mut self, tx: &Transaction) -> io::Result<()>;
    fn clear_journal(&mut self) -> io::Result<()>;
    fn reject(&mut self, archive_sha256: &str) -> io::Result<()>;
    fn clear_rejection(&mut self, archive_sha256: &str) -> io::Result<()>;
}
```

There is one `FileStore` and one test `MemStore`. Neither has binary methods or bundle
branches. `activate` only durably replaces `active-release`; it never mutates a version
directory.

## Update transaction

The application update sequence remains one durable transaction:

1. Refuse to begin while an old journal is unresolved.
2. Download the TUF-authenticated archive durably.
3. Safely extract, validate, and publish the immutable candidate directory.
4. Write the transaction naming predecessor, candidate, and archive digest.
5. Stop or quiesce the application.
6. Atomically switch `active-release` to the candidate.
7. Re-verify the active release and resolve its entrypoint.
8. Start it with the release directory as working directory, or signal the existing PID
   to re-read `active-release` and re-exec the candidate entrypoint.
9. Require health and exact version proof. The E2E sample proves the version from its
   bundled config.
10. Commit installed state with pending predecessor intent.
11. Clear the transaction journal.
12. Retain the predecessor until the confirmation window passes.

Extraction happens before the journal because an unreferenced staging failure cannot
affect the active application. Once the journal exists, boot recovery owns every outcome.

## Boot reconciliation

Recovery is derived from durable facts rather than an incremented phase field:

| Journal | Active release | Installed release | Result |
|---|---|---|---|
| None | Matches installed | Same | Verify and launch |
| None | Differs or corrupt | Same | Restore installed release if valid, otherwise fail closed |
| Present | Previous | Previous | Activation did not land; clear journal |
| Present | Candidate | Previous | Restore previous; clear journal after durable restoration |
| Present | Candidate | Candidate | Commit landed; clear spent journal |
| Any | Unverifiable | Any | Restore a verified referenced predecessor or fail closed |

A crash during the pending confirmation window activates the predecessor, verifies it,
commits it as installed, rejects the candidate archive digest, and relaunches. A healthy
candidate surviving the window clears `pending` and makes the predecessor eligible for
garbage collection.

The planner vocabulary becomes `ReleaseFix`/`ReleaseId`; all binary hash and rollback-file
concepts are removed.

## Launch resolution

The supervisor reads `active-release`, locates `versions/<release-id>`, verifies the
manifest, and resolves the manifest entrypoint beneath that exact directory. It passes an
absolute entrypoint and the release directory as `cwd` through the existing guardian
control request.

For reload mode, it instead passes the stable install root to the initially launched
application and invokes the configured reload command after activation. Placeholder and
environment vocabulary becomes release-oriented (`{release}`, `{entrypoint}`, and stable
install root) rather than retaining the obsolete `{binary}` contract. HUP itself remains
the normal command; the application discovers the candidate through `active-release`.

The guardian remains deliberately ignorant of bundles and manifests. It owns processes,
not installation policy. No control-protocol extension is needed because `CommandSpec`
already carries an arbitrary program and working directory.

## Publishing and selection

The publisher accepts a prepared release directory, validates or generates its manifest,
creates a deterministic `.tar.zst`, and publishes it as the platform's application target.
Archive construction must use stable ordering and normalized metadata.

`SelectedRelease` always represents a bundle and contains:

- authenticated target capability;
- semantic version;
- archive SHA-256 and length;
- product, channel, OS, and architecture.

There is no target-kind fallback. A target without the complete current metadata is invalid.

## Garbage collection

Garbage collection may never remove:

- the active release;
- the installed release;
- a pending predecessor;
- either release named by a journal;
- a directory still beneath `staging/`.

After confirmation, retain the active release and a small configurable number of previous
confirmed releases within a disk budget. Cleanup runs outside the commit path. Startup may
remove old abandoned staging directories only after proving that no journal references them.

## One-shot mode

`updated-oneshot` uses the same store, staging, state, transaction, recovery, and entrypoint
resolution code:

1. acquire the instance lock;
2. reconcile a journal;
3. select, download, and stage a bundle;
4. journal and activate it;
5. verify and commit installed state;
6. execute the active entrypoint with the release directory as `cwd`.

As today, one-shot mode cannot observe a post-exec confirmation window. Its install commit
is immediate. Supervised mode remains the choice when health-gated rollback is required.

## Required tests

### Manifest and extraction

- valid archive stages to the expected `ReleaseId`;
- absolute, parent, prefixed, empty, and overlong paths are rejected;
- links and non-regular entries are rejected;
- duplicate and case-fold-colliding paths are rejected;
- missing, extra, truncated, oversized, and hash-mismatched files are rejected;
- unknown manifest fields and schema values are rejected;
- product, version, platform, and entrypoint mismatches are rejected;
- Unix executable permissions come only from the manifest;
- extraction failure never creates an activatable release.

### Store and recovery

- activation changes only `active-release`;
- installed directories remain immutable;
- rollback activates the exact predecessor;
- corrupt active state fails closed;
- a verified predecessor restores a missing or corrupt candidate;
- every journal/active/installed combination follows the recovery table;
- garbage collection preserves every live reference;
- obsolete binary state and journals are rejected.

### End to end

- the sample app reads its version from bundled `config/release.toml`;
- updating changes the reported config version;
- rollback restores the predecessor's reported config version;
- using identical executable bytes across releases still updates correctly;
- Unix HUP reload re-execs the active bundle entrypoint in the same PID and drops no requests;
- HUP rollback re-execs the predecessor bundle in the same PID and proves its config version;
- reload cannot commit when health still reports the predecessor config version;
- tampering with the executable, manifest, or config fails closed;
- malicious archives never publish a version directory;
- health failure and a post-health crash revert and reject the bundle;
- killing the supervisor at every transaction boundary converges safely;
- supervisor crash, self-update, locking, reload where supported, and one-shot behavior remain correct;
- Windows SCM, launchd, and systemd stop/restart behavior remains clean.

## Implementation order

1. Change the sample app to read release version from `config/release.toml`.
2. Add strict manifest, `RelativePath`, `ReleaseId`, limits, and archive extraction.
3. Replace binary paths/state/journal with the bundle-only release model.
4. Replace binary swapping with immutable staging and `active-release` activation.
5. Generalize the boot planner terminology and recovery facts to releases.
6. Update publisher and TUF selection to emit and require bundle targets.
7. Convert supervisor, HUP/re-exec, and one-shot launch resolution.
8. Convert all unit, fault-injection, and E2E fixtures, including zero-downtime reload and rollback.
9. Remove every binary-install module, field, test, flag, and documentation path.
10. Run formatting, strict lint, workspace tests, full E2E, and all platform CI.

Each step must leave only one active design. Temporary compatibility branches should not
be merged.

## Definition of done

Bundle installation is complete when:

- every application target is a TUF-authenticated bundle;
- every bundle is bounded, safely extracted, fully manifested, and immutable;
- activation and rollback each change one durable `active-release` record;
- application state and journals contain only strict bundle release identities;
- every crash boundary converges to one complete verified release;
- health failure and confirmation-window crash restore the complete predecessor;
- the E2E sample reports the version read from its bundled configuration file;
- identical sample executable bytes can represent multiple releases through different signed config;
- Unix HUP update and rollback retain the same PID, preserve the listening socket, prove
  the active bundle's config version, and drop no requests under load;
- no binary installation, migration, target-kind, mixed rollback, or compatibility code remains;
- unit, fuzz/fault-injection, cross-platform E2E, Windows SCM, launchd, and systemd checks pass;
- deployment documentation explains immutable releases, external mutable state, permissions,
  disk limits, and reseeding.
