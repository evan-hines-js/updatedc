# Handoff: `updatectl` + making demo releases run through it

Context for an agent picking up the "releases should execute via `updatectl` in the demo"
task. The `updatectl` CLI and root-rotation support are **built, tested, and green**. The
remaining work is wiring the demo's release execution to go through `updatectl`. This doc
covers both so you have the full picture.

---

## Part 1 — What already exists (done)

### `updatectl` crate — `crates/updatectl/`
A small, CI-facing, Linux-only binary. Three subcommands:

- **`trust-root`** — one-time bootstrap. Generates the ed25519 role keys into a directory,
  initializes the empty TUF **release repository in S3**, and prints `root.json` (the value
  to paste into a group's `release_repository.root_json`). **Needs no Kubernetes access.**
- **`rotate-root`** — mint a successor root key, publish a **co-signed** new root version
  (activate standby, retire old, add fresh standby). Existing devices follow the chain
  automatically. Writes the successor to `--new-key-out`.
- **`deploy`** — per-release. Reads the **online** signing keys from a directory (a
  Vault→Secret→file mount in prod), builds the deterministic `tar.zst` bundle, signs +
  publishes it as a TUF target to S3, then **patches the named `UpdateGroup`'s
  `spec.deployment.application.{path,sha256}`** via a JSON merge patch. Touches k8s only for
  that one patch.

CI-native UX: every flag also reads a `UPDATECTL_*` env var; AWS creds come from
`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`; diagnostics → stderr, machine result → stdout
(`--output text|json`); GitHub Actions step outputs when `$GITHUB_OUTPUT` is set.

Key entry points in `crates/updatectl/src/main.rs`:
- `trust_root()`, `rotate_root()`, `deploy()` — the three commands.
- `build_store()` — wires the S3 `ObjectStore` from `Backend` + AWS env creds (reuses
  `updatec::runtime::s3_store`).
- `download_metadata()` / `repo_initialized()` — S3 metadata mirror + init check.
- `build_bundle()` — dir-or-single-file → `updated::bundle::create_bundle` (mirrors
  `server publish-app`'s single-file wrapping).
- `open_keys()` — resolves **online keys only** (targets/snapshot/timestamp); `deploy`
  deliberately does **not** need the root private keys.

### TUF library changes — `crates/updated-tuf/src/repo.rs`
Root rotation is a **multi-key-root** model (chosen over two independent anchors):

- `Keys` now holds `roots: Vec<PathBuf>` (was a single `root`). `Keys::in_dir` returns
  `root.pk8` plus `root.next.pk8` **if present** (so the operator's single-key assignment
  repo still works unchanged).
- `generate_keys` now mints **two** root keys (`root.pk8` active + `root.next.pk8` standby)
  alongside targets/snapshot/timestamp.
- `generate_root_key(path)` — new; mints one ed25519 key (0600) for a rotation successor.
- `init` registers **all** root keys in the root role (threshold 1) and signs with all.
- `rotate_root(repo_dir, retained, new_root_key, expiry_days)` — new. Builds root vN+1 =
  retained continuity keys + fresh successor, co-signed by the retained keys (authorizes the
  change under the current root) and the new key. Carries the online roles forward untouched.
  Writes `root.json` + `<n>.root.json`. Guards: retained key must be in the current root; new
  key must not already be; non-empty retained set required.

**Why this works without node changes:** `crates/updated-tuf/src/lib.rs` `load_repo` pins the
root and loads with `max_root_updates: 1024` + `ExpirationEnforcement::Safe`, so `tough`
already follows the versioned root chain (`N+1.root.json`, …). The control plane never
verifies signatures — the **node** does, against whatever pinned root the group declares.

### Tests (all green)
- `crates/updated-tuf/tests/rotate.rs` — 10 integration tests authoring real repos and
  verifying through the **real `tough` client** (client pinned to the original root follows
  the rotation; releases survive rotation; sequential rotations; all security guards).
- `crates/updatectl/src/main.rs` `#[cfg(test)]` — 3 tests incl. a full **S3 round-trip
  against an in-memory `ObjectStore`** (publish → download → rotate → re-publish → client
  verifies v2), plus `open_keys` online-only, plus `object_key` prefix normalization.

Run: `cargo test -p updated-tuf --test rotate` and `cargo test -p updatectl`.

### Workspace wiring
- `Cargo.toml`: added `crates/updatectl` member; pinned `clap = { features = ["derive",
  "env"] }`. `updatectl/Cargo.toml` dev-deps: `tough`, `url`.
- Business-facing guide already written: `crates/updatectl/ROLLOUT-SETUP.md`.

### Pre-existing unrelated breakage (NOT mine) — OBSOLETE
This once described a compile break from an `AgentDocument.status: Option<ManagedStatus>` field.
That external-managed-health scaffolding has since been removed (the product manages nodes outside
an orchestrator; nodes self-probe via their signed reconciler), so the field and the break are gone.

---

## Part 2 — The open task: make demo releases execute via `updatectl`

Goal (user's words): *"It should be how releases execute in the demo. Something should be
pushing to CI."* and *"Doesn't need to use a job, can be from the script."* So: the demo's
release path should run `updatectl` (the real CI tool), driven from the demo binary/script
(which plays the CI producer), with the root/signing config mounted.

### How the demo cuts releases TODAY
- **`crates/updatec-demo/src/demo.rs:822` `publish_release(major, broken)`** — the real
  release execution. It builds a bundle tree under `DEMO_REPOSITORY_DATA` (default
  `/release-data`) and shells out to **`/usr/local/bin/server publish-app`** against
  `/release-data/repository` + `/release-data/keys`. Called from the chaos/loop scenarios
  (`demo.rs:459,533,536`).
- **`patch_chaos_groups` (demo.rs ~885)** — shells `server target-sha256`, then patches
  `UpdateGroup`s' `spec.deployment.application`.
- **`crates/updatec-demo/src/publisher.rs` `KubernetesPublisher.publish`** — the "green
  button" path: merge-patches `UpdateRepository` with a pre-baked patch. Triggered via HTTP
  (`server.rs:138` parses a `ReleaseRequest`) → `demo.rs:95 apply()` → `publisher.publish()`.
  `ReleaseRequest::green()` = color-demo 2.0.0.

So the demo binary **is already the "CI"** — it builds+signs releases with `server`. The ask
is to swap `server publish-app`/`server target-sha256`/group-patch for **`updatectl deploy`**
(which does all three in one shot).

### The two TUF repositories (critical distinction)
1. **Assignment repo** — operator's per-agent configs, in **MinIO** bucket `updates`, signed
   by the `tuf-signing-keys` Secret. Root distributed to agents via enrollment. (Operator's,
   leave alone.)
2. **Release repo** — the app bundles. Served by the **`release-server` Deployment over
   HTTP** from local `/data/repository`, built by
   `crates/updatec/e2e/release-server.sh` (`server init` + `server publish-app`). Groups'
   `release_repository.{metadata_url,targets_url,root_json}` point at `release-server`; the
   root is extracted at `scripts/kind-updatec-e2e.sh:190-191` into `resources.yaml` (:212).

### THE key architectural decision for whoever does this
`updatectl` publishes to **S3**. The demo's release repo is currently **release-server on
local disk over HTTP**. To make `updatectl` the release path, pick one:

- **(Recommended) Host the release repo in MinIO.** Give it a bucket/prefix (e.g. reuse
  `updates` with prefix `releases/`, or a new bucket). `updatectl trust-root` bootstraps it;
  agents fetch `release_repository.metadata_url = http://minio:9000/<bucket>/releases/metadata/`
  (+ `targets/`) — MinIO serves objects over HTTP; set the prefix/bucket to anonymous
  download so the agent TUF client can GET them. Then `updatectl deploy` publishes new
  versions and patches the group. `release-server` becomes unnecessary for this app (it may
  still serve magnolia/providers in the broader e2e — scope carefully).
- (Alt) Keep `release-server` but back its `/data` with the same store `updatectl` writes —
  more plumbing, not recommended.

### Concretely, to wire it up
1. **Bootstrap (setup / `kind-updatec-e2e.sh` or demo `setup.rs`):** run
   `updatectl trust-root --keys-dir <dir> --bucket <b> --region us-east-1 --endpoint
   http://minio:9000 --prefix releases --root-out root.json`. Store the keys as a Secret and
   **mount them** into the demo/CI process (the "root config mount"). Put the emitted
   `root.json` into each color-demo group's `release_repository.root_json`, and set its
   `metadata_url`/`targets_url` to the MinIO HTTP URLs.
   - AWS creds: set `AWS_ACCESS_KEY_ID=minio` / `AWS_SECRET_ACCESS_KEY=minio123` in the
     process env (matches `scripts/kind-updatec-e2e.sh:207` `s3-credentials`).
2. **Release execution:** replace `demo.rs publish_release` + `patch_chaos_groups`'s
   `server`-shelling with a shell-out to `updatectl deploy --keys-dir <mounted> --bucket …
   --endpoint http://minio:9000 --prefix releases --namespace updated-system --group <name>
   --product app --channel stable --version <v> --entrypoint bin/app --source <bundle-dir>`.
   `deploy` signs, publishes, and patches the group in one call. (`--source` accepts a dir or
   a single file; single file gets wrapped at `--entrypoint`, mirroring the current tree
   build.) For the "broken" case, pass the corrupt entrypoint dir as `--source`.
3. **"Something pushing to CI":** the existing HTTP trigger (`server.rs`) / automated loop is
   the producer; it should invoke the `updatectl deploy` step (the CI job) instead of the
   merge-patch. Keep it script/subprocess-driven — no k8s Job needed.
4. Optionally demo **`rotate-root`** as a "rotate the signing root" button/step.

### Gotchas
- `deploy` errors if the release repo isn't initialized (`trust-root` must run first) and if
  the `UpdateGroup` doesn't exist (it does `groups.get` first).
- Target path convention (must match what the group/agents expect):
  `products/<product>/<channel>/<version>/<os>-<arch>/<component>`, `component == product`.
  The demo currently uses product `app`, channel `stable`, entrypoint `bin/app`. Keep those.
- `deploy` needs only the **online** keys in `--keys-dir`; root keys stay out of the release
  path (only `trust-root`/`rotate-root` use them). Mount accordingly.
- The demo runs inside a container that already has `/usr/local/bin/server` and
  `/usr/local/bin/sampleapp` and the `/release-data` mount; you'll need `updatectl` on the
  PATH there too (add it to the image build — see `crates/updatec/Dockerfile.e2e`).

---

## Part 3 — UI: show the CI + rotation flow cleanly

The demo already has the **rendering seam**; nothing needs to be re-plumbed to display CI
activity. What's missing is the *content* — the `updatectl`-driven release path must emit
clear events into it. Keep the UI honest: only describe a step once it's actually wired
(don't narrate a CI flow the backend isn't running yet).

### The seam that already exists
- **Audit log** — `ChaosState.events: Vec<String>` (`crates/updatec-demo/src/state.rs:84`),
  served at `GET /chaos` (`server.rs:104`), rendered into `<pre id="events">`
  (`page.rs:293`). Push human-readable strings here at each release step; the UI shows them
  with **no rendering change**.
- **Version cells** — cohort tiles read `reportedVersion` from the control plane
  (`/fleet`, `page.rs:416`). A CI release surfaces automatically as cells advance to the new
  version. Do **not** infer state from version numbers — the control plane is authoritative
  (existing rule, `state.rs:75`).
- **Section framing** — sections carry an "eyebrow" naming their role in the release path
  (`page.rs:52`, e.g. *Service level*, *Fleet*, *Release gate*, *Audit log*). A CI/signing
  step fits as its own eyebrow.

### What the release path should emit (so the log reads as a clean CI story)
Wherever the demo runs `updatectl` (replacing `publish_release`/`patch_chaos_groups`), push
one event per phase, e.g.:
- `CI ▸ building & signing app 23.0.0 (linux-x86_64)`
- `CI ▸ published signed target products/app/stable/23.0.0/linux-x86_64/app (sha 3f9c…)`
- `CI ▸ rolled group edge → 23.0.0`
- rotation: `CI ▸ rotated signing root → v2 (co-signed; fleet follows the chain)`

`updatectl deploy --output json` returns `{target, sha256, version, group, …}` on stdout and
prints progress to stderr — capture stdout and format these events from it, so the log line
matches exactly what was published.

### Optional affordances (only once wired)
- A **"Release path / CI"** status line in the masthead `.status-strip` (`page.rs:194`) or a
  dedicated eyebrow section showing the last CI action (`last release: 23.0.0 signed &
  rolled · 12s ago`), sourced from a new field on the demo state the release code sets.
- A small **`root vN`** badge so a rotation is visibly reflected (the current signing-root
  version), reinforcing that the fleet kept converging across a rotation with no flag day.
- Update the intro narrative (`page.rs:201-210`) to name the signing/CI step in the release
  path — **after** the flow is wired, so the page never claims a step that isn't running.

### Why no UI-renderer change is strictly required
The audit log + control-plane-sourced version cells already visualize "what's happening."
The clean-UI work is (a) emit the CI/rotation events above, and (b) optionally add the
status affordances. Both belong with the release-wiring change, which is why they're here
rather than done separately — doing them without the wiring would show an empty or
misleading story.

---

### Useful references
- CLI: `crates/updatectl/src/main.rs` (help text documents every flag).
- UI + state seam: `crates/updatec-demo/src/{page.rs,state.rs,server.rs}` (`ChaosState.events`,
  `/chaos`, `#events`, cohort version cells).
- Demo release code: `crates/updatec-demo/src/{demo.rs,publisher.rs,server.rs,setup.rs}`.
- Kind/MinIO/secrets/release-server: `scripts/kind-updatec-e2e.sh`
  (MinIO :95-103, release-server :125-206, secrets :206-207, resources :212).
- Existing baked release build: `crates/updatec/e2e/release-server.sh`.
- Typed CR generation the demo/e2e uses: `crates/updatec/examples/kind_resources.rs`.
- Business/ops framing of the whole flow: `crates/updatectl/ROLLOUT-SETUP.md`.
