# Cold-install crash-safety redesign — adversarial review

Review of the change set that (a) fixed the ordered-fallback descent and (b) replaced the
side-channel `install-unproven` marker with a `confirmed` bit on the install record.

## Fixed in this pass

- **Descent bug (`ordered_install_fallback=false` on the initial assignment).** The cold node
  could not descend past a broken assigned head. Root cause: `republish_assignment`
  (`crates/e2e/src/main.rs`) built the `publish-assignment` command *without* the
  `--ordered-install-fallback` marker check that `Ctx::publish_current_assignment` had — the
  initial assignment (the one a cold node resolves) shipped with the flag off, so the supervisor
  took the exact-pin branch, which returns `None` when the pinned bytes are rejected. Fixed by
  adding the marker check to `republish_assignment`. See **D2** for the underlying duplication.

- **Side-channel `install-unproven` marker removed.** The provisional-vs-confirmed state is now a
  `confirmed: bool` on `InstalledState`, atomic with the install record instead of a separate file
  that could desync. Cold install commits `provisional` (`confirmed: false`); the first passing
  health gate flips it via `state.confirm()`. The two reject sites (crash-at-boot, wedge-at-gate)
  now share one helper, `reject_provisional_head`, which no-ops on a confirmed head. Deleted
  `mark/clear/is_install_unproven` from the `Store` trait, `FileStore`, and the test store.

- **e2e diagnostics** now print `confirmed=` per node so a stuck descent is diagnosable.

## Verified safe (no change needed)

- **No hand-written `installed.json` fixtures.** Every write goes through `commit_installed` /
  `write_installed` via `InstalledState::confirmed|provisional`, so the new required field is
  always present; no embedded-JSON record fixture omits it.
- **Rollback / pending-confirm commits** rebuild `plan.commit` via `InstalledState::confirmed(...)`
  (proven predecessor → `confirmed: true`), so recovery never demotes a head to provisional.
- **Descent converges** within the 90s scenario cap: each broken level costs two boots
  (launch→crash, then reject→descend); three levels ≈ five boots, inside the guardian backoff.

## Second round — five parallel adversarial reviewers (supervisor / updated / TUF / e2e / operator+demo)

TUF-selection and e2e-integrity came back **clean** (no bypass/downgrade/bad-target; the descend
scenario genuinely gates on the feature with two distinct archive shas). The core `confirmed`
redesign was independently confirmed sound: the crash-reject never preempts rollback recovery, the
descent is idempotent and lineage-scoped, `confirmed` is correct on every commit path, and
`take_service_exit_marker`'s consume-semantics avert a runaway-descent brick.

Fixed this round:

- **THE fleet baseline-rejection root cause: a stale `service_exited` marker rejected the
  freshly-descended head before it launched.** Live agent log: `cold-installed application 22.0.0`
  immediately followed by `provisional head 22.0.0 crashed with no pending update; rejected` — with
  *no* launch line between. The crash-reject at `main.rs` fired on the exit marker left by the
  *previous* head (23.0.0's corrupt-entrypoint crash), attributing it to the just-installed 22.0.0.
  Fix: gate it `&& !situation.first_install` — a head installed this boot hasn't run, so a
  service-exit marker is always the prior head's. This stranded fresh/pod-killed nodes in broken
  cohorts on the healthy 22.0.0 baseline. (Requires a supervisor image rebuild to deploy.)

- **Related root cause: a descend *adopted the stale wedged process* instead of
  launching the freshly-installed bytes.** After `ensure_installed` re-installs a lower release, the
  guardian may still be holding the previous head's process (a wedged head stays alive — unlike a
  crash, which leaves nothing). `plan_boot` then took `Acquire::Adopt(pid)` on that stale pid,
  health-gated the *wrong* release, and rejected the just-installed release's bytes — so a fresh
  pod cold-installing a broken cohort would reject even the healthy baseline (22.0.0 in the demo)
  and strand once ordered fallback exhausted everything at/below the ceiling. Fix: a boot that
  (re)installed this cycle (`Situation.first_install`) now sets `quiesce` so the stale process is
  stopped and the freshly-installed bytes are launched — never adopted. Unit-tested in `boot.rs`
  (`a_reinstall_launches_fresh_and_stops_a_kept_alive_stale_process`, plus a guard that a plain
  restart still adopts). This only bit the **wedge** descent; the crash descent leaves no live
  process, which is why the crash e2e passed and the demo (wedged heads) did not.

- **Rollback dropped the restored predecessor's providers.** The three revert paths in `boot.rs`
  (`pending_revert_in_progress`, `reconcile_transaction`'s `is_rollback`, `confirm_or_revert`'s
  service-exit revert) committed the predecessor via bare `InstalledState::confirmed(...)`, losing
  its `lifecycle`/`healthcheck`/`process` refs — so a rolled-back custom deployment ran with no
  crash-watch and no provider health. Now all three carry the providers from `pending`/`tx`, like
  the confirm branch already did. **Rollback e2e (provider-failure-rollback, rollback-chaos,
  magnolia-shaped-rollback, selfupd-rollback) should be re-verified** — behavior is unchanged when
  providers are `None`, which is why unit tests stayed green.
- **`confirmed`/`pending` invariant now enforced** in `InstalledState::validate` — a provisional
  head must not carry a pending rollback.
- **Lying drain-hold doc comments corrected** (`config.rs` `drain_hold_seconds` + `ManagedStatus`,
  `update.rs` `DrainHold`) to describe *actual* behavior instead of unbuilt validation/early-exit.
- **`updatec/src/runtime.rs:826`** test-literal `TimeoutsSpec` was missing `drain_hold_seconds` —
  it broke the coverage/test compile (regular build didn't hit it). Fixed; full `cargo check
  --workspace --tests` is now clean.
- **TUF `roundtrip.rs:100`** indentation nit fixed.

## Open items (discussion / follow-up)

- [x] **D0 — Stateless (emptyDir-wipe) fuzz coverage. DONE.** The existing chaos only crashed with
  a *surviving* state dir (journal replay); nothing exercised the emptyDir-wipe → repeated
  cold-install/descend path where the stale-marker and adopt-stale bugs lived — which is why the
  *demo's* pod-kill chaos found them, not the suite. Added `stateless_descend_fuzz`
  (application.rs): a broken assigned head above a broken 2.0.0 and healthy floor 1.0.0, then a
  deterministic-LCG loop that deletes the whole install root at random points in the descent
  (8 pod-kills) and asserts the node never strands with "no installable application", plus a final
  untouched pod that must converge to 1.0.0 and settle. Green requires both descend fixes; red
  without them.

- [x] **D14 — Provider-hook HANG fuzz. DONE.** `provider_failure_case` covered a clean
  exit-nonzero at every phase; the other failure mode — a hook that *wedges and never returns* —
  was untested. Added `provider_hook_hangs_are_bounded` + a `hang-{phase}` fixture mode: each
  forward hook (preflight…finalize) hangs past the 5s provider timeout and must be killed and
  recovered from, leaving a live predecessor. Guards the "a hung hook stalls the whole update"
  failure class.

- [x] **D12 — Malformed-bundle ingest rejection. DONE — and it fixed a real hole, not just a test
  gap.** The update path rejected a malformed bundle and moved on (`check_application`), but
  `apply_install` (cold install) just propagated the error — a **cold node re-downloaded a
  malformed assigned head forever instead of descending past it**. Fixed: `apply_install` now
  rejects a malformed bundle (`rejected_archive()`) and re-selects inline, descending monotonically
  to the newest *installable* release. Tooling: a test-only `--corrupt=<garbage|truncate>` flag on
  `publish-app` signs a deliberately-broken archive (passes the download sha check, fails at
  extract). Scenario: `cold_install_descends_past_corrupt_bundle` stacks a truncated 2.0.0 and a
  garbage 3.0.0 above healthy 1.0.0 and asserts both are rejected at ingest (no launch) and the
  node lands on 1.0.0. (The `ColdInstall::NothingSelectable` refactor also makes a re-install that
  empties the descent *hold* the committed release rather than brick.)

- [x] **D13 — sha-mismatch on download retries, does not descend. DECIDED: intentional.** A sha
  mismatch at `download_target` is a transport (`Repository`) error carrying no rejectable archive,
  so the node retries rather than descending. This is the correct posture: a transient bad download
  should recover, and — unlike a malformed *signed* bundle — bytes that don't match the signed hash
  are indistinguishable from tampering, so descending on them would let a byte-corrupting MITM force
  a downgrade. A persistently-corrupt *served* head is an operational/security problem (fix the
  server), not a release to fall back past. No code change; the malformed-but-*validly-signed* case
  (D12) is the one that descends.

- [x] **D1 — Wedge-descent e2e. DONE.** Added `cold_install_descends_past_wedged_head` (unix.rs):
  the assigned heads are an executable that binds nothing and `exec sleep`s forever (alive but
  never healthy), so the node must stop each wedged head and descend past both to serve the healthy
  `1.0.0`. This is the scenario that reproduces the stale-process-adopt strand fixed above; without
  the fix it would time out (1.0.0 never serves).

- [ ] **D2 — Duplicate assignment publishers.** `Ctx::publish_current_assignment` (harness.rs) and
  `republish_assignment` (main.rs) are near-identical `publish-assignment` builders; their drift
  *was* the descent bug. Consolidate into one helper taking `(dir, metadata_url, targets_url,
  deployment)` so the marker/flag logic lives in exactly one place.

- [x] **D3 — Schema change / cross-version compat. WAIVED by the user.** `confirmed` is a required
  field with no serde default, so pre-change `installed.json` records read as `Invalid`. The user
  has explicitly directed: do not worry about backwards/data compatibility or migrations as long
  as e2e passes. No action — recorded only so the decision is traceable.

- [x] **D4 — Exact-pin rejected-head churn. RESOLVED by the `NothingSelectable` refactor.** A
  re-install that empties the descent no longer crash-loops on `apply_install` → fatal; it holds the
  committed release (`ColdInstall::NothingSelectable` → Ok(false)) and keeps serving. No brick-loop
  to log around.

- [x] **D15 — Corrupt *provider* bundle on a custom cold install. DONE.** `apply_install` now folds
  provider staging into the descent loop: a corrupt/rejected provider set for the selected app
  version rejects *that app version's* bytes and re-selects, so ordered fallback descends to a
  version whose signed provider set is good (app + providers are one signed unit). Previously it
  propagated the error and crash-looped on a version it could never bring up. (An e2e needs
  per-version corrupt provider sets — follow-up; the descent loop itself is exercised by
  `cold_install_descends_past_corrupt_bundle`.)

- [ ] **D6 — Narrow window: a healthy provisional head rejected on container restart.** Between the
  boot health gate passing and the `confirm()` write landing, a container restart (app killed →
  `service_exited=true`, state dir survives) makes the next boot see `provisional + service_exited`
  and reject a head that was actually healthy — spuriously descending one level. The window is a
  single file write and is **identical to the prior `install-unproven` marker behavior** (not a
  regression from this change). **Severity now bounded by the `NothingSelectable` refactor:** if the
  wrongly-rejected head is the only floor it is *held and re-confirmed* on the next passing gate
  (not bricked); otherwise it spuriously descends at most one level. **Accepted as-is.** The full
  fix needs the guardian to durably record "app signaled ready" *before* the confirm write and the
  crash-reject to consult it — an invasive change to crash-critical guardian+boot ordering that is
  not worth the risk for a microsecond-wide race whose worst case is now a one-level demotion.

- [x] **D5 — Drain-hold footgun + dead `Indefinite` variant. RESOLVED (the safety parts).** The
  `None`-default → `Indefinite` → warn-and-proceed footgun is gone: `DrainHold::Indefinite` (an
  unimplemented no-op) is deleted, an unset `drain_hold_seconds` now maps to `DrainHold::None` (no
  hold — deterministic, never a stall), matching the struct default, and the docs describe actual
  behavior (`Some(0)`/absent = no hold; `Some(n)` = bounded ceiling). The remaining piece — an
  *early-proceed* on the intermediary's signed `ManagedStatus.ready` and an explicit
  externally-managed "wait for drain-ack" mode — is a genuine **feature** (Increment 2), not a
  safety gap, and is tracked as future work in the config docs. `ManagedStatus.ready` stays as
  signed scaffolding for it.

- [ ] **D7 — Gateway telemetry ingest trusts a client-chosen node identity (security).**
  `gateway.rs` `telemetry_put` checks only `report.node == <path node>`; it never inspects the mTLS
  `peer_certificates`, so any fleet-CA cert holder can PUT a `NodeReport` for *any* node with
  arbitrary version/health. Since a report can release a rollout-throttle slot, forged telemetry
  can admit the next cohort onto a bad release. My `layout.rs` flip to `https://` made this path
  live in the demo. Fix: bind the mTLS cert subject/SAN to `node` before accepting. Not done blind
  because it depends on whether the fleet issues **per-node** certs (a shared fleet cert would make
  the check reject all telemetry and break the demo) — confirm the cert model first.

- [ ] **D8 — `release-server-deployer` RBAC binds the shared `default` ServiceAccount.**
  `setup.rs` grants updategroup(set) write to `default/updated-system`, so *every* pod in the
  namespace that omits `serviceAccountName` inherits control-plane write access. Give release-server
  a dedicated SA and bind the Role to that. Demo-scoped, needs the live cluster to verify.

- [ ] **D9 — Frozen convergence wait has no absolute ceiling.** `demo.rs` resets the 240s budget on
  every frozen tick, so a set left frozen makes the loop never time out and never return (silent
  hang in automated runs). Add a generous absolute ceiling. Demo-only.

- [x] **D10 — `pending` carried the *candidate's* providers, not the predecessor's. FIXED.**
  `pending` is the rollback intent to restore the *predecessor*, so it now stores
  `installed.{lifecycle,healthcheck,process}` (the predecessor's own signed providers) instead of
  `tx.*` (the candidate's). At the assigned head both are the same set (no behavior change, existing
  rollback e2e unaffected); across a provider-set revision they differ, and reverting the old
  release with the *new* providers would gate/watch it with the wrong hooks. This also makes the
  rollback-drops-providers fix correct — the reverted predecessor now carries *its own* providers.

- [ ] **D11 — Telemetry write/read trust asymmetry (demo).** Write side is mTLS; the healthproxy
  reads node health/version/groups anonymously from `http://minio:9000/updates`. No secrets, fine
  for the demo, noted for symmetry.
