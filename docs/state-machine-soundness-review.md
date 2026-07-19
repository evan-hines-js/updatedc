# State-machine soundness review

An adversarial pass over every state machine documented in `docs/state-machines.md`, asking the
design questions rather than the code-style ones: **missing states, redundant states, unsound
transitions, uncovered crash windows, and machines that disagree with each other.** Four
independent reviewers (install/update/rollback, guardian/self-update, control plane,
enrollment/health/telemetry) read the machines against their own stated invariants.

Nothing here is fixed yet — this is the assessment. Each item is tagged **CONFIRMED** (a real code
path, traced) or **RISKY** (reachable only in a degenerate/topology/operator-error case), and
**NEW** or **KNOWN** (already tracked in `docs/join-axum-hardening-review.md` / prior notes).

Bottom line: **the crash-safety core is sound** — the provisional/confirmed pivot, the three
recovery modes' partitioning, `classify_recovery`, the rank-driven rollback replay, ordered-fallback
descent, enrollment's consumed-once ordering, and the guardian's commit-after-liveness / pointer
atomicity / no-double-launch were all adversarially verified and hold. The findings are a small
number of real edges plus several doc overstatements.

## Priority summary

| # | Machine | Type | Severity | Status |
|---|---|---|---|---|
| **S1** | Update rollback | unsound transition | high | CONFIRMED · NEW |
| **S2** | Throttle ↔ telemetry | interaction / fail-open | high | CONFIRMED · NEW |
| **S3** | Guardian self-update | unsound transition | high | CONFIRMED · KNOWN |
| **S4** | Guardian self-update | unsound transition | med-high | CONFIRMED · NEW |
| **S5** | Throttle | unsound transition (concurrency breach) | medium | CONFIRMED · NEW |
| **S6** | Telemetry write | interaction / fail-open (auth) | high | CONFIRMED · KNOWN |
| S7 | Enrollment | missing state / brick | medium | RISKY · NEW |
| S8 | Windows/calendar | missing state / fail-open | medium | CONFIRMED · KNOWN |
| S9 | Guardian | unsound transition (livelock) | medium | CONFIRMED · NEW |
| S10 | Guardian ↔ init | uncovered window / contract | medium | RISKY · NEW |
| S11 | Throttle | liveness (starvation) | medium | CONFIRMED · KNOWN |
| S12 | Throttle | interaction (failover) | med (topology) | CONFIRMED · NEW |
| S13 | Reconcile lease | uncovered window (double-publish) | low (topology) | RISKY · NEW |
| S14 | Health gate | missing validation | low | RISKY · NEW |
| S15 | On-launch update | missing state (no rejection) | low | RISKY · NEW |

---

## Confirmed unsoundness (act on these)

### S1 — Rollback health-gates the predecessor with the *candidate's* health provider
`supervisor/src/main.rs:361-367`, `update.rs:943` via `selection.rs:232-238`; the dead field is
`Pending.healthcheck` (`state.rs:112-113`).

`Pending` deliberately stores the *predecessor's own* providers (comment `update.rs:823-826`:
"reverting the old release with the new providers would gate it with the wrong hooks"). The
rank-driven replay honors this for the **lifecycle** hooks, but the actual **health gate** does not:
the boot revert gates before `plan.commit` writes the predecessor record, so `store.installed()`
still returns the *candidate* record, and the in-process `roll_back` reuses the candidate-built
tower. So `pending.healthcheck` is carried but never consulted for gating.

**Failure:** update A→B where B revises the health-check probe (a probe only B serves). B fails in
its confirmation window → recovery restores A but gates A with **B's** probe → A can't satisfy it →
`boot_healthy=false` → the predecessor commit line is never reached → next boot replays and fails
identically → **permanent crash-loop on a healthy predecessor.** Narrow trigger (the update must
change the health provider *and* the new probe must reject the old release), but a clean
contradiction of the machine's own stated invariant. **Fix:** gate the restored predecessor with
`tx.healthcheck` (already carried), not the installed/candidate provider.

**Resolved.** Two changes close this. (1) The in-process `roll_back` was removed entirely: every
post-activation failure now returns `Outcome::RollbackPending` and hands the rollback to **boot
recovery**, so no live-tower rollback can gate with the candidate's provider. (2) The boot gate
(`main.rs`) selects the health/process providers from the recovery transaction (`tx.healthcheck` /
`tx.process` = the predecessor's own, carried in the journal) whenever `tx.is_rollback()`, falling
back to `store.installed()` otherwise. `Pending.healthcheck` is now consulted on the confirm-window
revert path via the same mechanism.

### S2 — Throttle `settled` ignores report freshness (fail-open *and* a liveness gap)
`throttle.rs:80-91`, `runtime.rs:500-523`. Flagged independently by two reviewers.

`settled` = every member node has a report with `deployment==published && healthy`. It never
consults `reported_at_ms`; `read_node_reports` applies no age filter. The freshness bound
(`REPORT_FRESHNESS`, 60s) exists and is honored by the **healthproxy** — but not by the throttle.
One missing check, two opposite hazards:

- **Fail-open (safety):** a node reports `{v2, healthy}` once, then is hard-powered-off (never writes
  a not-ready report). Its report persists → its group stays "settled" forever → the throttle keeps
  admitting downstream groups over a node that has since died. This directly contradicts
  `state-machines.md` §2 ("stale report ⇒ not settled, fail-safe") and §9 ("older than 60s reads
  not-ready"). **The doc believes this is handled; the code does not do it.**
- **Liveness:** a node that *never* reports (dead HW, agent never came up) keeps its group unsettled
  forever → the whole set's rollout **stalls indefinitely**. No timeout, no quorum. Deleting the
  `UpdateAgent` recovers (routing is rebuilt from live agents), so churn-by-deletion is safe, but
  churn-by-silence wedges the fleet.

**Fix is a policy decision, not a one-liner:** naively AND-ing freshness fixes the fail-open case but
worsens the liveness case (a node that stops heart-beating would un-settle a set). Wants a real
"settled = N-of-M fresh-and-healthy within a deadline" policy.

### S3 — Seeded initial supervisor bricks if `--supervisor` isn't re-passed (KNOWN)
`bootstrap/guardian.rs:474-481` (seed) + `492-529` (validate).

`seed_desired_supervisor` writes the raw `--supervisor` path into the durable pointer — a path
*outside* `supervisors/<hash>/`. On later boots `validate_supervisor_path` only accepts that
non-staging path through a special case that requires `cfg.initial_supervisor` to still be `Some`.
Drop the flag from the unit on any restart *before the first self-update* → validation rejects the
pointer → `run()` returns `Err` **before launching anything** → node outage + init-level crash loop.
The population at risk is exactly nodes that have never self-updated (post-update the pointer is a
staging path that validates flag-free). Worse than a normal fail-safe: the "app stays up" guarantee
only covers a *running* guardian, and here the guardian never reaches launch. **Fix:** stage the
seed binary into a content-addressed slot, or persist a durable "seeded-initial" exemption instead
of deriving it from the live flag.

### S4 — A healthy supervisor can be *permanently* rejected because `ready_timeout` gates on *app* health
`bootstrap/guardian.rs:262, 274-291` vs `supervisor/src/main.rs:396, 515`.

The candidate supervisor calls `signal_ready` only **after** it completes the full *application*
health gate (grace + successes×interval). The guardian's `ready_timeout` is armed at candidate
launch. If the app is slow/transiently-unhealthy *during the swap* (adoption re-health-gates it), the
candidate blows the deadline, is stopped, and its **content-addressed hash is rejected**
(effectively permanent — remedy is a byte-changing republish, not time). So a perfectly good new
supervisor binary becomes un-adoptable on that node because the app happened to be mid-restart when
it took over. The two timeouts are configured independently; nothing enforces
`ready_timeout > health_grace + slack`. Root defect: conflating "supervisor process is ready" with
"app is healthy." **Fix:** have the candidate signal supervisor-readiness before/independently of the
app gate, or don't reject on ready-timeout (only on exit).

### S5 — Re-targeting a group mid-rollout transiently breaches `max_concurrent`
`throttle.rs:95-98, 139`.

`is_rolling = admitted==desired && !settled` feeds `rolling_now` → `slots`. If group `a` is rolling
v1 (slots consumed) and the operator bumps `a`'s desired to v2, then `admitted[a](v1) != desired[a](v2)`
→ `is_rolling(a)=false` → `rolling_now` drops → a slot frees → a *second* group is admitted while
`a`'s nodes are still physically mid-upgrade to the last-published v1. The blast-radius cap is
breached for that window (self-heals once `a` settles). Root cause: "rolling" is defined against the
*current* desired, not "has an unsettled published generation in flight."

### S6 — `telemetry_put` doesn't bind the peer cert to the reported node (KNOWN)
`gateway.rs:500-513`. The fleet client CA is shared, and the handler only checks
`report.node == path`. Any fleet-cert holder can PUT a forged `{healthy:true}` report for another
node, and since S2's `settled` trusts reports blindly, this forges a group settled. Fix needs
per-node identity from the cert (join-mode leaves already carry a SPIFFE node SAN; mount-mode does
not) and a path/identity match. Compounds S2.

---

## Risky — reachable only in a degenerate / operator-error / topology case

- **S7 — Enrollment brick: join mode, `enrollment.json` + `.consumed` present, `agent.crt` gone**
  (`enrollment.rs:88-105, 345-356`). `steady_identity` points unconditionally at the persisted cert;
  re-enrollment is gated on bundle-or-consumed, never on the cert. If the cert (not the bundle) is
  lost after consumption (partial restore, operator wipe), the node loads its bundle happily but has
  no client identity and can *never* re-mint (consumed blocks `/join` forever) → silent permanent
  brick. Not crash-reachable; an unhandled on-disk combination the machine claims to cover.
- **S8 — Calendar "runs out → permanently open" (KNOWN)** (`window.rs:177-189`). Once every dated
  entry is past, gating stops entirely — a set whose only gate was an approved-dates calendar becomes
  ungated at *any* hour, the opposite of intent, and the recurring-window path fails *closed* while
  this fails *open*. Also a **missing state**: Open/Frozen can't distinguish "in an approved window"
  from "silently expired," and `frozen=false` in both, so an operator can't tell. Fix: surface an
  "exhausted/ungated" state or offer stay-frozen-on-exhaustion.
- **S9 — `send_hello` failure on a candidate doesn't reject → re-stage livelock**
  (`guardian.rs:264-267`). Every other candidate-failure path rejects the hash; this one returns
  `Backoff` without rejecting, so the predecessor relaunches, re-selects the same newest release,
  re-stages, re-hands-off, hello fails again — forever. App stays up (not a brick), but the
  supervisor flaps and update progress stalls. Fix: reject the hash on hello failure too.
- **S10 — NEITHER-owns edges around `ServiceExited`** (`guardian.rs:152, 166-173`, `record.rs:68-76`).
  (a) App exits 0 with an init policy that doesn't `Restart` on 0 → marker written, never consumed,
  tower stays down (systemd/launchd contract: needs `Restart=always`). (b) `mark_service_exited` I/O
  failure → guardian exits without the marker → next boot relaunches the unconfirmed crashing head
  **unreverted** (the exact hazard the marker exists to prevent). Both edge cases; the common
  app-exit-during-confirmation path is handled cleanly (verified — `poll_exit` preempts).
- **S11 — Shared-group starvation (KNOWN)** (`throttle.rs:183-206`). Most-constrained-first ordering
  fixes the *same-pass* sub-case only. A group in two sets whose siblings never free their slots in
  the *same* reconcile pass (sustained sibling churn) is never admitted. The doc's implication that
  ordering avoids starvation is an overstatement — it mitigates.
- **S12 — Throttle `admitted/` state is local; a leader failover to a replica with an empty dir
  re-seeds `admitted=desired` for every group → throttle bypassed, whole set rolls at once**
  (`runtime.rs:402`, `throttle.rs:75-78`). Latent in the shipped `replicas:1` + RWO-PVC topology
  (dir survives on the same PVC); becomes real if the PVC is swapped for `emptyDir` or a second
  replica with its own volume ever leads.
- **S13 — Lease double-publish window** (`runtime.rs:31-104`, `main.rs:110-146`). A leader learns it
  lost the lease only on its next 5s tick, so there's a ≤5s window where a taker has begun publishing
  while the old leader's in-flight reconcile could also publish (and CPU-bound TUF signing can starve
  the renewal branch past the 15s deadline). Bounded to latency by `replicas:1`+RWO (a second pod
  can't mount `state_dir`), but the lease advertises HA the topology doesn't safely deliver. The
  *cancel-on-lost-lease* path is half-publish-clean (verified: `timestamp.json` uploads last).
- **S14 — No validation that `health_grace ≥ health_successes × health_interval`**
  (`config.rs:386-396`). A misconfig (`grace=10s, successes=11, interval=1s`) fails a perfectly
  healthy app every boot → needless provisional-head rejection / descent. Add a validation.
- **S15 — On-launch update has no rejection / no health rollback** (`on_launch.rs:54-70`). Recovery
  only ever reverts the pointer; `candidate_rejection_required` is forbidden for `OnLaunch`, so a
  driving client that keeps selecting the same bad candidate loops activate→crash→revert with no
  suppression (the Supervised path rejects bad bytes to break exactly this). Appears deliberate (the
  one-shot client owns health), but it's the material asymmetry vs Supervised.

## Additional risk notes
- **R2 (provisional confirm on a read-only state dir):** `state.confirm()` failure after a passing
  gate is `warn`-only, so a proven-healthy head stays `confirmed=false` on disk; a later transient
  crash then descends past it. Degenerate (persistent write failure) but it's the one path that can
  turn a proven head into a rejected one.
- **R1 (pre-activation crash → full rollback replay):** a `NeverSwapped` (pre-activation) crash is
  driven through the whole rollback rank machine; harmless for stop-start, but runs the *candidate's*
  Stop/Activate/Start/Verify hooks for custom deployments where "discard journal, keep predecessor"
  would be correct and cheaper. Recommend short-circuiting `NeverSwapped`.
  **Resolved (with a follow-up fix).** `recovery_transaction` now replays the rollback machine only
  for `RestorePredecessor`. The first cut let a non-`RestorePredecessor` journal *fall through* to
  the confirm-window `Pending` branch, which re-synthesized a fresh `RollbackStarted` and re-ran the
  whole (already-finished) rollback — a non-minimal double-invoke of every lifecycle hook, caught by
  the `rollback_chaos_recovery` e2e at the `rolled-back` boundary (`calls_are_minimal=false`). The
  journal is now authoritative: it returns `Some` for `RestorePredecessor` and `None` otherwise, and
  a finished (`RolledBack`) journal is committed by the boot plan's `is_rollback` branch with zero
  lifecycle calls.
- **T3 (premature `healthy=true`):** `settled = pending.is_none() && last_ready.unwrap_or(true)`
  reports healthy before the first steady-state readiness sample (narrow window; the boot gate did
  pass).

---

## Missing states
- **Calendar "exhausted / ungated"** — collapses into Open with no distinct, observable state (S8).
- **Enrollment "join, bundle present, cert missing → re-mint"** — unhandled on-disk combination (S7).
- **Health kinds are not actually sequenced.** `Startup`/`Readiness`/`Liveness` are three
  *independent* kinds, not a k8s-style startup→readiness→liveness sequence; the boot gate uses
  Startup-or-Readiness, steady state samples Readiness/Liveness independently. `state-machines.md` §8
  slightly overstates the sequencing — worth a doc correction, not a code change.

## Too many / redundant states
Almost none — the state sets are right-sized (every `Phase`/`InstallPhase`/`Cycle` variant is
written and consumed). The only dead scaffolding:
- **`ManagedStatus.ready`** (`config.rs:199-212`) is signed into the assignment but explicitly not
  consumed (the drain hold ignores it) — a wired-in state with no reader today.
- Cosmetic: `begin_rollback` permits `Aborted→RollbackStarted` / `RollbackStarted→RollbackStarted`
  (unreachable-or-idempotent); `dispatch`'s `Ready` inner `if let Some(path)` is always `Some`. Not
  exploitable.

## Cross-machine disagreements (the interaction bugs)
1. **Throttle vs telemetry freshness** (S2): the throttle trusts reports the healthproxy would reject
   as stale — the two consumers of the same `NodeReport` apply different freshness rules.
2. **Guardian readiness vs supervisor app-health** (S4): the guardian's "supervisor ready" deadline
   is actually driven by the *supervisor's* app-health gate — two machines racing one timeout.
3. **Guardian revert-ownership vs init restart policy** (S10): the guardian rolls the exit code up and
   assumes the init system restarts; on exit 0 (or a lost marker) neither side owns recovery.
4. **Throttle pacing state vs lease failover** (S12/S13): the blast-radius pacing lives in
   replica-local files the lease machinery doesn't hand off.

## Doc corrections for `docs/state-machines.md`
- §2/§9 "stale report ⇒ not settled (fail-safe)" — **false for the throttle** (S2); only the
  healthproxy ages reports.
- §10 "the application keeps running the entire time" — **false in the update drain window**: a
  supervisor crash after `Stop` but before re-`Launch` leaves the app down for the backoff interval.
- §2 shared-group note — ordering **mitigates**, doesn't eliminate, starvation (S11).
- §8 three-kind health framing — the kinds are independent, not a sequence.

## Verified sound (adversarially, so the reader trusts the core)
Provisional↔confirmed invariant (no writer violates it; a head can't stick provisional except under
R2); the three recovery modes partition cleanly by `confirmed`+`pending`; `classify_recovery`
boundaries incl. the `commit_may_have_landed` straddle; rank-driven rollback replay is idempotent at
every boundary; ordered-fallback descent is monotonic with a reachable fail-open floor; enrollment
bundle-before-marker and join cert-before-bundle orderings; guardian commit-after-liveness ordering,
pointer-flip atomicity, no double-launch/orphan (Linux, via single App slot + PID adoption +
`PR_SET_PDEATHSIG`), backoff never gives up / never stops the app (except S10's drain carve-out),
per-launch nonce gate, rejection-hash naming; control-plane cancel-on-lost-lease half-publish safety,
`frozen: Some(...)` refresh (not a stale hazard — it's the fix), admitted-before-publish ordering
(journal-before-act in the safe direction).
