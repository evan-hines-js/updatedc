# Alerting on stuck state

Status: implemented. Conditions live in `updatec/src/alerts.rs`; the webhook is configured by `UPDATED_ALERT_URL` (with `UPDATED_ALERT_TOKEN_FILE` for the bearer token), like every other `updatec` setting. The payload is one generic JSON document per condition transition (`resource`, `condition`, `state`, `reason`, `evidence`, `generation`, `timestamp`) with an optional bearer token — no receiver-specific format.

## Problem

Every failure mode the system contains, it contains silently. A rollout held for six hours, a
group whose reports all went stale, a halted deployment
([`regression-response-design.md`](regression-response-design.md)) — the CRD status says so,
but nothing tells anyone. The operator's first signal is a human noticing.

## One path

Alerts are projections of planner verdicts, nothing else. The reconcile loop already computes,
every pass, the exact conditions worth waking someone for; this design gives those conditions
two outputs — a status condition and one webhook — and adds no new detection logic.

### Conditions

Set on the owning resource's status each reconcile, cleared the same way (standard k8s
condition semantics — `True`/`False` with a reason, never deleted):

- `RolloutStuck` on `UpdateGroup`: the group has been in `staging` with no node newly settled
  for longer than `stuckAfterSeconds` (new set-level field, default 3600). Derived from
  observation timestamps the admission gate already reads.
- `ReportsStale` on `UpdateGroup`: fewer than the group's admission quorum of nodes have fresh
  reports (`REPORT_FRESHNESS` is the one staleness definition; this reuses it). "Observable"
  means a node that has already uploaded a report at least once, never one that merely has a
  pinned key: enrollment pins the key generations before the node can fetch an assignment and
  report, so counting those would page on every mass enrollment and every scale-out larger than
  `maxUnavailable`, then resolve itself. This says "nodes stopped reporting", not "nodes have
  not started yet".
- `DeploymentHalted` on `UpdateGroupSet`: the regression verdict, with its evidence count.
- `ReconcileFailing` on the set: the loop itself erred on consecutive passes.

Conditions are the source of truth; the webhook is only a delivery of their transitions. An
operator who wants nothing but `kubectl wait` gets full fidelity without configuring anything.

### Webhook

One sink. `updatec` takes `UPDATED_ALERT_URL` (plus a bearer token read from the mounted secret file `UPDATED_ALERT_TOKEN_FILE` names);
unset means conditions-only. On a condition transition (False→True or True→False) it POSTs one
JSON document: resource, condition, state, reason, evidence, generation, timestamp.
An authenticated sink must use HTTPS so the bearer token is never sent in cleartext; unauthenticated
in-cluster sinks may use HTTP.

Delivery rules, in line with every other external operation in the core:

- Bounded: one in-flight request, deadline from the existing network-deadline discipline,
  bounded retry with the shared backoff, then drop. Alert delivery must never block or slow
  the reconcile loop — the condition on the resource remains the durable record, so a dropped
  webhook loses a notification, not a fact.
- Transitions only, no repeats, no batching, no templating, no per-alert routing. Fan-out,
  dedup windows, paging policy, and formatting belong to the receiver (Alertmanager or
  whatever the operator runs) — growing them here would be the start of a notification
  system, which fails the core feature test.

## Non-goals

No node-side alerting (a node's voice is its signed report), no email/chat integrations, no
alert history storage (conditions + receiver cover it), no threshold language beyond the two
duration fields named above.

## Testing

Condition derivation is planner-pure: unit tests per condition, both directions. The webhook
client is tested against a local listener for transition-only firing, deadline, and drop
semantics. The fleet e2e closes the loop end to end: an in-cluster receiver records every delivery
to a durable file, and the chaos generation's regression halt is asserted on all three of its
outputs — the set's `status.halted`, each affected group's `DeploymentHalted` condition, and the
fields of the document the control plane actually delivered. (Not yet implemented: an e2e scenario
asserting `RolloutStuck` rises on an induced wedge and clears after the fix generation.)
