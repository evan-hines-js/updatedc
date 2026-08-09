# Fleet-level regression response

Status: implemented, in `plan_rollouts` (`regression_halts`). The evidence is the report sequence this document describes — an update transaction in flight on the new assignment (`updating=true`), then settled again on the pre-attempt archive — remembered across passes by an in-memory `ObservationLog`, because a single snapshot cannot tell a fleet rolling back FROM a bad deployment apart from an operator retargeting TO the predecessor. Losing that memory (a restart, a leader change) only delays a halt until the contained nodes' sequences re-prove it. The verdict is enforced FLEET-WIDE per deployment identity (the effective threshold is the tightest `maxRegressions` among the sets naming it, default 1), and is projected onto each bound group's own status as well as the set's, so a halted set-less group is never an invisible freeze — bound meaning the halt stops the group's admitted current from taking further nodes OR stops its desired body from being admitted at all, since both freeze it. Evidence requires the node to be settled healthy on the target while running an archive that is neither the target's own application (that is a commit, not a rollback) nor the application of the body it moved from (a change that keeps the application has no distinguishable rollback), so retargeting a group back onto the deployment its contained nodes are already running — the documented exit from a halt — cannot halt the recovery target.

## Problem

A bad release is already *contained*: `maxUnavailable` admission stops advancing when health
gates fail, and each node independently rolls back and durably rejects the proven-bad bytes.
But containment is silent and local. Twelve nodes can each discover the same regression, each
pay the rollback, and the control plane never turns their evidence into a fleet verdict — it
just stops making progress and waits for an operator to notice.

The missing piece is one decision: when enough independent nodes prove a deployment bad, stop
admitting anyone else to it.

## Evidence

No new channel. The evidence is what nodes already assert through the signed `NodeReport`:

- A node assigned deployment X that reports the predecessor's `archive_sha256` with
  `settled=true` after its report previously showed X with an update transaction in flight has
  attempted X and rolled back. This is the report sequence the supervisor already publishes: the
  heartbeat emits every tick, `settled=false` with `updating=true` during the confirmation
  window, and the committed digest after commit or rollback. `updating` is reported separately
  from `settled` because an unsettled report also covers an ordinary readiness failure with no
  update anywhere near it, which is not evidence of anything.
- The control plane already tracks, per group, which nodes are placed on which body and what
  they last reported — the same `Observations` the admission gate reads.

A `regressed(deployment, node)` fact is therefore derivable inside `plan_rollouts` from state
it already holds. Nodes do not report "I rejected X" explicitly, and should not: the report
stays a statement of running state, not a general data channel.

## Verdict

One new field on `UpdateGroupSet`: `maxRegressions` (default 1). During planning, if the number
of distinct nodes with a `regressed` fact for a staged deployment reaches its threshold — the
tightest `maxRegressions` among the sets whose members name that deployment identity, defaulting
to 1 when none does — the deployment is **halted** FLEET-WIDE:

- Admission stops: no further node is moved to the halted deployment, in any group — sibling
  sets and groups no set governs included; a proven-bad body must not reach anyone through a
  second door.
  Nodes already on it are left where they are — they contained themselves, and yanking them
  back is the retarget-flap the rollout engine already refuses.
- The halt is projected into CRD status (`halted`, with the evidence count) and is one of the
  alertable conditions in [`alerting-design.md`](alerting-design.md).
- The halt is a planner verdict recomputed from evidence each reconcile, not stored state: it
  clears only when the staged deployment changes (the operator publishes a fix or retargets the
  predecessor). Republishing the identical body cannot un-halt it, because the rejecting nodes'
  evidence still stands — corrected bytes have a new digest, which is the same rule the node's
  own rejection record enforces.

## Explicitly not automatic

No automatic fleet retarget to the predecessor. Nodes that attempted the bad release have
already rolled themselves back; nodes that never attempted it are still on the predecessor.
After a halt the fleet is therefore already converged on the last good state — an automatic
retarget would add a control-plane-initiated deployment change with no operator intent behind
it, a second way to change desired state. Desired state changes remain exactly one path:
a signed publication by an operator.

## Testing

Planner unit tests: evidence below threshold admits normally; threshold halts the set;
a changed deployment identity clears the halt; nodes already on the halted body are not moved.
(Not yet implemented: an e2e chaos case asserting the halt lands before the second cohort is
admitted.)
