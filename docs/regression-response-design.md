# Fleet-level regression response

Status: implemented, in `plan_rollouts` (`regression_verdict`). The evidence is the node's own
signed statement that it has DURABLY REJECTED the release its assignment names
(`NodeReport::rejected`, schema 7) — never an inference from a report sequence. The verdict is
enforced FLEET-WIDE per deployment identity (the effective threshold is the tightest
`maxRegressions` among the sets naming it, default 1), and is projected onto each bound group's own
status as well as the set's, so a halted set-less group is never an invisible freeze — bound meaning
the halt stops the group's admitted current from taking further nodes OR stops its desired body from
being admitted at all, since both freeze it. The same evidence answers a second, per-group question:
see "A rejected rollout is OVER" below.

## Problem

A bad release is already *contained*: `maxUnavailable` admission stops advancing when health
gates fail, and each node independently rolls back and durably rejects the proven-bad bytes.
But containment is silent and local. Twelve nodes can each discover the same regression, each
pay the rollback, and the control plane never turns their evidence into a fleet verdict — it
just stops making progress and waits for an operator to notice.

The missing piece is one decision: when enough independent nodes prove a deployment bad, stop
admitting anyone else to it.

## Evidence

No new channel and no inference: the node SAYS SO. The agent already keeps a durable
rejection-by-content-hash record — the one that makes a proven-bad candidate never retried — and the
signed `NodeReport` carries one bit derived from it: *the release this assignment names is one I
have refused for good* (`NodeReport::rejected`).

A `regressed(deployment, node)` fact is therefore a node's own claim about the exact bytes it was
assigned, read straight off the report the control plane already fetches.

The alternative — inferring it from the report sequence an update transaction leaves behind
(`updating=true` on the new assignment, then settled again on the pre-attempt archive) — was
implemented first and is wrong in two ways that no amount of care fixes:

- **It cannot see the most ordinary bad release.** A rejection is recorded for a candidate that
  fails its ACTIVATION just as much as for one that fails its confirmation window, and a release
  that cannot start at all runs no update transaction: there is no sequence, so there is no
  evidence, so the fleet-wide halt never fires and the group containing it never stops rolling.
- **A missed transient is missed for ever.** The node never retries bytes it has rejected, so a
  control plane that was restarting, had just changed leader, or was merely slow during the few
  seconds `updating` was true could never learn the fact afterwards. The evidence had to be
  WATCHED, which made a durable verdict depend on uptime.

The report stays a statement of running state — this is the node describing itself, not a general
data channel — and the field carries a serde default in the fail-safe direction, so a node older
than schema 7 simply proves nothing (see [`wire-compatibility-design.md`](wire-compatibility-design.md)).

The plane remembers each claim it has seen (node, assignment identity) so that one unreadable report
object cannot un-halt a proven-bad release for a pass; the memory is monotone, is bounded by the
live fleet and the live deployment identities, and needs no durability because the claim stands in
the node's own report and is re-read on the next pass. A node WITHDRAWING its claim — the operator
break-glassed its rejection record — is honoured, because the alternative is a halt whose evidence
the operator has already destroyed.

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

## A rejected rollout is OVER

The same evidence answers a second question the halt cannot: **can this group's rollout still make
progress?** It is per-group and has no threshold — a rejecting group deadlocks its set's siblings
whether or not enough nodes rejected to halt the fleet — and the answer decides settlement, not
admission.

A node's report is healthy on the assignment it was handed while it executes the archive it rolled
back to, so it never reports the identity it was assigned: the group stayed `Rolling` for ever and
held its set's `maxConcurrent` slot for ever, and every sibling queued behind it waited on a rollout
the control plane would never finish. `plan_rollouts` therefore classifies a group whose nodes are
all either committed or durably rejected, with nothing left that can move, as **`Failed`**:

- It releases its set's concurrency slot — nothing is in flight to protect.
- It is NEVER counted settled: `dependsOn` does not open, the set's `settled` list excludes it, and
  the metrics carry it under its own `failed` state. It has its own `UpdateGroup` condition
  (`Ready=False`, reason `Rejected`) and its own `UpdateGroupSet.status.failed` list, so a failed
  rollout can never be read as a landed one.
- The exit is a deployment with a different identity, exactly as for the halt.

The verdict requires the node's own CLAIM, never the report's shape. A node healthy on the new
assignment while executing the old archive is also exactly what a node writes when it fetched the
assignment and could not yet fetch its archive — that one converges on a later tick, and calling its
group failed would release the set's slot mid-rollout and report a failure that never happened.

## Explicitly not automatic

No automatic fleet retarget to the predecessor. Nodes that attempted the bad release have
already rolled themselves back; nodes that never attempted it are still on the predecessor.
After a halt the fleet is therefore already converged on the last good state — an automatic
retarget would add a control-plane-initiated deployment change with no operator intent behind
it, a second way to change desired state. Desired state changes remain exactly one path:
a signed publication by an operator.

## Testing

Planner unit tests: evidence below threshold admits normally; threshold halts the set;
a changed deployment identity clears the halt; nodes already on the halted body are not moved; a
rejecting group releases its set's slot so a sibling rolls in the same pass, a transient fetch
failure does not (it is still in flight), and a group still converging around one rejection is
`Rolling` until its last node lands. A wiring test drives the whole projection from a real signed
report in the store and asserts the halt, the conditions, and the failed-rollout verdict survive a
controller restart.

The fleet e2e (`updatec-e2e`) drives it end to end: its chaos generation rolls a broken release to
one group of every even set with a sibling queued behind it, and asserts the sibling advances in the
SAME generation, that every affected set publishes the halt with its evidence count, that each
group's `DeploymentHalted` condition is True, and that the alert webhook actually received the
transition document.
