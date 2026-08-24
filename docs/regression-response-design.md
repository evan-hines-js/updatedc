# Fleet-level regression response

Status: implemented, in `plan_rollouts` (`regression_verdict`, and `rollback_response` for the
opt-in `onRegression: rollback` policy). The evidence is the node's own
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

The report stays a statement of running state—this is the node describing itself, not a general
data channel—and only the exact current report schema is accepted.

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
  second door. The count is per IDENTITY and never per group, so every claim counts wherever the
  machine that made it now sits: relabelled into another group, inside a group quarantined since
  (its nodes resolve to the pseudo-group `default`), or matching no group at all. Both cohorts are
  also protected BY the verdict — the unmatched machines take the repository default unthrottled,
  and "unthrottled" is not "exempt from proof". A group-spec accident is not a statement that the
  refused bytes became good.
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

## The response: `onRegression`, halt or rollback

Halting leaves one population unaddressed: nodes that attempted the bad release rolled
themselves back, and nodes that never attempted it are still on the predecessor — but nodes that
settled HEALTHY on the bad body before the evidence arrived stay on it. Whether they should is an
operator judgment (one node's rejection can be node-specific — bad hardware, a full disk — in
which case yanking its healthy peers is the wrong move; or it can prove the release bad for
everyone, in which case a mixed fleet is the wrong state). So it is a declared policy, per
`UpdateGroupSet`: `spec.onRegression: halt` (the default, everything above) or `rollback`.

`rollback` REBASES each affected group — one whose admitted current the verdict halted — onto the
deployment its rollout was staging away from. The halted body moves into the admitted `previous`
list (its nodes are still on it), the predecessor becomes `current`, and the revert is staged
under `maxUnavailable` exactly like the forward direction; movement TO the halted body stays
refused by the verdict, so the two directions cannot fight. This does not create a second way to
change desired state: the operator declared the intent ahead of time, on the resource that already
owns the regression threshold, and the CR's desired deployment is untouched — the group reports
halted-and-rolled-back until corrected bytes are published.

Three deliberately conservative gates:

- **Every rejecting node still ON the halted body must have completed its own rollback.** The
  response fires only when each such node shows an authentic, fresh report that is healthy and
  still states the rejection of that exact assignment. A rejecting node that is unhealthy or
  silent is a machine in an unknown state, not proof that reverting its healthy peers is safe —
  the halt alone stands until it recovers. A prover whose fresh report names a DIFFERENT
  assignment is not waited for: it has already been moved off the body, which is the outcome this
  gate exists to observe, and its claim still stands. Waiting for it as well made the gate
  unsatisfiable for a group that qualifies LATER — an earlier rebase had already reassigned the
  provers — so a set flipped to `rollback` mid-incident stayed frozen for ever.
- **A predecessor MOVEMENT is not blocked from must exist.** The walk back through `previous`
  reads the same union `assign_nodes` gates on: regression halts (a veto is one) and external
  compliance blocks alike. A group whose first-ever deployment regressed has nowhere to go, and
  neither has one whose every predecessor is refused (a rollback whose own install failed);
  rebasing onto a refused body would pin `current` on something no node may ever be handed. In
  both shapes the halt alone stands. Reading the regression halts alone here STOPPED the walk at
  a predecessor compliance had blocked — an older release with a known CVE is the ordinary case —
  turning a recoverable rollback, with a viable body one entry further back, into that freeze.
- **Unanimity.** A group governed by several sets rolls back only when every one of them says
  `rollback`; a set-less group never does. A freeze needs no intent; automatic movement does.

Rolling back consumes the evidence the halt is recomputed from — the rejecting nodes are
reassigned the predecessor, so their reports stop naming the bad assignment. The response
therefore records a durable **veto** of the identity in the admitted-state document — the `vetoed`
field of the single JSON blob the controller keeps in the `updatec-admitted-<repository>` index
ConfigMap and its `-a-NN`/`-b-NN` shards, alongside `admitted`, `routing` and `assignments`; there
is no separate veto file to inspect, and reading one out means reassembling the shards. The body
stays refused across controller restarts and leader changes, until no group's desired or admitted
deployments name it any more. The status says which shape a halt took (`halted[].rolledBack`, and
the `DeploymentHalted` condition message), and the exit is the same as ever: publish corrected
bytes, which have a new digest.

## Testing

Planner unit tests: evidence below threshold admits normally; threshold halts the set;
a changed deployment identity clears the halt; nodes already on the halted body are not moved; a
rejecting group releases its set's slot so a sibling rolls in the same pass, a transient fetch
failure does not (it is still in flight), and a group still converging around one rejection is
`Rolling` until its last node lands. A wiring test drives the whole projection from a real signed
report in the store and asserts the halt, the conditions, and the failed-rollout verdict survive a
controller restart. Two tests pin the per-identity count against the cohorts a per-group one lost:
quarantining the group whose node made the claim withdraws nothing (the sibling naming the same
body stays refused, and the operator sees the halt widen rather than disappear), and an unmatched
node's own rejection halts the repository default so the machine that enrolls next is not handed
it.

For the rollback response: an unrecovered rejector halts without rebasing; the pass it reports
healthy again the group is rebased, the veto recorded, and the status says `rolledBack`; with a
fresh observation log and no live claims the veto alone still refuses the body (the restart
shape); a different identity is admitted normally; a split halt/rollback policy across governing
sets freezes without moving anyone; a first-deployment regression with no predecessor only halts;
the walk steps OVER a predecessor external compliance blocks and rebases onto the viable one
behind it; and a group that qualifies late still rebases though its provers have already been
moved off the halted body.

The fleet e2e (`updatec-e2e`) drives it end to end: its chaos generation rolls a broken release to
one group of every even set with a sibling queued behind it, and asserts the sibling advances in the
SAME generation, that every affected set publishes the halt with its evidence count, that each
group's `DeploymentHalted` condition is True, and that the alert webhook actually received a
transition document for EACH halted cohort — matched by the resource it names and the
`group@version` identity in its evidence, so one delivered document cannot stand in for the rest.
