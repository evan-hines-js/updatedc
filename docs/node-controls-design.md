# Per-node operational controls

Status: implemented. `UpdateAgent.spec.hold` / `.cordon`; the cordon travels to `updated-healthproxy` through the endpoint projection the control plane publishes at `endpoints/state.json` beside the telemetry namespace (`updated-contracts/src/endpoints.rs`).

## Problem

The fleet has group-level controls (quarantine, rollout windows, `maxUnavailable`) but nothing
for the single machine an operator is about to touch. The two real-world asks:

1. **Hold**: freeze this node on exactly what it runs now — hardware swap tomorrow, do not
   move it tonight.
2. **Cordon**: take this node out of load-balancer rotation gracefully, without stopping the
   application and without the rollout engine counting it against the group's availability
   budget forever.

Both must survive the pull model: the control plane never reaches into a node, so every control
is a change to what gets *published for* the node, never a command sent *to* it.

## Hold

One new field: `UpdateAgent.spec.hold: true`.

During planning, a held node is carried forward on the exact body its recorded assignment
names — the same carry-forward mechanism quarantine-withheld nodes use, so this is a reuse of
an existing arm, not a parallel path. Specifically:

- The node keeps its current group membership for accounting but is excluded from admission:
  it neither advances to a staged deployment nor releases a rollout slot.
- The recorded body is republished verbatim. If that body is no longer available (the identity
  index cannot resolve it), planning fails closed for that node exactly as the quarantine
  carry-forward does — a hold can never silently become a move.
- Clearing `hold` returns the node to normal admission on the next reconcile; if its group
  advanced meanwhile, it becomes an ordinary candidate under `maxUnavailable`, not a special
  case.

A hold is visible in `UpdateAgent` status and counts in the group's `held` projection so a
forgotten hold is a visible condition, not a mystery. That count comes from the planner's own
membership — the group this pass's labels select — and never from the published routing: a held
node is never reassigned, so its routing keeps naming whichever group it was last published under,
and counting there attributed the hold to a group that no longer selects the machine while the
group the hold actually wedges reported zero.

## Cordon

One new field: `UpdateAgent.spec.cordon: true`.

Cordon changes only what the healthproxy programs, through the channel that already exists: the
control plane's endpoint projection. A cordoned node is published to the healthproxy inventory
as `drained` regardless of its report — the same drained state a stale report produces today,
so haproxy handling is unchanged. The application keeps running, the node keeps reporting, and
the agent is entirely unaware — cordon is invisible on the node because it changes nothing
the node owns.

Rollout accounting treats a cordoned node as absent (as departed nodes already are) rather than
unhealthy, so a cordon does not eat the group's availability budget and does not wedge an
in-flight rollout waiting for a machine the operator deliberately benched.

A cordon must fail SAFE — stay drained — against everything else the reconcile does, so the
cordoned set is collected from every agent of the repository before quarantine filtering, and the
projection is published before anything else in the pass can fail: the object store is built, the
agents are listed, the projection is written, and only then is the durable admitted state loaded.
Ordering it after that load left the one failure the loop cannot repair on its own (an unreadable
admitted-state ConfigMap fails every pass forever) wedging the cordon channel too. Otherwise
quarantining an agent, or any faulted generation, silently released the drain while the agent's
own `status.cordoned` still read true.

Hold and cordon compose: maintenance is typically `cordon` (drain traffic), then work, then
uncordon. `hold` is orthogonal — a node can be held but serving, or cordoned but updatable. When
both are set the two verdicts stay independent: hold decides ROUTING (the node is never moved,
always republished on the body its recorded assignment names) and cordon decides ACCOUNTING (it
is absent from the availability budget and from settlement). Letting hold's availability charge
survive a cordon wedged the group for ever — held, the node is never republished, so it never
reports, so its charge never cleared.

## Converge-now

Deliberately not a mechanism. Nodes pull on `check_interval_seconds` from the signed runtime
config; an operator who needs faster convergence lowers that value for the deployment. Adding a
kick channel would be the first control-plane→node push path, which the core forbids, to save
at most one poll interval.

## Testing

Planner unit tests: hold excludes from admission and republishes the recorded body, fails
closed on an unresolvable body, and releases cleanly; cordon projects drained endpoints while
reports stay fresh, and admission treats the node as absent. (Not yet implemented: an e2e kind
case asserting traffic drains while the update still lands.)
