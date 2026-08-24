# Per-node operational controls

Status: implemented. `UpdateAgent.spec.hold` / `.cordon`; the cordon travels through the same
controller-owned, revision-checked backend inventory that supplies healthproxy topology.

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

Cordon changes only what healthproxy programs. Each matching `UpdateBackend` projects one typed,
revision-checked Kubernetes inventory containing either an active `{node,address,publicKey}` entry
or a cordoned `{node}` entry. A cordoned identity is drained regardless of its report: HAProxy gets
an explicit `drain` for its predeclared server, while EndpointSlice omits the route. The application
keeps running, the node keeps reporting, and the agent is entirely unaware.

Rollout accounting treats a cordoned node as absent (as departed nodes already are) rather than
unhealthy, so a cordon does not eat the group's availability budget and does not wedge an
in-flight rollout waiting for a machine the operator deliberately benched.

A cordon must fail safe against malformed endpoint edits. A cordoned inventory entry therefore
requires only the node identity: its address and report key are deliberately absent. Clearing the
cordon attempts to reconstruct an active entry and must pass the complete route/key gate; an
invalid active entry remains explicitly drained and makes the backend status degraded. A broken
shard update leaves the last complete revision mounted, never a mixture of active and cordoned
shards. Backend reconciliation runs independently before
signed release publication, so a TUF signing or rollout-state failure cannot hold a drain hostage.

There is no S3 cordon document. S3 carries signed health reports; Kubernetes carries the topology
and operational routing intent the controller already owns. This removes an unsigned, replayable
second authority that could previously undo a cordon while preserving a valid healthy report.

Hold and cordon compose: maintenance is typically `cordon` (drain traffic), then work, then
uncordon. `hold` is orthogonal — a node can be held but serving, or cordoned but updatable. When
both are set the two verdicts stay independent: hold decides ROUTING (the node is never moved,
always republished on the body its recorded assignment names) and cordon decides ACCOUNTING (it
is absent from the availability budget and from settlement). Letting hold's availability charge
survive a cordon wedged the group for ever — held, the node is never republished, so it never
reports, so its charge never cleared.

## Converge-now

Deliberately not a mechanism. Nodes pull on `checkIntervalSeconds` from the signed runtime
config; an operator who needs faster convergence lowers that value for the deployment. Adding a
kick channel would be the first control-plane→node push path, which the core forbids, to save
at most one poll interval.

## Testing

Planner unit tests: hold excludes from admission and republishes the recorded body, fails closed on
an unresolvable body, and releases cleanly; admission treats a cordoned node as absent. Backend
contract tests prove a cordon needs only a safe identity, an uncordon restores the full address/key
gate, mixed inventory revisions are rejected, and a healthy S3 report cannot override a cordon.

The fleet e2e holds and cordons one machine in the externally-routed cohort, waits until its address
is absent from the real healthproxy-programmed EndpointSlice, then rolls a release at its group.
The group settles around it (`heldAgents: 1`, `Ready=True`) while the node stays on the old release;
clearing both controls converges it and returns its address to rotation.
