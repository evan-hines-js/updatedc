# updatedc core

## Mission

Continuously keep a fleet of long-lived machines on an exact, authenticated software state.

The system does four things:

1. Pull a signed release archive and its signed node-reconciler archive.
2. Verify their complete TUF chain, size, digest, platform, and manifests before execution.
3. Execute the reconciler through one bounded lifecycle protocol inside one crash-safe local
   transaction.
4. Publish signed health and running-version observations so the control plane can safely admit
   the next fleet cohort.

That loop is the product. At 1,000 machines it must remain deterministic, horizontally scalable,
pull-based, tolerant of disconnected nodes, and safe under interruption at every durable boundary.

## One path

```text
signed desired assignment
  -> TUF-authenticated archives
  -> verified immutable staging
  -> one node-reconciler protocol
  -> durable activation transaction
  -> health gate
  -> commit or rollback
  -> signed node report
  -> fleet rollout admission
```

There is no alternate unsigned install path, phase-specific hook path, remote-execution path, or
implicit state migration path.

## Ownership

- `updated-contracts` owns every serialized document crossing a process or trust boundary and the
  pure validation required to interpret it.
- `updated-tuf` owns authenticity, repository refresh, target selection, and verified download.
- `updated` owns bounded node-local mechanisms and conversion of verified contracts into local
  runtime objects.
- `supervisor` owns local policy, lifecycle sequencing, deadlines, health, recovery, rollback,
  telemetry, and self-update.
- `bootstrap` owns permanent process lifetime and no release or network policy.
- `updatec` owns fleet desired-state compilation, rollout admission, signed publication, and
  status projection. It never reaches into a node.
- The signed reconciler owns all application-specific machine effects.

## Hard boundary

Updatedc is not a configuration-management system or a distributed application orchestrator.

The reconciler may coordinate through S3, an application API, a database, or another system chosen
by the application. Updatedc authenticates and runs that reconciler; it does not provide mutable
KV storage, peer variables, messaging, locks, leader election, recipes, remote commands, or a
general workflow language.

Secrets use the one authenticated secret-reference path. Observed health uses the one signed
`NodeReport` path. Neither mechanism is a general data channel.

## Scale invariants

- Nodes pull; control-plane availability is never required to keep the last verified workload
  running.
- Publication is one immutable, content-addressed generation with one TUF commit point.
- A malformed resource is quarantined before publication; generations are never mixed.
- Rollout slots are released only by fresh, authentic node health for the exact deployment.
- Object and HTTP reads are bounded before allocation.
- All security-sensitive grammars and signature encodings have one canonical implementation.
- Every external operation has a deadline and cancellation behavior.
- Durable state is journaled before its corresponding external effect and replayed idempotently.
- Fleet size changes work per reconciliation, not the correctness model on each node.

## Feature test

A proposed feature belongs in the core only when it strengthens or is required by the path above.
If it interprets application topology, coordinates peers, converges arbitrary machine policy, or
adds another way to deliver or execute code, it belongs in the signed reconciler or an external
system.
