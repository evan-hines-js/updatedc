# Updated lifecycle state machine

`updated` owns release selection, TUF verification, process supervision, draining, health
gating, durable journaling, and rollback. The signed node reconciler owns only the
site-specific work around the application, through the four operations defined in
[LIFECYCLE_PROVIDER.md](LIFECYCLE_PROVIDER.md): `apply`, `healthcheck`, `rollback`, and
`inspect`. That document is the protocol; this one is where those operations sit inside the
agent's durable transaction.

The same state machine drives ordinary updates and crash recovery. Every transition is
journaled before its side effect. A retry of the same transaction keeps the same
`--attempt-id`; a later, newly selected update gets a new one.

## The normal update

```text
  reconciler operations                       supervisor / guardian

  current release serving
        |
        v
                                         PreflightStarted / PreflightCompleted
        |                                (durable checkpoints; no side effects yet)
        v
                                         PrepareStarted / Prepared
        |
        v
                                         PreDrainStarted
        |                                guardian withdraws readiness, then holds
        v                                for the configured drain hold
                                         DrainStarted / Drained
        |
        v
                                         StopStarted / guardian stops the predecessor /
        |                                Stopped   (managed mode only)
        v
  [apply --reason update] --failure-->   reject candidate + restart into boot recovery
        |                                ActivateStarted / CandidateActivated
        v
                                         StartStarted / guardian starts the candidate /
        |                                CandidateStarted   (managed mode only)
        v
  [healthcheck]           --failure-->   reject candidate + restart into boot recovery
        |                                HealthStarted / CandidateHealthy
        v
                                         FinalizeStarted / Finalized
        |
        v
                                         CommitStarted / Committed, with the pending
        |                                rollback intent written in the same record
        v                                guardian returns the app to traffic
  confirmed release after the confirmation window passes
```

In `provider-managed` mode the guardian performs no stop or start: `apply` converges the
workload processes itself. The ordering, the journal, and the gate are unchanged.

## Rollback and recovery

There is one rollback implementation: the boot state machine. A post-activation failure
records the candidate's rejection, leaves the journal in place, and ends the supervisor
process; the guardian relaunches it, and the fresh supervisor replays the journal —
restoring the predecessor, invoking `rollback` with the candidate and predecessor reversed,
and gating the restored predecessor with the **predecessor's own** signed reconciler
(carried in the transaction, because a release and its reconciler are one signed unit). The
rollback phases (`RollbackStarted` … `RolledBack`) mirror the forward ones.

## Operation reference

| Operation | Runs while | Purpose |
|---|---|---|
| `apply` | Traffic is already withdrawn and, in managed mode, the predecessor is stopped. Also on every launch as the per-boot converge, under `--attempt-id boot` and `--reason install`/`restart` | Idempotently converge machine state to the candidate: place a WAR or configuration into mutable locations, run migrations, register instances, prepare a JBoss home. `--reason` distinguishes a first install, a plain restart, and an update. |
| `healthcheck` | The one readiness gate: after the candidate starts, on every boot, and on the signed steady-state cadence | One bounded observation; exit zero means healthy. The agent owns cadence, the success threshold, and the grace window. `--attempt-id` is the transaction's own token when gating that transaction's candidate, and the reserved `boot`/`periodic` identity otherwise. |
| `rollback` | Boot recovery of a failed update | Idempotently restore or compensate toward the predecessor. It must tolerate an operation that never ran, ran partially, or already completed. The predecessor is supplied as the candidate for this invocation. |
| `inspect` | Steady state, under `--attempt-id fingerprint` | One bounded steady-state observation. Non-empty stdout is opaque fingerprint material; typed dependency outputs go to `--output-file`. |

## Failure and recovery rules

1. Every invocation receives the operation, the immutable candidate and predecessor paths and
   versions, the managed PID when one exists, and the `--attempt-id`.
2. Operations are direct argv executions with bounded timeouts, run as a contained process
   tree. Exit `0` means the requested outcome was reached; any other exit is failure.
3. A failure before readiness is withdrawn defers cleanly and the current release keeps
   serving. Once readiness is withdrawn, no failure is fatal: the supervisor restarts into
   boot recovery, which resumes from the journal's last durable phase.
4. Every post-activation failure rejects the candidate's exact bytes, so the same bytes cannot
   create a replay loop.
5. The supervisor never treats a reconciler as authority to select, verify, start, or stop a
   release. Those responsibilities remain in the supervisor and guardian.
6. No operation may mutate an immutable release directory. Mutable state belongs under the
   install root or the reconciler's external system of record.

## Example: a Java application server

```text
                    supervisor withdraws readiness, drains, and stops the old process
apply               back up content and configuration, place the new WAR, migrate the
                    repository, restore routing and scheduled jobs
                    supervisor starts the candidate
healthcheck         confirm application/schema/cluster state
                    supervisor commits and returns the node to traffic
rollback            restore the backup, routing, jobs, and predecessor runtime state
inspect             report the measured steady state for the node's signed report
```

The reconciler may internally call existing scripts, but operators have exactly one supported
entrypoint and four operations. This keeps long-running work such as application startup or
migration inside an explicit, bounded operation timeout rather than hiding it in the guardian.
