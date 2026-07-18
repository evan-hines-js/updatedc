# Updated lifecycle state machine

`updated` owns release selection, TUF verification, process supervision, health gating,
durable journaling, and rollback. A lifecycle provider owns only the site-specific work
around the application. It is one executable with one phase argument.

The same state machine is used for ordinary updates and crash recovery. Every transition
is journaled before its side effect. A retry of the same transaction keeps the same
`attempt_id`; a later, newly selected update gets a new one.

## The normal update

```text
                    provider hooks                 supervisor / guardian

  current release
        |
        v
  [PREFLIGHT] --failure--> reject candidate; current keeps serving
        |
        v
  [PREPARE]   --failure--> undo provider preparation; defer or retry
        |
        v
  [DRAIN]     --failure--> undo provider preparation; defer or retry
        |
        v
  [STOP]      --failure--> reject candidate; current process is untouched
        |
        v
  guardian stops predecessor                 (stop-start only)
        |
        v
  [ACTIVATE]  --failure--> reject + restore predecessor
        |
        v
  guardian starts candidate                  (stop-start only)
        |
        v
  [START]
        |
        v
  supervisor health gate
        |
        v
  [VERIFY]    --failure--> reject + restore predecessor
        |
        v
  [FINALIZE]  --failure--> reject + restore predecessor
        |
        v
  commit candidate; enter confirmation window
        |
        v
  confirmed release
```

In `reexec` mode, the guardian does not stop or start the application. `ACTIVATE` asks the
running master to adopt the candidate while preserving its PID and listening sockets.
The remaining ordering is unchanged.

## Hook reference

| Hook | Runs while | Purpose and appropriate use cases |
|---|---|---|
| `preflight` | Current release is serving; no mutation permitted | Read-only checks that the candidate is usable: binary/config validation, Java compatibility, schema compatibility, required tools, permissions, disk space. A failure means these exact bytes are bad, so the candidate is rejected and not retried until a new release appears. |
| `prepare` | Current release is still serving | Establish prerequisites that can be prepared without taking traffic: mount storage, fetch/unwrap secrets, create directories, warm caches, run an additive migration, or generate mutable configuration. Record ownership so rollback can undo only what this attempt created. |
| `drain` | Current release is serving | Remove the node from rotation and wait for in-flight work to finish: load-balancer drain, queue consumer pause, authoring-session quiesce, or connection draining. It must be bounded and idempotent. |
| `stop` | Immediately before the supervisor stops the predecessor | Final provider action that needs the predecessor alive: flush application state, disable a scheduler, close an admin endpoint, or take a final backup. Do not stop the process here; the supervisor/guardian owns that operation. Failure rejects before the running process or active pointer is touched. |
| `activate` | The application is stopped in stop-start mode, or the master is alive in reexec mode | Apply the release-specific handoff: select the candidate runtime, install a WAR/configuration into mutable locations, or request a same-PID master/worker reload. Do not download or verify artifacts; `updated` already did that. |
| `start` | After the supervisor has launched or reexeced the candidate | Perform integration needed after launch: register the instance, enable a worker, initialize a connector, or wait for an application-specific startup handshake. The supervisor still owns process creation. |
| `verify` | After the supervisor's independent health gate passes | Check provider-specific correctness not visible in the health endpoint: migration completion, cluster membership, schema version, background worker state, or a safe read-only CMS/API probe. |
| `finalize` | Candidate is healthy and before the update is confirmed | Complete external changes: restore traffic, remove the old pool member, publish completion metadata, or remove temporary preparation state. A failure rolls back; it is not a transient defer. |
| `rollback` | During recovery or an activation failure | Reverse provider-side effects and restore the predecessor's external state. It must tolerate a phase that never ran, ran partially, or already completed. The predecessor is supplied as the candidate for this invocation. A rollback failure keeps the journal and holds recovery rather than replaying indefinitely. |

## Failure and recovery rules

1. Hooks receive the phase, immutable candidate and predecessor paths, managed PID when
   applicable, and the transaction `attempt_id`.
2. Hooks are direct argv executions with bounded timeouts. Exit `0` means the requested
   outcome was reached; any other exit is failure.
3. `prepare` and `drain` failures are environmental and may defer a valid candidate.
   `preflight`, `stop`, and every post-activation failure reject the candidate so the same
   bytes cannot create a replay loop.
4. The supervisor never treats a hook as authority to select, verify, start, or stop a
   release. Those responsibilities remain in the supervisor and guardian.
5. A crash between any two steps resumes from the durable journal. Completed hooks are not
   replayed unnecessarily; rollback hooks are safe to repeat when recovery requires it.
6. No hook may mutate an immutable release directory. Mutable state belongs under the
   install root or the provider's external system of record.

## Example: a Java application server

```text
preflight  validate candidate runtime and configuration
prepare    ensure mounts, secrets, directories, and additive migration are ready
drain      remove node from the load balancer and wait for requests to finish
stop       flush state and disable scheduled jobs
            supervisor stops the old process
activate   place the candidate application/configuration in mutable runtime locations
            supervisor starts the candidate
start      register the new instance and wait for its startup handshake
            supervisor performs the health check
verify     confirm application/schema/cluster state
finalize   restore traffic and remove temporary migration state
rollback   restore routing, jobs, mounts, and predecessor runtime state as needed
```

The wrapper may internally call existing scripts, but operators have only this one
supported lifecycle entrypoint. This keeps long-running operations such as application
startup or migration inside an explicit, bounded hook timeout rather than hiding them in
the guardian.

