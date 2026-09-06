# Internal node execution protocol

Protocol version: `2`.

The agent automatically supplies a native, language-independent [reconciler helper](reconciler-helper.md)
for invocation context, structured results, file convergence, verified migration progress, and
boot identity. It ships with the agent; customers do not install a separate SDK or helper package.

Customers use `updatectl publish --entrypoint` with arbitrary scripts or executables. The
[native runtime](command-adapter.md) implements this protocol for them, generates results, and
handles replay policies; the entrypoint receives only its own arguments, never the protocol flags.

A deployment is one signed immutable package, including its execution metadata. The native runtime
is embedded in the agent. Durable state and signed reports bind its execution definition to the
package; unsupported APIs require an agent upgrade.

This grammar is a platform implementation detail. Customer entrypoints do not implement it.
Each invocation identifies one payload; recovery code keeps its own verified restoration evidence.

## Operations

- `converge` idempotently makes machine state match the supplied payload.
- `healthcheck` makes one bounded observation of that payload's readiness.
- `rollback` idempotently compensates changes made while converging the supplied failed payload.
- `inspect` emits deterministic measured-state bytes on stdout.

The package recovery procedure restores the previous application and compatible data explicitly.
After it succeeds, the agent activates the predecessor and invokes the runtime with `converge` under
the compensating identity. In that direction the runtime verifies health and restores recorded
outputs; it never implicitly runs the predecessor entrypoint. Failed health requires attention.

## Invocation grammar

The reconciler entrypoint is invoked with the operation as its first argument, followed by every
protocol flag in this exact order:

```text
ENTRYPOINT OPERATION
  --protocol 2
  --attempt-id ID
  --reason REASON
  --install-root PATH
  --state-dir PATH
  --payload-root PATH
  --payload-version VERSION
  --output-dir PATH
  --result-file PATH
  --input-dir PATH
```

The paths have these meanings:

- `--install-root`: the agent installation root; do not mutate agent-owned files beneath it.
- `--state-dir`: private durable reconciler state, stable across releases and retries.
- `--payload-root`: the verified immutable payload tree for this invocation. Never write to it.
- `--output-dir`: a fresh empty directory for this invocation's complete advertised outputs.
- `--result-file`: a fresh agent-owned path for the mutation result document.
- `--input-dir`: immutable files selected by the signed assignment for this invocation.

Unknown operations and unsupported protocol versions must be rejected. Customer arguments are
contained in the signed execution metadata, separate from this internal invocation grammar.

`REASON` is one of `install`, `restart`, or `update`. The valid operation/reason/attempt combinations
are:

| Operation | Reason | Attempt ID |
| --- | --- | --- |
| `converge` | `install` | `boot` |
| `converge` | `restart` | `boot` or `converge` |
| `converge` | `update` | transaction token or its compensating form |
| `healthcheck` | `install` | `boot` |
| `healthcheck` | `restart` | `boot`, `converge`, or `periodic` |
| `healthcheck` | `update` | transaction token or its compensating form |
| `rollback` | `update` | compensating transaction token |
| `inspect` | `restart` | `fingerprint` |

The compensating token is deterministically derived from the forward transaction token. A
reconciler must treat the attempt ID together with the operation as its idempotency scope.

## Mutation results

`converge` and `rollback` must atomically publish one bounded JSON result to `--result-file` before
exiting zero. Observations must not create that file.

Successful mutation:

```json
{
  "status": "succeeded",
  "schema": 1,
  "changed": true,
  "hostAction": "none",
  "message": null
}
```

`hostAction` is `none` or `reboot`. A zero-exit invocation may instead request a bounded retry:

```json
{
  "status": "retry",
  "schema": 1,
  "retryAfterSeconds": 5,
  "message": "waiting for the service manager"
}
```

When application state requires a decision, exit zero with:

```json
{"status":"needs-attention","schema":1,"message":"verify migration completion before recovery"}
```

This is neither success nor a request to retry. The platform records a durable installation hold,
stops subsequent mutations across restarts, and reports the hold as unhealthy in signed telemetry.
It carries no changed, host-action, output, or successful reconciliation claim. The
[command adapter](command-adapter.md) supplies receipt-bound operator resolution for its procedures.
Resume commands require a matching durable execution receipt.

Retries receive the identical operation, attempt ID, payload, and arguments. The agent bounds the
number of retries. Exit zero without a valid result, a malformed result, a non-zero exit, or a
timeout is a failed invocation.

A crash replay that finds the mutation already complete must return `changed: false`. Return
`hostAction: reboot` while that mutation still requires an OS reboot, and `hostAction: none` once
the reboot has actually occurred. Checkpointing the mutation or returning a reboot request does
not establish that the host rebooted. The reconciler must inspect actual state or retain the boot
identity with its progress so a crash before the agent accepts the result cannot lose the request.
The agent durably records an accepted reboot request before publishing outputs or advancing its
transaction, retries it across service restarts, and clears it only after the OS boot identity
changes. The conformance harness never reboots the host; it allows the same outstanding request
on replay.

## Outputs and inputs

A successful `converge` or `rollback` publishes the complete bounded set of regular files left in
`--output-dir`. The agent atomically replaces the prior snapshot; a retry or replay must therefore
re-emit every output, including when `changed` is false. Observations cannot replace outputs.

`--input-dir` is recreated for each invocation from authenticated assignment data. It is not a
durable cache. Secrets must not be copied into outputs, stdout, stderr, result messages, or payload
content.

The agent privately caches authenticated inputs before exposing a changed selection and pins the
transaction's inputs before its first mutation. Recovery consumes that pin without fetching inputs
from the network, even if the current assignment has changed. The pin remains until the transaction
and rollback guard have settled; unchanged selections use the in-memory snapshot.

## Health and process lifetime

`healthcheck` is a single observation: exit zero means healthy and non-zero means unhealthy. The
agent owns grace periods, consecutive-success requirements, intervals, and per-probe deadlines.

The agent contains and reaps the reconciler process tree when an invocation finishes or times out.
A workload that must outlive the invocation must be handed to a real service manager or otherwise
detached according to the platform contract.

## Durable update and rollback order

Forward update barriers record completed effects:

```text
Prepared
  -> verify candidate bytes and atomically activate candidate
Activated
  -> candidate reconciler converge(payload=candidate)
Converged
  -> immediate candidate health gate
Verified
  -> commit candidate with exact predecessor rollback guard
Committed
  -> clear journal
```

If a successful converge requires a reboot, the candidate may commit directly from `Converged` with
its rollback guard armed; the boot health gate supplies the authoritative post-reboot verdict.

While rollback protection is armed, a failed bounded health gate journals a revert to the exact
predecessor. Confirmation requires both an elapsed confirmation window and a fresh passing health
gate. An inconclusive probe retains the guard and retries without rejecting the release.

Rollback barriers are:

```text
RollbackPlanned
  -> candidate reconciler rollback(payload=failed candidate)
CandidateCompensated
  -> verify and activate exact predecessor
  -> predecessor reconciler converge(payload=predecessor)
Restored
  -> predecessor health gate
RollbackVerified
  -> commit predecessor
RolledBack
  -> clear journal
```

Each external effect is idempotent. A crash between an effect and its following journal write
replays that effect with the same attempt identity. Journal phases never claim an effect merely
started; they mean the named barrier completed.

## Reconciler requirements

- Treat the payload as immutable and opaque to the agent.
- Derive desired state from `--payload-root`, not from repository history or an active-pointer file.
- Make `converge` and `rollback` idempotent under crash replay.
- Keep sub-progress needed for safe replay in `--state-dir`.
- Make rollback compensate only the supplied failed payload; never guess a predecessor.
- Refuse unsupported protocol versions and invalid invocation combinations.

Idempotency and transition compatibility are separate obligations. Inspect actual files, services,
and data before choosing work; neither `--reason` nor a stored version marker proves completion.
Refuse an unsupported starting state before an incompatible mutation. Compensation must account
for persistent data changes: restoring predecessor files does not reverse a database migration.
See [installation and ordered upgrades](install-and-upgrade.md) for the checked sequence helper,
application-owned compatibility, and transition tests around this contract.
