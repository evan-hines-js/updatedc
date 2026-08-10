# Node reconciler protocol

Status: implemented. The invocation site is `supervisor::update::prepare_lifecycle_command`; the
four operations and the reserved attempt identities are typed in
`crates/updated-contracts/src/reconciler.rs`; the output manifest is
`updated_contracts::telemetry::OutputManifest`.

This is the one cross-organization surface in the system: the reconciler is authored by whoever
publishes the release, not by this repository, so its contract has to be published rather than
inferred from Rust types.

Every release carries one signed node reconciler. It may be a Bash or PowerShell script, a native
binary, or any other executable. The agent authenticates and invokes it but deliberately does not
interpret application or infrastructure semantics. The reconciler owns every workload process:
starting, stopping, draining, and restarting whatever the release runs is its domain behavior
(typically by driving the operator's init system), and the agent has no other way to touch one.

## Operations

The public interface has exactly four operations:

- `apply` — idempotently converge machine state to the candidate. `--reason` distinguishes
  `install`, `update`, and `restart`/repair.
- `healthcheck` — make one bounded readiness observation. Exit zero means healthy.
- `rollback` — idempotently restore or compensate toward the release being restored.

`--candidate` is always the release to converge ONTO, in both directions: on a rollback the
agent passes the release being restored as `--candidate` and the release that failed as
`--predecessor`. A reconciler that converges toward `--candidate` therefore needs no
direction-specific branch at all; `--predecessor` exists for compensation that must know what
it is undoing (which backup to restore, which schema to reverse).
- `inspect` — make one bounded steady-state observation. Non-empty stdout is opaque fingerprint
  material; typed dependency outputs are written to `--output-file`.

The agent owns artifact verification, placement, retry cadence, timeouts, durable transaction
state, crash replay, and rollout reporting. Those are intentionally not reconciler operations.

## Execution contract

Every operation is invoked **at least once**: the agent journals its intent durably before each
invocation, and after a crash it cannot know whether an invocation half-ran — so its only correct
recovery is to invoke again. A replay carries the *same* `--attempt-id` and the same arguments as
the invocation it repeats. The contract a reconciler must therefore satisfy is:

- Every operation tolerates being run again after any prefix of itself has already happened. The
  last completed invocation wins; there is no "exactly once".
- Effects must be keyed to the attempt, never to invocation count. `--attempt-id` is stable across
  replays of one attempt and never reused by another, so "have I already done this?" is answerable
  by marking completion under the attempt id.
- A reconciler that needs multi-step resumability writes its own sub-progress durably under
  `--state-dir` (its private directory, preserved across replays and boots) and skips completed
  sub-steps on replay. The agent never interprets that state.
- Exactly-once *effects* are buildable on top: use `--attempt-id` as the idempotency key and make
  each effect commit atomically with its completion marker — a same-filesystem rename that is both
  the effect and the marker, a database transaction that writes the marker row beside the change,
  or a downstream API's own idempotency token derived from the attempt id. A marker written
  *after* a non-atomic effect only narrows the duplicate window; it does not close it.
- `healthcheck` and `inspect` must be observations. The agent is free to repeat them any number of
  times, including concurrently with steady state; an observation with side effects turns every
  probe into a mutation replay.

The agent guarantees in return: one operation runs at a time per install root (never two
concurrently), intent is journaled before every invocation, a crashed transaction is resumed —
forward via `apply` or compensated via `rollback` — from its last durable checkpoint, and a
candidate whose attempt is rejected is never retried under a new attempt.

## Invocation

```text
reconciler OPERATION
  --protocol 1
  --attempt-id ID
  --reason install|restart|update
  --install-root PATH
  --state-dir PATH
  --candidate PATH
  --candidate-version VERSION
  --output-file PATH
  --input-file PATH
  --predecessor PATH
  --predecessor-version VERSION
  [-- PUBLISHER_ARGUMENTS...]
```

Arguments are passed directly as argv, never shell text, with a cleared environment and a null
stdin. The process runs as a contained tree (Unix process group / Windows job object) so a timeout
takes the whole tree down. `--attempt-id` is a transaction's own token when the operation gates that
transaction's candidate, or the reserved `boot`/`periodic` identity for an observation belonging to
no transaction.

The input file is a JSON object of typed values resolved from prerequisite groups — the same shape
as an output manifest's `values`. The output path is partitioned by the immutable candidate
identity, so a failed candidate's values cannot be attributed to a restored predecessor.

## Output manifest

An output manifest is atomically written to `--output-file` as:

```json
{
  "schema": 1,
  "values": {
    "endpoint": {"type": "string", "value": "https://service.internal:8200"},
    "join-token": {
      "type": "secret_ref",
      "secret": "service-bootstrap",
      "key": "join-token"
    }
  }
}
```

The document is closed: an unknown key, or an unknown `type`, is a rejection, not an ignored
extension. `schema` must be `1`. `values` holds at most 64 entries; each name is a safe path
component of at most 128 bytes; a `string` value is at most 4 KiB and contains no NUL; a
`secret_ref`'s `secret` and `key` are each 1–253 bytes. The whole file has a byte ceiling
(`MAX_OUTPUT_MANIFEST_BYTES`) so the manifest still fits inside the signed report envelope that
carries it.

Secret values must never appear in the manifest or in diagnostic streams. Only references are
transported; the reference is resolved through the authenticated secret-delivery path.

A manifest that fails any of these bounds is **dropped with a warning in the node's own log** and
the report simply carries no outputs. The consequence is remote and quiet: the dependent groups
wired to this producer never resolve their inputs, so they stay `Held` (`Ready=False`, reason
`Held`, and `updatec_group_progress{state="held"}`) with no fleet-side error naming the manifest.
Validate against the bounds above rather than against a rollout that appears to stall.

Exit status zero means success; any other status means failure. The agent can enforce ordering,
bounds, identity, and result handling, but cannot prove that a reconciler is idempotent, read-only,
safe, or semantically correct.

## Minimal Bash reconciler

```bash
#!/usr/bin/env bash
set -euo pipefail

operation=${1:?missing operation}
shift

protocol= reason= candidate= predecessor= input_file= output_file=
while (($#)); do
  case "$1" in
    --protocol) protocol=$2; shift 2 ;;
    --reason) reason=$2; shift 2 ;;
    --candidate) candidate=$2; shift 2 ;;
    --predecessor) predecessor=$2; shift 2 ;;
    --input-file) input_file=$2; shift 2 ;;
    --output-file) output_file=$2; shift 2 ;;
    --attempt-id|--install-root|--state-dir|--candidate-version|--predecessor-version)
      shift 2 ;;
    --) shift; break ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ $protocol == 1 ]] || exit 2

case "$operation" in
  apply)
    ./existing-installer --source "$candidate" --inputs "$input_file"
    ;;
  healthcheck)
    ./existing-status-command
    ;;
  rollback)
    # On a rollback, --candidate IS the release being restored.
    ./existing-restore-command --source "$candidate"
    ;;
  inspect)
    ./existing-status-command
    printf 'state=ready\n'
    ;;
  *)
    echo "unknown operation: $operation" >&2
    exit 2
    ;;
esac
```

## Runtime ownership

The reconciler owns workload processes; `apply` and `rollback` must converge them — including any
drain, stop, start, or restart the workload needs — as part of their domain behavior. The agent
never holds a workload process, so an agent restart, crash, or self-update can never disturb one.

## Secrets

The values behind the assignment's declared `SecretReference`s are present in every invocation's
environment, under the reference's `environment` name. They arrive only through the environment —
never argv, never a file the agent writes — and must not be echoed into the output manifest or
diagnostic streams.

## Compatibility

`protocol 1` is the only protocol. The output manifest is a wire contract under
`docs/wire-compatibility-design.md`, and a dual-direction one: the manifest travels node → control
plane inside a signed report (reader window), but the values it carries are resolved into
`ManagedRuntime.inputs` of the signed assignment other nodes read (writer restraint). A new
`OutputValue` variant therefore cannot be published until every supported node reads it.
