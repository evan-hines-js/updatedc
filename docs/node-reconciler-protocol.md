# Node reconciler protocol

Status: implemented. The invocation site is `agent::update::prepare_lifecycle_command`; the
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
- Effects must be keyed to the attempt, never to invocation count. A *transaction's* attempt token
  is stable across replays of one attempt and never reused by another, so within a transaction
  "have I already done this?" is answerable by marking completion under the attempt id. A
  transaction's forward direction and its compensating direction each carry their own token: an
  attempt id is never reused with different arguments, so "same attempt id and operation" always
  means "the same invocation, replayed".
- The reserved identities — `boot`, `periodic`, `fingerprint` — are stable, deliberately recurring
  names for operations that belong to no transaction. They are reused on every boot and every probe,
  so they must never be used as idempotency keys: an operation invoked under a reserved identity
  must do its full work on every invocation.
- A reconciler that needs multi-step resumability writes its own sub-progress durably under
  `--state-dir` (its private directory, preserved across replays and boots) and skips completed
  sub-steps on replay. The agent never interprets that state.
- Exactly-once *effects* are buildable on top: inspect the effect itself before doing its
  destructive half — a migration that finds its restore point already taken does not retake it — and
  where the effect can be made atomic, commit it together with its completion marker: a
  same-filesystem rename that is both the effect and the marker, a database transaction that writes
  the marker row beside the change, or a downstream API's own idempotency token derived from a
  transaction's attempt id. A marker written *after* a non-atomic effect only narrows the duplicate
  window; it does not close it.
- A hook that owns a detached workload must make the workload's reap handle (its pid file, service
  name, container id) durable *before* the workload can take traffic: the hook may be killed at any
  instant between starting it and recording it, and a workload nothing can name is a workload
  nothing can stop.
- `healthcheck` and `inspect` must be observations. The agent is free to repeat them any number of
  times, and the two may be in flight at the same time as each other; an observation with side
  effects turns every probe into a mutation replay.

The agent guarantees in return: `apply` and `rollback` never overlap any other operation on an
install root — the agent cancels and reaps a running `inspect` before either begins — while
`healthcheck` and `inspect` may overlap each other, so neither may assume exclusive use of
`--state-dir` scratch. Intent is journaled before every invocation, a crashed transaction is
resumed — forward via `apply` or compensated via `rollback` — from its last durable checkpoint, and
a candidate whose attempt is rejected is never retried under a new attempt.

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
stdin. The process runs as a contained tree (Unix process group / Windows job object). The agent
tears that tree down when the hook returns — on success, on failure, on timeout, and on cancellation
alike — so no descendant of an invocation outlives it. A hook that leaves a process running must
move it out of the tree first: `setsid` (Unix) or
`CREATE_BREAKAWAY_FROM_JOB | CREATE_NEW_PROCESS_GROUP | DETACHED_PROCESS` (Windows). A workload
started inside the tree is killed by its own successful `apply`. `crates/e2e/src/fixture.rs`'s
`detach()` is the reference implementation.

`--attempt-id` is a transaction's own token when the operation belongs to a transaction — including
a rollback's gate of the restored predecessor — or one of the three reserved identities for an
operation belonging to no transaction: `boot` (the per-boot and rotation converge,
`apply --attempt-id boot`, distinguished by `--reason install|restart`, and the boot readiness
gate), `periodic` (the steady-state `healthcheck` observation), and `fingerprint` (the steady-state
`inspect` observation). The reserved set is closed: any other value is a transaction token. For a
rollback operation `--candidate` is the restored predecessor and `--predecessor` is the failed
candidate, and `apply`, `healthcheck` and `rollback` all carry that transaction's compensating
token.

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
    # The workload must leave this invocation's process group, or the agent's teardown kills it
    # when this hook returns successfully.
    setsid ./existing-start-command --source "$candidate" </dev/null >>/var/log/app.log 2>&1 &
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
drain, stop, start, or restart the workload needs — as part of their domain behavior. A workload
belongs to the release, not to the invocation that started it: it must be detached from the hook's
contained tree (see Invocation) or the agent's teardown kills it when the hook returns. Once
detached, the agent holds no handle on it, so an agent restart, crash, or self-update cannot
disturb it.

## Secrets

The values behind the assignment's declared `SecretReference`s are present in every invocation's
environment, under the reference's `environment` name. They arrive only through the environment —
never argv, never a file the agent writes — and must not be echoed into the output manifest or
diagnostic streams.

A secret reference may not claim a reserved environment name. The reserved set covers both Unix and
Windows resolution variables — loader, interpreter, and module-search names such as `PATH`,
`LD_PRELOAD`, `SYSTEMROOT`, `PATHEXT`, and `PSMODULEPATH` — because a secret value is applied last
and would otherwise redirect code resolution for every hook the agent runs. Windows environment
matching is case-insensitive, so the check is by uppercased name and applies on every platform: an
assignment is validated once, centrally, not per node.

## Compatibility

`protocol 1` is the only protocol. The output manifest is a wire contract under
`docs/wire-compatibility-design.md`, and a dual-direction one: the manifest travels node → control
plane inside a signed report (reader window), but the values it carries are resolved into
`ManagedRuntime.inputs` of the signed assignment other nodes read (writer restraint). A new
`OutputValue` variant therefore cannot be published until every supported node reads it.
