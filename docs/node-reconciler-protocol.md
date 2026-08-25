# Node reconciler protocol

Status: implemented. The shared vocabulary and argv builder live in
`updated-contracts::reconciler`; the agent invocation is
`agent::update::prepare_lifecycle_command`.

Every release carries one signed reconciler: a script, native binary, or other executable. The
agent verifies and invokes it without interpreting application semantics. The reconciler is the
only component that starts, stops, drains, configures, or restarts a workload.

## Operations

The interface has exactly four operations:

- `apply` idempotently converges the machine to `--candidate` and emits that state's output files.
- `healthcheck` makes one bounded readiness observation. Exit zero means healthy.
- `rollback` idempotently restores `--candidate` and emits the restored state's output files.
- `inspect` makes one bounded steady-state observation. Non-empty stdout is opaque fingerprint
  material.

`--candidate` always names the release to converge onto. During rollback it is the release being
restored; `--predecessor` is the failed release being left. The same rule in both directions keeps
direction-specific behavior out of ordinary reconcilers.

The agent owns verification, artifact placement, retries, deadlines, durable transaction state,
crash recovery, and rollout reporting. None of those is a reconciler operation.

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
  --output-dir PATH
  --result-file PATH
  --input-dir PATH
  --predecessor PATH
  --predecessor-version VERSION
  [-- PUBLISHER_ARGUMENTS...]
```

`--reason` is exactly one of `install`, `restart`, or `update`.

Arguments are direct argv, never shell text. Stdin is null. The environment is cleared and then
given only a small platform resolution baseline (`PATH` on Unix; system and temporary-directory
variables on Windows). Configuration, credentials, and secret material have one application-facing
representation: ordinary files in `--input-dir`. They are never injected as environment variables.

Each invocation receives new private `--input-dir` and `--output-dir` directories plus a dedicated
`--result-file` path. They do not survive the invocation. `--state-dir` is the reconciler's durable
private state and does survive replays, releases, and boots.

The process runs as a contained tree (a Unix process group or Windows job object). The tree is torn
down when the hook returns, including on success. A workload that must outlive `apply` has to move
out of the tree first (`setsid` on Unix, or the corresponding detached/breakaway flags on Windows)
and durably record its service or process handle before accepting traffic.

`--attempt-id` is the deployment transaction token or one of four recurring reserved identities:

- `boot` for boot/restart convergence and its readiness gate;
- `converge` for steady-state desired-state convergence and its readiness gate;
- `periodic` for steady-state healthchecks;
- `fingerprint` for steady-state inspection.

Reserved identities are not idempotency keys because they are deliberately reused. A transaction
token is exactly 64 lowercase hexadecimal characters, is stable across crash replay, and is never
reused with different arguments. Its compensating direction appends `r` to that token.

The operation, reason, and attempt identity are one grammar, not independent options:

| Operation | Reason | Accepted attempt identity |
| --- | --- | --- |
| `apply` | `install` | `boot` |
| `apply` | `restart` | `boot` or `converge` |
| `apply` | `update` | transaction token or its compensating form |
| `rollback` | `update` | compensating transaction token |
| `healthcheck` | `install` | `boot` |
| `healthcheck` | `restart` | `boot`, `converge`, or `periodic` |
| `healthcheck` | `update` | transaction token or its compensating form |
| `inspect` | `restart` | `fingerprint` |

Every other combination is invalid and is refused before the hook is started.

## File dataflow

The reconciler sees files, not JSON, base64, secret references, object-store URLs, or provider-
specific values. This is the only configuration path.

`--input-dir` is immutable for the invocation and contains exactly the files selected by the signed
assignment. A missing or extra file makes the snapshot unusable before the reconciler is invoked.
The directory may be empty.

`--output-dir` starts empty on every invocation. A successful `apply` or `rollback` publishes
exactly the files left there as the release's new atomic output snapshot. The reconciler must emit
the complete snapshot on every replay; it cannot rely on files left by an earlier invocation.
`healthcheck` and `inspect` never publish outputs, even if they write into their disposable output
directories.

Snapshots are deliberately small and flat:

- at most 64 files;
- each name is one safe path component of at most 128 bytes;
- only regular files are accepted—no directories, symlinks, devices, or non-UTF-8 names;
- each file is at most 64 KiB;
- the serialized snapshot is at most 512 KiB.

An invalid output snapshot fails the otherwise-successful operation. The previous durable snapshot
remains authoritative. Inputs and outputs may contain secrets; reconcilers must not copy their
contents to stdout, stderr, argv, logs, or process-wide environment variables.

The agent serializes these files only at its private S3 boundary. A producer's successful snapshot
is bound to its signed health report, and a consumer receives a controller-built snapshot named by
an opaque keyed generation in its signed assignment. Changes cascade by republishing the affected
assignment and reapplying the consumer's last known release with `--reason restart`.

## Structured mutation result

Every successful `apply` and `rollback` must write one bounded JSON document to
`--result-file` before exiting zero. `healthcheck` and `inspect` must not create that file. A
missing, malformed, oversized, or contradictory document fails the invocation.

```json
{
  "schema": 1,
  "status": "succeeded",
  "changed": true,
  "hostAction": "none",
  "message": "optional one-line diagnostic"
}
```

- `status` is `succeeded` or `retry`.
- A `succeeded` result carries `changed` and `hostAction` (`none` or `reboot`) and never carries a
  retry delay.
- A `retry` result carries only `retryAfterSeconds` (from 1 through 3600) and `message`; it cannot
  claim completion, changed state, or a host action.
- `message` is optional, control-character-free, and at most 4 KiB.

The agent owns retry policy: it repeats the same operation, attempt id, and arguments up to five
times, sleeping the requested bounded delay. Retry exhaustion is an inconclusive node condition,
not evidence that the candidate bytes are bad.

The agent also owns reboot policy. After a successful mutation requests `reboot`, it durably
commits the transaction with its predecessor retained, invokes the fixed operating-system reboot
command, and does not ask the pre-reboot machine for a health verdict. On the next boot the ordinary
boot `apply` and `healthcheck` confirm the new state; failure restores the predecessor. A script
must request reboot whenever its desired state has not yet crossed the required reboot boundary.

For every successful mutation the agent durably records the operation, reason, attempt id, both
immutable release identities, structured result, and completion time before accepting success. The
latest record is included in the node's signed report.

## Replay and concurrency

There is no exactly-once invocation. An operation can be interrupted after any prefix of its work
and invoked again with the same arguments. Therefore:

- `apply` and `rollback` must be idempotent and must re-emit their complete output snapshot;
- durable multi-step progress belongs under `--state-dir`, keyed by transaction attempt id;
- a completion marker written after a non-atomic side effect does not make that effect exactly
  once—use an atomic effect, a transaction, or a downstream idempotency token;
- `healthcheck` and `inspect` are read-only observations and may overlap each other;
- `apply` and `rollback` do not overlap another operation on the same install root.

The last completed state-changing invocation wins. A rejected candidate is not retried under a new
attempt token.

## Exit and output

For `apply` and `rollback`, exit zero means the process produced an answer and `--result-file`
contains its semantic outcome. Any nonzero status means the reconciler could not answer. For
`healthcheck`, exit zero means healthy and nonzero means unhealthy. `inspect` must exit zero and
write a non-empty, stable measurement to stdout; the agent hashes the exact bytes. Other operations
must keep stdout empty. All stderr is diagnostic and bounded. The agent enforces structure and
limits but cannot prove the domain behavior is safe or correct.

## Conformance harness

```text
updatectl reconciler-check ./reconciler [--scratch DIR] [-- PUBLISHER_ARGUMENTS...]
```

The harness uses the shared argv builder, cleared environment, null stdin, fresh exchange
directories, and production snapshot validator. It checks:

- replayed `apply` and `rollback` succeed, report `changed: false`, and independently re-emit
  identical output files;
- every successful mutation publishes a valid result and observations publish none;
- replayed observations return consistent status without changing `--state-dir`;
- `inspect` emits identical non-empty stdout;
- unknown operations and protocols fail;
- every emitted output snapshot satisfies the production bounds.

It needs no repository, keys, object store, or Kubernetes access.

## Minimal Bash reconciler

```bash
#!/usr/bin/env bash
set -euo pipefail

operation=${1:?missing operation}
shift
protocol= reason= candidate= predecessor= input_dir= output_dir= result_file=

while (($#)); do
  case "$1" in
    --protocol) protocol=$2; shift 2 ;;
    --reason) reason=$2; shift 2 ;;
    --candidate) candidate=$2; shift 2 ;;
    --predecessor) predecessor=$2; shift 2 ;;
    --input-dir) input_dir=$2; shift 2 ;;
    --output-dir) output_dir=$2; shift 2 ;;
    --result-file) result_file=$2; shift 2 ;;
    --attempt-id|--install-root|--state-dir|--candidate-version|--predecessor-version)
      shift 2 ;;
    --) shift; break ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ $protocol == 1 ]] || exit 2

emit_outputs() {
  # Re-emit the complete snapshot on every apply/rollback invocation.
  printf '%s\n' "https://database.internal:5432" >"$output_dir/endpoint"
}

publish_success() {
  local changed=$1 host_action=${2:-none}
  printf '{"schema":1,"status":"succeeded","changed":%s,"hostAction":"%s","message":null}' \
    "$changed" "$host_action" >"$result_file"
}

case "$operation" in
  apply)
    ./existing-installer --source "$candidate" --config "$input_dir/application.conf"
    setsid ./existing-start-command --source "$candidate" </dev/null >>/var/log/app.log 2>&1 &
    emit_outputs
    publish_success true
    ;;
  healthcheck) ./existing-status-command ;;
  rollback)
    ./existing-restore-command --source "$candidate"
    emit_outputs
    publish_success true
    ;;
  inspect)
    ./existing-status-command
    printf 'state=ready\n'
    ;;
  *) echo "unknown operation: $operation" >&2; exit 2 ;;
esac
```

`protocol 1` is the only protocol. There is no legacy manifest or environment-secret path.
