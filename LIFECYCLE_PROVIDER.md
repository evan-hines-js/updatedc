# Node reconciler protocol

Every release carries one signed node reconciler. It may be a Bash or PowerShell script, a native
binary, or any other executable. Updatedc authenticates and invokes it but deliberately does not
interpret application or infrastructure semantics.

## Operations

The public interface has exactly four operations:

- `apply` — idempotently converge machine state to the candidate. `--reason` distinguishes
  `install`, `update`, and `restart`/repair.
- `healthcheck` — make one bounded readiness observation. Exit zero means healthy.
- `rollback` — idempotently restore or compensate toward the predecessor.
- `inspect` — make one bounded steady-state observation. Non-empty stdout is opaque fingerprint
  material; typed dependency outputs are written to `--output-file`.

Updatedc owns artifact verification, placement, draining, managed-process stop/start, retry cadence,
timeouts, durable transaction state, crash replay, and rollout reporting. Those are intentionally
not provider operations.

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
  --input-file PATH
  --output-file PATH
  --predecessor PATH
  --predecessor-version VERSION
  [--managed-pid PID]
  [-- PUBLISHER_ARGUMENTS...]
```

Arguments are passed directly as argv, never shell text. The input file is a JSON object containing
typed values resolved from prerequisite groups. The output path is partitioned by the immutable
candidate identity, so a failed candidate's values cannot be attributed to a restored predecessor.

An output manifest is atomically written as:

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

Secret values must never appear in the manifest or diagnostic streams. Only references are
transported. Updatedc validates names, types, counts, per-value sizes, and total file size before
including outputs in a healthy signed node report.

Exit status zero means success; any other status means failure. Updatedc can enforce ordering,
bounds, identity, and result handling, but cannot prove that scripts are idempotent, read-only, safe,
or semantically correct.

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
    --attempt-id|--install-root|--state-dir|--candidate-version|--predecessor-version|--managed-pid)
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
    ./existing-restore-command --source "$predecessor"
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

In `managed` mode updatedc owns the application process and performs its internal drain/stop/start
around `apply` or `rollback`. In `provider-managed` mode the reconciler owns workload processes;
`apply` and `rollback` must converge them as part of their domain behavior. Both modes use the same
four-operation interface.
