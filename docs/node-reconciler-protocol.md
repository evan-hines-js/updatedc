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
interpret application or infrastructure semantics.

## Operations

The public interface has exactly four operations:

- `apply` — idempotently converge machine state to the candidate. `--reason` distinguishes
  `install`, `update`, and `restart`/repair.
- `healthcheck` — make one bounded readiness observation. Exit zero means healthy.
- `rollback` — idempotently restore or compensate toward the predecessor.
- `inspect` — make one bounded steady-state observation. Non-empty stdout is opaque fingerprint
  material; typed dependency outputs are written to `--output-file`.

The agent owns artifact verification, placement, draining, managed-process stop/start, retry
cadence, timeouts, durable transaction state, crash replay, and rollout reporting. Those are
intentionally not reconciler operations.

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
  [--managed-pid PID]
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

In `managed` mode the agent owns the application process and performs its internal drain/stop/start
around `apply` or `rollback`. In `provider-managed` mode the reconciler owns workload processes;
`apply` and `rollback` must converge them as part of their domain behavior. Both modes use the same
four-operation interface.

## Compatibility

`protocol 1` is the only protocol. The output manifest is a wire contract under
`docs/wire-compatibility-design.md`, and a dual-direction one: the manifest travels node → control
plane inside a signed report (reader window), but the values it carries are resolved into
`ManagedRuntime.inputs` of the signed assignment other nodes read (writer restraint). A new
`OutputValue` variant therefore cannot be published until every supported node reads it.
