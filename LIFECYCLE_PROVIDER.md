# Node reconciler protocol

Every release has exactly one signed node reconciler. The reconciler is privileged executable
policy: anyone authorized to sign it is authorized to modify the node with the privileges of
`updated`.

The agent owns artifact authentication and delivery, process containment, deadlines, retries,
scheduling, durable transaction state, and crash replay. The reconciler owns application-specific
machine state and the operations required to move it between releases.

## Invocation

The bundle declares one executable entrypoint. The agent invokes that same entrypoint for every
operation:

```text
reconciler OPERATION
  --protocol 1
  --attempt-id ID
  --reason install|restart|update
  --install-root PATH
  --state-dir PATH
  --candidate PATH
  --candidate-version VERSION
  --predecessor PATH
  --predecessor-version VERSION
  [--managed-pid PID]
  [-- PUBLISHER_ARGUMENTS...]
```

Arguments are passed directly as argv, never as shell text. Paths containing spaces remain one
argument. Lifecycle context is not exported through environment variables.

`--state-dir` is a durable, reconciler-specific directory created by the agent. A reconciler may
store SQLite databases or ordinary files there. Prefer observing the machine directly and persist
only facts that cannot be reconstructed.

`--managed-pid` is present only when the agent currently owns a managed application process and
that process exists during the operation. A reconciler must not require it in `provider-managed`
mode.

Arguments after `--` are immutable publisher-configured arguments from the signed provider set.

Exit status `0` means success. Any other status means the operation failed. For `verify` and
`periodic`, a non-zero status means the current workload observation is unhealthy. The agent owns
retry and recovery policy; providers do not encode special retry exit codes.

Stdout and stderr are diagnostic output. Do not place secrets in them.

## Operations

- `preflight`: reject an incompatible candidate before changing machine state.
- `prepare`: perform idempotent preparation and create rollback material.
- `pre-drain`: begin application-level quiescence while the workload may still serve traffic.
- `drain`: remove readiness and finish draining external work.
- `stop`: perform application-specific work immediately before the managed process is stopped, or
  stop the workload in `provider-managed` mode.
- `pre-start`: prepare per-boot machine state before a workload starts.
- `activate`: reconcile installed files and machine configuration to the candidate release.
- `start`: perform post-launch work in managed mode, or start the workload in
  `provider-managed` mode.
- `verify`: make one bounded activation/boot verification observation.
- `periodic`: make one bounded steady-state readiness/liveness observation.
- `finalize`: commit external state that should change only after verification.
- `rollback`: idempotently restore the predecessor after a failed activation.

Every operation listed above is invoked by the agent state machine. There are no phase-specific
entrypoints and no optional compatibility hooks.

## Runtime ownership

- `managed` is the default. The guardian owns the application process. The agent stop-starts it
  during activation and may pass `--managed-pid` while it exists.
- `provider-managed` means the reconciler owns workload/process state. The agent never launches,
  signals, probes, or stops an application process. `verify` and `periodic` still drive agent
  readiness and rollout telemetry.

## Bash template

```bash
#!/usr/bin/env bash
set -euo pipefail

operation=${1:?missing operation}
shift

protocol=
attempt_id=
reason=
install_root=
state_dir=
candidate=
candidate_version=
predecessor=
predecessor_version=
managed_pid=

while (($#)); do
  case "$1" in
    --protocol) protocol=$2; shift 2 ;;
    --attempt-id) attempt_id=$2; shift 2 ;;
    --reason) reason=$2; shift 2 ;;
    --install-root) install_root=$2; shift 2 ;;
    --state-dir) state_dir=$2; shift 2 ;;
    --candidate) candidate=$2; shift 2 ;;
    --candidate-version) candidate_version=$2; shift 2 ;;
    --predecessor) predecessor=$2; shift 2 ;;
    --predecessor-version) predecessor_version=$2; shift 2 ;;
    --managed-pid) managed_pid=$2; shift 2 ;;
    --) shift; break ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[[ $protocol == 1 ]] || { echo "unsupported protocol" >&2; exit 2; }

case "$operation" in
  preflight)
    test -x "$candidate/bin/my-app"
    ;;
  activate)
    install -m 0644 "$candidate/config/my-app.conf" /etc/my-app.conf
    ;;
  start)
    systemctl start my-app
    ;;
  verify|periodic)
    systemctl is-active --quiet my-app
    ;;
  rollback)
    install -m 0644 "$predecessor/config/my-app.conf" /etc/my-app.conf
    systemctl restart my-app
    ;;
  prepare|pre-drain|drain|stop|pre-start|finalize)
    ;;
  *)
    echo "unknown operation: $operation" >&2
    exit 2
    ;;
esac
```

## PowerShell template

```powershell
$ErrorActionPreference = 'Stop'

if ($args.Count -lt 1) { throw 'missing operation' }
$Operation = $args[0]
$Values = @{}

for ($i = 1; $i -lt $args.Count; ) {
    if ($args[$i] -eq '--') { break }
    if ($i + 1 -ge $args.Count) { throw "missing value for $($args[$i])" }
    $Values[$args[$i]] = $args[$i + 1]
    $i += 2
}

if ($Values['--protocol'] -ne '1') { throw 'unsupported protocol' }

switch ($Operation) {
    'preflight' {
        if (-not (Test-Path "$($Values['--candidate'])\my-app.exe")) { exit 1 }
    }
    'activate' {
        Copy-Item "$($Values['--candidate'])\my-app.conf" 'C:\ProgramData\MyApp\my-app.conf'
    }
    'start' { Start-Service 'MyApp' }
    { $_ -in 'verify', 'periodic' } {
        if ((Get-Service 'MyApp').Status -ne 'Running') { exit 1 }
    }
    'rollback' {
        Copy-Item "$($Values['--predecessor'])\my-app.conf" 'C:\ProgramData\MyApp\my-app.conf'
        Restart-Service 'MyApp'
    }
    { $_ -in 'prepare', 'pre-drain', 'drain', 'stop', 'pre-start', 'finalize' } {}
    default { throw "unknown operation: $Operation" }
}
```

## Replay requirements

The agent may crash after a reconciler succeeds but before phase completion is durably recorded.
It will then invoke the same operation again with the same attempt ID. Each operation must
therefore converge when replayed. Use atomic replacement, compare-before-write, idempotent service
commands, and attempt-scoped state rather than assuming exactly-once execution.
