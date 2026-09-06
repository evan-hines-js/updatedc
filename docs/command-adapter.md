# Run a package entrypoint

Give updatedc a directory and the program to run. Your entrypoint can be arbitrary code in any
language, using your existing installers, service managers, or infrastructure tools.

In CI, with your release repository and online signing keys configured:

```sh
updatectl publish --source ./package --entrypoint install.sh \
  --product my-app --version 4.0.0
```

This publishes a package and prints its immutable reference. Operators select that reference in
`UpdateGroup` YAML; the CLI does not patch groups or start rollouts. See the
[CI publication workflow](ci-publication.md).

For an interpreted program, add `--interpreter python3` or `--interpreter pwsh` and name the
appropriate package file as the entrypoint. Interpreters must exist on the target machine.
Use repeated `--arg=value` options for literal arguments. No reconciler operation or protocol
flags are appended to your command. Native executables work directly on their target OS. On Unix, scripts run directly when executable
with a shebang; otherwise specify an interpreter such as `--interpreter sh`.

The CLI snapshots the package, generates and signs its execution metadata, and selects the native
runtime automatically. It leaves your source directory untouched. Customers do not write a protocol
wrapper or publish a separate reconciler executable. The runtime and optional helper are Rust code
included in the agent on Linux, macOS, and Windows; they upgrade with the agent. Signed metadata
names the required execution API, and an older agent refuses an unsupported API before mutation.
There is no separate runtime installation or upgrade workflow.

Exit zero means deployment completed. An optional `--healthcheck health.sh` adds an ongoing
application health check, using the same interpreter and a five-second deadline. Without it,
readiness means recorded successful execution; it does not assert that services or data remain
healthy or detect arbitrary drift. `--timeout-seconds` sets the deploy/recovery deadline, defaulting
to 300 seconds. The platform derives its outer invocation budget automatically.

After interruption or failure, the default is to pause for an operator decision. Add `--replay safe`
only when the entrypoint safely tolerates partial completion and repetition. Add `--recover recover.sh`
for explicit recovery, and `--recovery-replay safe` if that command also tolerates repetition.
Without a recovery command, recovery requires an operator. These policies concern uncertain
execution: a later deployment or changed assigned inputs can run a completed entrypoint again.

## What commands receive

Commands run with the immutable payload directory as their current directory. Write persistent
progress into `UPDATED_STATE_DIR`, not the payload. The adapter supplies:

| Environment variable | Value |
| --- | --- |
| `UPDATED_PAYLOAD_ROOT` | Absolute path to the verified payload |
| `UPDATED_PAYLOAD_VERSION` | Desired release version; not evidence of installed state |
| `UPDATED_INPUT_DIR` | Fresh directory of authenticated assigned input files |
| `UPDATED_STATE_DIR` | Persistent state shared across releases of this product |
| `UPDATED_ATTEMPT_ID` | Stable identity of this platform invocation |
| `UPDATED_OPERATION` | `converge`, `rollback`, `healthcheck`, or `inspect` |
| `UPDATED_REASON` | `install`, `restart`, or `update`; context, not proof of current state |
| `UPDATED_RECONCILER_HELPER` | Native helper executable; see the [helper API](reconciler-helper.md) |

Stdin is closed. Command stdout and stderr become invocation diagnostics; keep secrets out of them.
The runtime produces the structured result automatically. Use the optional helper for outputs,
reboot requests, retries, or operator attention; successful results and outputs survive replay.
An optional `--inspect` command supplies application-specific inspection through stdout.
A service must outlive the bounded invocation through its service manager; starting a background
child inside the invocation does not establish a persistent service.

## Replay and recovery

The adapter records `running` durably before starting a mutation and `complete` or `failed` after
it finishes. Receipt identity binds the immutable payload and exact configuration bytes, separately
from the deployment attempt. A process death can leave `running`; that is uncertainty, not proof
that nothing happened. An uncertain receipt cannot be bypassed by assigning a new attempt ID.

Choose a replay policy for deploy and, separately, for any recovery command:

| Policy | Meaning after an incomplete or failed invocation |
| --- | --- |
| `safe` | The procedure tolerates repetition, including after partial effects |
| `check` | Run the supplied observation command: exit 0 proves completion; 10 proves repetition is safe; any other result, timeout, or spawn failure requires attention |
| `manual` | Require an operator decision before repeating |

For a destination-aware replay check, add `--replay-check check.sh`. For recovery, use
`--recover recover.sh --recovery-check check-recovery.sh`. Each check returns 0 for completed work,
10 for safe repetition, or another exit code to require attention. These options use the selected
interpreter and command timeout. Do not combine a check with an explicit replay policy.

The check must inspect the destination. A local “ran once” marker cannot disambiguate a database
commit followed by process death. Use destination transactions, stable migration identities,
destination-supported idempotency keys, or a reliable completion query. Platform attempt IDs are
not application migration identities.

After a completed deploy with unchanged inputs, a same-attempt or routine convergence checks
health when configured. Passing health, or a completed receipt when health is omitted, avoids another deploy. Failed health invokes the selected replay policy; only an authorized
deploy may repair drift. Make the health command cover the configuration and application invariants
that matter. A version marker alone is insufficient. A new transaction after a completed deployment
runs deploy again. Changed input contents also trigger deploy after a completed invocation, even if
health still passes. A changed input snapshot during uncertain work requires attention. Input digests
stay in private receipts and are never published in fleet reports.

Recovery is explicit. Without `--recover`, recovery stops for an operator.
`--recover recover.py --recovery-replay safe` selects a recovery script and permits repetition,
using the same interpreter as the entrypoint.

The failed candidate's recovery procedure must restore the predecessor's required application and
data state, including any necessary file or service changes. The adapter then lets the platform
verify predecessor readiness; it never implicitly executes an old deploy script. Repeated completed
compensation is a no-op. Failed recovery creates an attention hold instead of reporting restoration.
Document what recovery actually restores, especially irreversible data migrations.

Compatibility remains an application decision: deploy must inspect actual machine state and refuse
unsupported transitions before changing it. Neither invocation reason nor numeric version order
establishes compatibility. Internal migration sequences can implement direct convergence; the adapter
does not stage required intermediate releases.
An entrypoint may dispatch to separate install and upgrade scripts after inspecting the application.
The optional native `sequence` helper runs the author's ordered steps through one checked executor;
see [installation and ordered upgrades](install-and-upgrade.md).

## Operator attention

A `needs-attention` result stops platform mutations and persists across agent restarts. Signed node
reports include the affected release, operation, attempt, and reason, with health false and no output
or fingerprint evidence. The agent makes a bounded best-effort report before exiting; failed delivery
leaves the local hold intact. Service restarts can refresh the report; a stopped service's report
expires normally. This adds report data and local controls, not a new fleet UI.

Inspect the hold without stopping the service:

```text
updated-agent command-status INSTALL_ROOT
```

To resolve it, stop the agent service, inspect the application and command receipts under its
persistent `commands/` directory, then record the decision:

```text
updated-agent command-resume INSTALL_ROOT retry
updated-agent command-resume INSTALL_ROOT complete
updated-agent command-resume INSTALL_ROOT recovered
```

Choose **one**: `retry` authorizes another execution of the held command; `complete` records your
verification that it completed; `recovered` records your verification that the transaction has been
recovered externally and suppresses its recovery command. `recovered` applies only to transaction
attempts. These commands acknowledge evidence you obtained; they do not inspect infrastructure.
Restart the service afterward. Normal transaction recovery ordering still applies: authorizing retry
of a forward command does not force an interrupted transaction to continue forward. Boot recovery
may instead require the configured recovery procedure. Resolution requires the matching execution receipt.

Resolution takes the agent's installation lock without waiting. Decisions are written durably before
the hold is removed; repeating the same decision finishes an interrupted resolution. Command locks
are also nonblocking and scoped to one reconciler product. Contention returns a bounded protocol
retry. Health and inspection acquire no command lock, and unrelated products have separate locks.

## Test the procedure

Validate a package without executing customer code:

```sh
updatectl check ./package --entrypoint install.sh
```

Exercise it with a predecessor fixture on a disposable test host:

```sh
updatectl check ./fixtures/v4 --entrypoint install.sh --against ./fixtures/v3
```

Use the same execution options as deployment. The harness copies regular files and executable
permissions into scratch directories and supplies the runtime environment. Customer code still
executes on the test host and can affect external systems. A manual recovery policy passes by
correctly requesting attention; an automatic recovery policy must pass compensation checks.
All packages use this runtime; the full protocol is an internal platform interface.

Add application assertions for clean install, same-version convergence, drift, supported and refused
transitions, interruption after each external effect, replay checks, repeated compensation, and
recovery. Native adapter tests exercise real subprocess death, deadlines, uncertain replay, operator
decision persistence, lock contention, and independent observations. They cannot prove a customer's
external effect is safe to repeat.

The adapter's `inspect` reports requested payload identity and observed readiness. It is not a
resource diff. A meaningful plan for a generic script requires that script's own read-only planning
interface; the platform does not fabricate one from command text.

Execution metadata is generated and signed by `updatectl`; do not author `.updated-execution.json`
in a package. Use one entrypoint and the small set of health, inspection, replay, and recovery
options. Language-specific orchestration and version transitions belong inside the package code.
