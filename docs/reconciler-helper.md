# Reconciler helper

Every reconciler invocation receives `UPDATED_RECONCILER_HELPER`, the absolute path to the native
helper supplied by its agent. Invoke that executable with `reconciler-helper`, send one UTF-8 JSON
request on stdin, close stdin, and read one JSON response from stdout. Exit zero means success;
failure returns nonzero and a structured error. No Rust toolchain, language SDK, shell, network
service, or separate helper installation is needed. The same interface works on Linux, Windows,
and macOS. The helper runs with the reconciler's existing privileges.

The helper is a subcommand of the agent executable. Before resolving a deployment, the agent copies
its executable into a private cache under its enrollment state, while holding its instance lock.
That copy stays available throughout the agent's invocations even if the distributed executable is
replaced. The next agent startup replaces the cache with its own build. This adds one executable
copy at startup, no helper downloads, and no copy or new waiting lock on a probe or reporting path.
The service installer must stop the old agent before starting its replacement.

## Calling it from any language

Python, inside the customer's reconciler:

```python
import json, os, subprocess

def helper(command, **values):
    process = subprocess.run(
        [os.environ["UPDATED_RECONCILER_HELPER"], "reconciler-helper"],
        input=json.dumps({"api": 1, "command": command, **values}).encode("utf-8"),
        stdout=subprocess.PIPE, check=False,
    )
    response = json.loads(process.stdout)
    if process.returncode or not response["ok"]:
        raise RuntimeError(response["error"]["message"])
    return response["value"]

context = helper("context")
# Customer code observes actual state and decides whether this transition is supported.
# For an explicitly owned UTF-8 configuration file:
changed = helper("file", path=config_path, content=desired_config)["changed"]
helper("succeed", changed=changed, outputs={"endpoint": advertised_endpoint})
```

Shell needs no SDK for a fixed result:

```sh
printf '%s' '{"api":1,"command":"succeed","changed":false}' |
  "$UPDATED_RECONCILER_HELPER" reconciler-helper
```

For PowerShell, use the call operator with `$env:UPDATED_RECONCILER_HELPER`. JSON stdin must be
UTF-8; Windows PowerShell 5.1 callers must set `$OutputEncoding` to UTF-8 when piping non-ASCII data.
The native helper itself has no PowerShell dependency. Callers in Go, Java, C#, and other languages
use the same subprocess and JSON interface. Platform invocation context is supplied automatically;
the `UPDATED_RECONCILER_CONTEXT` environment value is internal, so use the `context` command.

## API 1

All requests include `"api":1` and `"command"`. The current build supports one API, with no
legacy adapters. Unknown versions, fields, and commands fail before their requested effect.
Requests are limited to 1 MiB. Error messages never echo malformed requests, which may contain
credentials. Successful responses are `{"api":1,"ok":true,"value":...}`; failures contain
`{"api":1,"ok":false,"error":{"code":"busy|timeout|unsupported|failed","message":"..."}}`.

| Command | Additional fields | Behavior |
| --- | --- | --- |
| `capabilities` | None | Returns supported API numbers and capability names; works outside an invocation. |
| `context` | None | Validates protocol, operation, reason, and attempt; returns those values and the invocation paths. Customer arguments after `--` remain application-owned. |
| `boot-id` | None | Returns `bootId`, stable across service restarts and changed by an OS boot. |
| `file` | `path`, `content` | Converges one UTF-8 file using private atomic replacement; returns `changed`. Creates missing parent directories; refuses final symlinks and oversized existing files. |
| `output` | `name`, `content` | Writes one bounded UTF-8 output file into the invocation's output directory. |
| `succeed` | Optional `changed`, `reboot`, `message`, `outputs` | Builds and publishes a successful protocol result; booleans default to false. Covered by capability `result`. |
| `retry` | `afterSeconds`, optional `message` | Builds and publishes a bounded retry result. Covered by capability `result`. |
| `result` | `result`, optional `outputs` map of names to UTF-8 contents | Validates the protocol result and complete output snapshot, then atomically publishes the result file. Outputs are emitted even when `changed` is false. Retry results cannot publish outputs. |
| `sequence` | `resource`, `steps`, `timeoutSeconds` | Runs an ordered list of verified steps under one local resource lock, as described below. Use a one-element list for a single step. |

Only `context` and `boot-id` are available to observations inside an invocation. `capabilities`
needs no invocation. The other commands require `converge` or `rollback`. This is helper policy,
not an OS sandbox for customer code. `file` intentionally writes owner-only files; integrations
that require other ownership or permissions must implement and verify that explicit policy.
Each output is at most 64 KiB, with at most 64 outputs and the normal aggregate dataflow bound.
Output directories are fresh: every successful replay must advertise the entire output set.

## Verified progress, without a run-once promise

Example request, with paths supplied by the customer's integration:

```json
{
  "api": 1,
  "command": "sequence",
  "resource": "application-database",
  "timeoutSeconds": 120,
  "steps": [
    {
      "id": "schema-2",
      "definitionSha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "check": ["/absolute/path/to/customer-tool", "check-schema-2"],
      "apply": ["/absolute/path/to/customer-tool", "migrate-schema-2"],
      "timeoutSeconds": 120
    }
  ]
}
```

Use real digests identifying each migration's semantics. Identities are stable across deployment
attempts and releases. Reusing an identity with a different definition is refused. Resource and
step names use the portable identity grammar. Progress lives under `--state-dir/helper-steps`.
A sequence contains 1–128 steps with unique IDs. The helper validates every declaration and stored
identity before executing any child, including conflicts in later steps. It does not sort, infer,
or fill gaps in the supplied sequence; the application chooses the path from observed state.

`check` must inspect actual destination state: exit 0 means complete, 10 means applying is safe and needed,
and every other exit means observation failed. The helper checks on every invocation, even when
a completion record exists. When work is needed it records the definition, runs `apply`, and
checks again before recording completion. `apply` must exit zero; a failed or interrupted apply
leaves progress available for the next check. The first failure stops the sequence; subsequent steps
do not run. Error messages identify the failed step and its position. Successful completion returns
`{"changed": true, "completed": 1}` (with `changed` false if every check already passed).
Child arguments are passed directly, never evaluated by a shell. Child output and step positions go
to stderr so stdout remains the helper's JSON response.

One nonblocking OS lock protects the resource across the entire sequence, including all checks and
applies. Contention returns `busy` immediately; unrelated resources remain independent. Both the
sequence deadline and each step's deadline are bounded to 1–3600 seconds; the earlier deadline wins.
The sequence deadline covers the whole list, not a fresh allowance for every step. The deployment
entrypoint's outer deadline still applies and must budget for planning and helper execution.
On timeout the contained child tree is stopped. Process death releases the lock. Callers can convert
`busy` to the protocol's bounded retry result.

The customer must still make an interrupted external effect safe: use a destination transaction,
safe repetition, a destination idempotency key, or a reliable completion inspection. A local record
cannot establish exactly-once execution. The helper does not infer transition compatibility, undo
database migrations, exclude external writers that ignore its lock, or guess rollback policy.
The lock coordinates only callers sharing this local state directory; cluster-wide coordination
belongs to the application. Sequence failure does not reverse completed steps. The enclosing
deployment's replay and recovery policies still decide whether another invocation is authorized;
using `sequence` does not automatically make a deployment safe to repeat.

On an authorized retry, each supplied step is checked again. A check for an earlier transition must
recognize healthy later states when its effect is still satisfied; it must not try to downgrade the
application merely because its version is now higher. Unsupported, mixed, or uncertain states must
fail inspection unless the application can safely finish that particular transition. See
[install and upgrade paths](install-and-upgrade.md) for separate installation and ordered upgrades.

For reboot-dependent work, store the `boot-id` with the integration's progress and keep returning
`hostAction: reboot` until it changes or the integration verifies no reboot is needed. Recording a
request does not establish that a reboot occurred.

## Upgrades and validation

The helper and package runtime ship in the agent executable. The agent pins its running executable
once at startup, so replacing an agent binary cannot change helpers halfway through an attempt.
The package declares its execution API; unsupported APIs request an agent upgrade and do not
permanently reject application bytes. Upgrade agents before publishing packages requiring a new API.
Signed reports advertise the available helper API and capabilities.

`updatectl check` supplies the same helper automatically. Application integration tests should
assert actual state after install, drift, unsupported transitions, interruption, and recovery.
