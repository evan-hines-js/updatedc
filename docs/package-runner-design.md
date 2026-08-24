# Package-runner design

Status: implemented by this refactor. Supersedes the guardian/supervisor/app "process tower":
the agent no longer launches, adopts, signals, drains, or holds a PID of any workload, ever.

## The one sentence

The node agent is a package runner: it pulls signed TUF bundles, transactionally activates
them, and invokes the release's own reconciler hooks — `apply`, `healthcheck`, `rollback`,
`inspect` — and nothing else touches workload processes.

## Why

The previous design had two ways to run a workload: `managed` mode (the agent owned the
application process — launch, adopt-across-restarts, drain/stop/start, secrets-into-env,
PID handoff through the guardian) and `provider-managed` mode (the release's reconciler owns
its processes). Everything hard, platform-specific, and bug-prone in the node stack existed
to serve `managed` mode:

- The guardian owned the app so a supervisor could restart or self-update without disturbing
  it — a problem that only exists because the supervisor held the app in the first place. If
  the operator's init system (or the reconciler) owns the workload, agent restarts are free.
- Adoption (`APP_PID_ENV`, launched-secrets records, environment-digest comparison) existed
  so a restarted supervisor could prove a running process still matched current state.
- Process containment (process groups, `PR_SET_PDEATHSIG`, Windows Job Objects for the app),
  drain/stop/start sequencing, and readiness handshakes about the app all followed.

`provider-managed` mode already did none of this and lost nothing: health is the
`healthcheck` hook, convergence is `apply`, recovery is `rollback`. The e2e suite already
drove a real HAProxy through hooks alone. This refactor deletes `managed` mode and the tower
that served it. One mode. One way to touch a process: the release's own hooks.

This also repositions the product honestly: a generic, signed, transactional configuration/
deployment channel with zero learning curve. A release is any tarball/zip plus an entrypoint;
the entrypoint is a Bash/PowerShell script or binary the operator already knows how to write.
The agent guarantees delivery, verification, transactionality, health-gated rollback,
rejection-by-hash, and fleet reporting; the operator's script does whatever their environment
needs — `systemctl restart`, `sc.exe`, container runtimes, config reloads, anything.

## What the agent still owns (unchanged)

- TUF pull/verify, bundle staging, content-addressed immutable versions, atomic pointer flip.
- Durable transactions: journals, crash replay, confirmation windows, rollback,
  rejection-by-content-hash (a failed candidate is never retried).
- Hook invocation: bounded, contained (a hung hook's whole tree is killed on timeout),
  cleared environment, argv-only, and fresh per-invocation file exchange.
- Signed NodeReports: settlement, health (from the `healthcheck` hook), and exact-byte output
  bindings. File contents use the private object store, not telemetry.
- Agent self-update by pointer flip, gated by the launcher (below).
- Assignment-selected, keyed-blinded input publications from the private object store through
  short-lived exact-object capabilities. Their TUF-signed commitments authenticate S3 without
  publishing a low-entropy secret digest.

## What is deleted

- The agent's ownership of any workload process: launch, adopt, drain, stop, start, signal,
  PID tracking, `--managed-pid`, `APP_PID_ENV`, app process containment.
- The guardian's app half: holding the app, returning it to traffic, app stop grace/kill
  tree, the app-related guardian⇄supervisor IPC.
- The launched-secrets record and environment-digest adoption comparison.
- `managed` runtime mode in configuration, contracts, docs, and tests.

## Configuration dataflow

All application configuration, including secrets, reaches hooks as ordinary private files in a
fresh `--input-dir`. Hooks advertise ordinary files through a fresh `--output-dir`. The agent has
no scalar-secret, environment-variable, manifest, or proxy path. S3 is the durable data plane;
mTLS authorizes short-lived capabilities for one exact object and method. When a producer's files
change, dependent assignments receive a new opaque input generation and reapply their last known
release with `--reason restart`.

## Health

The `healthcheck` hook is the only health source. Process-aliveness signals are gone —
the agent has no process to observe. Confirmation windows, regression evidence, and
healthproxy pool membership all key off hook results and reports exactly as they already
did for provider-managed releases.

## The launcher (formerly the guardian)

One problem from the tower is real and stays solved: a self-updating agent must not brick
itself. Init restart loops do not revert pointers. The launcher is the guardian shrunk to
that single job:

- Launch the agent from the confirmed pointer.
- Hold a new agent candidate to a readiness deadline.
- On failure: revert the pointer and record a rejection by content hash, so a bad agent
  binary is never retried.

It knows nothing about workloads. It runs under the operator's init system (systemd unit,
launchd plist, Windows service — the shipped `deploy/` assets), which owns *its* restarts.

## Renames

Names must match the new shape, and nothing keeps its old name as an alias:

- crate `supervisor` → `agent` (binary `updated-agent`): it supervises nothing; it runs
  packages.
- crate `bootstrap` → `launcher` (binary `updated-launcher`).
- The reconciler protocol drops `--managed-pid`; `protocol` stays `1` — nothing is deployed,
  there is no compatibility surface yet, and the argument was optional.

## e2e disposition

- Hook-driven workload scenarios (application lifecycle, rollback, chaos-at-every-boundary,
  migration-shaped transactions, HAProxy) are rewritten where needed so the release's own
  entrypoint starts/stops the workload (a script + pidfile), proving the generic model with
  the same crash-injection coverage.
- Adoption and launched-secrets scenarios are deleted with the mechanism.
- Agent self-update scenarios keep their teeth with a sharper assertion: a hook-managed
  workload is *provably* untouched during agent self-update, crash, and rollback, because
  the agent has no means to touch it — asserted by workload PID stability and by the
  absence of hook invocations in the fixture's recorded history.

## Control plane

Unchanged. NodeReports, settlement semantics, regression evidence, alerting, metrics,
backend topology projections, and the healthproxy neither know nor care who owns workload
processes; they already operated purely on signed reports and hook-derived health.
