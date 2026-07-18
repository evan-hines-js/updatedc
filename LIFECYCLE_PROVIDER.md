# Generating a lifecycle wrapper

`updated` deliberately exposes one integration point instead of learning every
application server, init system, load balancer, or enterprise runbook. Point an AI coding
assistant at your current deployment procedure and this document. Ask it to generate one
lifecycle dispatcher that adapts that procedure to `updated`.

The supervisor's statically linked `default` provider implements this same protocol and
has exactly the supervisor version. This document describes an optional, separately
versioned and signed executable override with one manifested entrypoint.
The control plane puts its exact target reference, argv, and timeout in an immutable
provider set, then references that set from the desired deployment. It is never selected
from local node config or by a `latest` query.

The dispatcher may call existing scripts or small phase-specific helpers internally.
That factoring is private to the integration; `updated` still has one API and one entrypoint.

A nonzero `preflight` rejects those candidate bytes for the configured retry period.
Failures after journaling cause deferral or rollback according to the transaction stage;
a failed `rollback` is fatal and leaves recovery evidence intact. Use `preflight` only for
candidate-specific incompatibility. Put transient environmental readiness in `drain` or
`prepare` so an unavailable dependency does not classify valid release bytes as bad.

## Start with this prompt

Attach or select the current deployment scripts, service configuration, and runbook, then
paste this prompt into your coding assistant:

```text
Act as a production deployment engineer. Analyze the attached current deployment
runbook, scripts, and service configuration. Generate one executable lifecycle
dispatcher for the `updated` supervisor. Preserve the site's existing operational
behavior, but do not implement artifact download, signature verification, release
selection, process health gating, or durable rollback; `updated` owns those concerns.

The dispatcher is invoked directly as argv, not through a shell. It reads:
- UPDATED_LIFECYCLE_PHASE: preflight, prepare, drain, stop, activate, start, verify,
  finalize, or rollback
- UPDATED_LIFECYCLE_ATTEMPT_ID: fresh identity for this attempt, stable across its recovery retries
- UPDATED_CHILD_PID: managed master/application PID
- UPDATED_INSTALL_ROOT: mutable installation root
- UPDATED_CANDIDATE and UPDATED_PREDECESSOR: immutable release directories
- UPDATED_CANDIDATE_VERSION and UPDATED_PREDECESSOR_VERSION: their versions

Map the current deployment operations onto these phases:
- preflight: read-only validation of candidate compatibility and prerequisites
- prepare: establish external prerequisites needed by the candidate
- drain: remove or drain the currently serving instance before disruptive work
- stop: last provider action while the predecessor PID is available
- activate: apply environment changes while a stop-start app is down, or make a reexec
  master adopt the candidate
- start: post-launch integration after guardian start or the same-PID handoff
- verify: provider-specific verification after the supervisor's independent health gate
- finalize: restore traffic and finish external changes after candidate health passes
- rollback: undo drain/prepare/finalize effects after failure or crash recovery

For stop-start mode, the supervisor asks the guardian to stop after `stop`, then asks it
to launch the selected release before `start`.
For reexec mode, activate performs the program's same-PID master/worker reload.

Requirements:
1. Be idempotent for repeated (phase, UPDATED_LIFECYCLE_ATTEMPT_ID) calls, including after a
   machine or supervisor crash. Treat rollback as safe even when an earlier phase did not
   finish. A later attempt after a completed rollback gets a new ID; never deduplicate by
   candidate/predecessor version alone.
2. Use bounded waits and clear stderr diagnostics. Exit 0 only when the requested phase
   reached its required outcome; exit nonzero otherwise.
3. Never modify either immutable release directory. Put mutable state beneath
   UPDATED_INSTALL_ROOT or in the existing external system of record.
4. Do not accept candidate paths, PIDs, or commands from untrusted network input. Quote
   all shell values, avoid eval, and use least privilege.
5. Do not daemonize or leave an untracked background helper. The dispatcher must wait for
   each requested operation to finish.
6. Preserve credentials and secret handling already used by the deployment. Do not print
   secrets.
7. If exact rollback is impossible, fail and explain why instead of pretending success.
8. Produce: the dispatcher, any private helper scripts, installation/permission steps,
   the TOML configuration, and automated tests using fake dependencies.
9. Add a mapping table from every old runbook step to its new phase. Explicitly identify
   obsolete or duplicated old paths that should be removed.
10. End with assumptions and a short list of facts an operator must verify in staging.

Do not invent application-specific commands. Derive them from the attached material and
mark missing facts as TODO failures in the generated wrapper.
```

This prompt is intentionally strict. The generated code is an provider around the site's
known process, not an AI-designed deployment system.

## Add the matching shape

Append one of these sections to the base prompt when it matches the deployment.

### Stop/start application with drain and warm-up

```text
This application uses updated's default stop-start mode. Map traffic removal and
in-flight request draining to drain. Map mounts, generated local configuration, schema
compatibility checks, and other prerequisites to preflight or prepare. updated stops the
old process after drain and starts the candidate after prepare, so activate must do
nothing. Finalize may restore traffic only after updated has passed candidate health.
Rollback must restore traffic and reverse external preparation safely whether or not the
old process was ever stopped.
```

This is the usual shape for application servers, bespoke services, and applications
with existing `pre-stop`/`post-start` scripts.

### HAProxy-like same-PID reexec

```text
This service uses updated's reexec mode. Preflight must validate the candidate binary and
configuration without changing the running service. Activate must stage any stable-path
binary/configuration required by the service and signal UPDATED_CHILD_PID using the
service's documented master-worker reload operation. It must wait until the master has
accepted the operation, must not replace the master PID, and must return nonzero if the
new worker cannot start. Rollback receives the predecessor as UPDATED_CANDIDATE and must
use the same mechanism to make that master adopt it. Do not implement health polling that
duplicates updated's configured authenticated health/version proof.
```

For HAProxy this commonly maps to configuration validation followed by its master-worker
`SIGUSR2` flow. Derive exact flags, paths, ownership, and socket behavior from the actual
service configuration rather than copying a generic example.

### REST or load-balancer control plane

```text
The current deployment drains and restores traffic through an HTTP API. Reuse its
authentication mechanism and idempotency support. Use UPDATED_LIFECYCLE_ATTEMPT_ID as the API's
idempotency/correlation key when possible. Drain must poll the API only until the node is
out of rotation and its active work is below the documented threshold. Finalize restores
traffic. Rollback restores the pre-update routing state and must tolerate already-restored
or never-drained state. Apply finite connect, request, and overall timeouts; distinguish
retryable transport errors from a definitive API rejection in diagnostics.
```

### Filesystem, NFS, secrets, or generated local configuration

```text
The service depends on external filesystems or generated local files. Preflight should
perform read-only compatibility and availability checks. Prepare should wait with a
bounded deadline for required mounts/secrets, then atomically generate mutable local
configuration outside the immutable candidate directory. Record only the minimal state
needed for idempotent rollback, keyed by UPDATED_LIFECYCLE_ATTEMPT_ID. Rollback removes or
restores only resources owned by this lifecycle and must not unmount or delete shared
resources it did not create.
```

### Existing monolithic deployment script

```text
The attached deployment script currently performs the entire release. Refactor it into a
single phase dispatcher with private helper functions or scripts. Remove download,
verification, version choice, process start/stop, health gating, and release-directory
rollback that updated now owns. Split the remaining site-specific operations across the
six phases. Do not keep a second legacy entrypoint that can still perform deployments;
there must be one supported path after the migration.
```

## Review prompt

After generation, give the result and the old process to a fresh AI session with this
adversarial review prompt:

```text
Review this updated lifecycle integration as if it will fail at every instruction and
lose power between any two filesystem or API operations. Find cases that can cause
traffic to remain drained, mutate an immutable release, activate the wrong version,
signal the wrong PID, leak secrets, wait forever, report false success, or make rollback
unsafe. Verify every old deployment step is either owned by updated, mapped exactly once
to a phase, or intentionally deleted. Verify stop-start versus reexec responsibilities.
Write failing tests for each material issue, fix the implementation, and repeat the
review until no material issue remains. Do not weaken assertions to make tests pass.
```

## Operator acceptance checklist

AI generation reduces provider-writing effort; it does not remove staging validation.
Before rollout, verify:

- every phase succeeds when called twice with the same lifecycle ID;
- rollback is safe after each partially completed earlier phase;
- a nonzero phase exit leaves or restores the predecessor as documented;
- the configured timeout bounds hung scripts and network calls;
- stop-start mode never starts/stops from the wrapper;
- reexec mode preserves the master PID and listening sockets;
- candidate and predecessor paths are never modified;
- logs contain the lifecycle ID but no credentials;
- the old deployment entrypoint has been removed or made incapable of bypassing this path;
- real load, crash recovery, and the actual external systems pass in staging.

Keep the generated wrapper beside the service's deployment configuration and review it
like any other privileged production code.
