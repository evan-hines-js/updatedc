# Package execution

Customers publish a package and choose its entrypoint. The entrypoint can run arbitrary code in any
language. `updatectl publish --source ./package --entrypoint install.sh` generates the signed
execution metadata. Optional health, inspection, replay-check, and recovery commands extend this
same path; they do not introduce another deployment mechanism.

The agent embeds a native runtime and helper. Both upgrade through the host's normal agent package,
image, or service rollout. A running agent pins its executable once, so an attempt cannot acquire a
different helper halfway through execution. Unsupported execution APIs require an agent upgrade.

The core owns authenticated package selection, bounded extraction, immutable releases, atomic active
pointers, durable transaction ordering, process containment, deadlines, retries, health gates,
confirmation windows, and signed outcomes. Execution metadata is part of the package's identity.
A malformed authenticated package may be rejected; transport and local storage failures may not.

Entrypoints receive their own arguments, a predictable working directory, and optional environment
context. Assigned inputs and outputs use private files. The runtime implements the internal
reconciler protocol and persists completion evidence, including helper outputs and reboot requests.
Per-application mutation locks are nonblocking; health and inspection do not acquire them.

Execution completion and transition compatibility are separate. A version marker alone proves
neither correct machine state nor a supported upgrade. Application code must inspect actual state
and refuse unsupported transitions. The platform does not infer a plan from opaque scripts.
The entrypoint can choose distinct install and upgrade procedures from observed application state.
An optional helper sequence enforces the order of author-supplied checked steps, with one local
resource lock, bounded execution, and a stop at the first failure. See
[installation and ordered upgrades](install-and-upgrade.md).

Uncertain work pauses by default. Safe replay is explicit. A replay check can prove completion,
authorize repetition, or require operator attention. Local progress records cannot make an arbitrary
external effect exactly once: use destination transactions, idempotency keys, safe repetition, or
reliable inspection.

Recovery must explicitly restore the previous application and compatible data. The platform then
checks predecessor health; it never implicitly runs the predecessor's deployment procedure. Routine
repair preserves the original transaction identity while its confirmation window remains open.

The agent owns only its invocation process trees. Application code owns services and workloads,
which must outlive those invocations through their normal lifecycle manager or explicit detachment.
Agent restarts therefore do not imply workload restarts on a host.

`updatectl check` uses the production runtime locally. Integration tests add application assertions
for installation, no-op convergence, drift, supported and refused upgrades, interruptions, repeated
compensation, and recovery. Portable end-to-end tests exercise real signed repositories, agents,
workloads, and crashes at durable transaction boundaries.
