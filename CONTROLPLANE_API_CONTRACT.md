# Control-plane API contract

This document defines the node-facing contract a control plane must publish for
`updated`. A product may expose REST, gRPC, Ash resources, or another management
API to operators, but nodes consume immutable JSON and artifacts authenticated
by TUF over HTTPS.

The machine-readable schemas are the [desired deployment](schemas/desired-deployment.schema.json),
[provider set](schemas/provider-set.schema.json), and shared
[exact target reference](schemas/target-reference.schema.json). Complete examples
live in [schemas/examples](schemas/examples).

## Bootstrap contract

A node's local bootstrap configuration contains its assignment URL, the trust
root needed to authenticate that document, credentials needed to fetch it, and
local operational settings. Fleet placement, repository endpoints, application
selection, and provider selection are not local configuration.

The assignment URL identifies the node, not its group. The control plane may map
many nodes to one group and serve the same assignment bytes to all of them; it
does not need a distinct deployment document per node.

## Desired deployment

The signed routing document conforms to `desired-deployment.schema.json`. Its
`deployment` is an opaque correlation identifier. It must not select artifacts
or reset TUF rollback protection. TUF history is scoped to repository endpoints
and persists across assignment revisions.

Both target references are exact. A node requires the named TUF target to have
the stated SHA-256 digest. It must not substitute the newest release, search
another channel, or silently fall back to another target.

## Provider set

Every supervisor contains the real `default` provider implementation. It runs the same
phase protocol as an executable provider; it is statically linked only to make the common
case self-contained. Consequently its version is exactly the supervisor version and it
is never published, pinned, or upgraded independently.

A provider set is an exact TUF target containing typed overrides of the built-in
provider's capabilities. An empty override set selects the built-in implementation.
The optional `lifecycle` override is a separately signed executable implementing the
same protocol for stop/start and reexec activation. A capability may appear at most
once. Unknown capabilities, duplicate overrides, and malformed unused entries fail the
entire set closed; nodes never download and silently ignore provider entries.

The node authenticates and stages every provider artifact before beginning an
application lifecycle. Failure to resolve any provider leaves the current
deployment untouched. A provider-set-only assignment revision may be staged
without reinstalling the application.

## Publication transaction

CDN consistency makes publication order part of the contract. The control plane
must publish in this order:

1. Upload application and provider artifact bytes.
2. Publish TUF metadata authenticating those artifacts.
3. Upload the provider-set document.
4. Publish TUF metadata authenticating the provider set.
5. Publish the desired-deployment assignment last.

An assignment must never reference a target that is not already retrievable and
authenticated through its repository. Old immutable targets remain available
for recovery and explicit rollback.

## Node reconciliation

For each authenticated assignment, `updated` must:

1. Reject an unsupported schema or malformed document.
2. Refresh the assigned TUF repository without discarding rollback state.
3. Fetch the exact provider set and verify its digest.
4. Validate capability uniqueness and fetch every exact provider override artifact.
5. Fetch the exact application artifact.
6. Run `preflight`, `prepare`, and `drain` while the predecessor still serves.
7. Run the provider's `stop` phase, ask the guardian to stop if required, activate the
   candidate, ask the guardian to start if required, run `start`, independently prove
   health, run `verify`, and finally run `finalize`.
8. Preserve the previously committed deployment until the candidate commits.

Recovery uses exact identities recorded in durable node state; it does not
reinterpret a newer assignment while completing an interrupted transaction.

If a desired application is rejected, the node keeps serving the committed
application. Selecting a fleet-wide fallback is a control-plane decision: the
control plane publishes a new assignment explicitly referencing that fallback.

## Responsibility boundary

The control plane owns node-to-group mapping, desired deployments, publication
ordering, repository signing, rollout policy, and retention of referenced
immutable targets.

`updated` owns signature and digest verification, TUF rollback protection,
complete provider staging, lifecycle execution, health gates, crash recovery,
local rejection state, and preservation of the last committed deployment.

Credentials and rotation are bootstrap concerns and are deliberately absent
from signed desired-deployment and provider-set documents.
