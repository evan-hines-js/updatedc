# Control-plane API contract

This document defines the agent-facing contract a control plane must publish for
`updated`. A product may expose REST, gRPC, Ash resources, or another management
API to operators, but agents consume immutable JSON and artifacts authenticated
by TUF over HTTPS.

The machine-readable schemas are the [agent document](schemas/agent-document.schema.json),
[desired deployment](schemas/desired-deployment.schema.json),
[provider set](schemas/provider-set.schema.json), and shared
[exact target reference](schemas/target-reference.schema.json). Complete examples
live in [schemas/examples](schemas/examples).

## Bootstrap contract

A local bootstrap configuration contains a pinned routing root, one HTTP(S) routing
repository base URL, the exact agent-document target path, and local operational settings.
The base URL exposes the standard static TUF `metadata/` and `targets/` children and can
be backed directly by S3, a CDN, a static server, or an equivalent read-only gateway.
Fleet placement, release repository endpoints, application selection, and provider
selection are not local configuration.

Every agent has one stable target such as `assignments/agents/agent-123.json`. Its strict
`agent-document.schema.json` body contains only an exact TUF reference to a config
document. It never contains a group, selector, control-plane URL, or control-plane type.
Many agent documents may reference the same config document.

## Desired deployment

The config document conforms to `desired-deployment.schema.json`. Its
`deployment` is an opaque correlation identifier. It must not select artifacts
or reset TUF rollback protection. TUF history is scoped to repository endpoints
and persists across assignment revisions.

Both target references are exact. An agent requires the named TUF target to have
the stated SHA-256 digest. It must not substitute the newest release, search
another channel, or silently fall back to another target.

## Provider set

Every supervisor contains the real `default` provider implementation. It runs the same
phase protocol as an executable provider; it is statically linked only to make the common
case self-contained. Consequently its version is exactly the supervisor version and it
is never published, pinned, or upgraded independently.

A provider set is an exact TUF target naming exactly one node reconciler: the
`reconciler` object binds a separately signed executable by exact target reference,
its fixed arguments, and the per-operation timeout in milliseconds. The reconciler
implements the four-operation protocol (`apply`, `healthcheck`, `rollback`,
`inspect`). A set carries no other capability and no optional entries — a document
with an unknown field, an unsupported `schema`, an unconfined artifact path, or a
timeout outside `1..=86400000` fails the entire set closed, and the agent never
downloads and silently ignores parts of a set it could not fully parse.

The agent authenticates and stages the reconciler artifact before beginning an
application lifecycle. Failure to resolve it leaves the current deployment
untouched. A provider-set-only assignment revision may be staged without
reinstalling the application.

## Static HTTP repository contract

Agents require only ordinary `GET` requests for immutable objects below `metadata/` and
`targets/`. `HEAD` and open-ended byte ranges are recommended but are not semantic APIs.
Directory listing, S3 APIs, writes, group lookup, and agent lookup are not part of the
protocol. A control-plane gateway, when supplied, must serve the already-published bytes
and must not perform placement or synthesize documents at request time.

## Publication transaction

CDN consistency makes publication order part of the contract. The control plane
must publish in this order:

1. Publish application, provider, and provider-set targets in the release repository.
2. Publish release TUF metadata authenticating all referenced targets.
3. Upload every config document into the routing repository.
4. Upload every agent document referencing an exact config target.
5. Publish one routing TUF metadata generation authenticating the complete desired view,
   with `timestamp.json` as the final visibility/commit object.

A config document must never reference a target that is not already retrievable and
authenticated through its repository. Old immutable targets remain available
for recovery and explicit rollback.

## Agent reconciliation

On every check, `updated` must:

1. Refresh routing TUF without discarding rollback state.
2. Fetch and validate its exact agent document, then its exact config document.
3. Refresh the selected release TUF repository without discarding rollback state.
4. Fetch the exact provider set and verify its digest.
5. Validate the provider set and fetch its exact reconciler artifact.
6. Fetch the exact application artifact.
7. Withdraw readiness and hold for the configured drain while the predecessor still serves.
8. Ask the guardian to stop if required, run the reconciler's `apply` operation, ask the
   guardian to start if required, and gate the candidate on the reconciler's `healthcheck`
   operation before committing.
9. Preserve the previously committed deployment until the candidate commits.

Recovery uses exact identities recorded in durable agent state; it does not
reinterpret a newer assignment while completing an interrupted transaction.

If a desired application is rejected, the agent keeps serving the committed
application. Selecting a fleet-wide fallback is a control-plane decision: the
control plane publishes a new assignment explicitly referencing that fallback.

## Responsibility boundary

The control plane owns agent placement, desired deployments, publication
ordering, repository signing, rollout policy, and retention of referenced
immutable targets.

`updated` owns signature and digest verification, TUF rollback protection,
complete provider staging, lifecycle execution, health gates, crash recovery,
local rejection state, and preservation of the last committed deployment.

Credentials and rotation are bootstrap concerns and are deliberately absent
from signed desired-deployment and provider-set documents.
