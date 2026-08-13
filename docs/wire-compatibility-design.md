# Wire compatibility

Status: implemented. The reader windows live on `NodeReport::MIN_SUPPORTED_SCHEMA`,
`OutputManifest::MIN_SUPPORTED_SCHEMA`, and `EndpointProjection::MIN_SUPPORTED_SCHEMA`; the
writer-restraint rule is documented on `RepositoryAssignment::SCHEMA`, `AgentDocument::validate`,
`ProviderSet::SCHEMA`, `bundle::MANIFEST_SCHEMA`, and — for the half of it that crosses into an
assignment — `OutputManifest::MIN_SUPPORTED_SCHEMA`. The byte-exact lock is
`a_previous_schema_report_still_verifies`; the live schema census is `updatec_report_schema`.

## Problem

A fleet never upgrades atomically, and every wire contract in this system crosses the upgrade
boundary. The schema gates used to demand exact equality, which armed a cliff on every bump: when
`NodeReport` moved from 5 to 6, a control plane or healthproxy upgraded ahead of its nodes would
have refused every schema-5 report — draining the entire healthy fleet out of rotation and
stalling the very rollouts that deliver the node upgrade. The failure is self-sustaining, and it
is invisible until the first bump after the gate lands.

## One policy, two contract classes

Which side carries the compatibility obligation is decided by one question: **which side can be
upgraded first?**

**Reports (node → control plane, node → healthproxy; `NodeReport`, `OutputManifest`, and the
plane's own `EndpointProjection` to the healthproxy).** Readers upgrade first BY CONSTRUCTION —
nodes receive their agent through this very system, so the readers of a new report schema
are always running before any node can write it. Readers therefore accept a window
`[MIN_SUPPORTED_SCHEMA, SCHEMA]`; writers always write `SCHEMA`.

- Every field added inside the window carries a serde default chosen in the FAIL-SAFE direction,
  documented at the field. `updating` (schema 6) defaults false: an old node's reports prove
  nothing to the regression verdict — evidence is weaker during the upgrade, never wrong.
- The exact bytes a floor-schema writer signs are locked by a literal-payload test, so a
  defaultless field cannot land while the window claims to cover the old shape.
- Above the window is a writer newer than the reader — a violation of the supported order, and a
  refusal, not a transition. Below the window is an agent no release supports.
- Raising the floor is a deliberate act in its own commit, made when no supported fleet still
  runs the older writer. `updatec_report_schema{schema=...}` counts the nodes writing each schema,
  so that precondition is a fact an operator can check rather than a claim — and so the degraded
  window (a pre-6 node's rollbacks minting no regression evidence) is visible while it lasts.
- The stakes differ by fail direction and both are covered: a report refused fails CLOSED (a
  drained node), a projection refused fails OPEN (a released cordon) — the window exists so
  neither happens over a version the system still supports.

`OutputManifest` is only HALF a report contract. The values a reconciler publishes are resolved by
the control plane into `ManagedRuntime.inputs`, a field of the signed `RepositoryAssignment` that
nodes read, so `OutputValue`'s SHAPE answers to writer restraint below: a new variant, or a new
field on one, is refused by every not-yet-upgraded consumer — and refused as the whole assignment,
because the enum is internally tagged and `deny_unknown_fields`. No schema number has to move for
that to happen, and the dependency ordering guarantees the fatal case: the producer group upgrades
first by construction, so the stranded consumers are exactly the ones still awaiting theirs.

## Desired state (control plane → node; `RepositoryAssignment`, `AgentDocument`, `ProviderSet`, the bundle manifest, and `OutputValue`'s shape)

The readers are the nodes themselves, and no reader window can save them: an old node cannot be
taught to read a schema it predates, and the document it would fail to read is the one that
delivers its upgrade — a bump ahead of the fleet is a deadlock with no in-band cure. The WRITER
carries the obligation: the control plane must not publish a new schema until every supported
node runs an agent that reads it.

An optional field under an unchanged number is NOT a cheaper alternative here, and treating it as
one is the trap: every one of these documents is `deny_unknown_fields` (the published JSON schemas
are closed to match), so the first generation that emits the new key is refused by every older node
at deserialization, before any schema check can name the cause. Any change to the SHAPE of a
desired-state document — numbered or not — is a deliberate act behind a verified fleet floor.

The bundle manifest is the strictest of them. A manifest a node cannot accept is an
`InstallError::Archive` — a verdict on the bytes — which is recorded as a durable, never-expiring
rejection keyed by digest. Publishing ahead of the floor there does not merely stall the fleet: it
makes every older node permanently refuse every new bundle, and reverting the publisher does not
heal them, because the rejections outlive the revert. `ProviderSet` has the same shape on a cold
install, where the refusal descends the release list.

## Non-goals

No multi-schema publication (emitting old and new documents side by side), no capability
negotiation, no schema metadata in the store. The window plus writer restraint cover a fleet that
upgrades in the one order the system itself enforces; machinery for arbitrary orders would be
complexity with no reachable user.
