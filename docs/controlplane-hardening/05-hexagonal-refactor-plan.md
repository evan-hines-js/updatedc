# 5. Hexagonal refactor plan for `crates/updatec`

**Status: planned. This is the hardening phase; doc 4 (intra-group rolling) lands inside it.**

The control plane was assembled as a PoC. The domain logic (rollout admission, publication
planning, selection policy) is sound and partly pure already — but it is interleaved with kube-rs
and S3 I/O inside two large functions. Pull the domain into a testable core behind ports; make
kube, S3, TUF signing, and telemetry adapters.

## Where the domain is today (and how pure it already is)

| Module | LOC | Nature |
|--------|-----|--------|
| `throttle.rs` | 1249 (mostly tests) | **Pure domain.** `apply_throttle` already takes plain inputs; no I/O. Model to emulate. |
| `window.rs` | 731 | **Pure domain.** Rollout windows / calendars. Fully unit-tested. |
| `lib.rs` | 997 | Mixed: CRD types + `build_publication_plan` + `selector_matches` are pure; kube derive macros live here too. |
| `updated-tuf/select.rs` | — | **Pure domain.** Ordered-fallback selection policy. |
| `runtime.rs` | 1421 | **The seam.** `reconcile_once` — 228 I/O touchpoints (kube `Api<…>` for every CRD + ConfigMap + Secret + Lease, `ObjectStore`, telemetry read, TUF publish, lease). Domain and I/O fully interleaved. |
| `gateway.rs` | 1109 | **The seam.** Axum HTTP — enrollment, telemetry ingest, routing serve. |
| `join.rs` | 368 | CSR verification / per-node leaf minting (mostly pure crypto; some I/O). |
| `publisher.rs` | 142 | S3 upload ordering (adapter). |
| `subscription.rs` | 340 | `UpdateSubscription` handling. |

The good news: the two hardest domain pieces (`throttle`, `window`) are **already pure**. The work
is mostly extracting `reconcile_once` and the gateway handlers into `gather → decide (pure) → apply`.

## Target architecture

```
        ┌─────────────────────────── domain (pure, no kube/s3/tokio-io) ───────────────────────────┐
        │  reconcile planner:  DesiredState + Admitted + Reports + Keys + Clock                     │
        │      → resolve_node_groups → apply_throttle (set) → stage_nodes (intra-group, doc 4)      │
        │      → build_publication_plan → statuses  ⇒  ReconcileOutcome                              │
        │  selection policy (updated-tuf::select) · windows/calendar · publication planning         │
        └───────────────────────────────────────────────────────────────────────────────────────────┘
              ▲ ports (traits)                                        │ outcome
   ┌──────────┴───────────────────────────────────────┐              ▼
   │ InventorySource   AdmittedStore   TelemetrySource │      Publisher   StatusSink   LeaseGuard   Clock
   └──────────┬───────────────────────────────────────┘
              │ implemented by
        ┌─────┴──────────── adapters (impure) ─────────────┐
        │  kube adapter (Api<…> reads/writes, ConfigMap,   │
        │  Secret, Lease)   ·   s3 object-store adapter     │
        │  ·  TUF signing/publish adapter  ·  telemetry S3  │
        └───────────────────────────────────────────────────┘
```

### Ports (reconcile side)

- `InventorySource` — read the desired generation: repository spec, groups, sets, agents (name +
  labels + pinned public key). Pure data out; kube adapter lists CRDs.
- `AdmittedStore` — `load() -> AdmittedState`, `store(AdmittedState, cas_version)`. ConfigMap adapter.
- `TelemetrySource` — `reports(nodes) -> map<node, NodeReport>`. S3 adapter.
- `Publisher` — `publish(signed targets)`; the domain hands it a `PublicationPlan`, the adapter
  signs (TUF) + uploads (S3) in `upload_order`.
- `StatusSink` — write group/set/agent conditions + set statuses. kube patch adapter.
- `LeaseGuard` — `hold()?` leader check right before the irreversible publish. kube Lease adapter.
- `Clock` — `now()`. Real vs fixed-in-tests (removes the `chrono::Utc::now()` calls sprinkled in).

### Ports (gateway side)

- `EnrollmentService` — verify CSR + shared fleet cert, mint per-node leaf, persist identity.
- `TelemetryIngest` — verify signed report, store to object store.
- `RoutingSource` — serve the signed routing/assignment for a node.

The gateway HTTP handlers become thin: parse/authn → call a domain service → serialize.

### The pure planner

```rust
// domain::reconcile
pub fn plan_reconcile(
    state: &DesiredState,          // repository, groups, sets, nodes(+keys)
    admitted: &AdmittedState,      // group -> {current, previous}
    reports: &Reports,             // node -> signed NodeReport
    now: DateTime<Utc>,
) -> ReconcileOutcome {            // { publication: PublicationPlan, admitted: AdmittedState, statuses }
    // 1. resolve_node_groups (selectors)         — pure
    // 2. apply_throttle (set concurrency)         — pure (exists)
    // 3. stage_nodes (intra-group, doc 4)         — pure (new)
    // 4. build_publication_plan(node_deployments) — pure (adapted)
    // 5. statuses                                 — pure
}
```

`reconcile_once` becomes: `gather (ports) → plan_reconcile (pure) → apply (ports)`, with the lease
re-checked between plan and the irreversible publish (as today).

## Phased plan

**Phase 0 — land the convergence fix.** Commit doc-1 changes so the fleet-convergence fix is
durable and reviewable on its own, before any refactor.

**Phase 1 — extract the pure reconcile planner (no behavior change).**
- Define the reconcile ports and `DesiredState`/`AdmittedState`/`Reports`/`ReconcileOutcome` types.
- Move the domain steps out of `reconcile_once` into `plan_reconcile`. Wrap current kube/S3 code as
  adapters implementing the ports. `reconcile_once` shrinks to gather/plan/apply.
- Golden test: `plan_reconcile` with fakes reproduces today's decisions on a captured fixture.
- Acceptance: full unit suite green; `e2e --exit` unchanged.

**Phase 2 — intra-group rolling (doc 4), in the pure core.**
- `maxUnavailable` on the CRD; `previous` in `AdmittedState`; `stage_nodes`; per-node
  `build_publication_plan`. All unit-tested in the pure planner (doc 4 test plan).
- Collapse HAProxy to one group `maxUnavailable: 1`; delete the aspirational comments.
- Acceptance: unit tests + `e2e --exit` shows staggered HAProxy reexec at 100% SLA.

**Phase 3 — harden the gateway the same way.** Ports for enrollment / telemetry-ingest / routing;
handlers become thin; domain crypto (CSR verify, report verify) pure and unit-tested.

**Phase 4 — adapter hardening + dead-code sweep.**
- One error taxonomy per port (transport vs trust vs local — mirror the supervisor's split).
- Make every adapter write idempotent / CAS-guarded (the admitted ConfigMap already is; audit the
  rest). Assert the fail-closed invariants (ambiguous node → hold last-known-good; lease lost →
  abort publish) at the port boundary, not inline.
- Delete PoC scaffolding and any remaining dual paths (per "one way to do things").

**Phase 5 — end-to-end validation.** `e2e --exit` green including chaos and HAProxy; soak a few
`exercise` passes.

## Guardrails

- Keep `throttle.rs` and `window.rs` as the purity template — the new domain imports **no** kube/S3.
  Consider promoting the domain to its own crate (`updatec-domain`) with no `kube`/`aws`/`tokio-io`
  dependency so purity is enforced by the compiler, not discipline.
- Preserve the hard-won invariants already documented in `throttle.rs` tests (durable admitted state
  survives leader failover / cold PVC; forged/stale reports never settle; `max_concurrent` never
  breached). The intra-group staging must keep the "no new durable state" property (doc 4).
- No behavior change in Phase 1 — it is a pure extraction. Behavior changes start in Phase 2.
