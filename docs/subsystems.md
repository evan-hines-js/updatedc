# Conceptual subsystem map

This document groups the repository by responsibility rather than by directory. A subsystem has
its own invariant, runtime owner, and reason to change. Crates are implementation boundaries; they
do not always correspond one-to-one with subsystems.

## System context

```text
operator / CI
    │
    ▼
fleet control plane ── signed assignments and releases ──► repository / gateway
    ▲                                                        │
    │ signed node reports                                    ▼ pull
traffic membership ◄──────────────────────────────────── node update runtime
                                                             │
                                                             ▼
                                                    managed application

installer / operating system ──► permanent lifecycle owner ──► node update runtime
```

The important architectural boundary is directionality: the control plane publishes desired
state, nodes pull it, and nodes publish observed state. The control plane does not initiate a
connection to a node.

## 1. Permanent node lifecycle

**Purpose:** Keep the disposable update tower and managed application alive without acquiring
release, network, or policy responsibilities.

**Invariant:** Routine changes above this layer must remain deployable against an older,
statically linked guardian.

**Code:**

- `foundation` — dependency-isolated durability, process containment, time, platform, and logging
  mechanisms.
- `control` — frozen guardian/supervisor wire protocol and version negotiation.
- `bootstrap` — permanent guardian, application ownership, supervisor replacement, and
  OS-specific process control.
- `windows-service` plus `deploy/systemd`, `deploy/launchd`, and `deploy/windows` — adapters from
  the operating system's service manager to the bootstrap.

`foundation` and `control` are shared kernels, not general utility drawers. Their deliberately
small dependency surfaces are part of the architecture.

## 2. Node update runtime

**Purpose:** Turn verified desired state into one healthy local application release, and recover
to a safe release after interruption or failure.

**Invariant:** Activation and rollback cross only durable, recoverable boundaries; unverifiable
bytes never become executable.

**Code:**

- `supervisor` — runtime orchestration: startup recovery, selection, lifecycle-provider phases,
  health, rollback, secrets, garbage collection, telemetry, and supervisor self-update.
- `updated` — reusable node-local mechanisms: configuration materialization, bundles, enrollment
  persistence and transport, TLS, installed state, transaction journal, rejection records, and
  paths.
- `updated-contracts` — strict artifact, enrollment, and signed telemetry protocols shared across
  the node/control-plane boundary.
- `update-client` — shared “select, authenticate, download, and stage” use case.

The supervisor owns policy and sequencing. `updated` supplies durable node mechanisms;
`updated-contracts` owns data that crosses process or trust boundaries. `update-client` is the
acquisition boundary shared by front ends; it intentionally stops before activation and process
ownership.

## 3. Trust and artifact distribution

**Purpose:** Authenticate release intent and content across untrusted storage and transport.

**Invariant:** A caller can obtain a verified target only through a complete TUF verification
chain; only transport failures are blindly retryable.

**Code:**

- `updated-tuf::TrustedRepository`, `select`, `policy`, and `transport` — node-side repository
  refresh, exact target selection, and verified streaming.
- `updated-tuf::repo` — publisher-side repository construction, signing, and commit ordering.
- `updated::bundle` — deterministic bundle creation and bounded, manifest-verified extraction.
- `updated-contracts::artifact` — content-addressed target references, agent documents, and
  provider-set manifests.
- `schemas` — external JSON shapes for desired deployments, provider sets, agent documents, and
  target references.

This subsystem deliberately spans node and publisher processes. Sharing the format and signing
implementation prevents a publisher/client interpretation split.

## 4. Fleet control plane

**Purpose:** Compile fleet resources and observed node state into a consistent signed generation.

**Invariant:** One bad resource is quarantined; it does not produce a mixed or partially committed
repository generation.

**Code:**

- `updatec` CRD types — `UpdateRepository`, `UpdateGroup`, `UpdateGroupSet`, and `UpdateAgent`.
- `updatec::domain` — environment-neutral reconcile decisions.
- `updatec::rollout` and `window` — group membership, throttling, settlement, schedules, and
  calendars.
- `updatec::runtime` — Kubernetes observation, reconcile orchestration, publication, and status
  projection.
- `updatec::publisher` — object-store generation publication.
- `updatec::subscription` — signed change notifications.
- `updatec` binary and `deploy/kubernetes` — process entry point and Kubernetes packaging.

`runtime` should remain an adapter around the domain/rollout logic. Kubernetes types necessarily
appear at the outer boundary, while rollout decisions should be testable without a cluster.

## 5. Node identity and gateway data plane

**Purpose:** Bootstrap a node into a unique identity and expose the pull/report endpoints used
after enrollment.

**Invariant:** A shared enrollment identity can mint only the configured node identity; normal
routing, artifact, secret, and telemetry operations require the resulting per-node identity.

**Code:**

- `updatec::gateway` — TLS listeners and enrollment, repository, secret, and telemetry routes.
- `updatec::join` — CSR parsing, proof-of-possession, certificate minting, and public-key pinning.
- `updated-contracts::enrollment` — enrollment and renewal request/response documents.
- `updated::csr`, `enrollment`, `tls`, and `http` — node-side identity creation, persistence, and
  authenticated transport.
- `CONTROLPLANE_API_CONTRACT.md`, `docs/group-enrollment-design.md`, and
  `docs/fleet-rollout-endpoints.md` — external contracts.

This is conceptually separate from the fleet reconciler even though both ship in `updatec`: it is
a long-lived request/response data plane, while reconciliation is asynchronous control logic.

## 6. Health-derived traffic membership

**Purpose:** Convert signed node observations into load-balancer membership without adding a
proxy hop.

**Invariant:** Only a fresh, authentic, correctly attributed healthy report permits traffic.
A transient report-store fetch failure may reuse the last report only until its normal freshness
limit expires.

**Code:**

- `updated-contracts::telemetry` — `NodeReport`, canonical signing, verification, report paths,
  and freshness policy.
- `updated-healthproxy` core — report polling and desired membership.
- `updated-healthproxy::endpointslice` — Kubernetes EndpointSlice adapter.
- `updated-healthproxy::haproxy` — HAProxy adapter.

The `LoadBalancer` trait is the subsystem boundary: health interpretation is core policy; applying
the resulting complete member set is an infrastructure adapter.

## 7. Operator and publication tooling

**Purpose:** Give humans and CI a supported way to create keys, bundles, releases, and control
plane resources.

**Code:**

- `updatectl` — production-oriented CLI that reuses `updatec`, `updated-tuf`, and `updated`
  publication formats.
- `scripts` — orchestration entry points for demos, fuzz plans, and deployment-specific E2E runs.
- `deploy/ansible` and `deploy/bootstrap.toml` — installation examples and node configuration.

This is an adapter subsystem. It should invoke library use cases rather than grow a second
implementation of repository layout or bundle construction.

## 8. Verification, examples, and demonstrations

**Purpose:** Exercise subsystem contracts together and provide observable reference workloads.
This code is not part of the production runtime architecture.

**Code:**

- `e2e` — cross-platform harness and behavioral scenarios.
- `killfuzz` — crash-boundary fuzz driver built on the E2E harness.
- `server` — local/mock repository, enrollment, and telemetry service.
- `updatec-demo` — interactive Kubernetes fleet demonstration.
- `sampleapp` and `demo-lifecycle` — managed workload and lifecycle-provider fixtures.
- `crates/updatec/examples` and deployment/demo scripts — generation and verification helpers.

Keeping these components in the workspace is useful because they compile against real contracts.
They should not become dependencies of production crates.

## Crate-to-subsystem index

| Crate | Primary subsystem | Classification |
| --- | --- | --- |
| `foundation` | Permanent node lifecycle | shared mechanism kernel |
| `control` | Permanent node lifecycle | frozen protocol |
| `bootstrap` | Permanent node lifecycle | production runtime |
| `windows-service` | Permanent node lifecycle | OS adapter |
| `updated` | Node runtime; identity; distribution | node-local mechanisms and adapters |
| `updated-contracts` | Cross-system boundaries | versioned protocols and validation |
| `updated-tuf` | Trust and distribution | shared client/publisher library |
| `update-client` | Node update runtime | application use case |
| `supervisor` | Node update runtime | production runtime |
| `updatec` | Fleet control plane; gateway | production runtime and library |
| `updated-healthproxy` | Traffic membership | production runtime and adapters |
| `updatectl` | Operator tooling | production tool |
| `server` | Verification | test support |
| `e2e`, `killfuzz` | Verification | test support |
| `updatec-demo`, `sampleapp`, `demo-lifecycle` | Demonstration | fixtures/demo |

## Boundary assessment and refactoring candidates

All workspace crates fit one of the systems above. There is no clearly orphaned production crate.
The following issues are boundary pressure, listed in recommended order.

### 1. Keep the desired-state contract boundary closed

**Completed:** `updated-contracts` owns artifact references and provider manifests, repository
assignments and managed-runtime policy, enrollment and renewal documents, path/digest grammars,
and the complete signed `NodeReport` protocol. It also owns their pure validation. Control-plane,
node, trust, and health-membership code consume those contracts directly.

`updated` retains only node-local private-key operations, HTTP/TLS, persistence, installation,
journals, and the `MaterializeRuntime` adapter that turns a validated managed-runtime contract into
node-local paths and durations. Do not add serialized control-plane types or pure wire validation
back to `updated`.

### 2. Split `updatec` into control-plane core and gateway surfaces

**Signal:** `updatec` contains two independently changing runtimes: Kubernetes reconciliation and
an externally exposed TLS/HTTP gateway. `runtime.rs` and `gateway.rs` are each large orchestration
boundaries, and the current crate dependency surface includes both Kubernetes and HTTP server
stacks for every consumer, including `updatectl`.

**Recommendation:** First extract cohesive internal modules and narrow public exports. If compile
times or ownership remain problematic, form:

- `updatec-api` or use `updated-contracts` for CRD/shared specification types;
- `updatec-core` for publication, rollout, and environment-neutral decisions;
- `updatec-gateway` for TLS/HTTP routing and enrollment serving;
- the `updatec` binary as composition root.

Avoid splitting solely by file size; split where dependencies and runtime ownership differ.

### 3. Turn large composition functions into explicit use cases

**Signal:** `supervisor::main::run`, `supervisor::update::apply_update`, and
`updatec::runtime::reconcile_once` coordinate many responsibilities. Their size is a symptom that
transaction steps, ports, and outcomes are implicit in control flow.

**Recommendation:** Keep binaries as composition roots, but extract named operations with typed
inputs/outcomes: boot recovery, acquire candidate, activate transaction, assess health, publish
generation, and project statuses. Preserve the documented durable state machines while doing so;
this is readability and testability work, not a redesign of ordering.

### 4. Separate production code from in-module test mass

Several of the largest source files contain extensive unit tests alongside production code.
Moving tests into sibling `tests` modules or integration files will make module size a more honest
signal and reduce navigation cost. Do this only after establishing internal test APIs; do not make
implementation details public merely to relocate tests.

### 5. Keep verification components visibly non-production

`server`, `sampleapp`, `demo-lifecycle`, `updatec-demo`, `e2e`, and `killfuzz` all have clear roles,
but names such as `server` are ambiguous in dependency and deployment views.

**Recommendation:** Add package metadata or workspace grouping, and consider names such as
`updated-test-server` when compatibility permits. Enforce the existing direction with a CI check:
production crates must not depend on demo, fixture, or E2E crates.

## Rules for future placement

When adding code, place it by the invariant it enforces:

1. OS/process lifetime with no release policy → permanent lifecycle.
2. Local activation, recovery, or application health → node runtime.
3. Authenticity, target selection, bundle format, or repository commit → trust/distribution.
4. Fleet grouping, desired-state compilation, rollout admission, or Kubernetes status → control
   plane.
5. Enrollment or authenticated pull/report serving → gateway/identity.
6. Report-to-backend readiness → traffic membership.
7. Human/CI command wrapping an existing use case → tooling.
8. Scenario construction or fault injection → verification.

If code spans two entries, first look for a serialized contract or a small port/trait at the
boundary. If neither exists and both sides change for unrelated reasons, that is evidence for a
new subsystem boundary or refactor.
