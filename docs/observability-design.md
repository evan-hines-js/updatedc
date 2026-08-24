# Operator observability

Status: implemented. `UPDATED_METRICS_ADDRESS` and `HEALTHPROXY_METRICS_ADDRESS` each serve `GET /metrics` (plain Prometheus text exposition, hand-rolled, default off for a hand-run process). An OPERATOR-managed healthproxy — the deployment `updatec` builds for an `UpdateBackend` — always serves it, on the fixed `runtime::BACKEND_METRICS_PORT` (9090): that pod is the one observer of out-of-cluster nodes, and running it dark makes the freshness of the very projection that drains those machines unobservable exactly where it matters.

## Problem

The control plane compiles fleet state and projects it into CRD status, and every node publishes
a signed `NodeReport`, but none of it is observable without hand-querying resources. An operator
running the fleet cannot answer, at a glance: how far along is this rollout, which groups are
held and why, how many node reports are stale, what did the healthproxy drain.

This design adds metrics *export* only. It creates no new signal: every series below is a
projection of state the reconcile loop, gateway, and healthproxy already hold. That is what
keeps it inside the core feature test — it strengthens the existing path (specifically the
health gate and rollout admission) without adding another way to deliver, execute, or observe
anything.

## One path

Prometheus text exposition, hand-rolled. No metrics framework, no registry crate: the exposition
format is a stable, line-oriented text grammar, and the full set below is small enough that each
binary formats its own gauge lines from the state it already owns at scrape time. Scrape-time
projection means no counters to keep consistent across restarts and no sampling loop — the
scrape reads the same in-memory state the reconciler just wrote.

Two endpoints, no more:

- `updatec` serves `GET /metrics` on a dedicated listener (`UPDATED_METRICS_ADDRESS`, default off).
  It is plain HTTP, cluster-internal, read-only, and serves nothing else.
- `updated-healthproxy` serves `GET /metrics` the same way.

Nodes export nothing. A node's whole observable surface stays the signed `NodeReport`; scraping
1,000 machines would add a push/pull channel the core explicitly refuses, and the control plane
already aggregates every fact a node is allowed to assert.

## Series

`updatec` (all labeled by `set`/`group` where meaningful, from the state `reconcile_once` and
`publish_resource_statuses` already compute):

- `updatec_reconcile_timestamp_seconds`, `updatec_reconcile_duration_seconds`,
  `updatec_reconcile_failures_total` — is the loop alive and converging.
- `updatec_generation{deployment=...}` — the published generation, labeled per deployment name.
- `updatec_group_progress{group=...,state=...} 1` — one-hot projection of the planner verdict
  (staging, held, settled, failed, unobservable — `failed` being a rollout its nodes durably
  rejected, which is neither in flight nor done). Quarantine is not a planner verdict — a quarantined
  group is not planned at all — so it is reported by `updatec_quarantined_groups` and by the
  group's own failed `Ready` condition, never as a `group_progress` state.
- `updatec_group_nodes{group=...}` / `updatec_group_nodes_on_target{group=...}` — rollout
  progress as the admission logic counts it, not a re-derivation.
- `updatec_reports_fresh` / `updatec_reports_stale` — node reports inside/outside
  `REPORT_FRESHNESS`, the same staleness the admission gate applies. Both are sums of the planner's
  own per-group counts, so they cover the OBSERVABLE population and not the fleet: a node is stale
  only if it has a pinned key and has already uploaded at least one envelope, because a freshly
  enrolled node that has never reported is unobserved rather than silent — counting it would make
  every mass enrollment page and then resolve itself. Cordoned nodes and nodes no planned group
  selects are in neither series either. So `fresh + stale` is a lower bound on the agent count, not
  a partition of it: do not derive `stale = total − fresh`, and do not read `stale == 0` as "every
  machine checked in".
- `updatec_quarantined_groups` — size of the quarantine set.

`updated-healthproxy`:

- `healthproxy_backends{state=up|drained}` — what it programmed, per its one reconcile.
- `healthproxy_reports_stale_total` — drains caused by report staleness, the number that turns
  a silent freshness failure into a visible one.
- `healthproxy_reconcile_timestamp_seconds` — is it alive.
- `healthproxy_reports_timestamp_seconds` — when a usable fleet report index was last observed,
  the document readiness itself is read from. While the index is unreadable every node resolves
  through its cached report, and once
  those age out the WHOLE inventory drains. `reports_stale_total` counts that one node at a time
  and reads identically to a fleet that genuinely stopped heartbeating, so this series (and the
  two edges the proxy logs beside it) is what tells "the index is unreadable" from "everyone went
  silent".

## Non-goals

No histograms beyond what admission itself uses, no per-node series on the control plane (label
cardinality is bounded by groups, not nodes), no traces, no logs pipeline, no push gateway. If a
question cannot be answered from state the one path already holds, the answer is to strengthen
the path, not to grow the metrics surface.

## Testing

Exposition is a pure function of reconciler state: unit-test it as text against constructed
state, the same way status projection is tested. The kind e2e then scrapes both endpoints from
inside the cluster after convergence (`assert_metrics_exposed`) and asserts the settled fleet
shape. It reads sample VALUES, never series names: every `# HELP`/`# TYPE` pair is written
unconditionally, so a name check passes against an exposition that projected nothing — no planned
groups, no programmed backends, and a freshness stamp of zero, which is the very failure these
series exist to make alertable.
