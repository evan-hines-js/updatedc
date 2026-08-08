# Operator observability

Status: implemented. `UPDATED_METRICS_ADDRESS` and `HEALTHPROXY_METRICS_ADDRESS` each serve `GET /metrics` (plain Prometheus text exposition, hand-rolled, default off).

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
- `updatec_generation{deployment=...}` — the published generation, per deployment identity.
- `updatec_group_progress{group=...,state=...} 1` — one-hot projection of the planner verdict
  (staging, held, settled, quarantined), exactly the states the CRD status shows.
- `updatec_group_nodes{group=...}` / `updatec_group_nodes_on_target{group=...}` — rollout
  progress as the admission logic counts it, not a re-derivation.
- `updatec_reports_fresh` / `updatec_reports_stale` — node reports inside/outside
  `REPORT_FRESHNESS`, the same staleness the admission gate applies.
- `updatec_quarantined_groups` — size of the quarantine set.

`updated-healthproxy`:

- `healthproxy_backends{state=up|drained}` — what it programmed, per its one reconcile.
- `healthproxy_reports_stale_total` — drains caused by report staleness, the number that turns
  a silent freshness failure into a visible one.
- `healthproxy_reconcile_timestamp_seconds` — is it alive.
- `healthproxy_endpoints_timestamp_seconds` — when the control plane's endpoint projection was
  last observed. The projection fails OPEN by design, so once this falls further behind than the
  freshness window every cordon has been released and health alone governs — the one number that
  makes a silently lost cordon alertable, as `reports_stale_total` does for a silently aged-out
  report. The proxy also logs both edges of that observation, and says "no longer cordoned" rather
  than "health report ready" when a node rejoins because its cordon went away.

## Non-goals

No histograms beyond what admission itself uses, no per-node series on the control plane (label
cardinality is bounded by groups, not nodes), no traces, no logs pipeline, no push gateway. If a
question cannot be answered from state the one path already holds, the answer is to strengthen
the path, not to grow the metrics surface.

## Testing

Exposition is a pure function of reconciler state: unit-test it as text against constructed
state, the same way status projection is tested. The e2e kind script scrapes both endpoints once
after convergence and asserts the settled fleet shape.
