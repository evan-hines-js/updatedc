# 4. Intra-group rolling — design

**Status: designed, not built. Depends on the model in doc 3; best landed inside the hexagonal
domain core (doc 5).**

Goal: a group self-protects. At most `maxUnavailable` of its nodes are in-flight at once during a
roll; the rest stay serving on the previous deployment until a slot frees. Gated on the same
per-node telemetry that already decides "settled."

## Data-model changes

### CRD — `maxUnavailable` on the group deployment

Add an optional group-level rollout concurrency. **Default 1** (safe by default).

- Where: `crates/updatec/src/lib.rs`, on the group deployment spec (`DeploymentSpec` / its
  `RuntimeSpec` sibling — pick the group-rollout home, not the per-release runtime, since it's a
  rollout policy). Surface it on `DesiredDeployment` so the throttle sees it.
- Semantics: max nodes of this group that may be **non-settled** (in-flight) at once during a roll.
  `maxUnavailable: 0` is invalid (would wedge). Values ≥ group size mean "all at once" (today's
  behavior, opt-in).
- Regenerate the CRD (`cargo run -p updatec --example crdgen`) and the kind fixtures
  (`examples/kind_resources.rs`).

### Admitted state — remember the previous deployment

Today the durable admitted ConfigMap maps `group → DesiredDeployment` (the pinned/target
deployment). Held nodes need something to stay on, so extend the value to carry the **previous**
deployment during a roll:

```
admitted[group] = { current: DesiredDeployment, previous: Option<DesiredDeployment> }
```

- When a group re-targets (`desired != current`) and is admitted to roll, set
  `previous = old current`, `current = desired`.
- When the group is fully settled on `current`, clear `previous`.
- Format change is fine (no back-compat; the e2e reprovisions fresh). Keep it keyed by group.

## The throttle algorithm — stateless per-node staging

Keep the **set layer** (`apply_throttle`'s group concurrency) exactly as is: it decides which
*groups* may roll. Then, for each group that is admitted to roll, decide per-node which deployment
each node gets. This needs **no new per-node durable state** — it is derived each cycle from
sorted node order + settled counts:

For a group with target `current` (C), previous `previous` (P), `maxUnavailable = k`, and its
selected nodes sorted deterministically (by name):

```
settled_C  = nodes reporting C, healthy, fresh, signature-verified   # existing fresh_healthy()
advanced   = first (|settled_C| + k) nodes in sorted order
for each node in group:
    node_deployment = C if node in advanced else P
```

- `in-flight = advanced \ settled_C` has size ≤ `k` by construction.
- As a node settles C, `|settled_C|` grows, `advanced` grows by one → the next node advances.
- If an advanced node is unhealthy (on C but not settled), it stays in `advanced` and counts
  against `k`, so **no further node advances until it recovers** — self-protecting.
- First roll of a group with no previous (`P = None`): held nodes have nothing to hold on. On a
  true first install there is no previous and no protection is needed (baseline is not a throttled
  rollout — see the existing "seed baseline" logic); held nodes simply aren't published until they
  become `advanced`. Handle by treating `P = None` as "not yet publishable" only for the baseline
  case; in steady state a re-target always has a previous.

Group is **settled** (frees its set slot) when `|settled_C| == group size` — unchanged meaning,
now reached incrementally.

### Why sorted-order staging (not per-node admitted state)

It is a pure function of `(sorted nodes, settled set, k)`, so it survives leader failover and cold
PVC with zero extra durable state — the same property the group-level admitted set was carefully
designed to have (see the `leader_failover_…` test in `throttle.rs`). Adding a per-node admitted
map would reintroduce exactly the state-loss hazard that test guards against.

## Publication changes

`build_publication_plan` (`crates/updatec/src/lib.rs`) currently emits one config doc per group
(`{prefix}/configs/{group}.json`) and points each node's agent doc at its group's config. For
intra-group rolling, two nodes in one group can need **different** deployments at once.

Change the plan to be driven by **node → deployment** rather than **node → group**:

- Input: `node_deployments: BTreeMap<node, DesiredDeployment>` (from the throttle).
- Emit one config doc **per distinct deployment**, content-addressed (dedup by canonical-JSON
  hash), e.g. `{prefix}/configs/{deployment_id}.json` or a hash-named path.
- Each node's agent doc references its own deployment's config.
- `node_groups` (node → group) is still produced for status/telemetry mapping.

This is a clean generalization: the "group" becomes purely the label-selection + desired-deployment
*source*; the throttle turns group-desired into per-node-admitted; the publisher dedups configs.

Keep the all-or-nothing signed batch + `publication_digest` semantics.

## Sequencing in `reconcile_once`

1. Map nodes → groups (selectors) — split this out of `build_publication_plan` into a cheap
   `resolve_node_groups` so the throttle can run before the final publication is built.
2. `apply_throttle` (set layer) → per-group admitted `{current, previous}`.
3. Per-group node staging → `node_deployments`.
4. `build_publication_plan(node_deployments)` → signed targets.
5. Publish + write admitted state + statuses (unchanged adapters).

## HAProxy simplification (payoff)

- `crates/updatec-demo/src/haproxy.rs`: keep the single `UpdateGroup` of 2 replicas, set
  `maxUnavailable: 1` on its deployment. Delete the "one at a time" aspirational comments — it now
  is. No set needed. The front Service already excludes not-ready pods, so the reexecing node
  leaves the front and the settled node serves → genuinely zero-downtime.

## Test plan (domain, pure — see doc 5)

Unit tests on the staging function (no cluster):

- **one-at-a-time**: 3-node group, `k=1`, target C. Round 1 → only node-0 on C, 1,2 on P. After
  node-0 settles → node-1 on C. Etc. Never more than 1 in-flight.
- **k>1**: `k=2` advances two, holds the rest.
- **stall on unhealthy**: advanced node reports C-but-unhealthy → no further advance.
- **regression**: a settled node flips back to unhealthy → `advanced` shrinks, in-flight capped.
- **settle frees the set slot**: full-settled group releases its set concurrency slot (integration
  with the existing set-layer tests).
- **first baseline**: `previous = None` seeds all nodes without staging (baseline is not throttled).
- **leader failover / cold PVC**: staging is identical with an empty per-node state (proves no new
  durable state is needed).

Then the live `e2e --exit` must show the two HAProxy nodes reexec at **different** times and the
SLA at 100%.
