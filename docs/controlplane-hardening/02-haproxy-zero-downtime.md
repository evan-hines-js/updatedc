# 2. HAProxy zero-downtime flake — diagnosis

**Status: diagnosed, not yet fixed. The fix is doc 4 (intra-group rolling).**

## Symptom

After the fleet converges, the demo drives a 1.0.0 → 2.0.0 upgrade of the two updated-managed
HAProxy front instances and asserts zero dropped requests. It intermittently fails the SLA:

```
Error: "HAProxy upgrade dropped traffic: 1/90 requests failed (98.89% available, SLA 99.5%)"
```

One earlier run passed at `0/96` (100%). So it is a **marginal, timing-dependent flake**, not a
hard break — it passes or fails on luck.

## What actually happens

The two HAProxy nodes reexec at the **same second**:

```
haproxy-0: 01:27:05 applying update 1.0.0 -> 2.0.0 … [WARNING] Reexecuting Master process … upgraded (pid 49)
haproxy-1: 01:27:05 applying update 1.0.0 -> 2.0.0 … [WARNING] Reexecuting Master process … upgraded (pid 50)
```

Both are behind one front `Service` (`DEMO_HAPROXY_FRONT_SERVICE`). While *both* are inside their
(tiny) SIGUSR2 reexec window simultaneously, a request routed to either can drop. The front
Service has no healthy instance to fail over to because *both* are rotating at once.

This is **not** caused by the doc-1 fixes: the HAProxy nodes reexec via HAProxy's own master-worker
SIGUSR2 handoff, with no `launch spec` relaunch from the supervisor reconciliation (verified in
their logs). The supervisor reconciliation is quiet during a version-only upgrade (args unchanged).

## Root cause — the throttle has no within-group concurrency

The code *intends* one-at-a-time (comments in `crates/updatec-demo/src/haproxy.rs`: "the two
HAProxies re-exec in place **one at a time**"), but the mechanism to do it does not exist:

- The two HAProxies are a **single** `UpdateGroup` (`DEMO_HAPROXY_GROUP`) with 2 replicas.
- The throttle (`crates/updatec/src/throttle.rs`) caps concurrency at the **set** level
  (how many *groups* roll at once), and settles a group only when **every** node in it reports
  the target. There is **no per-node concurrency within a group** — confirmed, nothing in
  `throttle.rs` stages nodes.
- So both nodes of the HAProxy group flip to 2.0.0 together and reexec simultaneously.

The sample-app fleet gets away with all-nodes-at-once per group because it relies on the **set**
for availability (a sibling group serves behind the per-set Service while one group rolls). The
HAProxy tier has one group behind one Service, so there is no sibling to serve — it needs the two
*nodes* to roll one at a time.

## Why this is really a model problem, not an HAProxy-config problem

Even a perfectly seamless HAProxy reexec has a non-zero window; doing *both* at once doubles the
exposure and removes the fallback. The correct fix is to roll the two nodes one at a time so the
front Service always has one settled instance — i.e., the group must **self-protect**. That is a
throttle capability the system lacks today (see docs 3 and 4), not an HAProxy tuning knob.

Once intra-group rolling exists, HAProxy is simply "one group of 2, `maxUnavailable: 1`", and the
"one at a time" comment becomes true by construction. No `set` gymnastics required.

## Relevant code

- Config generation (missing nothing HAProxy-specific that would fix this): `haproxy_cfg` in
  `crates/updatec-demo/src/haproxy.rs` — master-worker + admin stats socket; the reexec is
  driven by the lifecycle provider's `activate` sending SIGUSR2.
- Group definition: `haproxy_group_deployment` + the `UpdateGroup` apply in the same file
  (single group, `DEMO_HAPROXY_REPLICAS` = 2, selector `demo.updated.dev/cohort = haproxy`).
- Front Service: `apply_haproxy_front_service` (selects `demo.updated.dev/kind: haproxy`, only
  ready pods — so a reexecing/unready pod *does* leave the front, which is what makes one-at-a-time
  actually zero-downtime once we stagger them).
- SLA assertion: `assert_haproxy_zero_downtime_upgrade` + `DEMO_SLA_TARGET` (99.5%).
