# 3. The rollout model — group vs set, and why "protected by default" was missing

**Status: conceptual alignment reached with the user. Motivates docs 4 and 5.**

## The two concepts as they exist today

**Group (`UpdateGroup`)** — the atomic *rollout batch* and the version/config-assignment unit.
Nodes are selected into a group by label; every node in a group shares **one** deployment
(version, provider set, args, health checks). The throttle admits a whole group at once — all its
nodes flip together — and calls it *settled* only when **every** node it selects reports the
admitted deployment identity, healthy (signed telemetry via `report_url`). There is **no
within-group node concurrency**.

**Set (`UpdateGroupSet`)** — a *rotation / availability domain*. A load balancer fronts its
member groups; `max_concurrent` caps how many member groups roll at once, so sibling groups keep
serving. Zero-downtime is a **set-level** property today, achieved by rotating groups while
siblings serve — never a group-level property.

## The surprising, wrong part

Intuitively, "a group of servers" should be **intrinsically protected**: rolling it updates
members incrementally and keeps the group serving throughout. That is how a Kubernetes Deployment,
an AWS target group, and an autoscaling group all behave — protection is a property of the group
itself (`maxUnavailable`).

This system **inverted** that:

- **Group** = the thing that goes down *together* (no protection).
- **Set** = where protection was bolted on (rotation across groups).

So "group" here means the opposite of the industry default. That inversion is exactly why the
HAProxy tier drops traffic (doc 2): it is one *group* of two nodes behind a Service, so both go
at once and the LB has no sibling to fail over to.

## The direction — make a group self-protecting

Protection belongs on the group, matching intuition:

- **Group** = a pool of nodes on one deployment, rolled **safely within itself** via an intra-group
  concurrency (`maxUnavailable`, **default 1** — safe by default). Self-protecting: at most
  `maxUnavailable` of its nodes are ever in-flight at once, gated on the same per-node telemetry
  that already decides "settled."
- **Set** = still a genuine rotation domain, but now only *earns its keep* when multiple
  **independently-versioned** groups share one LB (what the sample-app fleet actually
  demonstrates: cohorts diverging to different versions behind a per-set Service). It is no longer
  the *only* source of availability.

With that:

- **HAProxy** is one group of 2, `maxUnavailable: 1` → rolls one node at a time, zero-downtime,
  no set required. The "one at a time" comment becomes true by construction.
- **Sample-app fleet** keeps its sets (multiple independently-versioned groups, per-set LBs), and
  additionally every group self-protects — strictly safer.

## Naming

We considered renaming (the current "group" behaving like a batch is what feels wrong). Conclusion:
**do not rename** — fix the *behavior* so the names mean what they say. A "group of servers" that
rolls safely within itself matches intuition; a "set" that spans independently-versioned groups
behind one LB is a coherent higher-level rotation domain. The confusion came from the missing
protection, not the labels.

## Consequences to design for (doc 4)

- The throttle must admit at **node** granularity within a group, not just group granularity.
- A "held" node needs a deployment to stay pinned to — the group's **previous** deployment — so
  the durable admitted state must remember it during a roll.
- The publication must be able to point two nodes *in the same group* at **different** deployments
  (advancing vs held) simultaneously.
