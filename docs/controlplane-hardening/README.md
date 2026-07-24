# Control-plane hardening — design & plan

This series captures the work uncovered while fixing a fleet-convergence regression in the
`updated` control plane, and the deliberate refactor + hardening it points to. It exists so
implementation can resume cleanly (written 2026-07-22; implementation deferred on quota).

The thread started as a bug ("fleet stuck at 16/32 converging to 22.0.0") and unwound into a
design problem: the control plane was assembled as a PoC, and the seams are now visible.

## The documents

| # | Doc | What it covers |
|---|-----|----------------|
| 2 | [02-haproxy-zero-downtime.md](02-haproxy-zero-downtime.md) | The HAProxy tier drops ~1/90 requests on upgrade. Diagnosis: two nodes reexec simultaneously because the throttle has no within-group concurrency. |
| 3 | [03-rollout-model.md](03-rollout-model.md) | What **group** and **set** actually mean, why "a group is not intrinsically protected" is the surprising-and-wrong part, and the safe-by-default direction. |
| 4 | [04-intra-group-rolling-design.md](04-intra-group-rolling-design.md) | Concrete design for **self-protecting groups**: `maxUnavailable`, node-granularity admission, stateless per-node staging, publication changes, test plan. |
| 5 | [05-hexagonal-refactor-plan.md](05-hexagonal-refactor-plan.md) | The **hexagonal (ports & adapters)** target for `crates/updatec`, the current seams, and a phased plan that lands #4 inside a clean domain core. |

## Status at time of writing

- **Diagnosed, not yet fixed**: the HAProxy zero-downtime flake (doc 2) and its root cause in
  the rollout model (doc 3).
- **Designed, not yet built**: intra-group rolling (doc 4) and the hexagonal refactor (doc 5).

## Guiding principles (from the user)

1. **Safe by default** — a group is protected: it rolls one node at a time unless it opts into
   more (`maxUnavailable` defaults to 1).
2. **Hexagonal** — the pure domain (rollout admission, publication planning, selection policy)
   belongs in a testable core behind ports; kube-rs, S3, TUF signing, and telemetry are adapters.
3. **One way to do things** — single path, no back-compat shims, rip out dead code.
