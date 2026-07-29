# Documentation map

This directory contains current contracts only. Historical reviews and implementation plans are
deleted when their conclusions land so they cannot become a second source of truth.

- [`state-machines.md`](state-machines.md) — authoritative node, update, rollback, and recovery
  state machines.
- [`core.md`](core.md) — the product mission, single execution path, ownership boundaries, and
  explicit non-goals.
- [`workflow-engine-design.md`](workflow-engine-design.md) — authoritative lifecycle-provider
  execution model.
- [`group-enrollment-design.md`](group-enrollment-design.md) — authoritative enrollment,
  per-node identity, and renewal model.
- [`fleet-rollout-endpoints.md`](fleet-rollout-endpoints.md) — authoritative fleet data-plane
  endpoint contract.
- [`subsystems.md`](subsystems.md) — conceptual subsystem boundaries, crate ownership, dependency
  direction, and prioritized refactoring candidates.

Deployment procedures live under [`../deploy`](../deploy/README.md). The repository-level
[`README`](../README.md) is the product overview and [`WALKTHROUGH`](../WALKTHROUGH.md) is the
operator walkthrough.
