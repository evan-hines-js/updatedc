# Node reconciliation execution model

The supervisor is a transactional host for one signed node reconciler. It is not a workflow
engine and does not execute independently configured hooks.

The reconciler bundle declares one executable. The supervisor invokes it with one of four public
operations (`apply`, `healthcheck`, `rollback`, `inspect`) and named argv context using protocol
version 1. Internal preparation, draining, process transitions, commit, and crash recovery are not
part of the provider ABI. See
[`LIFECYCLE_PROVIDER.md`](../LIFECYCLE_PROVIDER.md) for the complete Bash/PowerShell-oriented
contract.

The supervisor owns:

- artifact authentication and immutable materialization;
- operation ordering and durable attempt identity;
- crash replay and rollback scheduling;
- process-tree containment and deadlines;
- bounded diagnostic capture;
- managed application process ownership, when configured.

The reconciler owns:

- application-specific machine inspection and mutation;
- service-manager, configuration, database, mount, and network-policy changes;
- idempotency of every operation;
- interpretation of readiness and verification evidence.

`managed` uses guardian-owned stop/start. `provider-managed` delegates workload ownership to the
reconciler and performs no application process operations. There is no artifact-selected reload
strategy and no alternate phase-specific entrypoint.
