# Node decommission via signed tombstone (v0)

## Goal

Retire a node from the fleet so that the external state it created is cleaned up and its
control-plane records are reaped — **without the control plane ever reaching the node**, and
without leaking the infrastructure the lifecycle provider manages.

Decommission is a desired-state transition like any other in this system, so it flows the
same way every other one does: the control plane publishes a **signed artifact** to shared
storage, and the agent discovers it on its normal poll and acts. There is no inbound
connection to a node, ever — a "go decommission yourself" instruction is a **tombstone in
the repository**, not an RPC.

This is the node-side mirror of the operator finalizers already in place
(`crates/updatec/src/runtime.rs`): the `UpdateRepository` finalizer prunes published TUF
artifacts on repository delete; decommission prunes **node state** on node retirement. Both
are control-plane-initiated, both go through signed artifacts, both fail closed.

## Non-goals

- **Not a local-command-first design.** A local `updated uninstall` exists only as
  break-glass for a node the control plane has lost (see the last section); it is never the
  primary path.
- **No rollback of a decommission** in the sense of restoring the wiped application — there is
  no predecessor to bring back. But an uninstall does **not** destroy the node: it returns it
  to the empty, enrolled state (see below), from which a later assignment cold-installs.
- **`updated` never kills the guardian.** The guardian is the permanent process the outer
  lifecycle owner (systemd/launchd/SCM/installer) placed and supervises; only that owner
  removes it. Uninstall makes the node idle and unready, it does not exit the process.
- Not a fleet-wide pause or drain; this retires an individual node (or a selected set).

## The tombstone: a signed decommission intent on the agent document

The per-node instruction the agent already pulls and TUF-verifies is the **agent document**
(`AgentDocument`, `crates/updated/src/config.rs`) — schema-versioned, digest-pinned as an
exact TUF target, and today carrying the assignment plus an optional signed `status`. The
tombstone is one more optional, signed field on that document:

```rust
pub struct AgentDocument {
    pub schema: u32,
    // …assignment, status…
    /// Present only to retire this node. Its presence in the SIGNED, digest-pinned agent
    /// document is the whole instruction; absence means "run normally".
    #[serde(default)]
    pub decommission: Option<Decommission>,
}

pub struct Decommission {
    /// Opaque id the operator stamps, echoed back in the node's terminal report so the two
    /// sides agree on which retirement completed (mirrors a lifecycle attempt id).
    pub id: String,
}
```

Two properties are load-bearing:

1. **Absence is never decommission.** A node that cannot reach the repository, a transient
   publish gap, or an accidentally deleted object must all continue meaning *"keep running
   the last verified bundle"* — the system's fail-closed rule. Decommission is the single
   most destructive instruction in the system, so it must be a **positive** object that
   *says* decommission, never inferred from a missing one.
2. **The signature is the authorization.** The tombstone rides the same TUF-signed,
   pinned-root path as a release, so a party who can only write to object storage cannot
   forge it — exactly the property that already protects releases ("compromising the
   distribution path cannot forge a release"), extended to the most dangerous instruction.
   A node never self-destructs on unsigned or unverifiable data.

## Agent side: the decommission transaction

Detection sits in the same place the agent resolves its assignment each cycle: if the
verified agent document carries `decommission`, the agent enters a decommission transaction
instead of the normal select/install/update path. Like every other durable action here it
is **journaled, crash-safe, resumable, and idempotent** — a crash at any point resumes from
the journal, and a replayed step converges.

Phases, in order:

1. **Quiesce** — stop taking new work; withdraw readiness so a health-driven load balancer
   drains the node (the same drain edge an update uses).
2. **Provider `uninstall`** — run the lifecycle provider's `uninstall` phase (already
   implemented; see `LIFECYCLE_PROVIDER.md`, `scripts/haproxy/`, `crates/demo-lifecycle/`).
   This is the only thing that knows about the node's **external** state — LB/DNS/cloud
   registrations, generated config, external installs, mounts it made — so it must run
   **before** the install root is wiped, with the currently-installed release as
   `UPDATED_CANDIDATE`, plus `UPDATED_INSTALL_ROOT` and `UPDATED_CHILD_PID`.
3. **Stop the application** — the guardian stops the managed process (it owns process
   lifetime; the provider does not kill it).
4. **Wipe the install root** — remove `updated`'s own state (`versions/`, `state/`, runtime
   dirs). The provider handled everything outside the install root in step 2; `updated`
   owns everything inside it.
5. **Return to the empty, enrolled state — the guardian does not exit.** Write one final,
   ECDSA-signed `NodeReport` marking the node uninstalled (echoing `Decommission.id`) so the
   control plane learns it completed over the same reporting path it already reads. Then the
   guardian **keeps running, app-less and always unready**: readiness is withdrawn so a load
   balancer drains it and the control plane sees it not-settled, but the process the outer
   lifecycle owner (systemd/launchd/SCM) supervises stays up. `updated` never kills the
   guardian — that is the outer owner's job, decoupled from decommission. The node is now
   indistinguishable from a freshly enrolled node that has never installed anything.

There is no rollback phase in the sense of restoring the old application: a half-wiped node
that crashes resumes forward to a clean empty state, never backward. But the node is not
destroyed — it sits idle awaiting either removal by its outer owner or a new assignment.

### An assignment after an uninstall is a cold install

Because uninstall returns the node to the empty/enrolled state, there is no separate
"re-install" concept. If the control plane later publishes a real assignment (replacing the
tombstone), the node processes it through the **normal cold-install path** — there is no
predecessor to update from, so **an update after an uninstall is an install**. This unifies
the retired node with the never-installed one: a node with no active release and a real
assignment always cold-installs, whether it just enrolled or was just wiped. The two exits
from the uninstalled state are therefore symmetric — the outer owner removes the guardian
(truly gone), or a new assignment cold-installs it (reused).

## Control plane: publish and reap (the `UpdateAgent` finalizer)

Trigger is the natural Kubernetes gesture — `kubectl delete updateagent <node>` — intercepted
by a finalizer so deletion does not complete until the node is actually gone:

1. **Finalizer holds** the `UpdateAgent` CR in `Terminating`.
2. **Publish the signed tombstone**: the operator sets `decommission` on that node's agent
   document and re-signs/publishes it, exactly as it publishes a desired release. It keeps
   the tombstone published — it must not delete the node's assignment first, or the tombstone
   would vanish before the node reads it (deletion is not the signal; the signed tombstone
   is).
3. **Wait for the terminal report**: hold until the node's signed decommissioned report for
   this `Decommission.id` appears (verified against the node's pinned key, like every other
   report), **bounded** by a deadline.
4. **Force-reap escape**: a node that is already dead or permanently unreachable can never
   confirm — the mirror of "a node that cannot reach the repository keeps running." So the
   operator needs an explicit force path (a deadline, or an operator annotation) to reap a CR
   whose node will never answer, accepting that its external state may not have been cleaned.
   This must be deliberate, never automatic on a transient gap.
5. **Prune per-node artifacts**: on confirmation, remove the node's published artifacts — the
   agent-document target, the enrollment Secret (already `controller_owner_ref`'d, so k8s GC
   handles it once the CR goes), and the node's telemetry object under
   `<prefix>/telemetry/<node>.json`. This is the same "don't orphan artifacts in the bucket"
   discipline as the `UpdateRepository` finalizer.
6. **Remove the finalizer** → the `UpdateAgent` CR is deleted.

The control plane's job ends at the CR and the published artifacts; it does **not** stop the
guardian, which keeps sitting there idle and unready. Actually removing the guardian process
is the outer lifecycle owner's concern (a `systemctl disable`, an uninstall of the node
package) — decoupled from, and usually later than, the CR reap. Equally, the operator may
choose **not** to reap: republishing a real assignment in place of the tombstone reuses the
idle node, which cold-installs it. Reap and reuse are the two exits, and both start from the
same idle, unready state.

## Safety invariants

1. **Absence ≠ decommission.** A missing/unreachable/blipped assignment means keep running;
   only a present, signed tombstone retires a node.
2. **Signature required.** The tombstone (and the terminal report) are TUF/ECDSA-verified
   against pinned keys; a node never acts on unsigned or unverifiable teardown data.
3. **Idempotent + resumable.** Every decommission phase is journaled and safe to replay; a
   crash resumes forward.
4. **Provider `uninstall` before install-root wipe**, so external state is cleaned while the
   provider still has the release, PID, and install root.
5. **Uninstall returns the node to empty, it does not destroy it.** No rollback restores the
   wiped application, but the guardian stays up, idle and always unready; `updated` never kills
   it (the outer lifecycle owner does). A later real assignment cold-installs the node — an
   update after an uninstall is an install.
6. **Bounded confirmation + deliberate force-reap.** The operator holds the CR until the node
   confirms, with an explicit (never automatic) escape for a node that can never answer.
7. **Never delete shared resources.** The provider's `uninstall` removes only what it
   created (it must not unmount a shared filesystem or drop a shared database it merely used).

## Break-glass: local `updated uninstall`

For a node the control plane has lost — decommissioned by hand, or being physically
reclaimed — a local `updated uninstall <install-root>` runs the same sequence locally
(provider `uninstall` → guardian stop → wipe). It is a fallback for a human at the node, not
the fleet path, and it cannot substitute for the control-plane flow (nothing reaps the CR or
prunes artifacts without the operator).

## Open decisions

- **Field vs. schema bump.** `decommission` as an added optional field vs. an `AgentDocument`
  schema increment. Given `deny_unknown_fields`, an additive optional field with `#[serde(default)]`
  is the lighter path and matches how `status` was added.
- **Terminal-report shape.** Reuse `NodeReport` with a decommissioned marker + the
  `Decommission.id`, or a distinct terminal object. Reusing `NodeReport` keeps one reporting
  path and one signing scheme.
- **Group-level decommission.** Deleting an `UpdateGroup` could fan a tombstone to all its
  members; likely a thin layer over the per-`UpdateAgent` flow rather than a separate path.
