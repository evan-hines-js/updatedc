# Installation and ordered upgrades

Operators declare one desired target and a release graph in `UpdateGroup.spec.deployment.application`
(or `UpdateRepository.spec.defaultDeployment.application`). Apply the YAML with kubectl or GitOps.
`updatectl publish` supplies each package's immutable target path and SHA-256; it does not deploy it.

The graph belongs to the current rollout, not to an old package. When publishing v2, declare that
v2 accepts v1; when publishing v3, declare that v3 accepts v1 if that direct upgrade is supported.
Neither declaration requires v1 to know about future releases or changes v1's package bytes.

```yaml
application:
  target: "1.35.0"
  releases:
    "1.31.0":
      package: {path: products/kubernetes/stable/1.31.0/linux-x86_64/kubernetes, sha256: <digest-131>}
      installable: true
    "1.32.0":
      package: {path: products/kubernetes/stable/1.32.0/linux-x86_64/kubernetes, sha256: <digest-132>}
      upgradeFrom: ["1.31.0"]
    "1.33.0":
      package: {path: products/kubernetes/stable/1.33.0/linux-x86_64/kubernetes, sha256: <digest-133>}
      upgradeFrom: ["1.32.0"]
    "1.34.0":
      package: {path: products/kubernetes/stable/1.34.0/linux-x86_64/kubernetes, sha256: <digest-134>}
      upgradeFrom: ["1.33.0"]
    "1.35.0":
      package: {path: products/kubernetes/stable/1.35.0/linux-x86_64/kubernetes, sha256: <digest-135>}
      upgradeFrom: ["1.34.0"]
      installable: true
```

Replace the digest placeholders with the publisher's exact SHA-256 values. Versions are exact
semantic versions, and every predecessor must be declared. Upgrade edges must advance the version; explicit `rollbackFrom` edges must descend.
There are no implicit edges, ranges, inferred reversals, or historical-package fallback. Keep the source
packages in the graph while machines may still run them. A release's graph version must match its
signed package version, and an installed source must match both version and package digest.

In this example an existing 1.31.0 installation advances through 1.32.0, 1.33.0, 1.34.0, and 1.35.0.
A new installation can start directly on 1.35.0 because it is installable. The integration must still
prove the cluster is absent before installing it; an empty agent state does not prove that.

## Route selection and preflight

The shared planner finds a shortest complete route to the requested target. Equal-length routes
use stable lexical ordering. An installed node starts from its committed package; a fresh install
can start from any declared installable release. Installable defaults to false and never grants an
upgrade edge. Missing or rejected metadata candidates cannot supply an agent's route.

For example, with installable roots v1 and v2, edges v1 → v3 → v6 and v2 → v4, a fresh installation
targeting v6 chooses v1. An existing v2 node is blocked until the author adds a safe connection to v6.
The system cannot turn that node into a fresh v1 installation.

Before admitting a changed rollout, the controller checks every selected node's complete route.
An existing assigned node needs a fresh authenticated report; unknown or disconnected nodes block
preflight. A newly enrolled node without a prior assignment is checked for a complete installation
route, with application absence checked by its entrypoint. A stranded node blocks publication of
the new generation for everyone. The repository status names the node, source, and target when
route planning fails (`kubectl describe updaterepository <name>`); controller logs carry repository
transport and trust diagnostics.

Retargeting a rollout also checks the remaining routes in the node's published and reported
assignments. A node may finish a hop after sending its report; the replacement graph must preserve
that possible landing's package identity and provide a route onward. A prior graph with no complete
executable route cannot advance the node and does not prevent a valid correction.

Preflight verifies the release repository's TUF signatures, expiry, exact package references,
version and product/platform metadata, admission policy, and availability of objects on every
complete eligible route. This includes alternative branches an agent could select; an installed
source used only as an identity anchor is not a hop to execute.
It opens and immediately closes object streams through the normal repository transport, without
reading or storing bundle bodies. It does not download every version, unpack every archive, or run
scripts. Agents check route availability and download only the next hop, verifying its complete
hash, archive, and execution definition before running it. Retention remains bounded by the normal
storage policy, independent of route length.

Availability is an observation, not a reservation. Missing routes and unavailable objects are
caught before rollout; later network failures, corrupt bundle contents, and execution failures can
still occur. Total controller preflight time is bounded within the shared report-freshness window, so a slow
release repository cannot indefinitely delay health publication. Each successful hop passes its
existing health and confirmation gate before the next hop runs. An intermediate version is never reported as convergence to the final target.

## Multi-version rollback

The same graph and executor handle return routes. The current catalog lists the exact higher
versions each release can restore from in `rollbackFrom`; this defaults to an empty list. Add a
return edge when the newer release is introduced and that return has been tested. This updates
rollout metadata, not the older package, and cannot give its code an unimplemented capability.
For a reversible application:

```yaml
application:
  target: "3.0.0"
  releases:
    "1.0.0":
      package: {path: products/app/stable/1.0.0/linux-x86_64/app, sha256: <digest-1>}
      installable: true
      rollbackFrom: ["2.0.0"]
    "2.0.0":
      package: {path: products/app/stable/2.0.0/linux-x86_64/app, sha256: <digest-2>}
      upgradeFrom: ["1.0.0"]
      rollbackFrom: ["3.0.0"]
    "3.0.0":
      package: {path: products/app/stable/3.0.0/linux-x86_64/app, sha256: <digest-3>}
      upgradeFrom: ["2.0.0"]
```

Retargeting this application to 1.0.0 plans 3.0.0 → 2.0.0 → 1.0.0, downloading and confirming one
hop at a time. A restart resumes planning from the durable installed version. Return paths can
use different intermediate versions from the original upgrade. Every declared return must be
implemented and tested by the package author; Kubernetes upgrades do not acquire downgrade
support merely because a graph can describe it.

For automatic fleet rollback, the existing `UpdateGroupSet.spec.onRegression: rollback` policy
must be unanimous across the group's governing sets. Before admitting a changed rollout, preflight
checks return paths from every possible completed hop and the actual starting versions to the
chosen prior deployment. It verifies metadata, admission, and availability for those return hops
without downloading their bundles. Missing return edges block the forward rollout too.

A failed hop first completes its existing journaled recovery. Once the rejecting nodes are healthy,
the controller restores the prior target and configuration using the current catalog, which knows
about the intermediate releases. Nodes then execute any remaining return hops under normal rollout
throttles. Historical assignment bodies remain available while nodes still carry them, and the
failed assignment remains durably vetoed. A first installation has no prior deployment to restore.

## Responsibilities and recovery

| Package author owns | updatedc owns |
| --- | --- |
| Declaring tested installation roots and upgrade edges | Finding a complete route from the installed package |
| Checking actual application state before mutation | Whole-rollout route and signed-metadata preflight |
| Install, upgrade, health, and recovery scripts | One bounded command-adapter and transaction path |
| Kubernetes node ordering, draining, coordination, and version skew | Per-hop health, confirmation, rejection, and rollout throttling |
| Proving effects safe to replay | Existing durable journals and explicit recovery policy |

One package entrypoint dispatches installation, update, or repair using its invocation context and
observed application state. Separate implementation scripts are fine; there is one package API.
The optional `sequence` helper is for checked operations *inside* that package's hop, using the
same executor as other operations. It does not discover release packages or replace kubectl.

A failed first installation is not automatically reinstalled through another root. Recovery must
inspect partial effects and follow the declared recovery policy. In particular, restoring an older
package is not proof that Kubernetes or a database can safely be downgraded.

## Workloads outside Kubernetes

Backend topology and signed health-report publication continue independently of rollout admission.
The existing health proxy still translates fresh authenticated readiness into EndpointSlice or
HAProxy membership. Kubernetes Services and ingress retain ownership of entrypoints and load
balancing; updatedc does not implement an ingress controller. A blocked upgrade preserves existing
assignments, while unhealthy, cordoned, or stale backends continue to drain through the same health
path. A healthy older package can continue serving while its upgrade is blocked.
