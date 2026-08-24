# updatec

The `updated` control plane: the reconciling controller and the mTLS enrollment gateway.

```sh
# First resolve an immutable build release and verify the downloaded chart, CRD, image-digest
# manifest, and SHA256SUMS as described in the full walkthrough below.
kubectl apply -f "$release_dir/updated.dev_crds.yaml"

helm upgrade --install updatec \
  "$release_dir/updatec-chart.tgz" \
  --namespace updated-system --create-namespace \
  --set publicUrl=https://updates.example.com \
  --set certManager.enabled=true \
  --set gateway.service.type=LoadBalancer
```

Full walkthrough: [docs/kubernetes-install.md](../../../docs/kubernetes-install.md).

## CRDs

Shipped in `crds/`, generated from the Rust types, and published as a release asset. Helm installs
a chart's CRDs but never upgrades them, so manage them with `kubectl apply` as above. CI fails the
build if the checked-in copy has drifted from the types, so the file is always current.

`UpdateRepository.spec.stateMaxShards` (default 8, range 1–64) is the live, per-repository bound on
durable rollout state. Each shard holds at most 768 KiB; changing the field atomically rebalances
the complete state. This is CRD configuration, not a chart value.

Managed repository prefixes are not configurable. The controller owns exactly
`routing/<namespace>/<repository>` in the configured bucket, binds that scope into status before it
adds the deletion finalizer, and prunes exactly that scope on deletion after every issued object
capability has expired. The same finalizer removes the repository's admitted-state ConfigMaps and
local TUF epoch before releasing its name. Bucket, region, endpoint, and the credential Secret
reference are write-once. Rotate credentials by updating that Secret's contents; the public
endpoint may also change without changing ownership.

## Values

| Key | Default | Notes |
| --- | --- | --- |
| `publicUrl` | *(required)* | The URL nodes return to. Minted into **immutable** signed enrollment bundles — a wrong value cannot be repaired by editing it. |
| `image.repository` / `image.tag` | `ghcr.io/evan-hines-js/updatec` / appVersion | Mutable development reference; released charts embed a digest instead. |
| `image.digest` | `""` in source | `sha256:<64 hex>`. Released charts populate it; mutually exclusive with `tag`. |
| `image.requireDigest` | `false` | Make a bare tag a render-time failure. |
| `repository` | `default` | The `UpdateRepository` this control plane serves. |
| `gateway.service.type` | `ClusterIP` | `LoadBalancer` for nodes outside the cluster. |
| `gateway.ingress.enabled` | `false` | Requires TLS **passthrough**; see below. |
| `gateway.tlsSecretName` | `gateway-tls` | Server cert + the CA agents are verified against. |
| `gateway.issuingCaSecretName` | `fleet-ca` | Fleet CA *with its private key*, so `/enroll` can sign node CSRs. |
| `gateway.enrollmentClientCN` | `updated-agent` | CN a bootstrap client must carry to call `/enroll`. |
| `gateway.secretResourceNames` | `[]` | Pin `secrets: get` to repository credential Secrets. Empty grants no Secret access. |
| `gateway.fleetReportMaxShards` | `4` | Exact pending/stored serialized-report ceiling, in 16 MiB shards. Range 1–64; a change rolls the gateway and rebalances. |
| `certManager.enabled` | `false` | Issue the fleet root and gateway certificate from a self-signed root. |
| `controller.persistence.*` | 1Gi RWO | The signed TUF repository — durable state, **not** a cache. See below. |
| `controller.metrics.enabled` | `false` | `GET /metrics`. |
| `controller.alerting.url` | `""` | POST condition transitions to a webhook. |
| `healthproxy.image.*` | published healthproxy image | Executable used for operator-owned `UpdateBackend` workloads; topology is configured only through CRDs. |

`helm show values` lists the rest with commentary.

## Identities

The controller and the gateway run as **separate** ServiceAccounts, always. They are not equally
trusted: the controller reconciles the whole namespace and holds the publisher lease, while the
gateway is the only externally exposed listener.

| | controller | gateway |
| --- | --- | --- |
| `secrets` | **get** only | **get** only |
| `configmaps` | exact durable names: get/update/delete; admission-bounded dynamic children: create/patch/delete | — |
| `serviceaccounts`, `deployments`, `roles`, `rolebindings` | create, patch, delete operator-owned `UpdateBackend` children (`deployments` also get) | — |
| `endpointslices` | get, create, patch, delete, namespace-wide (required to delegate narrower dynamic Roles) | — |
| `updateagents` | get, list, watch, create, + `/status` | get, list, create, update |
| `updaterepositories` | get, list, watch, create, patch, update, + `/status` | **get** only |
| `updateadmissionpolicies` | get, list, watch | — |
| `updatebackends` | list, patch, + `patch /status` | — |
| `updategroups`, `updategroupsets`, `updatesubscriptions` | get, list, watch, create, + `/status` | — |
| `leases` | get, create, update | get/update on the one enrollment lock |

Neither workload receives cluster-scoped RBAC. Managed repository key spaces are derived from the
Kubernetes namespace/name pair, so the finalizer never needs a cross-namespace overlap scan.

The gateway reads Kubernetes Secrets only to construct the repository's object-store client.
Application configuration—including secret material—has no Kubernetes Secret delivery path; it is
stored in private S3 file snapshots. Pin the gateway to the repository's
`spec.s3.credentialsSecretRef`:

```sh
--set 'gateway.secretResourceNames={updatedc-store}'
```

The gateway Role has no Secret rule by default. Setting this value adds one exact-name grant; the
gateway never receives namespace-wide Secret access and cannot read signing keys through its
ServiceAccount. A repository using workload identity leaves the list empty. A repository using a
credentials Secret must keep this allow-list aligned with `spec.s3.credentialsSecretRef` or the
gateway deliberately stays unavailable.

Enrollment is serialized across gateway replicas through one chart-precreated Lease. The gateway
can get/update only that exact Lease and cannot create Lease objects. While holding it, `/enroll`
counts the live UpdateAgents for this repository and creates at most one new identity; stale status
is not an admission input, so a concurrent bootstrap burst cannot overshoot the 10,000-agent product
bound. The list permission exists only for that exact live count.

The gateway's `updateagents` verbs are also fenced by the
`…-gateway-updateagents` ValidatingAdmissionPolicy. A create must be a complete enrolled identity in
this release's repository, use that repository's operator-owned enrollment labels, start unheld and
uncordoned without a backend address, and add no metadata labels, annotations, finalizers, or owner
references. The repository is a fail-closed policy parameter, so a missing object denies the write.
An update must be the exact `reserved` → `enrolled` completion and preserve every other spec and
metadata field. Extracting the gateway's bearer token therefore cannot turn its broad Kubernetes
verb into a way to rewrite existing fleet inventory.

The controller's EndpointSlice grant is namespace-wide, and covers `create` and `delete` as well as
`patch`, because Kubernetes's RBAC anti-escalation check will not let it create a Role containing a
permission it does not already hold. What keeps that from being the controller's own reach is not
RBAC but the `…-controller-no-endpointslices` ValidatingAdmissionPolicy, which denies every
EndpointSlice write made by the controller's ServiceAccount. The chart's dynamic `configmaps`
grants are bounded the same way. Both policies render regardless of `rbac.create`: a hand-written
Role carries the same breadth and needs the same fence.

Generated healthproxy identities do not inherit that breadth: each can patch only the two
deterministic IPv4/IPv6 slice names for its `UpdateBackend`. Target changes and deletion terminate
and drain the workload before those generated permissions are replaced or removed.

## Running the controller HA

Single-writer scheduling comes from the `updatec-publisher` lease — every replica must acquire or
renew it before reconciling, and a follower reconciles nothing. The visible S3 `timestamp.json`
commit is independently compare-and-swapped against the previously observed object version, so a
late request from a cancelled former leader cannot overwrite a newer generation. More than one
replica is safe; it buys **failover**, not throughput.

What decides whether it is possible is the volume. Two pods cannot bind one ReadWriteOnce claim, so
the default deployment is one replica under the `Recreate` strategy. Give it a shared volume and the
chart switches to `RollingUpdate`:

```sh
--set controller.replicaCount=3 \
--set 'controller.persistence.accessModes={ReadWriteMany}' \
--set controller.podDisruptionBudget.enabled=true \
--set controller.podDisruptionBudget.minAvailable=2
```

Asking for replicas on a ReadWriteOnce claim is refused at render time rather than discovered as
pods stuck `Pending`. PDBs render only when a workload has more than one replica — a `minAvailable`
over a single pod blocks node drains forever. The gateway is stateless and scales freely.

## Guardrails

The chart refuses to render configurations that would wedge a fleet, because each of them fails
later in a way that names none of its cause:

- no `publicUrl`, or one that is not an `https://` URL — nodes would be told to return to nowhere
  or to something they cannot resolve, permanently, since the value is signed into their bundles
- an ingress that terminates TLS — strips the client certificate that *is* the node's identity
- one ServiceAccount name for both workloads, or `serviceAccount.create=false` with a name left
  empty — either binds the controller's namespace-wide Role to the internet-facing gateway
- `certManager.bootstrapIssuer.kind` other than `Issuer` while the chart is creating that issuer —
  the fleet CA would reference an object that does not exist
- `certManager.agentCertificate.commonName` ≠ `gateway.enrollmentClientCN` — every enrollment
  rejected at the TLS layer
- `gateway.fleetReportMaxShards` outside 1–64 — the gateway refuses to start
- `controller.replicaCount > 1` on a volume not declared ReadWriteMany — the extra pods would sit
  `Pending`, or (on `emptyDir`) each would hold its own copy of the generation floor
- `image.requireDigest` with no digest, a malformed digest, or a tag and digest together

## The controller's state volume

This is **not** a cache, despite holding a "repository directory". The controller numbers each TUF
generation from the metadata it finds on this volume, and it fails closed if that metadata is
missing or behind what the object store already serves — it will not re-initialize at version 1
over a store serving version N, because every node would reject that as a rollback. Losing the
volume does not degrade performance; it stops publishing until the volume is restored.

That is why the claim carries `helm.sh/resource-policy: keep`, why `persistence.enabled=false` is
only appropriate for a repository that never has to survive a restart, and why multiple replicas
require a *shared* (ReadWriteMany) volume rather than one volume each.

## Notes

- The gateway does not open its health listener until its `UpdateRepository` exists. On a fresh
  install it is usually waiting for that resource, not failing. `helm --wait` will time out on it.
- The controller uses `Recreate` while its volume is exclusive (the default RWO), because a rolling
  update would deadlock waiting for the old pod to release it. Declaring ReadWriteMany
  `accessModes` switches it to `RollingUpdate` automatically.
- `accessModes` is read as your declaration of what the volume is even when you supply
  `existingClaim` — the chart cannot inspect a claim it did not create, so that value is how it
  learns the volume is shared.
