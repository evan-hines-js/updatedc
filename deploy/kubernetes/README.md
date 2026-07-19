# Kubernetes operator (`updatec`)

`updatec` is one possible control plane for `updated`. Kubernetes stores its desired
state, but an `UpdateAgent` may represent an agent in this cluster, another cluster, a
VM, bare metal, or an embedded device. The operator signs the complete routing view as
one TUF generation and publishes it to S3-compatible object storage. Agents consume the
standard static TUF layout either directly through S3/CDN/static hosting or through the
optional read-only `updatec` gateway.

This is the authoritative operator deployment guide. The example manifest is
[`updatec.yaml`](updatec.yaml), and the executable end-to-end example is
[`../../scripts/kind-updatec-e2e.sh`](../../scripts/kind-updatec-e2e.sh).

## Operating model

- The `UpdateRepository` named by `UPDATED_REPOSITORY` is reconciled in
  `UPDATED_NAMESPACE`. `UpdateGroup` and `UpdateAgent` objects opt into it with an
  explicit `repositoryRef`, so multiple independent repositories can share a namespace.
- The repository contains the default deployment. Named groups contain their deployment
  inline and have a non-empty label selector.
- A node record must match zero or one non-default group. Overlapping matches reject the whole
  reconciliation and leave the last signed publication active.
- For each of N node records, `updatec` publishes a minimal agent document containing only
  an exact reference to one of M opaque config bundles. Group names and membership never
  enter the agent protocol.
- The operator uses a Kubernetes Lease to enforce a single publisher.
- TUF `timestamp.json` is uploaded last, so clients see either the previous complete
  generation or the new complete generation.
- The PVC contains TUF version history and is part of the repository's durable state.

Application bundles and lifecycle-provider artifacts must already exist in their release
TUF repositories. `updatec` publishes routing assignments that pin those artifacts by
target path and SHA-256; it does not build or upload application releases.

## Prerequisites

- A Kubernetes cluster with a default `StorageClass` and cluster-admin access for initial
  CRD/RBAC installation.
- An S3-compatible bucket. The controller and optional gateway need access; agents do not
  need bucket access when the gateway is used.
- An `updatec` container image in a registry visible to the cluster.
- Four PKCS#8 TUF signing keys: `root.pk8`, `targets.pk8`, `snapshot.pk8`, and
  `timestamp.pk8`.
- A securely distributed pinned `root.json` for every node. Never establish trust by
  downloading this root from the same unauthenticated endpoint it is meant to secure.

Generate the signing material and pinned root offline with:

```sh
cargo build --release -p server
target/release/server init --repo ./routing-seed --keys ./routing-keys
```

Back up `routing-keys` securely and distribute
`routing-seed/metadata/root.json` to nodes through trusted configuration management.
The operator initializes the live routing repository with the same role keys.

## Build and install

Build and push the image, replacing the example name with your immutable registry tag:

```sh
docker build -f crates/updatec/Dockerfile -t registry.example/updatec:1.0.0 .
docker push registry.example/updatec:1.0.0
```

Generate and install the CRDs, then create the namespace and secrets:

```sh
cargo run -q -p updatec --example crdgen > updatec-crds.yaml
kubectl apply -f updatec-crds.yaml
kubectl create namespace updated-system

kubectl -n updated-system create secret generic tuf-signing-keys \
  --from-file=./routing-keys/root.pk8 \
  --from-file=./routing-keys/targets.pk8 \
  --from-file=./routing-keys/snapshot.pk8 \
  --from-file=./routing-keys/timestamp.pk8
```

For static S3 credentials, create this optional Secret. Omit it when using workload
identity:

```sh
kubectl -n updated-system create secret generic s3-credentials \
  --from-literal=AWS_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID" \
  --from-literal=AWS_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY"
```

Edit `deploy/kubernetes/updatec.yaml` to use the pushed image and an appropriate PVC size,
then apply it after creating the desired-state resources below:

```sh
kubectl apply -f deploy/kubernetes/updatec.yaml
```

The supplied RBAC is entirely restricted to `updated-system`; `updatec` does not read
Kubernetes Nodes, Pods, or workloads. The container
runs as UID 65532 with a read-only root filesystem. Durable controller state goes only to
its PVC; `/tmp` is an explicitly bounded, memory-backed `emptyDir` and is never durable.

The manifest runs two explicit modes of the same binary. `updatec controller` is the
single-writer control plane. `updatec serve` is a stateless, read-only gateway for the
private bucket. The gateway exposes exactly:

```text
GET|HEAD /metadata/<TUF metadata path>
GET|HEAD /targets/<TUF target path>
GET|HEAD /healthz
```

It performs no placement, group lookup, document generation, or writes. Its object keys
are `<s3.prefix>/metadata/...` and `<s3.prefix>/targets/...`; traversal, encoded paths,
query strings, unknown namespaces, and other methods are rejected. Open-ended byte ranges
are supported for resumable target downloads.

The gateway is optional. To serve the bucket through S3, a CDN, or another static server,
delete the `updatec-gateway` Deployment and Service and point `routing.base_url` at the
same published layout. This changes transport only; agent documents and agent behavior
are identical. Keep the bucket private when using the gateway.

## Declare desired state

Declare a repository with the fallback deployment. `releaseRepository` is one TUF
lineage: `metadataUrl` is the authenticated metadata endpoint and `targetsUrl` is the
transport base for every target authenticated by that metadata. Target paths and hashes
are per artifact; duplicating `targetsUrl` on each artifact would permit inconsistent
origins inside one signed lineage.

```sh
kubectl apply -f - <<'YAML'
apiVersion: updated.dev/v1alpha1
kind: UpdateRepository
metadata: {name: default, namespace: updated-system}
spec:
  defaultDeployment:
    name: web-default
    releaseRepository:
      metadataUrl: https://updates.example/releases/metadata/
      targetsUrl: https://updates.example/releases/targets/
    application:
      path: products/web/stable/1.0.0/linux-x86_64/app
      sha256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    providerSet:
      path: provider-sets/web-1.json
      sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
  signingSecretRef: {name: tuf-signing-keys}
  assignmentPrefix: assignments
  s3:
    bucket: production-updates
    prefix: routing
    region: us-east-1
    credentialsSecretRef: {name: s3-credentials}
    # endpoint: https://s3-compatible.example
---
apiVersion: updated.dev/v1alpha1
kind: UpdateGroup
metadata: {name: edge, namespace: updated-system}
spec:
  repositoryRef: {name: default}
  selector:
    matchLabels: {updated.dev/role: edge}
  deployment:
    name: web-edge
    releaseRepository:
      metadataUrl: https://updates.example/releases/metadata/
      targetsUrl: https://updates.example/releases/targets/
    application:
      path: products/web/stable/2.0.0/linux-x86_64/app
      sha256: cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
    providerSet:
      path: provider-sets/web-1.json
      sha256: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
YAML
```

Declare logical agents explicitly; these records do not imply that the agents run in
Kubernetes. An agent matching no named group receives `defaultDeployment`:

```sh
kubectl apply -f - <<'YAML'
apiVersion: updated.dev/v1alpha1
kind: UpdateAgent
metadata: {name: worker-1, namespace: updated-system}
spec:
  repositoryRef: {name: default}
  identity: {kind: manual}
  labels: {updated.dev/role: edge}
---
apiVersion: updated.dev/v1alpha1
kind: UpdateAgent
metadata: {name: vm-42, namespace: updated-system}
spec:
  repositoryRef: {name: default}
  identity: {kind: manual}
  labels: {}
YAML
```

After the routing generation is published, the controller records the exportable Secret
in agent status. Export the portable enrollment bundle without giving the machine any
Kubernetes credentials:

```sh
secret="$(kubectl -n updated-system get updateagent worker-1 \
  -o jsonpath='{.status.enrollmentSecretRef.name}')"
kubectl -n updated-system get secret "$secret" \
  -o jsonpath='{.data.enrollment\.json}' | base64 --decode > worker-1.enrollment.json
```

The immutable Secret is owned by the `UpdateAgent`. Its file contains the pinned public
routing root, exact assignment identity, the initial agent/config targets, and the TUF
timestamp/snapshot/targets proof needed to verify that initial configuration offline.
The agent never reads Kubernetes or edits CRDs.

Dynamic agents receive only the enrollment URL and shared secret. For the supplied gateway,
expose its Service through an HTTPS ingress or load balancer:

```toml
[enrollment]
url = "https://updates.example/"
client_cert = "/etc/updated/agent-tls/tls.crt"
client_key = "/etc/updated/agent-tls/tls.key"
ca = "/etc/updated/agent-tls/ca.crt"
```

Enrollment is authenticated by mutual TLS: the agent presents a client certificate the fleet
CA signed, and trusts that CA for the gateway. cert-manager (or any issuer) mints the material;
the config holds only paths, so it stays secretless.

The gateway registers a stable generated `UpdateAgent`; operators then select it through
CRDs. Manual provisioning instead creates a manual `UpdateAgent` and exports the immutable
enrollment Secret shown above. Agents never receive Kubernetes credentials or edit CRDs.

## Verify operation

```sh
kubectl -n updated-system rollout status deployment/updatec-controller
kubectl -n updated-system rollout status deployment/updatec-gateway
kubectl -n updated-system logs deployment/updatec-controller
kubectl -n updated-system get lease updatec-publisher -o yaml
```

A successful cycle logs `desired state reconciled` with the deterministic plan digest.
Changing an inline deployment, selector, `UpdateAgent` labels, or repository destination causes
a new signed generation. Deleting a node or group removes its logical route from new TUF
metadata; immutable historical target objects remain available to clients holding older
metadata.

Run the production-shaped local integration test with:

```sh
./scripts/kind-updatec-e2e.sh
# Fast functional pass without the fleet-fuzz/fault-recovery phase:
./scripts/kind-updatec-e2e.sh --fuzz-rounds 0
```

The test keeps MinIO private, reaches routing only through the in-cluster gateway, and
runs five real bootstrap/supervisor/sampleapp towers as a StatefulSet. Two agents select
the `edge` deployment, two select `batch`, and one uses the default. An in-cluster
Kubernetes Job curls each application's `/version` endpoint and prints the five observed
versions before the test passes; no host port-forwarding participates. The test also
then runs a seeded fleet fuzzer (one generation by default): every generation publishes
new monotonic group versions, randomly reassigns the agents, and disrupts the controller,
gateway, or release origin while five indexed observer pods log health/version transitions.
A verifier Job proves exact fleet convergence after every generation. Finally, the test
introduces an overlapping group and proves the rejected reconciliation did not change the
published routing timestamp. Pass `--fuzz-rounds N` to control the soak length; zero
skips the entire fleet-fuzz/observer/fault-recovery phase. `UPDATEC_FUZZ_ROUNDS` remains
an environment fallback for CI, and `UPDATEC_FUZZ_SEED` reproduces a placement sequence.
A separate scheduled CI soak uses
additional rounds so the normal release gate stays deterministic and short.

Each agent container exposes the guardian—not the application—on port 9090. Kubernetes
uses `/startupz`, `/readyz`, and `/livez` directly. The E2E suite proves a planned update
becomes unready while remaining live. It separately crashes a managed application,
observes the guardian roll up the container, waits for Kubernetes to restart it, and
verifies the committed bundle becomes ready again.

## Failure and recovery

- Invalid JSON, invalid artifact references, missing resources, overlapping selectors,
  signing failures, and storage failures do not publish `timestamp.json`; clients retain
  the last complete generation.
- Do not delete or replace the PVC after publication. Losing it resets TUF metadata
  version history, and existing clients correctly reject that rollback. Back it up and
  restore it as a unit.
- Signing keys cannot be changed in place. The controller fails closed if persisted key
  bytes differ from the Secret. Root-key rotation requires an explicit, separately
  audited TUF root-rotation procedure.
- Keep the example at one replica unless all replicas can mount the same durable state.
  The Lease prevents concurrent publishers but does not replace shared TUF history.
- If reconciliation fails, inspect the operator log and Kubernetes events, correct the
  desired resource, and allow the next cycle to retry. Do not edit the bucket metadata or
  files inside the PVC manually.
