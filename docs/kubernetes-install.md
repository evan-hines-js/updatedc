# Installing the control plane on Kubernetes

Status: implemented. `deploy/kubernetes/updatec.yaml` carries the workloads and RBAC only. The
prerequisites below are not in it, and applying it without them fails — first at apply time
(the namespace does not exist), then in a crash loop (`the server could not find the requested
resource`, because the `updated.dev` CRDs do not exist).

`scripts/kind-updatec-e2e.sh` performs this whole sequence against a kind cluster and is the
executable version of this document.

## 1. CRDs

The custom resource definitions are generated from the Rust types, so there is no checked-in copy
to drift:

```sh
cargo run -q -p updatec --example crdgen >crds.yaml
kubectl apply -f crds.yaml
```

## 2. Namespace

Every object in `deploy/kubernetes/updatec.yaml` is namespaced to `updated-system`:

```sh
kubectl create namespace updated-system
```

## 3. TUF signing keys

The controller signs every generation and never stores a private key in CRD status. Generate a
repository's keys and load them as the Secret named by `UpdateRepository.spec.signingSecretRef`:

```sh
cargo run -q -p server -- init --repo seed-repo --keys keys
kubectl -n updated-system create secret generic tuf-signing-keys \
  --from-file=keys/root.pk8 --from-file=keys/targets.pk8 \
  --from-file=keys/snapshot.pk8 --from-file=keys/timestamp.pk8
```

Distribute the *pinned root* (`seed-repo/metadata/root.json`) to nodes out of band, as part of the
enrollment bundle. It is the trust anchor: a node that fetches its root over the same channel it
fetches targets is not verifying anything.

## 4. Object store credentials

Only when `UpdateRepository.spec.s3.credentialsSecretRef` is set; omit it to use workload identity.
The Secret carries the standard AWS entries:

```sh
kubectl -n updated-system create secret generic s3-credentials \
  --from-literal=AWS_ACCESS_KEY_ID=... --from-literal=AWS_SECRET_ACCESS_KEY=...
```

## 5. Gateway TLS and the fleet CA

The gateway Deployment mounts two Secrets that nothing in this repository creates:

- `gateway-tls` — the gateway's server certificate and key.
- `fleet-ca` — the CA that issues agent client certificates, mounted at
  `UPDATED_ISSUING_CA_DIR`. Enrollment is authenticated by mutual TLS against it; there is no
  shared enrollment secret.

Issue both from cert-manager (a self-signed `Issuer` → an `isCA` `Certificate` named `fleet-ca` →
a CA `Issuer` over that Secret → a server `Certificate` named `gateway-tls`), or supply equivalent
Secrets from an existing PKI. `scripts/kind-updatec-e2e.sh` contains a working set of manifests.

## 6. Workloads

```sh
kubectl apply -f deploy/kubernetes/updatec.yaml
```

Then create the `UpdateRepository`, `UpdateGroup`, `UpdateGroupSet`, and `UpdateAgent` objects for
the fleet. `cargo run -q -p updatec --example kind_resources` prints a complete working set.

## Verifying

`kubectl -n updated-system get upr,updategroups,updategroupsets` shows the projected status: the
repository's `Ready` condition and agent count, each group's progress, each set's rolling/held/
halted lists. `UPDATED_METRICS_ADDRESS` additionally exposes the series in
`docs/observability-design.md`.
