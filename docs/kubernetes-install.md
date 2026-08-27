# Installing the control plane on Kubernetes

Status: implemented. The control plane installs from the `updatec` Helm chart. You need `helm`, the
GitHub CLI (`gh`), `sha256sum`, and a cluster — not a Rust toolchain, not a checkout of this
repository, and not a hand-edited manifest.

`scripts/kind-updatec-e2e.sh` performs this whole sequence against a kind cluster using the same
chart, and is the executable version of this document.

## The short version

```sh
repo=evan-hines-js/updatedc
release="$(gh api "repos/$repo/releases/latest" --jq .tag_name)"
commit="${release#build-}"
test "$release" = "build-$commit" && test "${#commit}" -eq 40
case "$commit" in *[!0-9a-f]*) echo "refusing non-immutable release $release" >&2; exit 1;; esac

release_dir="$(mktemp -d)"
gh release download "$release" --repo "$repo" --dir "$release_dir" \
  --pattern SHA256SUMS --pattern IMAGE_DIGESTS \
  --pattern updated.dev_crds.yaml --pattern updatec-chart.tgz
for asset in SHA256SUMS IMAGE_DIGESTS updated.dev_crds.yaml updatec-chart.tgz; do
  gh attestation verify "$release_dir/$asset" --repo "$repo"
done
(cd "$release_dir" && sha256sum --check --ignore-missing SHA256SUMS)

# CRDs first: Helm installs a chart's CRDs but never upgrades them, so they are managed explicitly.
kubectl apply -f "$release_dir/updated.dev_crds.yaml"

helm upgrade --install updatec \
  "$release_dir/updatec-chart.tgz" \
  --namespace updated-system --create-namespace \
  --set publicUrl=https://updates.example.com \
  --set certManager.enabled=true \
  --set gateway.service.type=LoadBalancer
```

`latest` is used only to discover a release name. Every byte executed with cluster authority is
downloaded from the resolved immutable `build-<commit>` release, verified against its GitHub build
provenance, and checked against the attested checksum manifest. The packaged chart itself contains
the two exact multi-architecture image digests; it never asks the cluster to trust a tag.

Then create the fleet's `UpdateRepository`, `UpdateGroup`, `UpdateGroupSet`, and `UpdateAgent`
objects, and install agents (see [agent-install.md](agent-install.md)).

Everything below explains what those flags decide.

## `publicUrl` — the one value with no safe default

This is the URL nodes are told to come back to, and the controller mints it into **immutable**
signed enrollment bundles. A node that enrolled against a wrong value cannot be repaired by editing
it later; its bundle must be reissued. The chart refuses to render without it.

Set it to the address agents resolve from **outside** the cluster — not the in-cluster Service
name, unless your nodes genuinely run in this cluster.

## Exposing the gateway

The gateway terminates mutual TLS itself, and its clients are agents rather than browsers. Exposure
is an L4 concern:

```sh
--set gateway.service.type=LoadBalancer
```

An ingress works only in **TLS passthrough** mode. A proxy that terminates TLS strips the client
certificate that *is* the node's identity, so the gateway would authenticate the proxy instead of
the node. The chart stamps the ingress-nginx passthrough annotation and refuses to render a
terminating ingress unless you explicitly acknowledge that your controller forwards the client
certificate some other way:

```sh
--set gateway.ingress.enabled=true \
--set gateway.ingress.className=nginx \
--set gateway.ingress.host=updates.example.com
```

Remember that ingress-nginx requires `--enable-ssl-passthrough` on the controller itself.

## TLS material

The gateway mounts three logical material sets (the first two use the same Secret by default):

- **`gateway-tls`** — its own server certificate and key.
- **client trust** — `gateway.clientCaSecretKey` from `gateway.clientCaSecretName`; when the name is
  empty, this defaults to `ca.crt` from `gateway-tls`. A separate operator-owned Secret is the
  rollover path because cert-manager must not rewrite an old+new overlap bundle.
- **`fleet-ca`** — the fleet CA *including its private key*, so `/enroll` can sign a node's CSR
  into a client certificate the mTLS listener accepts. This widens the gateway's blast radius;
  scope that CA to the fleet and nothing else.

`--set certManager.enabled=true` has the chart create both from a self-signed fleet root, which is
the right shape for a fleet whose only relying parties are its own agents and gateway. Add every
name agents will address the gateway by:

```sh
--set certManager.enabled=true \
--set 'certManager.gatewayCertificate.dnsNames={updates.example.com}'
```

To root the fleet CA in an existing chain instead, point the chart at your own issuer:

```sh
--set certManager.enabled=true \
--set certManager.bootstrapIssuer.create=false \
--set certManager.bootstrapIssuer.name=corporate-ca \
--set certManager.bootstrapIssuer.kind=ClusterIssuer
```

Or supply the server-identity and issuing-CA Secrets yourself from an existing PKI and leave
`certManager.enabled` off. Supply a separate client-trust Secret as well when `gateway-tls` does not
contain its `ca.crt`; the gateway pod stays in `ContainerCreating` until every configured key exists.

### Fleet CA rollover

The gateway reloads its server identity, client trust bundle, and issuing CA every minute. It swaps
them only as one coherent generation after proving that a leaf from the candidate issuer is accepted
by the candidate verifier. A partially projected Secret update therefore leaves the previous working
generation live. `ca.crt` may contain multiple PEM certificates, which provides the rollover overlap.

A fleet-root key change is necessarily staged because each agent also pins that CA file locally:

1. Create an operator-owned Secret containing the old+new PEM bundle (for example, key `ca.crt` in
   Secret `fleet-client-trust`), set `gateway.clientCaSecretName: fleet-client-trust`, and append the
   new root to every agent's configured `ca` file. Retain the old root in both places.
2. Wait for that configuration to reach the fleet and for every gateway replica to reload it.
3. Replace `fleet-ca` with the new certificate and key, then issue the gateway certificate from the
   new CA. During this phase the old+new bundle accepts both existing 90-day leaves and new leaves.
4. After every old node leaf, shared bootstrap certificate, and gateway certificate has expired or
   been renewed, remove the old root from agents and the operator-owned client-trust Secret.

Changing the issuer before step 1 is rejected by the gateway's coherence check, but no in-band
protocol can repair an agent whose local trust anchor was removed too early. The chart-created CA
therefore renews with `privateKey.rotationPolicy: Never`; a root-key replacement is an explicit
operator rollover using the sequence above.

## TUF signing keys

The controller signs every generation and never stores a private key in CRD status. Generate a
repository's keys and load them as the Secret named by `UpdateRepository.spec.signingSecretRef`:

The `updatec` image carries the `server` binary for exactly this, so the first install step does
not demand a Rust toolchain:

```sh
updatec_digest="$(awk '$1 == "updatec" { print $2 }' "$release_dir/IMAGE_DIGESTS")"
updatec_digest_hex="${updatec_digest#sha256:}"
test "$updatec_digest" = "sha256:$updatec_digest_hex" && test "${#updatec_digest_hex}" -eq 64
case "$updatec_digest_hex" in *[!0-9a-f]*) echo "invalid verified updatec digest" >&2; exit 1;; esac
mkdir keys && docker run --rm -u "$(id -u)" -v "$PWD/keys:/keys" \
  --entrypoint /usr/local/bin/server "ghcr.io/evan-hines-js/updatec@$updatec_digest" \
  init --repo /keys/seed-repo --keys /keys

kubectl -n updated-system create secret generic tuf-signing-keys \
  --from-file=keys/root.pk8 --from-file=keys/root.next.pk8 \
  --from-file=keys/targets.pk8 \
  --from-file=keys/snapshot.pk8 --from-file=keys/timestamp.pk8
```

Distribute the *pinned root* (`seed-repo/metadata/root.json`) to nodes out of band, as part of the
enrollment bundle. It is the trust anchor: a node that fetches its root over the same channel it
fetches targets is not verifying anything.

## Object store credentials

Only when `UpdateRepository.spec.s3.credentialsSecretRef` is set; omit it to use workload identity.
The Secret carries the standard AWS entries:

```sh
kubectl -n updated-system create secret generic s3-credentials \
  --from-literal=AWS_ACCESS_KEY_ID=... --from-literal=AWS_SECRET_ACCESS_KEY=...
```

## Durable rollout-state capacity

The serialized rollout baseline is bounded by `UpdateRepository.spec.stateMaxShards` (default 8,
range 1–64). Each shard is capped at 768 KiB. The index selects one complete digest-verified slot;
the controller writes a second slot during a commit, atomically switches the index, then deletes the
old slot. Thus steady serialized state is bounded by `stateMaxShards × 768 KiB`, with at most the
old plus new configured bounds during a live rebalance.

Change the CRD field at any time. Even when rollout content is unchanged, the next reconcile
rebalances the complete document to the new width. A decrease that cannot hold the current state
fails before mutating the active projection with `StateCapacityExceeded`; raise the field and retry.
This setting is deliberately not a Helm value or environment variable because capacity belongs to
the repository whose state it bounds.

```yaml
spec:
  stateMaxShards: 8
```

## Optional: Draupnir release admission

Admission behavior is Kubernetes configuration, not a Helm value or process flag. Create the
request-auth Secret and one namespaced policy, then reference it from the repository.

The two directions authenticate differently. The **request** carries an HMAC proving which caller
is asking; the **response** is signed by Draupnir with its own key and verified against a pin, so
this control plane cannot mint a verdict of its own:

```sh
kubectl -n updated-system create secret generic draupnir-webhook \
  --from-literal=key='<at-least-32-bytes-of-random-key-material>'   # request auth only
```

```yaml
apiVersion: updated.dev/v1alpha1
kind: UpdateAdmissionPolicy
metadata:
  name: draupnir
  namespace: updated-system
spec:
  webhook:
    url: http://draupnir.updated-system.svc/admission
    secretRef:
      name: draupnir-webhook
    # Draupnir's admission public key: hex of an uncompressed P-256 point (65 bytes, 04-prefixed),
    # the same encoding UpdateAgent.spec.identity.publicKey uses. Every decision is verified
    # against it, so a decision this key did not sign is never acted on. Required; a malformed pin
    # holds movement rather than falling back to something weaker.
    decisionPublicKey: "04a1b2...<130 hex chars>"
  actions:
    nonCompliant: Block
    noInformation: Allow
---
apiVersion: updated.dev/v1alpha1
kind: UpdateRepository
metadata:
  name: default
  namespace: updated-system
spec:
  admissionPolicyRef:
    name: draupnir
  # ...the repository's ordinary fields...
```

Both actions are required and independent. Endpoint failure, `pending`, and malformed or incomplete
responses always hold movement; they are not `noInformation`. The exact protocol, cache semantics,
and failure behavior are in [draupnir-admission.md](draupnir-admission.md).

## Secrets from a secret store (External Secrets Operator, and friends)

The chart **references** Secrets by name and creates none of them. That is deliberate, and it is
the seam that lets any provisioning mechanism work: External Secrets Operator, sealed-secrets,
SOPS, Vault Agent injection, or plain `kubectl create secret`. The chart templates no
`ExternalSecret` objects, because doing so would couple it to one operator's CRDs and to
per-organization store references, refresh intervals, and property paths — in exchange for saving
one manifest.

With ESO, materialize each Secret under the name the chart or the CRs already reference:

```yaml
apiVersion: external-secrets.io/v1
kind: ExternalSecret
metadata: {name: draupnir-webhook, namespace: updated-system}
spec:
  secretStoreRef: {name: vault, kind: ClusterSecretStore}
  target:
    name: draupnir-webhook          # the name UpdateAdmissionPolicy.spec.webhook.secretRef points at
  data:
    - secretKey: key                # the entry the control plane reads
      remoteRef: {key: updatedc/admission, property: hmac}
```

The same pattern covers `tuf-signing-keys` (entries `root.pk8`, `root.next.pk8`, `targets.pk8`,
`snapshot.pk8`, `timestamp.pk8`) and `s3-credentials` (`AWS_ACCESS_KEY_ID`,
`AWS_SECRET_ACCESS_KEY`).

**What must not go through a secret store:**

- **`decisionPublicKey`** and **`UpdateAgent.spec.identity.publicKey`** are *public* keys. They are
  pins, not secrets. Putting a trust anchor behind a store that can rotate it out of band is the
  opposite of pinning it — and it hides from review the one value whose change matters most. They
  belong in the CR, in Git, where a change shows up in a diff.
- **The pinned TUF root** distributed to nodes, for the same reason.
- **`gateway-tls` and `fleet-ca`** when `certManager.enabled` is set — cert-manager already owns
  those Secrets, and two systems owning one Secret is a rotation race.

If you pinned the gateway's Secret read with `gateway.secretResourceNames`, note that it names
Secrets, not their source: ESO-materialized Secrets satisfy it unchanged.

## Optional: metrics and alerting

Both are off by default.

```sh
--set controller.metrics.enabled=true \
--set controller.metrics.service.enabled=true \
--set controller.alerting.url=https://alerts.example/hook \
--set controller.alerting.tokenSecret=alert-token
```

The alert token is mounted as a file and re-read per delivery, so rotating the Secret rotates the
token without restarting the controller. A token-bearing alert URL must use HTTPS; plain HTTP is
accepted only for an unauthenticated in-cluster receiver. The metric series are described in
[observability-design.md](observability-design.md).

## Pinning the image

The short version above passes no image flag because the verified release chart already embeds the
registry digests produced by its image job for `updatec` and `updated-healthproxy`. `appVersion`
still records the source commit for operator visibility, but it is not used as runtime authority.
A registry tag — even one spelled as a commit — is mutable; only the digest binds the bytes.

Rendering the chart out of a **checkout** is the exception. Source cannot know which registry a
future build will be pushed to, so a source-tree install must provide both image digests:

```sh
--set image.requireDigest=true --set image.digest=sha256:<64 hex> \
--set healthproxy.image.requireDigest=true --set healthproxy.image.digest=sha256:<64 hex>
```

A tag remains available for local development, but it is explicitly the weaker mode:

```sh
--set image.tag=<locally-controlled-tag>
```

`digest` and `tag` are mutually exclusive — a digest already names an exact image, and silently
preferring one over the other is how a release ends up running something other than what it says.
The chart never resolves a tag into a digest for you. Doing so would require reaching a registry
while rendering, which breaks air-gapped `helm template` and makes the output depend on *when* it
was rendered. Resolve it yourself and pass the result:

```sh
digest="$(crane digest ghcr.io/evan-hines-js/updatec:<commit-sha>)"
```

## Upgrading

```sh
# Repeat the immutable release resolution, download, attestation, and checksum steps from the short
# version into a fresh $release_dir. CRDs are not upgraded by Helm, so apply them explicitly first.
kubectl apply -f "$release_dir/updated.dev_crds.yaml"
helm upgrade updatec "$release_dir/updatec-chart.tgz" ...
```

Upgrading means verifying and installing a newer immutable release. The two image digests move with
its chart. Remove any old `--set image.tag=...` overrides when adopting release-embedded digests; an
explicit value you set remains an override Helm will keep honouring.

The controller's PVC carries `helm.sh/resource-policy: keep`: it holds TUF version monotonicity
state, and a repository that restarts its version counter is one clients reject.

Note that the in-cluster control plane upgrades by image, through Helm — unlike an agent, which
updates itself through the fleet's own signed TUF channel. Both are the same mechanism applied to
different units: a container image here, a signed tarball there. If you run the control plane on a
host rather than in Kubernetes, publish it into a channel and it self-updates like anything else.

## The load balancer

`updated-healthproxy` programs a load balancer's backend set from the fleet's own signed health, so
a drained node leaves rotation with no data-path hop of ours. Declare each projection as an
`UpdateBackend`; the updatec operator derives its inventory from `UpdateAgent` labels, creates one
isolated healthproxy workload, and grants that workload access to exactly the two EndpointSlices it
owns. Adding or removing an agent from the selector updates membership automatically.

Selected agents must carry the address the load balancer can reach:

```yaml
spec:
  labels: {role: edge}
  # Host only. The UpdateBackend target below is the one owner of the service port.
  backendAddress: 10.20.0.14
```

Then declare the selectorless Service projection:

```yaml
apiVersion: updated.dev/v1alpha1
kind: UpdateBackend
metadata:
  name: edge
  namespace: updated-system
spec:
  repositoryRef: {name: default}
  selector: {matchLabels: {role: edge}}
  healthBase: https://cdn.example/updated
  target:
    kind: endpointSlice
    service: edge
    port: 8080
    portName: http
```

For HAProxy, use the same selector with `target.kind: haProxy`, `target.endpoints` containing its
Runtime API sockets, and `target.backend` naming the predeclared backend. Deleting an
`UpdateBackend`, changing target kind/service, or selecting zero agents
drains the old workload before the operator removes its generated access. Ordinary membership
changes rewrite a revisioned projected inventory without restarting the workload; healthproxy
adopts it only after all eight protocol-defined shards report the same complete revision. That
fixed projection is sized for the repository's 10,000-agent admission ceiling, including maximum
length identities and addresses; there is no second operator or reader-side shard-count path.

## Verifying

```sh
kubectl -n updated-system rollout status deployment/updatec-controller
kubectl -n updated-system rollout status deployment/updatec-gateway
kubectl -n updated-system get upr,updategroups,updategroupsets,updatebackends
```

The last command shows the projected status: the repository's `Ready` condition and agent count,
each group's progress, and each set's rolling/held/halted lists.

Note that the gateway does not open its health listener until its `UpdateRepository` exists, so a
gateway that is not yet ready on a fresh install is usually waiting for that resource rather than
failing.

## Installing from a checkout

The chart lives at `deploy/charts/updatec`, and its CRDs at
`deploy/charts/updatec/crds/updated.dev_crds.yaml`. They are generated from the Rust types
(`cargo run -q -p updatec --example crdgen`) and CI fails the build if the checked-in copy has
drifted, so the shipped file is always current.
