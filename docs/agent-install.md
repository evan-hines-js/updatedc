# Installing agents on nodes

An `updated` node is installed and upgraded through the platform's normal software lifecycle:

```
installer / .deb / .rpm / Ansible  ──>  agent runtime + service definition
signed TUF channel                 ──>  workload releases and desired configuration
```

The service manager runs `updated-agent` directly and restarts it after any exit. Upgrade the agent
with the package manager, an image rollout, or the same configuration-management system that owns
other host software. The agent does not publish, stage, or replace its own executable.

## Choosing a method

| Method | Use when |
| --- | --- |
| `.deb` / `.rpm` | Debian/Ubuntu or RHEL-family hosts. The package owns root-only directory modes, the privileged unit, and config-merge-on-upgrade. |
| `install.sh` | One-off hosts, macOS, or anything without dpkg/rpm. On deb/rpm systems it installs the package anyway. |
| Ansible | Fleets. Wraps the package and adds per-host identity and config. |
| DaemonSet | Not provided — see [Kubernetes nodes](#kubernetes-nodes). |

Every method installs the same agent binary from the same attested release, and registers the same
service definition (`deploy/systemd/updated-agent.service`). There is one unit, not four. An
attestation is a security property only when it is verified: network installs require an immutable
`build-<commit>` tag and bind provenance to that commit and this repository's CI workflow.

## Packages

### FIPS builds

FIPS is selected when building the agent, not by preparing or changing a laptop's operating system:

```sh
cargo build --release -p agent --features fips
target/release/updated-agent stage-runtime dist/agent
```

Distribute every file in the staged directory together. On macOS and Windows, this includes the
exact shared AWS-LC FIPS module linked by the build. No separately installed FIPS program, SDK,
package manager, or library search environment is required on the destination. The standard release
packaging includes these companions, and the macOS installer places them before launching the
agent. Linux's normal FIPS build links the module statically.

The agent also embeds its companion module bytes so pinning a helper preserves the same runtime
through an agent upgrade. Customer commands still receive the normal scrubbed environment. Building
with FIPS support does not change the whole machine into a FIPS mode; applicable validation depends
on the cryptographic module and its operating environment.

### Installing a package

```sh
repo=evan-hines-js/updatedc
tag="$(gh release view --repo "$repo" --json tagName --jq .tagName)"
[[ "$tag" =~ ^build-[0-9a-f]{40}$ ]] || exit 1
mkdir updated-bootstrap
gh release download "$tag" --repo "$repo" --dir updated-bootstrap \
  --pattern updated-agent_amd64.deb --pattern SHA256SUMS
for asset in updated-agent_amd64.deb SHA256SUMS; do
  gh attestation verify "updated-bootstrap/$asset" --repo "$repo" \
    --signer-workflow "$repo/.github/workflows/ci.yml" \
    --source-ref refs/heads/main --source-digest "${tag#build-}" \
    --deny-self-hosted-runners
done
awk '$2 == "updated-agent_amd64.deb"' updated-bootstrap/SHA256SUMS \
  > updated-bootstrap/SHA256SUMS.wanted
(cd updated-bootstrap && sha256sum --check SHA256SUMS.wanted)
sudo apt install ./updated-bootstrap/updated-agent_amd64.deb
```

`.rpm` and `arm64` builds are published alongside. The package installs the service **stopped**: a
node cannot enroll before it has an identity, and a service that crash-loops on a config skeleton
teaches operators to ignore it. Finish the bootstrap:

1. Edit `/etc/updated/config.toml` — the gateway URL and this node's name.
2. Place `tls.crt`, `tls.key`, and `ca.crt` in `/etc/updated/agent-tls/` (mode 0600, owned by root).
3. `systemctl enable --now updated-agent`

Tune the service through `/etc/updated/agent.env`, never by forking the unit. `UPDATED_STATE_DIR`
selects the persistent state directory and `UPDATED_CONFIG` selects the canonical configuration
file used by the unit.

## install.sh

```sh
repo=evan-hines-js/updatedc
tag="$(gh release view --repo "$repo" --json tagName --jq .tagName)"
[[ "$tag" =~ ^build-[0-9a-f]{40}$ ]] || exit 1
gh release download "$tag" --repo "$repo" --pattern install.sh
gh attestation verify ./install.sh --repo "$repo" \
  --signer-workflow "$repo/.github/workflows/ci.yml" \
  --source-ref refs/heads/main --source-digest "${tag#build-}" \
  --deny-self-hosted-runners
sudo ./install.sh --tag "$tag" \
  --gateway-url https://updates.example.com \
  --node-name web-01 \
  --bootstrap-cert ./tls.crt --bootstrap-key ./tls.key --ca ./ca.crt
```

The script refuses mutable release tags. For every network install it verifies both the downloaded
artifact and `SHA256SUMS` against provenance signed by this repository's CI at the commit embedded
in the tag, then verifies their digest agreement. `--dry-run` prints the plan and changes nothing.

For air-gapped hosts, stage the release once and install from disk:

```sh
gh release download "$tag" --repo "$repo" --dir ./artifacts
for asset in ./artifacts/*; do
  gh attestation verify "$asset" --repo "$repo" \
    --signer-workflow "$repo/.github/workflows/ci.yml" \
    --source-ref refs/heads/main --source-digest "${tag#build-}" \
    --deny-self-hosted-runners
done
sudo ./artifacts/install.sh --local-dir ./artifacts \
  --gateway-url https://updates.example.com ...
```

Do that verification while connected, then transfer the directory unchanged over an authenticated
channel. The local installer does not contact GitHub; that verified staging step is the operator's
trust boundary.

## Ansible

```sh
tag="$(gh release view --repo evan-hines-js/updatedc --json tagName --jq .tagName)"
ansible-playbook -i inventory deploy/ansible/install-agent.yml \
  -e updated_release_tag="$tag" \
  -e updated_enrollment_url=https://updates.example.com
```

The role refuses mutable tags for network installs, verifies CI provenance for the artifact and
`SHA256SUMS`, verifies their digest agreement, installs the package, and writes each host's config
and identity. It compiles nothing on the target.

Required per host — pull them from your secret store rather than committing them:

```yaml
updated_enrollment_client_cert: "{{ lookup('community.hashi_vault.hashi_vault', ...) }}"
updated_enrollment_client_key:  "{{ ... }}"
updated_enrollment_ca:          "{{ ... }}"
```

Required for network installs: `updated_release_tag` (an immutable `build-<commit>` release).
Useful overrides: `updated_release_local_dir` (air-gapped artifacts staged and provenance-verified
on the control node, so no target needs a route to GitHub) with
`updated_verify_attestation=false`,
`updated_agent_started: false` (stage a fleet, cut it over separately). See
`deploy/ansible/roles/updated_agent/defaults/main.yml`.

## Enrollment identity

Mutual TLS against the fleet CA **is** the enrollment identity. There is no shared enrollment
secret. There are three explicit shapes.

### Shared bootstrap certificate (simple, weaker)

One certificate with the CN the gateway admits (`gateway.enrollmentClientCN`, default
`updated-agent`) is distributed to every host, and each node self-asserts its name in
`config.toml`. The gateway mints that name into the node's certificate and creates an `UpdateAgent`
under it when the repository explicitly selects open enrollment:

```yaml
spec:
  enrollment:
    mode: open
    labels: {}
```

The weakness is exactly what it looks like: **any host holding that certificate can enroll under
any name it asserts**, including one already in use by a node you care about. Use this for labs and
for fleets where every host is already equally trusted.

### Reserved inventory (explicit approval, still shared authority)

Set the repository policy to `reservedOnly`:

```yaml
spec:
  enrollment:
    mode: reservedOnly
    labels: {}
```

Pre-create the `UpdateAgent` with `identity.kind: reserved` before the node boots:

```yaml
apiVersion: updated.dev/v1alpha1
kind: UpdateAgent
metadata: {name: web-01, namespace: updated-system}
spec:
  repositoryRef: {name: default}
  identity: {kind: reserved}
  labels: {cohort: web}
```

`/enroll` then *completes that specific object in place* — stamping the node's minted identity and
pinned public key onto it under a resourceVersion-guarded replace — rather than creating a new one.
An absent name is rejected with `403 Forbidden`; the shipped admission policy independently denies
the gateway's Kubernetes CREATE request unless this same repository policy is `open`. Thus
`reservedOnly` limits enrollment to names and labels the operator already approved. It does
**not** make the shared bootstrap certificate a per-node credential: any holder can still claim
any unclaimed reserved name first. Use controlled distribution if that shared authority is
acceptable. Use manual provisioning below when the initial key-to-name binding itself must be
operator-pinned.

### Fully offline provisioning

`identity.kind: manual` is never completable over a bootstrap certificate — `/enroll` refuses it
outright. Generate the node's P-256 key first and derive the exact canonical inventory pin with the
operator CLI:

```sh
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out agent.key
updatectl node-public-key --key agent.key
```

Create the `UpdateAgent` with that output as `identity.publicKey`:

```yaml
identity:
  kind: manual
  publicKey: 04…
```

The operator then supplies both the signed enrollment bundle the controller publishes and a
fleet-CA-signed client leaf for that exact key, name, and repository SPIFFE identity. The node never
receives the fleet bootstrap private key. After bootstrap it uses the same key-bound repository,
input, output, report, and renewal paths as an online-enrolled node; only initial delivery differs.
`scripts/kind-updatec-e2e.sh` exercises the complete path end to end.

The bundle is not a Kubernetes Secret. Wait for
`UpdateAgent.status.enrollmentObjectKey`, read that repository-relative object from the private S3
prefix with operator credentials, and place its exact bytes at `enrollment.json` in agent state.
The key is content-addressed and bound to the current signed repository generation, node identity,
and assignment path. The per-node certificate and private key remain a separate offline-PKI input;
the bundle contains neither, and S3 never holds the private key.

## Kubernetes nodes

There is no DaemonSet, and that is deliberate rather than an omission. Workload processes belong to
each release's own reconciler hooks and their own service units; that model wants a host, not a
pod, and a DaemonSet would need host mounts and elevated privileges to fake one. A Kubernetes node
is a host — install the OS package on it like any other machine.

What *does* run in Kubernetes is the control plane
([kubernetes-install.md](kubernetes-install.md)) and operator-owned healthproxy workloads, which
program Services' EndpointSlices from the fleet's signed health so out-of-cluster machines can
back in-cluster Services.

## Windows

`updated-windows-x86_64.zip` carries `install-updated-agent.bat` beside the agent and SCM service
adapter, on the
same rule as the Linux unit and the macOS plist: the release ships the service definition, so
registering the service never needs a checkout of this repository.

Unpack the archive into `C:\Program Files\updated`, place the pinned signed enrollment bundle and
`config.toml` beside the binaries, then run `install-updated-agent.bat` from an elevated prompt. It
registers the SCM service and its restart policy as LocalSystem. Configuration management is
machine-wide, and signed packages are the authorization boundary for those privileges.

## Verifying a node

```sh
systemctl status updated-agent
journalctl -u updated-agent -f
kubectl -n updated-system get updateagent web-01 -o yaml
```

An enrolled node shows a pinned public key and an `Enrolled` state on its `UpdateAgent`. Enrollment
happens once — after `enrollment.json` exists in agent state it is never retried, so editing
`config.toml` afterwards does not re-enroll an established node.
