# Proxmox chaos lab

This is the one deployed chaos environment for updatec. It uses real Linux
VMs and real virtual disks on Proxmox so network and filesystem failures cover
behavior that the portable E2E suite and KIND-on-Docker cannot reproduce.

`lab/chaos/deploy.sh` is the only entrypoint. It performs one idempotent path:

1. verify every local and remote immutable artifact;
2. plan and apply the four-VM Terraform topology;
3. derive a host-key-pinned Ansible inventory through Proxmox/QEMU guest agent;
4. install the checksum-pinned k3s binary with Ansible;
5. install the checksum-pinned Chaos Mesh chart;
6. prove real pod-to-pod network partition and persistent-volume I/O failure,
   including recovery after each fault;
7. build and side-load the current source, then start the permanent release campaign;
8. expose the campaign, updatec, Kubernetes, disk, and network history in Grafana.

The topology deliberately separates failure targets:

| VM | Default address | Purpose |
| --- | --- | --- |
| `updatedc-chaos-control` | `10.0.0.250` | k3s API and the Chaos Mesh controller |
| `updatedc-chaos-storage` | `10.0.0.251` | storage-backed target workloads |
| `updatedc-chaos-agent-a` | `10.0.0.252` | first update-agent failure domain |
| `updatedc-chaos-agent-b` | `10.0.0.253` | second update-agent failure domain |

These are separate kernel and disk failure domains, not separate physical
hypervisors. Hypervisor-loss testing therefore remains out of scope.

## Configure

Copy `deploy.env.example` to the ignored `deploy.env` and fill the artifact
paths and Proxmox API token. The API token is passed as the sensitive Terraform
variable `TF_VAR_proxmox_api_token`; it is never written into a tracked file.
The SSH public key installed in guests is derived from the configured private
key, so there is no second key declaration to drift.

The default site binding targets `poweredge-md` at `10.0.0.206`, VM IDs
300–303, and the addresses above. Override those values with ordinary
`TF_VAR_*` variables only when deliberately moving the entire lab.

The cached Ubuntu image is an input, not a Terraform-owned shared resource.
Deployment verifies its bytes over the pinned Proxmox SSH channel before any
plan is applied.

## Deploy

```sh
lab/chaos/deploy.sh
```

To inspect the exact Terraform plan without applying it:

```sh
lab/chaos/deploy.sh --plan
```

On success, the generated kubeconfig is
`lab/chaos/infrastructure/.state/kubeconfig.yaml`. Chaos Mesh admits injection
only into namespaces explicitly annotated with
`chaos-mesh.org/inject=enabled`; its dashboard is not installed.

Do not run fault experiments in `chaos-mesh`, `kube-system`, or against the
Proxmox host. Fault targets belong in a disposable, explicitly annotated
namespace and must carry `updated.dev/chaos-target=true`.

## Permanent campaign

The `updatec-soak` deployment is the only campaign driver. Every seeded round
selects one or more cohorts, assigns signed release bytes, injects exactly one
bounded Chaos Mesh fault, checks the exact expected fleet state, removes the
fault, and records the result. The fault cycle covers cross-node network
partition, persistent-volume EIO, agent pod loss, and controller pod loss.
Every tenth round deliberately publishes an unlaunchable release and requires
the rollout to reject it, preserve its predecessor, and converge after a
corrected release.

Campaign state and its append-only JSONL journal live on the
`updatec-soak-state` PVC. A restart first removes any abandoned fault and
reconciles the fleet to the last proven desired state; there is no separate
recovery script. The release repository, controller state, MinIO object store,
and each node identity also use persistent volumes.

Grafana is available from the local network at
`http://10.0.0.250:30300`. Its generated admin password remains in the ignored
`lab/chaos/infrastructure/.state/grafana-admin-password` file. The
`updatec 24/7 Campaign` dashboard reports campaign reliability, fleet
convergence, injected faults, recovery count, and convergence latency; the
`updatec Chaos Reliability` dashboard retains the underlying node and control
plane signals.
