# `updatedc` with Ansible

Two playbooks live here:

- **`demo.yml`** — the whole operator demo on **one server** (below).
- **`install-agent.yml`** — install the agent on a **fleet of VMs** (production; further down).

---

## The demo on one server — `demo.yml`

The entire demo UX is a single playbook, run **on the server** (an x86_64 Linux box, for
Magnolia):

```sh
git clone <this repo> updatedc && cd updatedc
ansible-playbook deploy/ansible/demo.yml
# …then browse to http://<this-server>/
```

It brings up **everything** on that one host:

1. **deps** — Docker, kind, kubectl, the Rust toolchain (`demo_deps`).
2. **the kind demo** — operator + CDN + fleet + Magnolia, and the ingress controller published
   on the host's ports 80/443 (`demo_cluster`).
3. **nginx routing** — the browser reaches the UI at `http://<server>/`, and the co-located
   agent reaches the control plane at `http://updatec-gateway` — both through the same nginx
   (`demo_ingress`).
4. **a co-located out-of-cluster agent** — a real agent on this same host, outside kind, that
   enrolls with the in-cluster control plane and becomes the **manual Magnolia node**. It
   resolves `updatec-gateway`/`release-default` to `127.0.0.1` (nginx) — no socat, no LAN-IP
   (`demo_colocated_agent`).
5. **the demo layer** — fleet scale, groups/sets, per-set services + ingress, the reconciler,
   and labeling the co-located agent into the manual group (`demo_app`, via `updatec-demo setup`).

Click **Upgrade Magnolia** in the UI and the operator publishes v2 to the CDN; the co-located
agent on this same host rolls the real in-place Magnolia upgrade.

---

## Installing the agent on a fleet of VMs — `install-agent.yml`

This is the VM-fleet counterpart to the Kubernetes operator. The **same** agent (bootstrap +
supervisor) that runs in a pod runs on a VM; ansible builds it from source on the target and
runs it as a systemd service that enrolls with your control plane. From then on the node is
managed exactly like any other — the control plane signs its assignments, it pulls and
verifies releases, and it reports health back.

### Usage

Inventory (`inventory.ini`):

```ini
[updated_agents]
10.0.0.206 ansible_user=root
```

Run:

```sh
ansible-playbook -i inventory.ini install-agent.yml \
  -e updatedc_source=/path/to/updatedc \
  -e updated_enrollment_url=https://gateway.example.com \
  -e updated_enrollment_client_cert="$(base64 -w0 client.crt)" \
  -e updated_enrollment_client_key="$(base64 -w0 client.key)" \
  -e updated_enrollment_ca="$(base64 -w0 ca.crt)" \
  -e updated_hostname=vm-magnolia-1
```

| Var | Required | Meaning |
|-----|----------|---------|
| `updatedc_source` | yes | Path to the `updatedc` workspace on the control node; rsync'd to the target and built there (native binaries, no cross-compile). The former `updated_source` name remains a compatibility alias. |
| `updated_enrollment_url` | — | Control-plane enrollment endpoint, HTTPS (default `https://updatec-gateway`). |
| `updated_enrollment_client_cert` / `_client_key` / `_ca` | yes | base64 PEM of the fleet client certificate, its key, and the fleet CA — the mTLS identity (cert-manager issues these; there is no shared secret). |
| `updated_hostname` | — | Stable identity the control plane addresses the node by (default: inventory name). Written verbatim as `name` in `/etc/updated/bootstrap.toml`; the gateway mints it as the node's certificate CN and creates the `UpdateAgent` object under exactly this string. |
| `updated_demo_shim_host` / `updated_demo_shim_port` | — | **Demo only.** When set, the role points the in-cluster gateway names at a local `socat` forward to `host:port` — used by `updatec-demo` to reach the kind gateway exposed on the laptop's LAN. Omit in production. |

## What it installs

- `/usr/local/bin/{bootstrap,supervisor}` — built from source on the target.
- `/etc/updated/bootstrap.toml` — the enrollment bootstrap: `url`, `name`, `client_cert`,
  `client_key`, `ca`. No secret; the certificate material is written alongside it under
  `/etc/updated/agent-tls/`.
- `updated-agent.service` — the guardian, restarted on failure; its readiness/liveness probe
  is served on `:9090` (`/readyz`, `/livez`, `/startupz`), the same surface Kubernetes probes.
- `updated-gateway-shim.service` — demo only (the socat forward).
