# Running the `updated` operator demo

This is a **live, end-to-end** demo. It builds a local Kubernetes cluster in Docker (kind),
runs the real control plane and a fleet of managed nodes, and drives real signed rollouts,
rollbacks, throttling, chaos, and a real Magnolia CMS install — plus, optionally, a genuine
**out-of-cluster VM** installed with Ansible that becomes the manual Magnolia node.

Everything runs on your workstation except that optional VM. The first run builds images and
seeds the cluster, so it takes several minutes.

---

## 1. What your workstation needs

### Required tools

| Tool | Minimum | Recommended | Why |
|------|---------|-------------|-----|
| **Docker** | 24 | latest | Builds the images and hosts the kind cluster. Docker Desktop (macOS) or Docker Engine (Linux). |
| **kind** | 0.20.0 | latest | Creates the single-node Kubernetes cluster. Uses kind's default node image (Kubernetes ≈ 1.29–1.31). |
| **kubectl** | 1.28 | within ±1 minor of the cluster | All cluster operations. |
| **Rust (cargo/rustc)** | 1.82 stable | latest stable | Builds and runs the demo orchestrator (`updatec-demo`) and helper crates. Edition 2021. CI uses the `stable` channel. |
| **CMake** | 3.20 | latest | The host build compiles `aws-lc-rs` (the one crypto lib), which builds C via CMake. |
| **C/C++ compiler** | — | Xcode CLT (macOS) / gcc or clang (Linux) | Same — `aws-lc-rs`. |
| **NASM** | 2.15 | latest | **x86-64 only** (`aws-lc-rs` assembly). Not needed on Apple Silicon / arm64. |
| **curl** | any | — | Health checks during setup. |
| **git**, **bash** | any | — | Clone + run the scripts. |

### Docker resources

The cluster runs ~40 pods at rest (34 agents + 4 Magnolia + control plane + minio + ingress),
and Magnolia is a real Java/Tomcat install. Give Docker room:

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPUs | 4 | 6+ |
| Memory | 10 GB | 12–16 GB |
| Disk | 40 GB | 60 GB (images, build cache, kind volumes) |

On Docker Desktop set these in **Settings → Resources**.

### Network

Internet access is required on the first run to pull crates and these pinned images:

- `minio/minio:RELEASE.2025-04-22T22-12-26Z`, `minio/mc:RELEASE.2025-04-16T18-13-26Z`
- `registry.k8s.io/ingress-nginx/controller-v1.11.2` (kind provider manifest)
- `kindest/node` (kind default), `rust:1-bookworm`, `ubuntu:22.04`

### Platform / architecture

- **macOS** (Apple Silicon or Intel) and **Linux** both run the core demo. The only
  macOS-specific bit is the optional VM path, which auto-detects your LAN IP with
  `ipconfig getifaddr en0`; on Linux, set `DEMO_HOST_IP` yourself.
- **Magnolia requires `linux-x86_64`.** The real Magnolia CMS nodes (author/publisher) and the
  manual "Upgrade Magnolia" VM are only available when the cluster's platform is x86_64 — the
  install provider fetches an x86_64 JRE. On **Apple Silicon (arm64)** the demo detects that
  Magnolia isn't published and **runs everything except Magnolia**. To see Magnolia and the
  manual VM upgrade, **run the whole demo on an x86_64 Linux box** (an x86_64 Docker host).

### Verify your versions

```sh
docker --version          # >= 24
kind --version            # >= 0.20
kubectl version --client  # >= 1.28
cargo --version           # >= 1.82 (stable)
cmake --version           # >= 3.20
nasm --version            # x86-64 only
```

macOS install (Homebrew):

```sh
brew install --cask docker
brew install kind kubectl cmake nasm
# Rust: https://rustup.rs  → rustup toolchain install stable
xcode-select --install    # C compiler
```

---

## 2. Run it

From the repository root, with Docker running:

```sh
./scripts/demo.sh start
```

The first run builds the kind environment (a few minutes). When it's ready it opens
**http://127.0.0.1:8088** (open it manually if your browser doesn't). Keep the terminal open —
the demo drives the cluster while it runs.

Other commands:

```sh
./scripts/demo.sh e2e --exit   # the automated CI path: build, exercise, assert, exit
./scripts/demo.sh reset        # delete the demo cluster
```

Environment:

| Variable | Default | Meaning |
|----------|---------|---------|
| `UPDATEC_DEMO_PORT` | `8088` | Local UI port. |
| `UPDATEC_DEMO_CLUSTER` | `updatec-demo` | kind cluster name. |

### Run it on a remote server (recommended for the full demo)

You don't have to run the kind cluster on your laptop. If you set `DEMO_REMOTE_HOST` to a
configured, reachable server, the launcher syncs the repo there, runs the **whole** demo on
that server (kind, image builds, Magnolia, the on-network VM), and **tunnels the UI back** to
`http://127.0.0.1:$PORT` on your laptop:

```sh
export DEMO_REMOTE_HOST=root@build-box   # x86_64 Linux, passwordless SSH
./scripts/demo.sh start                  # runs remotely, UI tunneled to your browser
```

This is the natural way to get the **full** demo: Magnolia needs x86_64, and the VMs share the
server's network. The laptop just drives it. If `DEMO_REMOTE_HOST` is unset or unreachable, the
demo runs locally as above.

**The server needs** everything in Section 1 (Docker, kind, kubectl, Rust + build deps), the
SSH user able to run Docker (root or the `docker` group), and `rsync`. It should be
**x86_64** for Magnolia. Override the sync directory with `DEMO_REMOTE_DIR` (default
`updated-demo` in the SSH user's home).

---

## 3. Optional: the real out-of-cluster VM (manual Magnolia node)

The "Upgrade Magnolia" button in the UI rolls the **manual** Magnolia node. That node is a
**real VM outside Kubernetes** — installed by the shipped Ansible role (`deploy/ansible`),
enrolled with the same control plane, and fronted by the `updated-healthproxy` reconciler.
Click the button and *our agent on the VM* performs the real custom in-place upgrade v1 → v2.

This part is **entirely optional and guarded**: if it isn't configured, or the VM isn't
reachable over passwordless SSH, the demo skips it and continues.

### Extra workstation tools (only for the VM path)

| Tool | Minimum | Why |
|------|---------|-----|
| **Ansible** (`ansible-core`) | 2.14 | Installs the agent on the VM. |
| **`ansible.posix` collection** | 1.5 | The role uses the `synchronize` (rsync) module — `ansible-galaxy collection install ansible.posix`. |
| **OpenSSH client** (`ssh`, `scp`) | any | Passwordless (key-based) access to the VM. |

### The VM itself

- A reachable Linux VM: **Ubuntu 20.04 or 22.04** (apt-based), with **root** SSH.
- **Passwordless SSH** from your workstation (`ssh root@<vm> true` must succeed with no prompt).
- On the **same LAN** as your workstation: the VM must reach the workstation on **TCP 18080**
  (the demo exposes the in-cluster gateway there with `kubectl port-forward --address 0.0.0.0`).
- The VM builds the agent from source, so it needs outbound internet (rustup, crates, apt).
  First provision takes a few minutes.

### Enable it

```sh
DEMO_EXTERNAL_VM=root@10.0.0.206 ./scripts/demo.sh start
```

| Variable | Default | Meaning |
|----------|---------|---------|
| `DEMO_EXTERNAL_VM` | *(unset → skipped)* | SSH target of the VM, e.g. `root@10.0.0.206`. |
| `DEMO_EXTERNAL_VM_KEY` | `~/.ssh/id_ed25519` | SSH private key to use. |
| `DEMO_HOST_IP` | `ipconfig getifaddr en0` (macOS) | Your workstation's LAN IP the VM dials back to. **Required on Linux.** |

You can also run the Ansible role directly against any fleet, independent of the demo — see
[`deploy/ansible/README.md`](deploy/ansible/README.md).

---

## 4. Troubleshooting

- **"Another demo runner is already active":** a previous run left its lock. Re-run with
  `--force` (`./scripts/demo.sh start --force`, or `DEMO_FORCE=1`) to clear it — it propagates
  to the remote server too.
- **Rebuild from scratch:** `./scripts/demo.sh reset`, then `start` again.
- **Not enough pods / OOM / pods stuck `Pending`:** raise Docker's CPU/memory (Section 1).
- **`aws-lc-rs` build fails on x86-64:** install NASM (`brew install nasm` / `apt-get install nasm`).
- **The VM never appears as `magnolia · manual`:** check `ssh root@<vm> true` works without a
  prompt, that the VM can reach `http://<DEMO_HOST_IP>:18080`, and that `ansible-playbook` and
  the `ansible.posix` collection are installed. The demo logs the reason and continues without it.
