# Group join tokens + CSR enrollment (v0)

## Goal

Let an operator provision N nodes into a fleet with **only a group ID and a shared
join token** — no per-node certificates. Nodes mint their own mTLS identity by
generating a keypair locally and getting a CSR signed by the control plane. Group
creation (a CRD) is the authorization event that mints the token.

This *adds* a bootstrap mode; it does not remove the existing one. Two deploy
environments, two modes, selected by which fields the bootstrap carries:

- **Mount mode (Kubernetes / cert-manager, unchanged):** `client_cert` + `client_key`
  are mounted per pod. The agent presents them as mTLS to the existing `/enroll`.
  This is exactly today's path.
- **Join mode (immutable infra / Rancher userdata, new):** no cert is mounted; the
  bootstrap carries `group_id` + a shared `nonce`. The agent generates a keypair,
  gets a CSR signed via `/join`, and uses the minted cert thereafter.

**Precedence:** if `client_cert`/`client_key` are present, use mount mode. Otherwise,
if `group_id`/`nonce` are present, use join mode. `ca` is required in both (it pins
the server). Exactly one credential set must be present.

## Model

Two credentials, cleanly separated:

- **Group join credential** = `{ group_id, nonce }`. Shared across every node in a
  group, intentionally reused, rotatable. Its only job is to authorize *joining*.
  The `nonce` is a **secret** (bearer join token). It is minted by the controller
  when a group is created and stored in a Secret.
- **Node credential** = the per-node leaf cert minted at join. Unique, attributable,
  individually revocable. The node's private key is generated on the node and never
  leaves it; only the public key (in the CSR) is sent.

The old flow authenticated the *node* with mTLS at the gateway and used the nonce
only to name the agent. The new flow authenticates the *join* with the group token
over a server-TLS-only listener, then issues the cert that unlocks the existing
mTLS gateway for all steady-state traffic (TUF fetches, telemetry). Nothing about
the TUF data plane changes.

## Why node naming must change

Today: `agent-<sha256(nonce)[..24]>`. Under a shared group nonce every node in the
group hashes to the **same** agent name — a collision. So the node keeps a durable,
locally-generated, per-node random value (`instance`, exactly what the current
`registration-nonce` already is) that names it, and the *group* `nonce` becomes a
separate shared secret. The node sends both:

- `nonce` — shared group secret; authorizes the join (never stored server-side in
  clear beyond the Secret; compared, not logged).
- `instance` — per-node durable random; names the agent and makes join idempotent
  on retry (`agent-<sha256(instance)[..24]>`, `registration_sha256 = sha256(instance)`
  exactly as today).

This preserves the existing idempotent-create and deterministic-naming properties
while adding per-node uniqueness under a shared token.

## Flow

```
Admin: kubectl create UpdateGroup canary
  controller reconcile:
    - mint group_id  (bound to CR UID, stable)
    - mint nonce     (high-entropy secret)
    - write Secret  <group>-join { nonce }
    - status.groupId, status.joinSecretRef

Admin: read Secret, hand { join_url, group_id, nonce, ca } to N nodes (identical)

Node boot (no cert yet):
  - durable instance = rand token (persist, reuse on retry)
  - generate keypair locally
  - build CSR (subject/SAN irrelevant — CP ignores them)
  - POST /join { groupId, nonce, instance, csr }  over server-TLS (verify CA pin)

Control plane /join listener (server-TLS only, NO client cert required):
  - load UpdateGroup by group_id; load its <group>-join Secret
  - constant-time compare nonce  → 401 on mismatch
  - name = agent-<sha256(instance)[..24]>
  - sign leaf: take ONLY the CSR public key; CP sets subject/SAN =
      CN=<name>, URI SAN spiffe://fleet/group/<group_id>/node/<name>
      issuer = repository issuing CA (private key held by CP)
      short TTL
  - create/patch UpdateAgent { identity: Enrolled, registration_sha256,
      labels += { updated.dev/group: <group> } }   (idempotent, 409-tolerant)
  - assemble EnrollmentBundle (unchanged assembly)
  - respond { leafPem, caChainPem, bundle }

Node:
  - persist agent.key (0600) + agent.crt + ca to state dir
  - from now on: identity = { state/agent.crt, state/agent.key, bootstrap.ca }
  - proceed exactly as today: mTLS gateway, TUF, telemetry
```

The joined agent carries `updated.dev/group=<group>`; the group's selector matches
that label, so the existing `build_publication_plan` routing is unchanged.

## Immutable infra / Rancher churn

The design target is baked-once userdata. Rancher (and any autoscaler) churns nodes
constantly, so **the only thing installed is the node agent**, and its config is a
per-group template that is identical across every machine in the pool:

```
# cloud-init / Rancher userdata — same bytes for every node in the group
join_url = https://cp.fleet:8443
group_id = <UpdateGroup status.groupId>
nonce    = <shared group join token>
ca       = <pinned CP CA>
+ node-agent package
```

Nothing per-node is baked in. At first boot the agent self-mints everything unique:
durable `instance` (random, persisted), keypair, CSR → its own cert + `agent-<…>`
identity. Consequences that fall out of this:

- **Ephemeral disk ⇒ ephemeral identity, by design.** A fresh VM has no persisted
  `instance`, so it becomes a new `UpdateAgent`. A reboot of the same VM keeps its
  `instance`+cert and stays the same node (idempotent). Both are intended.
- **The nonce lives in userdata** — readable by anyone who can read the machine
  template / cloud metadata. Acceptable *only because* it is group-scoped and
  rotatable; never a fleet-wide root secret. Rotate = update the template + bump
  `rotateNonce`.
- **Churn ⇒ stale agents.** Dead VMs leave orphan `UpdateAgent` objects and certs
  valid until expiry. This needs (follow-up, promoted by churn):
  - a **reaper** — drop agents whose last telemetry is older than a threshold;
  - **short leaf TTL** so a dead node's cert cannot be replayed — which in turn
    makes **renew-over-mTLS** (`/renew`, no nonce) load-bearing rather than optional
    once TTL < node lifetime.

## Storage model — join mode needs persistence, mount mode does not

This is the load-bearing operational difference between the two modes:

| | credential origin | survives pod kill on `emptyDir`? | volume |
|---|---|---|---|
| **Mount** | external (cert-manager Secret, re-mounted) | **yes** — the cert comes back on remount | `emptyDir` fine |
| **Join** | self-minted on the node, stored nowhere else | **no** — the private key is gone | **PVC required** |

In mount mode the node's authentication identity lives in a Secret and is re-presented
on every start, so the pod is effectively stateless: kill it, it re-mounts the same
cert. In join mode the node **generates its own keypair at first boot**; that private
key exists only on the node's state volume. If that volume is ephemeral (`emptyDir`),
a restart loses the key, and the node must re-join — minting a **new** identity and
leaving an orphan `UpdateAgent`. To keep a join-mode pod's identity stable across
restarts it must persist `state/` (durable `instance`, `agent.key`, `agent.crt`,
`enrollment.json`, and the install state machine) on a **PVC**. The footprint is a
keypair, a cert, and a few JSON docs, so a **16 MiB PVC** is ample.

This also cleanly separates the two install paths the demo exercises:

- Join node whose **PVC survives** a restart → loads existing install state →
  **upgrade** (same identity, in-place).
- **Fresh** join node (new VM / wiped PVC) → **cold reinstall** from scratch.

For churned VMs (Rancher) the ephemeral-identity behavior is *intended* — a dead VM is
gone. For a Kubernetes pod that should keep its identity across restarts, the PVC is
what makes it so.

## Demo topology

The demo runs a mixed fleet to exercise both paths side by side:

- **Half the nodes are mount-mode** (cert-manager Secret, `emptyDir`) — today's path.
- **Half are join-mode** (group token, 16 MiB PVC) — the new path.
- The managed **app is installed on both halves**, so the demo can show a join node
  **upgrading** in place across a restart (PVC intact) versus a fresh node doing a
  **cold reinstall** — and that both halves converge to the same version through the
  normal group rollout.

## Blast radius / lifecycle

- **Nonce is group-scoped.** A leak lets someone join *that* group, not mint an
  arbitrary identity. Group authz is coarse (what the group may update) anyway.
- **Revoke the whole group** = delete the UpdateGroup → Secret gone → nonce dead →
  no new joins. Already-joined nodes are unaffected (they hold node certs).
- **Rotate** = controller regenerates the Secret on a `rotateNonce` spec bump; old
  token stops working, joined nodes unaffected.
- **Per-node revoke** = delete the UpdateAgent / short leaf TTL. Independent of the
  group lifecycle.
- **v0 scope:** long-ish leaf TTL, **no renewal endpoint yet** (documented follow-up:
  `/renew` over mTLS with the current cert, no nonce). Open-join within a valid
  nonce; no max-node cap. Enrollments are logged.

## Listeners

`updatec serve` gains a **third listener**:

| listener | port (default) | TLS | client auth | serves |
|---|---|---|---|---|
| gateway (existing) | 8080 | server | **required** (fleet CA) | TUF metadata/targets, telemetry |
| health (existing) | 8081 | none | none | `/healthz` |
| **join (new)** | 8443 | server | **none** | `POST /join` |

The join listener is server-TLS-only because a join-mode node has no cert yet — that
is the whole chicken-and-egg this solves. The node still verifies the CP via the
pinned `ca`. The mTLS `POST /enroll` **stays** for mount mode; `/join` is additive.
Bundle assembly is refactored into a shared helper both handlers call.

## The CA (one CA, both modes)

There is a single fleet CA, provisioned by cert-manager as a self-signed `Issuer`
→ CA `Certificate` (`isCA: true`). It plays three roles:

- cert-manager issues **mount-mode** per-pod client certs from it (a CA `Issuer`);
- its key is mounted into the `serve` pod so `/join` can **sign join-mode CSRs**
  from the same CA;
- its cert is the gateway's mTLS `client_ca`, so certs from *both* modes are
  accepted on the steady-state gateway. No CA bundle to manage.

Referenced by a new `issuing_ca_secret_ref` on `UpdateRepository` (`tls.crt` +
`tls.key`) for the join handler; the gateway `client_ca` mount points at the same
CA cert.

## Code touch points

**`crates/updated` (agent side)**

- `enrollment.rs`
  - `EnrollmentBootstrap` gains join-mode fields; both modes coexist:
    `{ url, ca, client_cert?, client_key?, group_id?, nonce? }`. Validation: `ca`
    required; **exactly one** of `{client_cert, client_key}` (mount) or
    `{group_id, nonce}` (join). In join mode the **`nonce` is a secret**, so the
    bootstrap file is a mounted Secret — the "no secret in bootstrap" invariant now
    holds only for mount mode; relax it to "no secret unless join mode".
  - New `JoinRequest { group_id, nonce, instance, csr }` and
    `JoinResponse { leaf_pem, ca_chain_pem, bundle }` (bundle = existing
    `EnrollmentBundle`).
  - Frontend branches on mode. Mount mode keeps `load_or_enroll_http` verbatim.
    Join mode (`load_or_join`): reuse durable `instance` (today's
    `registration-nonce`), generate keypair + CSR, POST `/join`, persist
    key/cert/ca to state dir, then feed the embedded bundle through the existing
    `load_or_enroll` consumed-once path. After a join, `identity()` resolves to the
    persisted `state/agent.{crt,key}` + `bootstrap.ca`; steady-state traffic is then
    identical to mount mode.
- `tls.rs`
  - Add `server_config_no_client_auth(cert, key)` for the join listener.
  - Add CSR/keypair generation helper (new `csr` module; `rcgen`).
- new dep: `rcgen` (CSR build on node; CSR signing on CP).

**`crates/updatec` (control plane)**

- `lib.rs`
  - `UpdateGroupStatus` += `group_id: Option<String>`, `join_secret_ref: Option<LocalSecretReference>`.
  - `UpdateGroupSpec` += optional `rotate_nonce: Option<String>` (rotation trigger).
  - `UpdateRepositorySpec` += `issuing_ca_secret_ref: LocalSecretReference`.
  - Reword `EnrollmentSpec` doc (no longer "authenticated by mTLS").
- `runtime.rs`
  - Group reconcile: mint `group_id` (from UID) + `nonce` Secret if absent; publish
    to status. Handle `rotate_nonce`.
  - Plan compile: treat `updated.dev/group=<name>` as an implicit membership label
    so operators don't have to hand-write the selector.
- `gateway.rs`
  - Refactor bundle assembly out of `enroll` into a shared helper.
  - New `join` handler + third listener (server-TLS-only). Load group + Secret,
    constant-time nonce compare, sign CSR with issuing CA (`rcgen`
    `CertificateSigningRequestParams` → `signed_by`; verify CSR self-signature for
    proof-of-possession), create UpdateAgent, respond with leaf + chain + bundle.
  - Remove `enroll` / `/enroll`.
- `main.rs`: `UPDATED_JOIN_LISTEN` (default `0.0.0.0:8443`); mount issuing CA key
  dir; load it for the join handler.

**Deploy**

- `deploy/kubernetes/updatec.yaml`: cert-manager self-signed Issuer + CA
  Certificate; mount CA key into `serve`; set gateway `client_ca` = issuing CA
  cert; add join Service port. RBAC already covers Secrets.
- Bootstrap templates (`deploy/ansible/...`, `deploy/bootstrap.toml`): new
  `{ join_url, group_id, nonce, ca }` shape, mounted as a Secret.

## Open decisions (flag if you disagree; otherwise these are the defaults)

1. **CA provisioning** = cert-manager self-signed issuing CA, CP holds the key
   (matches existing cert-manager server-cert pattern). Alternative: CP
   self-generates a CA into a Secret on first boot (less deploy wiring, worse trust
   distribution story).
2. **Both modes kept** — mount-mode `/enroll` (cert-manager/K8s) and join-mode
   `/join` (userdata/Rancher) coexist; bootstrap picks by which fields are set.
3. **No renewal in v0** — long-ish leaf TTL; `/renew` over mTLS is a follow-up.
4. **Group is the join anchor** (per-group nonce), per your call — not per-repository.
