# Enrollment: shared fleet cert + per-node CSR signing (v0)

## Goal

Let an operator provision N nodes into a fleet with **two files and a name** — a
shared, fleet-wide enrollment certificate (cert + key) and the CA that pins the
gateway — and nothing per-node baked in. Each node mints its own steady-state mTLS
identity at first boot: it generates a keypair locally, self-asserts a `name`, and
gets a CSR signed by the control plane into a per-node leaf it uses thereafter.

There is exactly **one** enrollment path. The earlier design carried two (a
mount-mode client cert *and* a join-mode group token over a separate server-TLS
listener); that duality is gone. The single path is mutual-TLS `POST /enroll`.

## Model

Two credentials, cleanly separated:

- **Fleet enrollment credential** = the shared `client_cert` + `client_key`, issued
  by cert-manager into a Secret and identical on every node. Its only job is to
  authenticate the `/enroll` handshake by mutual TLS. A party that holds it may enroll
  a node under any name — this is the accepted flat-trust property of a shared
  credential. Individual attribution and revocation do **not** come from it.
- **Node credential** = the per-node leaf cert minted at enrollment. Unique,
  attributable, individually revocable. The node's private key is generated on the
  node and never leaves it; only the public key (in the CSR) is sent, and the control
  plane pins it on the `UpdateAgent` so it can later verify the node's *signed*
  telemetry against the same key that certifies its mTLS leaf.

The mTLS handshake *is* the authentication — there is no bearer token in the request
body, so there is no secret to constant-time-compare or keep out of logs. The node
self-asserts its `name` in the body; the control plane sets the leaf's `CN` to that
name and certifies only the CSR's public key. An approval gate on the resulting
`UpdateAgent` (below) is the place to require a human to authorize a requested name.

## Node naming

The node's `name` is self-asserted and free-form (a DNS-safe label, validated by
`EnrollmentRequest::name_is_wellformed`). It becomes:

- the minted certificate's `CN`,
- the `UpdateAgent` the enrollment creates, and
- `registration_sha256 = sha256(name)`, the stable idempotency key: the same node
  coming back on the same name resolves to the same `UpdateAgent` (409-tolerant
  create), and a conflicting name that does not match never mints a certificate.

## Flow

```
Admin: cert-manager issues the shared fleet enrollment cert into a Secret; hand
       { url, ca, client_cert, client_key } + a per-node `name` to each node.
       (Everything except `name` is identical across the whole fleet.)

Node boot (no steady-state cert yet):
  - generate a durable keypair locally (persist, reuse on retry)
  - build a CSR (subject/SAN irrelevant — the CP ignores them)
  - POST /enroll { name, csr }  over MUTUAL TLS, presenting the shared fleet cert

Control plane /enroll handler (mTLS, client cert REQUIRED):
  - the handshake already authenticated the caller (shared fleet cert, fleet CA)
  - reject a malformed name (400)
  - pin the CSR public key; sign the CSR into a leaf: take ONLY the CSR public key;
      CP sets subject/SAN = CN=<name>, URI SAN spiffe://updated.fleet/scope/<repo>/node/<name>
      issuer = repository issuing CA (private key held by CP), short TTL
  - create/patch UpdateAgent { identity: Enrolled, registration_sha256, public_key,
      labels += repository.enrollment.labels }   (idempotent, 409-tolerant)
  - assemble EnrollmentBundle (shared with the operator's published enrollment Secret)
  - respond { leaf, chain, bundle }

Node:
  - persist agent.key (0600) + agent.crt to state dir
  - from now on: identity = { state/agent.crt, state/agent.key, bootstrap.ca }
  - proceed as steady state: mTLS gateway, TUF, signed telemetry
```

Group routing is by selector only: the agent carries the repository's enrollment
labels, and a group's `selector.matchLabels` matches them. There is no implicit
group-membership label anymore.

## Storage model — enrollment needs persistence

The node **generates its own keypair at first boot**; that private key exists only on
the node's state volume. If that volume is ephemeral (`emptyDir`), a restart loses the
key and the node must re-enroll — minting a **new** identity and leaving an orphan
`UpdateAgent`. To keep a pod's identity stable across restarts it must persist `state/`
(durable key, `agent.crt`, `enrollment.json`, and the install state machine) on a
**PVC**. This cleanly separates the two install paths the demo exercises:

- Node whose **PVC survives** a restart → loads existing install state → **upgrade**
  (same identity, in-place).
- **Fresh** node (new VM / wiped PVC) → **cold reinstall** from scratch.

For churned VMs (an autoscaler) the ephemeral-identity behavior is *intended* — a dead
VM is gone. For a Kubernetes pod that should keep its identity across restarts, the PVC
is what makes it so.

## Blast radius / lifecycle

- **Shared enrollment cert.** A leak lets someone enroll a node under any name. This is
  the accepted trade for a dynamic, template-once deployment; the mitigation is a
  future **approval gate** (below), not per-node enrollment secrets.
- **Per-node revoke** = delete the `UpdateAgent` / short leaf TTL. Independent of the
  enrollment credential.
- **Rotate the fleet cert** = cert-manager re-issues the enrollment Secret; nodes that
  already hold their own node certs are unaffected (they never use the enrollment cert
  for steady-state traffic).
- **v0 scope:** **bounded leaf TTL (90-day default, `join::LEAF_CERT_TTL_DAYS`)** so a
  leaked leaf is time-limited, not permanent — **no renewal endpoint yet** (documented
  follow-up: `/renew` over mTLS with the current cert, which makes an even shorter TTL
  sustainable). Enrollments are logged.

## Future: approval gate

Because `/enroll` sits behind mutual TLS and creates an `UpdateAgent`, a `requireApproval`
field on the repository (or group) is a clean forward hook: enrollment would create the
`UpdateAgent` in a pending state, and a rollout would route to it only after a human (or
policy) marks it approved. This is the answer to "any holder of the shared cert can enroll
any name" for environments that want it — not yet implemented.

## Listeners

`updatec serve` binds two listeners:

| listener | port (default) | TLS | client auth | serves |
|---|---|---|---|---|
| data (gateway) | 8080 | server | **required** (fleet CA) | TUF metadata/targets, telemetry, `POST /enroll` |
| health | 8081 | none | none | `/healthz` |

`/enroll` is a route on the one mTLS data listener — the shared fleet enrollment cert
authenticates it at the handshake, so there is no separate client-cert-less listener.

## The CA

There is a single fleet CA, provisioned by cert-manager as a self-signed `Issuer` → CA
`Certificate` (`isCA: true`). It plays three roles:

- cert-manager issues the **shared fleet enrollment** cert from it;
- its key is mounted into the `serve` pod so `/enroll` can **sign per-node CSRs** from
  the same CA (`UPDATED_ISSUING_CA_DIR`, `IssuingCa::load`);
- its cert is the gateway's mTLS `client_ca`, so both the enrollment cert and every
  minted node leaf are accepted on the steady-state gateway. No CA bundle to manage.

## Code touch points (as built)

**`crates/updated` (agent side)**

- `enrollment.rs` — `EnrollmentBootstrap { url, ca, name, client_cert, client_key }`,
  `deny_unknown_fields` (a stale `group_id`/`nonce`/`token` field fails loudly).
  `EnrollmentRequest { name, csr }` + `name_is_wellformed`; `EnrollResponse { leaf,
  chain, bundle }`. `load_or_enroll_http` is the single mTLS enroll flow.
- `csr.rs` — durable keypair + CSR generation (`rcgen`).

**`crates/updatec` (control plane)**

- `join.rs` — `IssuingCa::load` + `sign_client_csr(scope, name, csr)` (certifies only
  the CSR public key; CP sets `CN`/SAN); `csr_public_key` (pins the key for telemetry
  verification). Pure, unit-tested.
- `gateway.rs` — the single `enroll` handler on the mTLS data listener; `register_agent`
  assembles the bundle (shared with the operator's published enrollment Secret).
- `main.rs` — loads the issuing CA (`UPDATED_ISSUING_CA_DIR`) and passes it to `serve`.

**Deploy**

- `deploy/kubernetes/updatec.yaml`: cert-manager self-signed Issuer + CA Certificate;
  mount the CA key into `serve`; gateway `client_ca` = the same CA cert. One mTLS data
  listener; no join port.
