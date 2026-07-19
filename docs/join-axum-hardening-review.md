# Join-mode + Axum-gateway adversarial review

Adversarial pass over the join-mode enrollment changes and the Axum/hyper gateway rewrite
(`updatec/gateway.rs`, `join.rs`, `runtime.rs`, `updated/{enrollment,tls,csr}.rs`, the Kind e2e
join fleet, and `deploy/kubernetes/updatec.yaml`). Four independent reviewers (Axum hardening,
security, dup-code, shell/deploy). Fixed items were changed in place; `cargo test -p updated -p
updatec -p updated-healthproxy` and the workspace build stay green, and the e2e assertions were
strengthened (not weakened) to match.

## Fixed in this pass

### Axum gateway hardening (transport regressions the rewrite introduced)
- **Streamed response body had no timeout** (`gateway.rs::repo_get`). A backend that returned
  headers fast then stalled mid-body pinned the connection *and its budget permit* forever →
  256 such requests against a degraded store = a data-plane outage that never self-heals. Restored
  the original per-chunk bound via `timed_object_stream` (each chunk wrapped in `IO_TIMEOUT`; a
  stall yields a final error item and ends the stream).
- **No header/body read timeout (slow-loris)** (`gateway.rs::serve_http`, routers). `header_read_timeout`
  (via a `TokioTimer`) now bounds the request-line/header phase, and a `tower_http` `TimeoutLayer`
  (30s, 408) bounds the handler+body-read phase on the data and join routers. Streaming responses
  are unaffected (the handler returns the `Body` before the layer fires; the stream is bounded
  per-chunk).
- **Plaintext health listener was unbudgeted + untimed** (`gateway.rs::serve_plain`). A slow-loris
  there could exhaust process fds and starve the mTLS/join listeners' `accept`. It now has its own
  64-connection budget and the same header timeout.
- **A control-char backend ETag 500'd the whole object** (`gateway.rs::repo_get`). An ETag that is
  not a valid header value is now skipped, not fatal — the object is still served.
- **Restored dropped traversal test cases** (`/targets/../app`, `/targets//app`) so a future
  routing/normalization change can't silently regress the read-path traversal defense.
- **HTTP/1-only serving** (`gateway.rs::serve_http`, second-round finding). `header_read_timeout`
  is h1-only; `hyper_util`'s `auto::Builder` still served an HTTP/2 prior-knowledge preface with no
  frame-read timeout, so an h2-preface slow-frame client could hold a connection. Switched to
  `hyper::server::conn::http1::Builder` (h1 only) — matching the original hand-rolled server and the
  TLS configs' lack of h2 ALPN — so no h2 frame phase is left unbounded.

### Join / enrollment hardening
- **CSR now signed only after the agent create/conflict check** (`gateway.rs::join`). Previously a
  conflicting request (wrong group/instance) still minted a certificate before the 409. Signing
  moved after `create_agent_idempotent`, so a rejected join produces no cert.
- **Unauthenticated `/join` no longer scans the apiserver** (`gateway.rs::lookup_group_nonce`,
  `runtime.rs::ensure_group_join_credentials`). It used to LIST every `UpdateGroup` (etcd quorum,
  linear in fleet size) to map the opaque `group_id` → its Secret *before* checking the token, so
  64 unauthenticated connections could amplify garbage `/join`s into apiserver/etcd load. The token
  Secret is now named `join-<group_id>` and carries the group name + repository, so the gateway
  resolves and checks the token with a single GET by a deterministic key — no scan, no pre-auth
  amplification. (Delete+recreate protection is preserved: a new group has a new id ⇒ a new Secret;
  the old, GC'd one 404s.)
- **Enrollment crash-brick window closed** (`updated/enrollment.rs::load_or_enroll`). The bundle is
  now written *before* the consumed marker. The reverse order left an ill-timed crash with the
  marker set and no bundle — permanently fatal ("missing after bootstrap eligibility was consumed").
  The consumed-once guarantee still holds (once both exist, deleting the bundle can't re-enable).

### Deploy / e2e
- **Join PVC 16Mi → 1Gi.** 16Mi could not hold the installed binary + retained inactive releases;
  it only passed because kind's local-path provisioner ignores the request. Sized to the fleet's
  install footprint; on a real CSI backend 16Mi would ENOSPC on the first upgrade.
- **Join pods now mount only `ca.crt`, not the shared client cert+key.** They were mounting the full
  `agent-tls` Secret (the mount-mode client identity) to read one file — handing join nodes the very
  credential join mode withholds. Now `items: [{key: ca.crt}]`.
- **Join token via `secretKeyRef`, not a plaintext env `value`.** The decoded nonce was baked into
  the pod spec (etcd, `kubectl describe`); it now reads straight from the Secret.
- **`restart = upgrade` assertion made meaningful.** It only checked the deterministic name still
  existed (which survives a lost PVC), so its "PVC did not persist" branch was unreachable. It now
  asserts the restarted container's log has no "cold-installed" — i.e. it reused install state.

### Dedup / dead code
- `enroll` now calls `join::agent_name` instead of open-coding it (single source of the naming rule).
- Extracted `create_agent_idempotent` + `agent_assignment` (gateway) and `load_existing_or_fresh` +
  `success_body` (enrollment) — removes the copy-pasted create-409 and consumed-once/success blocks.
- Removed dead `desired_group_names` (`lib.rs`, no callers).
- (`tls.rs` rustls-builder boilerplate was already deduped via `load_roots`/`load_cert_chain`/`load_key`.)

## Verified sound (checked, not defects)

CSR signing neutralizes CA:TRUE / arbitrary CN-SAN / keyCertSign / key substitution and enforces
proof-of-possession; `nonce_matches` is constant-time with the length folded in; the join Secret
nonce round-trips cleanly (no double-decode); no nonce/token/csr/leaf is logged; `agent.key` is
0600 from creation; join-listener router isolation is structural; aws-lc-rs is the provider on every
*explicit* config and the process default.

## Open — discussion (not fixed here; each needs a design decision)

- **`ring` is compiled in via `object_store`/`quinn`; outbound S3 TLS may not use aws-lc-rs**
  (FIPS boundary). Our listeners and the agent client are aws-lc-rs, but the gateway's object_store
  backend builds its own reqwest/rustls stack; under `--features fips` the `crypto_provider()`
  assertion does not cover it, so backend traffic *may* run non-validated crypto while the binary
  advertises FIPS. Pin object_store/reqwest to the installed default, or document the boundary.
- **Gateway RBAC/ServiceAccount is over-broad** (`deploy/kubernetes/updatec.yaml`). The `updatec`
  Role grants `secrets: [get,list,watch,create]` namespace-wide with no `resourceNames`, and the
  internet-facing gateway shares the controller's SA — so a gateway compromise = every Secret
  (CA key, TUF signing keys, S3 creds) + full CRD mutation. Split the gateway onto a minimal SA
  scoped to what it mounts/needs.
- **`fips_enabled` (`updated/tls.rs`) is unused.** A trivial public accessor with no callers — either
  wire it into startup logging or drop it. Left as-is (harmless, plausibly intentional).

### Still open from the prior join-mode pass (unchanged, re-listed so they aren't lost)
- **Telemetry has no writer-identity authorization** (HIGH): the fleet client CA is shared, so any
  cert-holder can `PUT /telemetry/<any-node>.json` a forged healthy report and defeat `max_concurrent`
  (fails *open*). Fix needs per-node identity from the cert (join-mode leaves now carry a SPIFFE
  node SAN — mount-mode does not) and a path/identity match.
- **TUF root is trust-on-first-use at enrollment** (MEDIUM): the routing root is delivered in the
  bundle, bounded only by fleet-CA server auth; pin it (or its hash) in the bootstrap.
- **Join leaves are ~80-year certs with no revocation**; **orphaned `<group>-join` Secret isn't
  self-healing**; **group-existence timing oracle** on the extra Secret GET — all documented v0
  tradeoffs; the short-TTL + renew-over-mTLS follow-up in `docs/group-enrollment-design.md` covers
  the first.
