# Migrating the `updatec` gateway to Axum

## Goal & scope

Replace the hand-rolled HTTP/1.1 layer in the `updatec` **gateway** (`crates/updatec/src/gateway.rs`)
with [Axum] (over `hyper` + `tower`), keeping the exact same externally observable
behaviour, TLS posture, and crypto provider. The pure request-handling logic
(enrollment, join, telemetry, TUF object serving) stays; only the transport,
request parsing, routing, and connection management change.

**In scope:** the `updatec serve` gateway — its three listeners and every route.

**Out of scope:**

- **`updated-healthproxy`** — it has *no inbound HTTP server*. It is a control loop
  that polls node health reports from the CDN (`reqwest` client) and programs
  Kubernetes EndpointSlices; it deliberately stays out of the data path
  (`crates/updated-healthproxy/src/lib.rs`). There is nothing to port to Axum unless
  we reintroduce an in-path proxy, which is a separate decision.
- **The demo** (`crates/updatec-demo/src/server.rs`) — its hand-rolled server may stay
  as-is; it is throwaway UI infrastructure, not a production surface.
- **The agent → gateway client** (`reqwest` in `updated`/`updated-tuf`) — unchanged.

## Why migrate

The gateway hand-parses HTTP/1.1: header accumulation with a `\r\n\r\n` scan
(`HEADER_LIMIT`), a manual request-line split, hand-rolled `Content-Length` body
reads (`read_body`), and hand-rolled `Range`/`Content-Range`/`ETag`/206 logic
(`parse_range`, `repository_key`). Each is correct today but is bespoke code we
own, test, and must keep RFC-correct. Axum/hyper gives us: a battle-tested HTTP
implementation (keep-alive, chunked bodies, malformed-input handling), `tower`
middleware for the cross-cutting concerns we currently inline (timeouts, body
limits, concurrency limiting, tracing), and testable handlers (`oneshot`) instead
of a socket-level `serve_connection`.

## Current surface (what must be preserved exactly)

Three listeners, dispatched today by the `ListenerRole` enum so each listener only
exposes its own routes:

| Listener | Port (env) | TLS | Client cert | Routes |
|---|---|---|---|---|
| **Data** | 8080 (`UPDATED_LISTEN`) | server | **required** (fleet CA) | `GET/HEAD /metadata/*`, `GET/HEAD /targets/*`, `POST /enroll`, `PUT /telemetry/<node>.json`, `GET /healthz` |
| **Health** | 8081 (`UPDATED_HEALTH_LISTEN`) | none | none | `GET/HEAD /healthz` (probe-only) |
| **Join** | 8443 (`UPDATED_JOIN_LISTEN`) | server | **none** | `POST /join`, `GET /healthz` |

Per-route behaviour that must survive the port:

- **Repository GET/HEAD** (`/metadata/*`, `/targets/*`): streams objects from an
  `object_store::ObjectStore`; supports `Range` (single offset), replies `206` with
  `Content-Range` + `Accept-Ranges: bytes`, emits a safe `ETag`, honours `HEAD`
  (headers, no body), and returns `416` for an unsatisfiable range and `404` for a
  missing object. This is the **hardest** part to port (see below).
- **`POST /enroll`**: mTLS-authenticated (the handshake *is* the auth); body is an
  `EnrollmentRequest`; creates/idempotently reconciles an `UpdateAgent` and returns an
  `EnrollmentBundle`. Data listener only.
- **`POST /join`**: group-token-authenticated; body is a `JoinRequest`; validates the
  nonce against the group Secret, signs the CSR, registers the agent, returns a
  `JoinResponse`. Join listener only.
- **`PUT /telemetry/<node>.json`**: stores a `NodeReport` to the object store. Data
  listener only.
- **`GET /healthz`**: `200` on every listener.

Cross-cutting, currently inline:

- **TLS**: `tokio_rustls::TlsAcceptor` built from `updated::tls::server_config` (mTLS,
  `WebPkiClientVerifier`) and `updated::tls::server_config_no_client_auth` (join).
  **Crypto provider is aws-lc-rs**, asserted FIPS-capable under the `fips` feature —
  this must not regress to `ring`.
- **Concurrency**: a shared `Semaphore::new(256)` across data + join listeners.
- **Timeouts**: `IO_TIMEOUT` (30s) around reads and each object stream chunk.
- **Limits**: `HEADER_LIMIT` (16 KiB) and a body limit in `read_body`.
- **Resilience**: a transient `accept()` error logs and continues (never tears down
  the listener).

## Target design

### Crate choices

- `axum` (routing, extractors, `Router`).
- `hyper` + `hyper-util` (`hyper_util::server::conn::auto::Builder` to serve a
  `tower::Service` per connection, HTTP/1 + optional HTTP/2).
- `tower` / `tower-http` for middleware (`TimeoutLayer`, `RequestBodyLimitLayer`,
  `TraceLayer`, a concurrency limit).
- **Keep `tokio-rustls`** for the TLS accept loop — do **not** adopt `axum-server`.

### TLS: keep a manual accept loop (do not use `axum-server`)

`axum-server` would hide the acceptor, and its default rustls wiring risks pulling a
non-aws-lc-rs provider — unacceptable given the FIPS assertion. Instead keep the
current structure: our own `tokio::net::TcpListener` accept loop per listener, our
own `tokio_rustls::TlsAcceptor` (built from the existing `updated::tls` functions, so
the provider stays aws-lc-rs and mTLS client-cert enforcement is unchanged), and hand
each accepted, TLS-terminated stream to hyper:

```rust
let acceptor = TlsAcceptor::from(Arc::new(updated::tls::server_config(cert, key, client_ca)?));
let app: Router = data_router(state);            // one Router per listener role
let make = app.into_make_service();              // or hand the Router to hyper directly
loop {
    let (tcp, peer) = match listener.accept().await { Ok(a) => a, Err(e) => { warn!(..); continue } };
    let acceptor = acceptor.clone();
    let tower = app.clone();
    tokio::spawn(async move {
        let Ok(tls) = acceptor.accept(tcp).await else { return };   // mTLS enforced HERE
        let io = TokioIo::new(tls);
        let svc = hyper_util::service::TowerToHyperService::new(tower);
        let _ = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
            .serve_connection(io, svc).await;
    });
}
```

Because the **data** listener's `TlsAcceptor` uses `WebPkiClientVerifier`, a client
without a fleet-CA cert never completes the handshake and never reaches a handler —
exactly as today. Handlers therefore need no per-request certificate extraction; the
connection's existence is the proof. (If we ever need the peer identity in a handler,
`tls.get_ref().1.peer_certificates()` can be threaded in as a request extension.)

### One `Router` per listener role

The `ListenerRole` exclusion (join listener can't serve `/enroll` or repository
content, etc.) becomes *structural* — each listener is built from a different
`Router`, so an unavailable route simply isn't mounted (404 by construction):

```rust
fn data_router(s: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/enroll", post(enroll))
        .route("/telemetry/{node}", put(telemetry_put))
        .route("/metadata/{*path}", get(repo_get).head(repo_head))
        .route("/targets/{*path}",  get(repo_get).head(repo_head))
        .with_state(s)
        .layer(common_layers())
}
fn join_router(s: JoinState) -> Router {
    Router::new().route("/healthz", get(healthz)).route("/join", post(join)).with_state(s).layer(common_layers())
}
fn health_router() -> Router { Router::new().route("/healthz", get(healthz)) }
```

`AppState` (Axum `State`) carries `Arc<dyn ObjectStore>`, `prefix`, and the
`EnrollmentContext`; `JoinState` adds the `Arc<IssuingCa>`. These are the same values
`serve()` already threads through.

### Route mapping

- **`enroll` / `join` / `telemetry_put`**: keep the existing function bodies almost
  verbatim; they become Axum handlers taking `State(..)` + `Bytes` (or `Path<String>`
  for the telemetry node) and returning `impl IntoResponse`. The manual `status(..)`
  writes become `StatusCode` / `(StatusCode, Json<..>)` return values. The security-
  critical logic (nonce check, CSR signing, `resolve_signed_enrollment`, bundle
  assembly) is untouched.
- **Repository `GET`/`HEAD`**: an Axum handler taking `Path` + the `Range`/`If-*`
  headers via a typed extractor, returning a `Response` whose body is
  `axum::body::Body::from_stream(get_result.into_stream())`. Range/`206`/`Content-Range`/
  `Accept-Ranges`/`ETag`/`416`/`HEAD` are set explicitly (see next section). `404` maps
  from `object_store::Error::NotFound`, `504` from the per-request timeout layer.

### The hard part: ranged, streamed object serving

There is no drop-in for "serve an `object_store` object with Range support" (unlike
`tower_http::services::ServeDir` for the filesystem). So the current `parse_range` +
`repository_key` + streaming logic is **preserved as a helper**, invoked inside the
Axum handler:

1. Parse the `Range` header (reuse the existing single-offset `parse_range`, or adopt
   `headers::Range` from the `headers`/`axum-extra` crate).
2. `store.head()` for size/ETag when a range is present; `416` if the start is past EOF.
3. `store.get_opts(key, GetOptions{ range, head, .. })`.
4. Build the response: status `200`/`206`, `Content-Length`, `Accept-Ranges`,
   `Content-Range` (partial), `ETag`; body = `Body::from_stream(result.into_stream())`
   for `GET`, empty for `HEAD`.

This keeps our proven digest-addressed key mapping and range semantics; only the byte
plumbing moves from manual `write_all` to a streamed `Body`.

### Cross-cutting via `tower` layers

- **Timeouts**: `tower_http::timeout::TimeoutLayer` (per request) replaces the inline
  `IO_TIMEOUT`. hyper's own header-read timeout covers slow-loris on the header phase.
- **Body limit**: `tower_http::limit::RequestBodyLimitLayer` replaces the `read_body`
  cap; hyper's max header size replaces `HEADER_LIMIT`.
- **Concurrency**: a `tower::limit::GlobalConcurrencyLimitLayer` (or a shared
  `Semaphore` acquired in the accept loop) replaces `Semaphore::new(256)`. Keep it
  **shared across the data and join listeners** to match today's single budget.
- **Tracing**: `tower_http::trace::TraceLayer` replaces the ad-hoc `tracing::warn!`
  per failed request.
- **Accept resilience**: the accept loop keeps the "log and continue on transient
  accept error" behaviour verbatim.

## What stays unchanged

- `crates/updatec/src/join.rs` (CSR signing, nonce compare, naming) — pure, no HTTP.
- `resolve_signed_enrollment` and the `EnrollmentBundle` assembly.
- `EnrollmentContext` / `JoinContext` (may gain `Clone` derive for `State`, already have).
- `updated::tls::*` TLS config builders (aws-lc-rs) — reused by the accept loop.
- `updated::enrollment` contract types (`EnrollmentRequest`, `JoinRequest`, bundles).
- The deploy manifest, ports, and env vars — the listeners bind the same addresses.

## Incremental migration plan

Port listener-by-listener so each step is independently shippable and testable:

1. **Add deps**, introduce the accept-loop-over-hyper helper, and port the **health**
   listener (one route) — smallest surface, proves the TLS/accept/serve scaffold.
2. Port the **join** listener (`POST /join` + `/healthz`) — one non-trivial handler,
   server-TLS-only, exercises `State` + `Bytes` + JSON responses.
3. Port the **data** listener's **`/enroll`** and **`/telemetry`** — JSON in/out,
   mTLS-gated by the acceptor.
4. Port the **data** listener's **repository `GET`/`HEAD`** — the streaming/range work.
5. **Delete** `serve_connection`, `read_body`, `parse_range` bespoke plumbing, the
   `ListenerRole` enum, and the manual `status`/`response` writers once every route is
   on Axum.

Each phase keeps the pure handler logic; only its wrapper changes, so behaviour is
diffable route-by-route.

## Testing

- Replace the socket-level `serve_connection(.., ListenerRole::Content)` test with
  `Router` unit tests via `tower::ServiceExt::oneshot` — construct a request, assert
  the `Response` (status, headers, body). Faster and finer-grained than today.
- Keep an integration test that stands up the real TLS accept loop on an ephemeral
  port and drives it with a `reqwest` client presenting a fleet-CA cert, to prove
  mTLS enforcement and the streaming/range path end to end.
- The Kind e2e (`scripts/kind-updatec-e2e.sh`) is unchanged — same ports, same routes,
  so it validates the port at the system level (including join-mode).

## Risks & open questions

- **Crypto provider**: must stay aws-lc-rs (FIPS). The manual-acceptor approach keeps
  full control; add a build-time check that no `ring`-backed rustls sneaks in via a
  new dependency's default features.
- **Range extractor**: reuse our `parse_range` (known-correct, single-offset) vs adopt
  `axum-extra`/`headers` `Range` (multi-range, more surface). Recommend keeping the
  minimal single-offset parser we already trust.
- **HTTP/2**: `auto::Builder` enables h2; agents use `reqwest` (fine). Decide whether
  to allow h2 or pin h1 to match today exactly. Low risk either way.
- **Graceful shutdown**: opportunity to add `hyper`'s graceful shutdown (drain
  in-flight requests on SIGTERM), which the hand-rolled loop lacks today.
- **Dependency weight**: adds `axum`/`tower(-http)`/`hyper-util`. All are already in the
  transitive graph via `kube`/`reqwest`, so the marginal cost is small.

## Non-goals

- No change to the agent-side client, the TUF/verification model, the CRD schema, the
  enrollment/join contracts, or the ports/addresses.
- No reintroduction of an in-path health proxy (separate decision).
- No change to the demo's server.

[Axum]: https://docs.rs/axum
