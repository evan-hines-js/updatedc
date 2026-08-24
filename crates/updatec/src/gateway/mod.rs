//! Read-only HTTP data plane for repositories published by `updatec`.
//!
//! The transport is Axum over hyper, one `Router` per listener role, but the TLS accept loops stay
//! ours (`tokio-rustls`) so the crypto provider remains aws-lc-rs and the mTLS client-certificate
//! requirement is enforced at the handshake exactly as before. Two listeners:
//!
//! * **data** (mTLS, client cert required) — every route `data_router` mounts, in full:
//!   `/metadata/{*rest}` and `/targets/{*rest}` (repository content), `/enroll` (the shared fleet
//!   enrollment cert authenticates it), `/renew` (per-node certificate re-issue),
//!   `/v1/node/inputs/{assignment_sha256}` (the assignment-bound file snapshot),
//!   `/v1/node/outputs` and `/v1/node/report` (exact S3 write capabilities), and
//!   `/healthz`.
//! * **health** (plaintext): `/healthz` and `/`, for orchestrator probes that cannot present a
//!   cert. Nothing else.
//!
//! Each listener is a different `Router`, so a route it must not expose simply is not mounted —
//! which is exactly what makes the lists above an inventory of the exposed surface rather than a
//! sample of it. A route added to either router belongs in its bullet.

use std::sync::Arc;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, FromRef, OriginalUri, Path, State};
use axum::http::{header, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use k8s_openapi::api::coordination::v1::{Lease, LeaseSpec};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime;
use kube::api::{Api, ListParams, PostParams};
use kube::{Client, ResourceExt};
use object_store::path::Path as ObjectPath;
use object_store::signer::Signer;
use object_store::ObjectStore;
#[cfg(test)]
use object_store::{ObjectStoreExt, PutPayload};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::{sleep, timeout};
use tokio_rustls::TlsAcceptor;
use tower_http::timeout::TimeoutLayer;

/// Bound on a single blocking store operation (a `head`/`get`/`put`) — not the whole streamed
/// response body, which hyper backpressures. A hung backend must not pin a connection forever.
const IO_TIMEOUT: Duration = updated_contracts::dataflow::GATEWAY_REQUEST_TIMEOUT;
/// S3 checks expiry when the request begins, so an honest transfer may finish after this window;
/// a retry asks for a fresh URL. Private-object retirement uses this same shared lifetime.
const OBJECT_CAPABILITY_TTL: Duration = updated_contracts::dataflow::OBJECT_CAPABILITY_TTL;

/// Upper bound on enrollment, renewal, and bundle request bodies. Payloads never enter the gateway;
/// they move through exact S3 capabilities.
const BODY_LIMIT: usize = updated_contracts::dataflow::MAX_DATAFLOW_BODY_BYTES;

/// How long a handshaken client has to finish everything it does on one connection while holding a
/// budget permit.
///
/// Every phase a *server* controls is already bounded — the handshake by [`IO_TIMEOUT`], the
/// request head by `header_read_timeout`, and the handler/body read by the router's `TimeoutLayer`.
/// This outer bound covers the remaining peer-controlled phase: a client that stops reading a
/// control response after hyper has returned its body.
///
/// Five minutes leaves ample room for control responses. Payload bytes, including enrollment
/// bundles, never consume this connection.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Enrollment count-and-create is allowed one minute and fenced by a two-minute Kubernetes Lease.
/// The critical section is deliberately shorter than the lease: a cancelled or crashed request
/// loses its ability to create before another replica may take over.
const ENROLLMENT_TRANSACTION_TIMEOUT: Duration = Duration::from_secs(60);
const ENROLLMENT_LOCK_SECONDS: i32 = 120;
const ENROLLMENT_LOCK_WAIT: Duration = Duration::from_secs(10);
const ENROLLMENT_LOCK_RETRY: Duration = Duration::from_millis(50);

/// The same bound for the plaintext health listener, sized by what THAT listener serves.
///
/// The health listener has no control plane: one route, a two-byte body, no store I/O, no
/// authentication. Sharing the data listener's larger bound made this port the cheapest way to
/// take the gateway down — [`HEALTH_CONNECTIONS`] permits, held by anyone who can reach the port,
/// each for up to half an hour (pipeline a few MB of `GET /healthz` and stop reading: the response
/// write blocks with no header-read timer armed). `serve_plain` then blocks in `acquire_owned`,
/// probes stop being answered, and the chart points BOTH the readiness and liveness probes at this
/// port — so the kubelet marks the gateway NotReady and then kills it, taking the enrollment and
/// enrollment control plane with it, for no credentials at all.
///
/// A minute covers every honest use with room to spare: the request head is already bounded by
/// `header_read_timeout` ([`IO_TIMEOUT`]), and what follows is writing "ok".
const HEALTH_CONNECTION_TIMEOUT: Duration = Duration::from_secs(60);

/// Max concurrent connections on the authenticated data listener.
const DATA_CONNECTIONS: usize = 256;
/// The plaintext health listener is unauthenticated; bound it so a slow-loris there cannot exhaust
/// process file descriptors and starve the mTLS data listener's `accept` calls. The permits are
/// themselves an exhaustible resource, which is why they are held for at most
/// [`HEALTH_CONNECTION_TIMEOUT`] rather than the data plane's much larger deadline.
const HEALTH_CONNECTIONS: usize = 64;

mod data;
mod enroll;
mod identity;
mod repository;
mod serve;
mod state;
#[cfg(test)]
mod tests;

pub(crate) use data::*;
pub(crate) use enroll::*;
pub(crate) use identity::*;
pub(crate) use repository::*;
pub use serve::*;
pub use state::*;
