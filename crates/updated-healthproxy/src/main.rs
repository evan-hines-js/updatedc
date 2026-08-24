//! `updated-healthproxy`: program a load balancer's backend set from the fleet's own signed
//! health, so traffic reaches only healthy nodes and a drained node leaves rotation — with no
//! data-path hop of ours. The load balancer is pluggable: this binary wires either the Kubernetes
//! EndpointSlice backend or the HAProxy backend, chosen by `HEALTHPROXY_HAPROXY_ENDPOINTS` below.
//! See the library for design.
//!
//! Configuration is entirely `HEALTHPROXY_*` environment variables:
//!
//! - `HEALTHPROXY_HEALTH_BASE`         (required) CDN base; the fleet report document is at
//!   `<base>/telemetry/fleet.json`.
//! - `HEALTHPROXY_HAPROXY_ENDPOINTS`   comma-separated HAProxy TCP admin sockets (`host:port`).
//!   Non-empty ⇒ program that cluster over the Runtime API; absent ⇒ program
//!   Kubernetes EndpointSlices. This one variable selects the whole backend.
//! - `HEALTHPROXY_HAPROXY_BACKEND`     HAProxy backend name to program (default `fleet`); read
//!   only on the HAProxy path.
//! - `HEALTHPROXY_SERVICE`             selectorless Service to program — required on the
//!   EndpointSlice path, unused on the HAProxy path, which touches no Service.
//! - `HEALTHPROXY_INVENTORY_DIR`       (required) operator-projected, revisioned inventory shards;
//!   active members carry node/address/pinned report key, while cordoned members carry only the
//!   identity to drain. The key is the node's enrollment EC point in hex (65 bytes,
//!   `04`-prefixed), so a report the node did not sign can never place it in rotation.
//!   The projection has one protocol-defined width of eight shards; there is no reader-side knob.
//! - `HEALTHPROXY_NAMESPACE`           Service namespace (default `default`).
//! - `HEALTHPROXY_PORT` / `_PORT_NAME` endpoint port and name (default `8080` / `http`).
//! - `HEALTHPROXY_INTERVAL_SECS`       reconcile cadence (default `2`).
//! - `HEALTHPROXY_HEALTH_TIMEOUT_SECS` per-fetch timeout (default `2`).
//! - `HEALTHPROXY_METRICS_ADDRESS`     serve `GET /metrics` on this address (default off).

use std::sync::Arc;

use updated_healthproxy::endpointslice::EndpointSliceLb;
use updated_healthproxy::{run, Config, LoadBalancer};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The DNS resolve pass sizes its fan-out from the blocking pool, because `getaddrinfo` holds
    // one of those threads per lookup; pin the pool to the value that derivation is written
    // against instead of inheriting whatever tokio defaults to.
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(updated_healthproxy::BLOCKING_POOL_THREADS)
        .build()?
        .block_on(serve())
}

async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    // Health documents may live on an HTTPS CDN; install the one crypto provider the rest of
    // the system uses. Idempotent, so a double install is not fatal.
    updated::tls::install_crypto_provider();

    let config = Config::from_env().await?;
    // The health→membership core is identical; only the backend differs. A HAProxy target programs a
    // cluster of HAProxy admin sockets over the Runtime API; otherwise we program a Kubernetes
    // EndpointSlice. The HAProxy backend needs no kube client, so only build one for the slice path.
    let load_balancer: Arc<dyn LoadBalancer + Send + Sync> = match &config.haproxy {
        Some(target) => {
            eprintln!(
                "healthproxy: programming {} HAProxy instance(s) (backend {}) from {} nodes, health {}",
                target.endpoints.len(),
                target.backend,
                config.inventory.len(),
                config.health_base
            );
            Arc::new(updated_healthproxy::haproxy::HAProxyLb::new(
                target.endpoints.clone(),
                target.backend.clone(),
            ))
        }
        None => {
            let kube_client = kube::Client::try_default().await?;
            Arc::new(EndpointSliceLb::new(
                kube_client,
                &config.namespace,
                config.service.clone(),
                config.port_name.clone(),
                config.port,
            ))
        }
    };
    // The EndpointSlice path logs its target here; the HAProxy path already logged its own above.
    if config.haproxy.is_none() {
        eprintln!(
            "healthproxy: programming EndpointSlice for Service {}/{} from {} nodes, health {}",
            config.namespace,
            config.service,
            config.inventory.len(),
            config.health_base
        );
    }
    // The per-fetch budget is owned by the poll plan (`tokio::time::timeout` around each request
    // AND its bounded body read), which is what the fan-out arithmetic reasons about. Redirect
    // refusal still comes from the one outbound-client policy every operator endpoint uses.
    let http = updated::http::outbound_client(updated::http::OutboundDeadline::ExternallyEnforced)?;

    run(http, config, load_balancer, shutdown_signal()).await;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if let Err(error) = result {
                    eprintln!("healthproxy: failed to listen for an interrupt: {error}");
                }
            }
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    if let Err(error) = tokio::signal::ctrl_c().await {
        eprintln!("healthproxy: failed to listen for an interrupt: {error}");
    }
}
