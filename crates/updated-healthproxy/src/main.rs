//! `updated-healthproxy`: program a load balancer's backend set from the fleet's own signed
//! health, so traffic reaches only healthy nodes and a drained node leaves rotation — with no
//! data-path hop of ours. The load balancer is pluggable (Kubernetes EndpointSlices today,
//! DNS/HAProxy later); this binary wires the Kubernetes backend. See the library for design.
//!
//! Configuration is entirely `HEALTHPROXY_*` environment variables:
//!
//! - `HEALTHPROXY_HEALTH_BASE`         (required) CDN base; a node's report is at
//!   `<base>/telemetry/<node>.json`.
//! - `HEALTHPROXY_SERVICE`             (required) selectorless Service to program.
//! - `HEALTHPROXY_MEMBERS`             (required) `node=address=pubkeyhex,…` fleet inventory; the
//!   pinned public key (the node's enrollment EC point in hex — 65 bytes, `04`-prefixed) is what
//!   its health report is verified against, so a report the node did not sign can never place it
//!   in rotation. A key of any other shape is refused at startup rather than draining that node.
//! - `HEALTHPROXY_NAMESPACE`           Service namespace (default `default`).
//! - `HEALTHPROXY_PORT` / `_PORT_NAME` endpoint port and name (default `8080` / `http`).
//! - `HEALTHPROXY_INTERVAL_SECS`       reconcile cadence (default `2`).
//! - `HEALTHPROXY_HEALTH_TIMEOUT_SECS` per-fetch timeout (default `2`).

use std::sync::Arc;

use updated_healthproxy::endpointslice::EndpointSliceLb;
use updated_healthproxy::{run, Config, LoadBalancer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Health documents may live on an HTTPS CDN; install the one crypto provider the rest of
    // the system uses. Idempotent, so a double install is not fatal.
    updated::tls::install_crypto_provider();

    let config = Config::from_env()?;
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
    let http = reqwest::Client::builder()
        .timeout(config.health_timeout)
        .build()?;

    run(http, config, load_balancer).await;
    Ok(())
}
