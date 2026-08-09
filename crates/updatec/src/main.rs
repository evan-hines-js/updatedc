//! `updatec`, the minimal Kubernetes control plane for `updated`. Reconciliation lives behind
//! the library so Kind tests can exercise the same code without mocking Kubernetes.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    updated::tls::install_crypto_provider();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let mode = std::env::args()
        .nth(1)
        .ok_or("usage: updatec <controller|serve>")?;
    if !matches!(mode.as_str(), "controller" | "serve") || std::env::args().nth(2).is_some() {
        return Err("usage: updatec <controller|serve>".into());
    }
    // Controller-only settings, each off by default, configured the way every other updatec
    // setting is — environment variables, not a second (argv) configuration surface:
    // UPDATED_METRICS_ADDRESS — serve GET /metrics on this address.
    // UPDATED_ALERT_URL — POST condition transitions to this webhook.
    // UPDATED_ALERT_TOKEN_FILE — bearer-token file for the webhook, re-read per delivery.
    let metrics_address: Option<std::net::SocketAddr> = std::env::var("UPDATED_METRICS_ADDRESS")
        .ok()
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse()
                .map_err(|e| format!("UPDATED_METRICS_ADDRESS: {e}"))
        })
        .transpose()?;
    let alert_url = std::env::var("UPDATED_ALERT_URL")
        .ok()
        .filter(|value| !value.is_empty());
    let alert_token_file: Option<std::path::PathBuf> = std::env::var("UPDATED_ALERT_TOKEN_FILE")
        .ok()
        .filter(|value| !value.is_empty())
        .map(Into::into);
    let client = kube::Client::try_default().await?;
    let namespace = std::env::var("UPDATED_NAMESPACE").unwrap_or_else(|_| "updated-system".into());
    let repository = std::env::var("UPDATED_REPOSITORY").unwrap_or_else(|_| "default".into());
    let public_url =
        std::env::var("UPDATED_PUBLIC_URL").map_err(|_| "UPDATED_PUBLIC_URL is required")?;
    if mode == "serve" {
        let addr = std::env::var("UPDATED_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into());
        let health_addr =
            std::env::var("UPDATED_HEALTH_LISTEN").unwrap_or_else(|_| "0.0.0.0:8081".into());
        let (destination, store) = loop {
            match updatec::runtime::repository_store(client.clone(), &namespace, &repository).await
            {
                Ok(configured) => break configured,
                Err(error) => {
                    tracing::warn!(%error, "gateway storage is not configured yet; retrying");
                    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                }
            }
        };
        let enrollment = updatec::gateway::EnrollmentContext {
            client: client.clone(),
            namespace: namespace.clone(),
            repository: repository.clone(),
            public_url,
        };
        // The gateway's mTLS material is a cert-manager-issued secret mounted as files. The
        // standard cert-manager keys are tls.crt / tls.key / ca.crt.
        let tls_dir =
            std::env::var("UPDATED_GATEWAY_TLS_DIR").unwrap_or_else(|_| "/etc/gateway-tls".into());
        let tls = updatec::gateway::GatewayTls {
            cert: std::path::Path::new(&tls_dir).join("tls.crt"),
            key: std::path::Path::new(&tls_dir).join("tls.key"),
            client_ca: std::path::Path::new(&tls_dir).join("ca.crt"),
            enrollment_client_cn: std::env::var("UPDATED_ENROLLMENT_CLIENT_CN")
                .unwrap_or_else(|_| "updated-agent".into()),
        };
        // The join endpoint signs node CSRs with the fleet CA — the same cert-manager CA the gateway
        // trusts as its client CA, mounted here with its private key so leaves it mints are accepted
        // on the mTLS listener. Standard cert-manager keys are tls.crt / tls.key.
        let ca_dir =
            std::env::var("UPDATED_ISSUING_CA_DIR").unwrap_or_else(|_| "/etc/issuing-ca".into());
        // Paths, not contents: cert-manager rotates these in place and the gateway re-reads them.
        let issuing_ca = updatec::gateway::IssuingCaPaths {
            cert: std::path::Path::new(&ca_dir).join("tls.crt"),
            key: std::path::Path::new(&ca_dir).join("tls.key"),
        };
        return updatec::gateway::serve(
            updatec::gateway::GatewayAddresses {
                data: addr,
                health: health_addr,
            },
            store,
            destination.prefix,
            enrollment,
            issuing_ca,
            tls,
        )
        .await
        .map_err(Into::into);
    }
    let state = std::env::var("UPDATED_STATE_DIR").unwrap_or_else(|_| "/var/lib/updatec".into());
    let identity =
        std::env::var("HOSTNAME").unwrap_or_else(|_| format!("updatec-{}", std::process::id()));
    // The metrics listener: plain HTTP, cluster-internal, read-only, off unless asked for. It
    // reads the snapshot the loop below writes after each pass — scrape-time projection, no
    // sampling loop.
    let metrics: updatec::metrics::SharedMetrics = std::sync::Arc::default();
    if let Some(address) = metrics_address {
        let metrics = metrics.clone();
        tokio::spawn(async move {
            if let Err(error) = updatec::metrics::serve(address, metrics).await {
                tracing::error!(%error, "metrics listener failed");
            }
        });
    }
    // The one alert sink: unset means conditions-only.
    let sink = match alert_url {
        Some(url) => Some(std::sync::Arc::new(
            updatec::alerts::AlertSink::new(url, alert_token_file)
                .map_err(|error| format!("UPDATED_ALERT_URL: {error}"))?,
        )),
        None => None,
    };
    let mut hooks = updatec::runtime::ReconcileHooks::new(sink);
    loop {
        match updatec::runtime::acquire_or_renew_lease(
            client.clone(),
            &namespace,
            "updatec-publisher",
            &identity,
        )
        .await
        {
            Ok(true) => {}
            // Not the leader, or the lease op itself failed: this replica reconciles nothing, so
            // the failure streak it was carrying belongs to a leadership epoch that is over. The
            // streak counts CONSECUTIVE failed passes — `ReconcileFailing` exists to tell a loop
            // that is not converging apart from one ordinary transient — and carrying it across
            // the gap let a single failed pass minutes or hours later reach the threshold and
            // page, while another replica had meanwhile reconciled cleanly and cleared the
            // condition on every set.
            Ok(false) => {
                hooks.consecutive_failures = 0;
                // A follower has no fleet view: serving the last leader-epoch snapshot as if it
                // were current let a scrape read week-old gauges as fresh. The failure counter
                // stays — it is this process's own history.
                metrics.write().expect("metrics lock").last = None;
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
            Err(error) => {
                hooks.consecutive_failures = 0;
                tracing::error!(%error, "leader lease operation failed");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        }
        // The future borrows `hooks` mutably, so it is scoped: the failure handling below needs
        // `hooks` again, which is only possible once the (finished or cancelled) future is dropped.
        let result = {
            let reconciliation = updatec::runtime::reconcile_once(
                client.clone(),
                &namespace,
                &repository,
                std::path::Path::new(&state),
                &public_url,
                &identity,
                &mut hooks,
            );
            tokio::pin!(reconciliation);
            loop {
                tokio::select! {
                    result = &mut reconciliation => break Some(result),
                    _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                        match updatec::runtime::acquire_or_renew_lease(
                            client.clone(), &namespace, "updatec-publisher", &identity,
                        ).await {
                            Ok(true) => {}
                            Ok(false) => {
                                tracing::warn!("publisher lease lost; cancelling reconciliation");
                                break None;
                            }
                            Err(error) => {
                                tracing::error!(%error, "publisher lease renewal failed; cancelling reconciliation");
                                break None;
                            }
                        }
                    }
                }
            }
        };
        match result {
            Some(Ok(outcome)) => {
                tracing::info!(digest = %outcome.digest, "desired state reconciled");
                if let Some(snapshot) = outcome.snapshot {
                    metrics.write().expect("metrics lock").last = Some(snapshot);
                }
            }
            Some(Err(error)) => {
                // Full detail (which may name the bucket/endpoint/object key) goes to the
                // operator log only; the CR status gets a generic category so a reader with
                // `get` on the CRs learns nothing about the storage backend.
                tracing::error!(%error, "reconciliation failed; last publication remains active");
                metrics
                    .write()
                    .expect("metrics lock")
                    .reconcile_failures_total += 1;
                let status_message = updatec::runtime::generic_failure_status(error.as_ref());
                if let Err(status_error) = updatec::runtime::record_repository_failure(
                    client.clone(),
                    &namespace,
                    &repository,
                    status_message,
                )
                .await
                {
                    tracing::error!(%status_error, "recording repository failure status failed");
                }
                if let Err(status_error) = updatec::runtime::record_reconcile_failing(
                    client.clone(),
                    &namespace,
                    &mut hooks,
                )
                .await
                {
                    tracing::error!(%status_error, "recording ReconcileFailing on group sets failed");
                }
            }
            // A cancelled pass (lost lease) is a follower outcome, not a failure — and it ends
            // this replica's leadership epoch, so the streak resets with it for the same reason
            // the non-leader arms above reset it.
            None => hooks.consecutive_failures = 0,
        }
        // Poll for desired-state changes once per second so a freshly patched
        // rollout is republished promptly and the fleet starts converging fast.
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
