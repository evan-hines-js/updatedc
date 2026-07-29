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
            Ok(false) => {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
            Err(error) => {
                tracing::error!(%error, "leader lease operation failed");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        }
        let reconciliation = updatec::runtime::reconcile_once(
            client.clone(),
            &namespace,
            &repository,
            std::path::Path::new(&state),
            &public_url,
            &identity,
        );
        tokio::pin!(reconciliation);
        loop {
            tokio::select! {
                result = &mut reconciliation => {
                    match result {
                        Ok(digest) => tracing::info!(%digest, "desired state reconciled"),
                        Err(error) => {
                            // Full detail (which may name the bucket/endpoint/object key) goes to the
                            // operator log only; the CR status gets a generic category so a reader with
                            // `get` on the CRs learns nothing about the storage backend.
                            tracing::error!(%error, "reconciliation failed; last publication remains active");
                            let status_message =
                                updatec::runtime::generic_failure_status(error.as_ref());
                            if let Err(status_error) = updatec::runtime::record_repository_failure(
                                client.clone(), &namespace, &repository, status_message,
                            ).await {
                                tracing::error!(%status_error, "recording repository failure status failed");
                            }
                        }
                    }
                    break;
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                    match updatec::runtime::acquire_or_renew_lease(
                        client.clone(), &namespace, "updatec-publisher", &identity,
                    ).await {
                        Ok(true) => {}
                        Ok(false) => {
                            tracing::warn!("publisher lease lost; cancelling reconciliation");
                            break;
                        }
                        Err(error) => {
                            tracing::error!(%error, "publisher lease renewal failed; cancelling reconciliation");
                            break;
                        }
                    }
                }
            }
        }
        // Poll for desired-state changes once per second so a freshly patched
        // rollout is republished promptly and the fleet starts converging fast.
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
