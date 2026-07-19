//! `updatec`, the minimal Kubernetes control plane for `updated`. Reconciliation lives behind
//! the library so Kind tests can exercise the same code without mocking Kubernetes.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| "installing rustls crypto provider failed")?;
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
    if mode == "serve" {
        let addr = std::env::var("UPDATED_LISTEN").unwrap_or_else(|_| "0.0.0.0:8080".into());
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
        return updatec::gateway::serve(&addr, store, destination.prefix)
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
        );
        tokio::pin!(reconciliation);
        loop {
            tokio::select! {
                result = &mut reconciliation => {
                    match result {
                        Ok(digest) => tracing::info!(%digest, "desired state reconciled"),
                        Err(error) => tracing::error!(%error, "reconciliation failed; last publication remains active"),
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
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }
}
