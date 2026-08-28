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
    let metrics_address: Option<std::net::SocketAddr> =
        std::env::var(updatec::env::METRICS_ADDRESS)
            .ok()
            .filter(|value| !value.is_empty())
            .map(|value| {
                value
                    .parse()
                    .map_err(|e| format!("{}: {e}", updatec::env::METRICS_ADDRESS))
            })
            .transpose()?;
    let alert_url = std::env::var(updatec::env::ALERT_URL)
        .ok()
        .filter(|value| !value.is_empty());
    let alert_token_file: Option<std::path::PathBuf> =
        std::env::var(updatec::env::ALERT_TOKEN_FILE)
            .ok()
            .filter(|value| !value.is_empty())
            .map(Into::into);
    let client = kube::Client::try_default().await?;
    let namespace =
        std::env::var(updatec::env::NAMESPACE).unwrap_or_else(|_| "updated-system".into());
    let repository = std::env::var(updatec::env::REPOSITORY).unwrap_or_else(|_| "default".into());
    let public_url = std::env::var(updatec::env::PUBLIC_URL)
        .map_err(|_| format!("{} is required", updatec::env::PUBLIC_URL))?;
    // This origin is signed into every node's durable enrollment bundle. Refuse it before either
    // mode starts so a typo or URL credential can never become fleet state.
    let public_url = updated::http::network_endpoint(
        &public_url,
        updated::http::EndpointTransport::HttpsOnly,
        updatec::env::PUBLIC_URL,
    )?
    .to_string();
    if mode == "serve" {
        let addr = std::env::var(updatec::env::LISTEN).unwrap_or_else(|_| "0.0.0.0:8080".into());
        let health_addr =
            std::env::var(updatec::env::HEALTH_LISTEN).unwrap_or_else(|_| "0.0.0.0:8081".into());
        let enrollment = updatec::gateway::EnrollmentContext {
            client: client.clone(),
            namespace: namespace.clone(),
            repository: repository.clone(),
            public_url,
            lock_name: std::env::var(updatec::env::ENROLLMENT_LOCK_NAME)
                .ok()
                .filter(|name| !name.trim().is_empty())
                .ok_or_else(|| {
                    format!(
                        "{} is required in gateway mode",
                        updatec::env::ENROLLMENT_LOCK_NAME
                    )
                })?,
        };
        // The server identity and public client-trust bundle are mounted separately. This lets an
        // operator stage old+new roots without editing a cert-manager-owned leaf Secret.
        let tls_dir = std::env::var(updatec::env::GATEWAY_TLS_DIR)
            .unwrap_or_else(|_| "/etc/gateway-tls".into());
        let tls = updatec::gateway::GatewayTls {
            cert: std::path::Path::new(&tls_dir).join("tls.crt"),
            key: std::path::Path::new(&tls_dir).join("tls.key"),
            client_ca: std::env::var(updatec::env::GATEWAY_CLIENT_CA)
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|_| "/etc/client-ca/ca.crt".into()),
            enrollment_client_cn: std::env::var(updatec::env::ENROLLMENT_CLIENT_CN)
                .unwrap_or_else(|_| "updated-agent".into()),
        };
        // The join endpoint signs node CSRs with the fleet CA — the same cert-manager CA the gateway
        // trusts as its client CA, mounted here with its private key so leaves it mints are accepted
        // on the mTLS listener. Standard cert-manager keys are tls.crt / tls.key.
        let ca_dir = std::env::var(updatec::env::ISSUING_CA_DIR)
            .unwrap_or_else(|_| "/etc/issuing-ca".into());
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
            enrollment,
            issuing_ca,
            tls,
        )
        .await
        .map_err(Into::into);
    }
    let state =
        std::env::var(updatec::env::STATE_DIR).unwrap_or_else(|_| "/var/lib/updatec".into());
    let backend_runtime = updatec::runtime::BackendRuntimeConfig {
        image: std::env::var(updatec::env::HEALTHPROXY_IMAGE).map_err(|_| {
            format!(
                "{} is required in controller mode",
                updatec::env::HEALTHPROXY_IMAGE
            )
        })?,
        image_pull_policy: std::env::var(updatec::env::HEALTHPROXY_PULL_POLICY)
            .unwrap_or_else(|_| "IfNotPresent".into()),
    };
    // Validated HERE, where the environment is read, like every other process-startup setting: an
    // empty image or a misspelled pull policy is a chart value nobody can fix from inside the loop,
    // and checking it per pass only turned it into an error log once a second while every
    // UpdateBackend kept whatever status it last had.
    updatec::runtime::validate_backend_runtime(&backend_runtime)?;
    let identity = std::env::var(updatec::env::HOSTNAME)
        .unwrap_or_else(|_| format!("updatec-{}", std::process::id()));
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
                .map_err(|error| format!("{}: {error}", updatec::env::ALERT_URL))?,
        )),
        None => None,
    };
    let report_shards = updated_contracts::telemetry::parse_fleet_report_max_shards(
        std::env::var(updated_contracts::telemetry::FLEET_REPORT_MAX_SHARDS_ENV)
            .ok()
            .as_deref(),
    )?;
    let mut hooks = updatec::runtime::ReconcileHooks::new(sink).with_report_shards(report_shards);
    // Start watching the fleet BEFORE the loop, and on every replica rather than only the leader:
    // a follower that already holds a synced store takes over instantly instead of paying a
    // full-fleet LIST at the exact moment leadership moves. `start` returns only once the store is
    // complete, so the first pass never plans against a half-filled view.
    let fleet = updatec::runtime::FleetWatch::start(client.clone(), &namespace, &repository)
        .await
        .map_err(|error| format!("watching the fleet failed: {error}"))?;
    loop {
        // A frozen store is indistinguishable from a fleet that has stopped changing, so this
        // replica must not keep planning against one. Exiting hands the problem to Kubernetes,
        // which restarts the pod into a fresh watch; carrying on would publish decisions from a
        // view that stopped advancing at an unknown moment.
        if !fleet.is_live() {
            return Err("the fleet watch stopped; restarting to re-establish it".into());
        }
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
                hooks.end_leadership_epoch();
                // A follower has no fleet view: serving the last leader-epoch snapshot as if it
                // were current let a scrape read week-old gauges as fresh. The failure counter
                // stays — it is this process's own history.
                metrics.write().expect("metrics lock").last = None;
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
            Err(error) => {
                hooks.end_leadership_epoch();
                tracing::error!(%error, "leader lease operation failed");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
        }
        // The future borrows `hooks` mutably, so it is scoped: the failure handling below needs
        // `hooks` again, which is only possible once the (finished or cancelled) future is dropped.
        //
        // BOTH halves of the pass run inside the watchdog below, not just publication. Backend
        // materialization is a full fleet LIST plus, per backend, an access check, inventory
        // ConfigMap applies, SA/Role/RoleBinding/Deployment applies and a status patch; run ahead
        // of the watchdog it could outlast the 15s lease on a throttled apiserver, and this replica
        // would then walk into publication as a former leader while a peer had already taken over.
        let result = {
            let reconciliation = async {
                // One read of the watched fleet per pass, shared by both halves: they answer
                // different questions about the same objects, and nothing between them writes an
                // UpdateAgent. This is a clone of `Arc` handles out of the reflector store, not a
                // request — the apiserver sees nothing here.
                let agents = fleet.agents();
                if let Err(error) = updatec::runtime::reconcile_backends(
                    client.clone(),
                    &namespace,
                    &repository,
                    &backend_runtime,
                    &agents,
                )
                .await
                {
                    // Backend materialization is an independent projection of the same CRD
                    // inventory. A Kubernetes/RBAC outage here must be visible and retried, but it
                    // must not freeze signed update publication for agents that do not serve
                    // traffic — so it is logged and the pass continues, never propagated.
                    tracing::error!(%error, "backend reconciliation failed; existing projections remain active");
                }
                updatec::runtime::reconcile_once(
                    updatec::runtime::ReconcileRequest {
                        client: client.clone(),
                        namespace: &namespace,
                        repository_name: &repository,
                        state_dir: std::path::Path::new(&state),
                        public_url: &public_url,
                        identity: &identity,
                        agents,
                    },
                    &mut hooks,
                )
                .await
            };
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
            Some(Ok(updatec::runtime::ReconcileOutcome::Reconciled { digest, snapshot })) => {
                tracing::info!(%digest, "desired state reconciled");
                if let Some(snapshot) = snapshot {
                    metrics.write().expect("metrics lock").last = Some(snapshot);
                }
            }
            Some(Ok(updatec::runtime::ReconcileOutcome::WaitingForRepository)) => {
                // A chart is normally installed before its first repository CR, and deletion may
                // leave this controller running. Neither is an error or a status write against an
                // object known not to exist. Do not expose the last incarnation's fleet gauges as
                // current while waiting for the next one.
                metrics.write().expect("metrics lock").last = None;
                tracing::debug!(%repository, "waiting for UpdateRepository");
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
            None => hooks.end_leadership_epoch(),
        }
        // Poll for desired-state changes once per second so a freshly patched
        // rollout is republished promptly and the fleet starts converging fast.
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
