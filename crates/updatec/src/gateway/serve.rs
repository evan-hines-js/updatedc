//! The listeners. Data and health are separate sockets with separate connection budgets and
//! deadlines, and the TLS material behind them is reloaded in place so a rotated certificate does
//! not need a restart.

use super::*;
use rustls::pki_types::pem::PemObject;

/// Repository creation and Secret rotation run on different clocks. The former is a startup
/// dependency that the operator may satisfy a moment after the pod starts; the latter is steady
/// maintenance where a minute avoids needless API and object-store churn. Keeping these bounds
/// distinct prevents a normal creation race from holding enrollment offline for a full minute.
const INITIAL_REPOSITORY_RETRY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// The plaintext process-health router. Liveness says the process can still make progress;
/// readiness says the authenticated data listener has a configured repository behind it. Keeping
/// those as different facts lets the gateway wait for its operator-created `UpdateRepository`
/// without either receiving traffic early or being killed in a configuration crash loop.
pub(crate) fn health_router(readiness: Arc<std::sync::atomic::AtomicBool>) -> Router {
    Router::new()
        .route("/livez", get(healthz))
        .route("/readyz", get(readyz))
        .with_state(readiness)
}

/// Run the gateway: liveness starts immediately, readiness remains closed until the initial object
/// destination exists, and the mTLS data listener then serves for the process lifetime. Initial
/// destination acquisition and later reloads live in this one lifecycle so Kubernetes cannot kill
/// a healthy process merely because the operator has not created its repository yet.
pub async fn serve(
    addresses: GatewayAddresses,
    enrollment: EnrollmentContext,
    issuing_ca: IssuingCaPaths,
    tls: GatewayTls,
) -> std::io::Result<()> {
    if tls.enrollment_client_cn.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the enrollment client Common Name must not be empty",
        ));
    }
    let health_listener = TcpListener::bind(&addresses.health).await?;
    let readiness = Arc::new(std::sync::atomic::AtomicBool::new(false));
    tokio::spawn(serve_plain(
        health_listener,
        health_router(readiness.clone()),
        Arc::new(Semaphore::new(HEALTH_CONNECTIONS)),
    ));

    let storage = loop {
        match crate::runtime::repository_store(
            enrollment.client.clone(),
            &enrollment.namespace,
            &enrollment.repository,
        )
        .await
        {
            Ok(configured) => break configured,
            Err(error) => {
                tracing::warn!(%error, "gateway storage is not configured yet; retrying");
                tokio::time::sleep(INITIAL_REPOSITORY_RETRY_INTERVAL).await;
            }
        }
    };

    // Both the listener identity and the issuing CA are cert-manager Secrets rotated in place.
    // Install them only as one verified snapshot: a cross-Secret skew keeps the previous coherent
    // generation instead of minting leaves the listener cannot authenticate.
    let materials = Arc::new(Reloadable::new(load_gateway_materials(&tls, &issuing_ca)?));
    tokio::spawn(reload_materials(
        GatewayTls {
            cert: tls.cert.clone(),
            key: tls.key.clone(),
            client_ca: tls.client_ca.clone(),
            enrollment_client_cn: tls.enrollment_client_cn.clone(),
        },
        issuing_ca,
        materials.clone(),
    ));

    let data_listener = TcpListener::bind(&addresses.data).await?;
    tracing::info!(
        data = %addresses.data, health = %addresses.health,
        "repository gateway listening (mTLS data + plaintext health)"
    );

    let destination = Arc::new(Reloadable::new(Destination {
        store: storage.objects,
        signer: storage.signer,
        upload_signer: storage.upload_signer,
        prefix: Arc::from(storage.destination.prefix),
    }));
    tokio::spawn(reload_destination(
        enrollment.client.clone(),
        enrollment.namespace.clone(),
        enrollment.repository.clone(),
        destination.clone(),
    ));
    let content = ContentState { destination };
    // Enrollment is a route on the one mTLS data listener now: the shared fleet enrollment cert
    // authenticates it, so there is no separate client-cert-less listener.
    let data_router = data_router(DataState {
        content,
        authorization: Arc::new(AuthorizationMemo::default()),
        enrollment,
        enrollment_client_cn: Arc::from(tls.enrollment_client_cn),
    });

    // Data: mTLS, runs on this task so `serve` stays alive for the whole process. Publish readiness
    // only after the listener, trust material, destination, and router all exist.
    readiness.store(true, std::sync::atomic::Ordering::Release);
    serve_tls(
        data_listener,
        materials,
        data_router,
        Arc::new(Semaphore::new(DATA_CONNECTIONS)),
        "data",
    )
    .await;
    readiness.store(false, std::sync::atomic::Ordering::Release);
    Ok(())
}

pub(crate) fn load_issuing_ca(paths: &IssuingCaPaths) -> std::io::Result<crate::join::IssuingCa> {
    let cert = foundation::file::read_bounded_regular_string(
        &paths.cert,
        updated::tls::TLS_MATERIAL_MAX_BYTES,
        foundation::file::FinalSymlink::Follow,
    )
    .map_err(|error| std::io::Error::other(format!("reading issuing CA certificate: {error}")))?;
    let key =
        updated::tls::read_private_key_pem(&paths.key, foundation::file::FinalSymlink::Follow)
            .map_err(|error| std::io::Error::other(format!("reading issuing CA key: {error}")))?;
    crate::join::IssuingCa::load(&cert, &key)
}

/// Load the listener verifier and leaf issuer as one generation, proving the issuer by minting a
/// throwaway client leaf and checking it through the exact verifier returned in this snapshot.
/// A CA bundle may contain both old and new roots, which is how a rollover is staged without
/// rejecting either generation of node leaf.
pub(crate) fn load_gateway_materials(
    tls: &GatewayTls,
    issuing_ca: &IssuingCaPaths,
) -> std::io::Result<GatewayMaterials> {
    let issuing_ca = load_issuing_ca(issuing_ca)?;
    let key = updated::csr::generate_key().map_err(|error| {
        std::io::Error::other(format!("generating CA trust probe key: {error}"))
    })?;
    let csr = updated::csr::csr_for(&key, "gateway issuer trust probe").map_err(|error| {
        std::io::Error::other(format!("generating CA trust probe CSR: {error}"))
    })?;
    let leaf = issuing_ca
        .sign_client_csr("gateway-materials", "trust-probe", &csr)
        .map_err(|error| std::io::Error::other(format!("signing CA trust probe: {error}")))?;
    let leaf = rustls::pki_types::CertificateDer::from_pem_slice(leaf.as_bytes())
        .map_err(|error| std::io::Error::other(format!("parsing CA trust probe: {error}")))?;
    let server_config = updated::tls::server_config_accepting_issued_client(
        &tls.cert,
        &tls.key,
        &tls.client_ca,
        &leaf,
    )?;
    Ok(GatewayMaterials {
        server_config: Arc::new(server_config),
        issuing_ca,
    })
}

/// Re-read the mounted certificate material forever, swapping in each new value that loads cleanly.
///
/// Rebuilding unconditionally rather than diffing bytes keeps this to one code path; the work is a
/// few file reads a minute. A failed load — a partially-written rotation, a removed mount — is
/// logged and the previous value stays live, which is the fail-safe direction: the alternative is
/// dropping the fleet's only authenticated channel over a transient read.
pub(crate) async fn reload_materials(
    tls: GatewayTls,
    issuing_ca: IssuingCaPaths,
    materials: Arc<Reloadable<GatewayMaterials>>,
) {
    loop {
        tokio::time::sleep(MATERIAL_RELOAD_INTERVAL).await;
        reload_materials_once(&tls, &issuing_ca, &materials);
    }
}

pub(crate) fn reload_materials_once(
    tls: &GatewayTls,
    issuing_ca: &IssuingCaPaths,
    materials: &Reloadable<GatewayMaterials>,
) {
    match load_gateway_materials(tls, issuing_ca) {
        Ok(loaded) => materials.set(loaded),
        Err(error) => tracing::warn!(
            %error,
            "reloading coherent gateway TLS and issuing-CA material failed; keeping the loaded generation"
        ),
    }
}

/// Rebuild the object store forever, on the same timer and with the same fail-safe rule as the
/// certificate material: a build that fails leaves the working store live.
///
/// Object-store credentials are baked in at construction — deliberately, since
/// `runtime::repository_store` is also the credential-resolution path the controller uses — so
/// nothing about a live store follows a rotated key or a renewed STS session token. The controller
/// rebuilt per reconcile and the gateway never did, which is the whole asymmetry: with one-hour
/// temporary credentials the entire data plane began answering 502 after an hour while the
/// `UpdateRepository` still reported Ready. Rebuilding unconditionally (rather than diffing the
/// spec) keeps this to one code path, and it picks up a changed `destination.prefix` with it. The
/// hot path is untouched: handlers read one `Arc` clone per request.
pub(crate) async fn reload_destination(
    client: Client,
    namespace: String,
    repository: String,
    destination: Arc<Reloadable<Destination>>,
) {
    loop {
        tokio::time::sleep(MATERIAL_RELOAD_INTERVAL).await;
        rebuild_destination(&client, &namespace, &repository, &destination).await;
    }
}

/// One rebuild, with the fail-safe: a store that cannot be built leaves the live one serving.
/// Separate from the timer above so the rule is testable — a rebuild that swapped in nothing on
/// failure would take the data plane down for a transient apiserver blip.
pub(crate) async fn rebuild_destination(
    client: &Client,
    namespace: &str,
    repository: &str,
    destination: &Reloadable<Destination>,
) {
    match crate::runtime::repository_store(client.clone(), namespace, repository).await {
        Ok(storage) => destination.set(Destination {
            store: storage.objects,
            signer: storage.signer,
            upload_signer: storage.upload_signer,
            prefix: Arc::from(storage.destination.prefix),
        }),
        Err(error) => {
            tracing::warn!(%error, "rebuilding the repository object store failed; keeping the loaded one")
        }
    }
}

/// The pause after a failed `accept` before trying again.
///
/// The failures that matter are the PERSISTENT ones — EMFILE/ENFILE/ENOBUFS — where the process has
/// no descriptor to accept onto and retrying cannot clear the condition. Without a pause the loop
/// is a tight spin that saturates a core and emits one log line per iteration, turning recoverable
/// fd pressure into a gateway outage. Never tear the listener down instead: that crash-loops the
/// process precisely when it is resource-starved.
pub(crate) const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// Accept one connection, pausing after each failure. The single accept chokepoint — both listeners
/// go through it, so neither can be written without the backoff.
pub(crate) async fn accept_next(
    listener: &TcpListener,
    label: &'static str,
) -> (tokio::net::TcpStream, std::net::SocketAddr) {
    loop {
        match listener.accept().await {
            Ok(accepted) => return accepted,
            Err(error) => {
                tracing::warn!(%error, listener = label, "gateway accept failed; pausing before retry");
                tokio::time::sleep(ACCEPT_ERROR_BACKOFF).await;
            }
        }
    }
}

/// Accept TLS connections and serve `app` on each. A client that fails the handshake never reaches
/// a handler.
pub(crate) async fn serve_tls(
    listener: TcpListener,
    materials: Arc<Reloadable<GatewayMaterials>>,
    app: Router,
    budget: Arc<Semaphore>,
    label: &'static str,
) {
    loop {
        let (tcp, peer) = accept_next(&listener, label).await;
        let Ok(permit) = budget.clone().acquire_owned().await else {
            return;
        };
        // Take the current identity per connection, so a rotated certificate applies to the next
        // handshake rather than to the next process.
        let materials = materials.get();
        let acceptor = TlsAcceptor::from(materials.server_config.clone());
        let app = app.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let tls = match timeout(IO_TIMEOUT, acceptor.accept(tcp)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    tracing::debug!(%peer, %error, listener = label, "rejected client at the TLS handshake");
                    return;
                }
                Err(_) => {
                    tracing::debug!(%peer, listener = label, "TLS handshake timed out");
                    return;
                }
            };
            // Bind the CA-verified client identity to every request on this connection, so a
            // per-node authorization check reads the trusted cert CN rather than the node's
            // self-claimed path. `None` is used only by the plaintext health listener.
            let identity = peer_identity(tls.get_ref().1);
            // The handler signs through the same generation that authenticated this connection,
            // even if a reload lands while the request is in flight.
            let app = app.layer(Extension(identity)).layer(Extension(materials));
            serve_http(TokioIo::new(tls), app, CONNECTION_TIMEOUT).await;
        });
    }
}

/// The plaintext accept loop (health only), bounded by its own connection budget.
pub(crate) async fn serve_plain(listener: TcpListener, app: Router, budget: Arc<Semaphore>) {
    loop {
        let (tcp, _) = accept_next(&listener, "health").await;
        let Ok(permit) = budget.clone().acquire_owned().await else {
            return;
        };
        let app = app.clone();
        tokio::spawn(async move {
            let _permit = permit;
            serve_http(TokioIo::new(tcp), app, HEALTH_CONNECTION_TIMEOUT).await;
        });
    }
}

/// Serve one connection's requests with hyper, dispatching into the Axum `Router`. HTTP/1 only —
/// matching the original hand-rolled server and, deliberately, refusing the HTTP/2 prior-knowledge
/// path (the TLS configs advertise no h2 ALPN), so there is no h2 frame-read phase left unbounded.
/// `header_read_timeout` bounds the request-line/header phase so a client that completes the
/// handshake and then trickles (or withholds) its headers cannot pin the connection — and thus its
/// budget permit — indefinitely (slow-loris), and `deadline` bounds everything after it, including
/// the response-write phase no per-operation timeout can reach.
///
/// The deadline is the caller's because it is the one thing here that is not shared between the two
/// listeners: it is sized for authenticated control exchanges on [`CONNECTION_TIMEOUT`] and for a
/// two-byte probe answer on [`HEALTH_CONNECTION_TIMEOUT`]. Payload bytes always move directly
/// between the client and S3 under a short-lived capability.
pub(crate) async fn serve_http<I>(io: I, app: Router, deadline: Duration)
where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
{
    let service = TowerToHyperService::new(app);
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(IO_TIMEOUT);
    match timeout(deadline, builder.serve_connection(io, service)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => tracing::debug!(%error, "gateway connection error"),
        Err(_) => tracing::debug!("gateway connection exceeded its overall deadline; dropping it"),
    }
}

pub(crate) async fn healthz() -> &'static str {
    "ok"
}

pub(crate) async fn readyz(
    State(readiness): State<Arc<std::sync::atomic::AtomicBool>>,
) -> StatusCode {
    if readiness.load(std::sync::atomic::Ordering::Acquire) {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    }
}
