//! The listeners. Data and health are separate sockets with separate connection budgets and
//! deadlines, and the TLS material behind them is reloaded in place so a rotated certificate does
//! not need a restart.

use super::*;

/// The plaintext health router: `/healthz` (and `/`) → 200, everything else 404. It serves no
/// repository content, so exposing it without mTLS reveals nothing — it exists only for the
/// orchestrator's probes, which cannot present a client certificate.
pub(crate) fn health_router() -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/", get(healthz))
}

/// Run the gateway: the mTLS data listener (repository objects, enrollment, telemetry) and the
/// plaintext health listener, until one of them fails.
///
/// `store`/`prefix` are the INITIAL destination and are the caller's to supply even though
/// [`reload_destination`] re-derives the same pair from `enrollment` every
/// [`MATERIAL_RELOAD_INTERVAL`]. The two are not the same rule: a gateway with no store cannot
/// serve, so the first build must block until it succeeds, while [`rebuild_destination`] is
/// deliberately fail-safe and keeps the live store on a transient apiserver blip. Building the
/// first one here would put a retry-until-ready loop inside a function whose contract is "already
/// listening".
pub async fn serve(
    addresses: GatewayAddresses,
    storage: crate::runtime::RepositoryStore,
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
    // Both the listener identity and the issuing CA are cert-manager Secrets rotated in place. They
    // are loaded here and then re-read on a timer, so a rotation lands in a running gateway.
    let server_config = Arc::new(Reloadable::new(updated::tls::server_config(
        &tls.cert,
        &tls.key,
        &tls.client_ca,
    )?));
    let ca = Arc::new(Reloadable::new(load_issuing_ca(&issuing_ca)?));
    tokio::spawn(reload_materials(
        tls.cert.clone(),
        tls.key.clone(),
        tls.client_ca.clone(),
        issuing_ca,
        server_config.clone(),
        ca.clone(),
    ));

    let data_listener = TcpListener::bind(&addresses.data).await?;
    let health_listener = TcpListener::bind(&addresses.health).await?;
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
        ca,
    });

    // Health: plaintext, no TLS, its own small connection budget.
    tokio::spawn(serve_plain(
        health_listener,
        health_router(),
        Arc::new(Semaphore::new(HEALTH_CONNECTIONS)),
    ));
    // Data: mTLS, runs on this task so `serve` stays alive for the whole process.
    serve_tls(
        data_listener,
        server_config,
        data_router,
        Arc::new(Semaphore::new(DATA_CONNECTIONS)),
        "data",
    )
    .await;
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

/// Re-read the mounted certificate material forever, swapping in each new value that loads cleanly.
///
/// Rebuilding unconditionally rather than diffing bytes keeps this to one code path; the work is a
/// few file reads a minute. A failed load — a partially-written rotation, a removed mount — is
/// logged and the previous value stays live, which is the fail-safe direction: the alternative is
/// dropping the fleet's only authenticated channel over a transient read.
pub(crate) async fn reload_materials(
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
    client_ca: std::path::PathBuf,
    issuing_ca: IssuingCaPaths,
    server_config: Arc<Reloadable<rustls::ServerConfig>>,
    ca: Arc<Reloadable<crate::join::IssuingCa>>,
) {
    loop {
        tokio::time::sleep(MATERIAL_RELOAD_INTERVAL).await;
        match updated::tls::server_config(&cert, &key, &client_ca) {
            Ok(config) => server_config.set(config),
            Err(error) => {
                tracing::warn!(%error, "reloading gateway TLS material failed; keeping the loaded one")
            }
        }
        match load_issuing_ca(&issuing_ca) {
            Ok(loaded) => ca.set(loaded),
            Err(error) => {
                tracing::warn!(%error, "reloading the issuing CA failed; keeping the loaded one")
            }
        }
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
    server_config: Arc<Reloadable<rustls::ServerConfig>>,
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
        let acceptor = TlsAcceptor::from(server_config.get());
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
            let app = app.layer(Extension(identity));
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
