//! Best-effort rollout telemetry. A remotely enrolled node requests one exact report-object
//! capability from its routing gateway and writes its signed state directly to S3. Local/offline
//! routing has no capability endpoint and therefore emits no heartbeat.

use std::time::{Duration, Instant};

use updated::config::Routing;
use updated_contracts::dataflow::{FileSnapshot, OutputPublication, MAX_DATAFLOW_BODY_BYTES};
use updated_contracts::telemetry::{encode_signed_report, NodeReport};

async fn upload_via_capability(
    control_client: &reqwest::Client,
    object_client: &reqwest::Client,
    endpoint: &str,
    body: Vec<u8>,
    what: &str,
) -> Result<(), CapabilityWriteError> {
    let response = control_client
        .get(endpoint)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .map_err(|error| {
            CapabilityWriteError::Failed(
                updated::http::redacted_reqwest_error(
                    &format!("requesting {what} capability"),
                    &error,
                )
                .to_string(),
            )
        })?;
    if response.status() == reqwest::StatusCode::FORBIDDEN {
        return Err(CapabilityWriteError::Refused);
    }
    if !response.status().is_success() {
        return Err(CapabilityWriteError::Failed(format!(
            "requesting {what} capability returned HTTP {}",
            response.status()
        )));
    }
    let bytes = updated::http::read_bounded(
        response,
        "object write capability",
        updated_contracts::dataflow::MAX_CAPABILITY_BODY_BYTES,
    )
    .await
    .map_err(|error| CapabilityWriteError::Failed(error.to_string()))?;
    let capability: updated_contracts::dataflow::UploadCapability = serde_json::from_slice(&bytes)
        .map_err(|error| {
            CapabilityWriteError::Failed(format!("decoding {what} capability: {error}"))
        })?;
    capability
        .validate()
        .map_err(CapabilityWriteError::Failed)?;
    let mut form = reqwest::multipart::Form::new();
    for (name, value) in capability.fields {
        form = form.text(name, value);
    }
    // S3 requires the file field last. `Part::bytes` also lets reqwest calculate the multipart
    // length up front; S3 evaluates the signed `content-length-range` against this upload.
    form = form.part("file", reqwest::multipart::Part::bytes(body));
    let response = object_client
        .post(&capability.url)
        .timeout(Duration::from_secs(5))
        .multipart(form)
        .send()
        .await
        .map_err(|error| {
            CapabilityWriteError::Failed(
                updated::http::redacted_reqwest_error(
                    &format!("writing {what} to object storage"),
                    &error,
                )
                .to_string(),
            )
        })?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(CapabilityWriteError::Failed(format!(
            "writing {what} to object storage returned HTTP {}",
            response.status()
        )))
    }
}

#[derive(Debug)]
enum CapabilityWriteError {
    /// The mTLS control plane rejected the live node identity. A 403 from S3 itself is not this
    /// verdict: signed-URL expiry and storage policy failures remain ordinary transient errors.
    Refused,
    Failed(String),
}

impl std::fmt::Display for CapabilityWriteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused => formatter.write_str("the capability endpoint refused this identity"),
            Self::Failed(message) => formatter.write_str(message),
        }
    }
}

/// The node's own identity, derived from the exact routing target it resolves
/// (`<prefix>/agents/<node>.json`), read through the one parser of that layout. Returns `None` if
/// the assignment is not a routing target naming a valid node identity, in which case the node
/// simply never reports.
pub fn node_identity(routing: &Routing) -> Option<String> {
    updated_contracts::telemetry::split_assignment_path(&routing.assignment)
        .map(|(_, node)| node.to_string())
}

/// What the node is running right now — the signed payload of one heartbeat, gathered by the
/// caller from the assignment it just acted on and its own committed install record.
pub struct RunningState<'a> {
    /// The deployment identity the control plane currently assigns this node.
    pub deployment: &'a str,
    /// Digest of the exact signed assignment document behind that deployment name. This is what
    /// lets the control plane stage a change that keeps the name — a new archive, argument,
    /// input file or resolved dependency — one `maxUnavailable` batch at a time.
    pub assignment_sha256: &'a str,
    /// The version actually answering, empty before the first install completes.
    pub version: &'a str,
    /// The SHA-256 of the archive that version was installed from, empty alongside `version`.
    pub archive_sha256: &'a str,
    /// The signed provider-set document whose reconciler is actually installed.
    pub provider_set_sha256: &'a str,
    /// Settled: acted on the assignment and healthy. Never true mid-rollout.
    pub healthy: bool,
    /// An update transaction is in flight: this node committed an update whose confirmation window
    /// has not closed. It is the OTHER half of an unsettled report — the half that says the
    /// transaction genuinely ran, told apart from an ordinary readiness failure — and only this
    /// writer can tell them apart, so it is reported rather than guessed at by a reader.
    pub updating: bool,
    /// This node has DURABLY REJECTED the release its assignment names: either its application
    /// archive or provider-set document is in the node's content-addressed rejection record. Only
    /// this node knows it — the record covers a candidate that failed its ACTIVATION as well as one
    /// that failed its confirmation window, and the first runs no completed update transaction, so
    /// no observer of the report stream can infer it.
    pub rejected: bool,
    /// Latest successful opaque node-state fingerprint, when one is currently publishable.
    pub fingerprint: Option<&'a updated_contracts::telemetry::Fingerprint>,
    /// The node's layout and the manifest digest identifying the running archive — the two inputs
    /// [`load_outputs`] needs to find this release's output snapshot. The outputs themselves are
    /// read here, not by the caller, so the rule that only a settled report carries them is
    /// enforced in exactly one place.
    pub paths: &'a updated::config::Paths,
    pub manifest_sha256: &'a str,
}

/// Read and validate the running archive's bounded output snapshot. A missing file means the
/// reconciler emitted no outputs; malformed or oversized data is omitted rather than weakening
/// the health report itself.
pub fn load_outputs(paths: &updated::config::Paths, manifest_sha256: &str) -> Option<FileSnapshot> {
    if manifest_sha256.is_empty() {
        return None;
    }
    let path = paths.reconciler_output_snapshot(manifest_sha256);
    // The size bound is the *envelope* bound worked backwards (see
    // `MAX_OUTPUT_SNAPSHOT_BYTES`): a snapshot larger than this signs into a report no hop on the
    // publish path would accept, and since outputs ride only on healthy reports, attaching it
    // would silently drain a healthy node forever. Omitting the outputs keeps the node published.
    let bytes = match foundation::file::read_bounded_regular(
        &path,
        MAX_DATAFLOW_BODY_BYTES,
        foundation::file::FinalSymlink::Refuse,
    ) {
        Ok(bytes) => bytes,
        Err(error) => {
            crate::warn(&format!(
                "reconciler output snapshot is not a bounded regular file ({error}); omitting outputs"
            ));
            return None;
        }
    };
    let snapshot: FileSnapshot = match serde_json::from_slice(&bytes) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            crate::warn(&format!(
                "decoding reconciler output snapshot failed ({error}); omitting outputs"
            ));
            return None;
        }
    };
    if let Err(error) = snapshot.validate() {
        crate::warn(&format!(
            "invalid reconciler output snapshot ({error}); omitting outputs"
        ));
        return None;
    }
    Some(snapshot)
}

/// The report endpoint's standing refusal of this node, and when reporting may next be attempted.
///
/// A `403` there is a verdict about identity, not a transient failure: the gateway admits a report
/// only from a provisioned node whose live `UpdateAgent` pins the public key in the presented leaf.
/// Transient control-plane failures return 5xx; a `403` is reserved for a missing, revoked, or
/// malformed live identity and will keep failing until that identity changes.
///
/// So a refusal drops reporting to the slowest cadence the agent already has, the agent-check
/// interval, and warns once. Nothing is given up: a report that would be refused carries no
/// information to any reader, and a node whose identity is later completed recovers on its own at
/// that cadence without a restart.
#[derive(Default)]
pub struct Refusal {
    /// When a report may next be attempted. `None` while the endpoint is accepting — which is also
    /// what re-arms the single warning, so a later refusal is reported again rather than silently.
    retry_after: Option<Instant>,
}

#[derive(Default)]
pub struct OutputPublisher {
    current: Option<CachedOutput>,
}

struct CachedOutput {
    publication: OutputPublication,
}

impl OutputPublisher {
    async fn publish(
        &mut self,
        control_client: &reqwest::Client,
        object_client: &reqwest::Client,
        control_base: &str,
        node: &str,
        state: &RunningState<'_>,
    ) -> Option<String> {
        if !state.healthy {
            return None;
        }
        let Ok(node_identity) = updated_contracts::identity::ResourceName::new(node) else {
            crate::warn("invalid node identity; skipping output publication");
            return None;
        };
        let snapshot = load_outputs(state.paths, state.manifest_sha256)?;
        let same = self.current.as_ref().is_some_and(|current| {
            current.publication.node == node
                && current.publication.deployment == state.deployment
                && current.publication.assignment_sha256 == state.assignment_sha256
                && current.publication.archive_sha256 == state.archive_sha256
                && current.publication.snapshot == snapshot
        });
        if !same {
            self.current = Some(CachedOutput {
                publication: OutputPublication {
                    schema: OutputPublication::SCHEMA,
                    node: node_identity,
                    deployment: state.deployment.to_string(),
                    assignment_sha256: state.assignment_sha256.to_string(),
                    archive_sha256: state.archive_sha256.to_string(),
                    snapshot,
                },
            });
        }
        let current = self
            .current
            .as_ref()
            .expect("created above or already present");
        // Re-upload before every report. A previous success proves nothing about the current object
        // store: the repository can move buckets without changing this assignment, and an object
        // can be deleted independently. The PUT is idempotent; skipping it would report a digest
        // whose bytes may no longer exist, wedging every dependent until the output changed.
        let body = match current.publication.to_bounded_body() {
            Ok(body) => body,
            Err(error) => {
                crate::warn(&format!(
                    "preparing node outputs failed ({error}); omitting them"
                ));
                return None;
            }
        };
        let target = updated_contracts::dataflow::outputs_url(control_base);
        let output_sha256 = updated_contracts::digest::sha256_bytes(&body);
        if let Err(error) =
            upload_via_capability(control_client, object_client, &target, body, "node outputs")
                .await
        {
            crate::warn(&format!(
                "publishing node outputs through {target} failed ({error}); omitting them from telemetry"
            ));
            return None;
        }
        Some(output_sha256)
    }
}

impl Refusal {
    /// Whether a report may be attempted now.
    fn admits(&self, now: Instant) -> bool {
        self.retry_after.is_none_or(|at| now >= at)
    }

    /// Record a refusal, returning whether this is the first of an episode (and so the one that
    /// warns).
    fn refused(&mut self, now: Instant, backoff: Duration) -> bool {
        let first = self.retry_after.is_none();
        self.retry_after = Some(now + backoff);
        first
    }

    /// The endpoint accepted a report: full cadence resumes and the next refusal warns.
    fn accepted(&mut self) {
        self.retry_after = None;
    }
}

/// Write the node's running state through its routing gateway. Strictly best-effort: any
/// error (local routing, no derivable identity, network failure, non-success status)
/// is logged and swallowed so reporting can never disrupt the update loop.
///
/// `backoff` is how long a refused node stays quiet before trying again (see [`Refusal`]).
pub struct ReportChannel<'a> {
    pub control_client: &'a reqwest::Client,
    pub object_client: &'a reqwest::Client,
    pub control_base: Option<&'a str>,
    pub node: Option<&'a str>,
    pub signing_key: Option<&'a [u8]>,
    pub refusal_backoff: Duration,
}

pub async fn report_running_state(
    channel: &ReportChannel<'_>,
    state: &RunningState<'_>,
    refusal: &mut Refusal,
    outputs: &mut OutputPublisher,
) {
    let (Some(control_base), Some(node)) = (channel.control_base, channel.node) else {
        return;
    };
    // Checked before the report is even built: a refused node pays no signing, no output read, and
    // no request until its backoff elapses.
    if !refusal.admits(Instant::now()) {
        return;
    }
    // No key means nothing publishable. A report is a signed DSSE envelope — there is no unsigned
    // form — and writing one no reader could verify would be worse than writing nothing: it would
    // OVERWRITE this node's last good report, so a consumer that had a fresh healthy record would be
    // left with an unverifiable one and drain the node. Staying quiet leaves the previous report to
    // age out honestly on its own freshness bound.
    let Some(key) = channel.signing_key else {
        crate::warn("no telemetry signing key available; skipping the rollout heartbeat");
        return;
    };
    let reconciliation = match updated::reconciler::read_last_reconciliation(
        &state.paths.last_reconciliation,
    ) {
        Ok(Some(record)) => Some(record),
        Ok(None) if state.version.is_empty() => None,
        Ok(None) => {
            crate::warn(
                "the installed release has no reconciliation evidence; skipping rollout telemetry",
            );
            return;
        }
        Err(error) => {
            crate::warn(&format!(
                "reading the last reconciliation record failed ({error}); skipping rollout telemetry"
            ));
            return;
        }
    };
    let Ok(mut report) = NodeReport::new(
        node,
        state.deployment,
        state.assignment_sha256,
        state.version,
        state.archive_sha256,
        state.provider_set_sha256,
        state.healthy,
    ) else {
        crate::warn("invalid node identity; skipping rollout telemetry");
        return;
    };
    report.updating = state.updating;
    report.rejected = state.rejected;
    report.fingerprint = if state.healthy {
        state.fingerprint.cloned()
    } else {
        None
    };
    report.reconciliation = reconciliation;
    // Store the private object first, then bind its exact bytes into the signed report. A failed
    // output write cannot make an old object look current, and storage cannot substitute new bytes
    // under the same node key.
    report.output_sha256 = outputs
        .publish(
            channel.control_client,
            channel.object_client,
            control_base,
            node,
            state,
        )
        .await;
    // Signed with the node's per-node key so the throttle and the health proxy can verify authenticity
    // end-to-end, rather than trusting the write hop.
    // Encoded under the ceiling every reader decodes with, so an over-large report fails here,
    // on the one machine that can do anything about it, rather than being dropped by the fleet.
    let body = match encode_signed_report(&report, key) {
        Ok(body) => body,
        Err(error) => {
            crate::warn(&format!(
                "preparing rollout telemetry failed ({error}); continuing"
            ));
            return;
        }
    };
    let target = updated_contracts::dataflow::report_url(control_base);
    let result = upload_via_capability(
        channel.control_client,
        channel.object_client,
        &target,
        body,
        "node report",
    )
    .await;
    match result {
        Ok(()) => refusal.accepted(),
        Err(CapabilityWriteError::Refused) => {
            if refusal.refused(Instant::now(), channel.refusal_backoff) {
                crate::warn(&format!(
                    "rollout telemetry to {target} was refused (403): this node is not an enrolled \
                     member of its repository presenting its pinned key, so the control plane \
                     cannot verify anything it reports and stages it blind. Reporting backs off to \
                     one attempt every {}s and recovers on its own if the identity is completed.",
                    channel.refusal_backoff.as_secs()
                ));
            }
        }
        Err(error) => crate::warn(&format!(
            "publishing rollout telemetry through {target} failed ({error}); continuing"
        )),
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn routing(assignment: &str) -> Routing {
        Routing {
            root: std::path::PathBuf::from("/root"),
            base_url: "https://cdn/".into(),
            assignment: assignment.into(),
            transport_timeout: Duration::from_secs(5),
            mtls: updated::tls::Identity::new("tls.crt", "tls.key", "ca.crt"),
        }
    }

    #[test]
    fn node_identity_is_the_assignment_target_stem() {
        assert_eq!(
            node_identity(&routing("assignments/agents/agent-123.json")).as_deref(),
            Some("agent-123")
        );
    }

    #[test]
    fn output_files_are_release_partitioned_bounded_and_validated() {
        let root = tempfile::tempdir().unwrap();
        // The real layout, resolved the one way production resolves it: a test that spelled the
        // outputs directory itself would keep passing after the layout moved under the hook.
        let paths = updated::config::Paths::resolve(root.path(), root.path());
        let identity = "a".repeat(64);
        let path = paths.reconciler_output_snapshot(&identity);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let snapshot = FileSnapshot {
            files: BTreeMap::from([(
                "endpoint".into(),
                updated_contracts::dataflow::FileValue::from_bytes(b"https://vault-0:8200")
                    .unwrap(),
            )]),
        };
        std::fs::write(&path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
        assert_eq!(load_outputs(&paths, &identity), Some(snapshot));
        assert_eq!(load_outputs(&paths, &"b".repeat(64)), None);

        std::fs::write(path, vec![b'x'; MAX_DATAFLOW_BODY_BYTES + 1]).unwrap();
        assert_eq!(load_outputs(&paths, &identity), None);
    }

    #[test]
    fn node_identity_is_none_without_a_usable_stem() {
        assert_eq!(node_identity(&routing("assignments/agents/.json")), None);
        assert_eq!(node_identity(&routing("agents/agent")), None);
    }

    /// A report endpoint that answers every request with one fixed status, counting the requests it
    /// actually receives. `connection: close` keeps the client from pooling, so one connection is
    /// one request and the count is exactly what the writer put on the wire.
    fn report_endpoint(status: &'static str) -> (String, Arc<AtomicUsize>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let base = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&requests);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                counted.fetch_add(1, Ordering::SeqCst);
                let mut reader = BufReader::new(stream);
                // Drain the whole request before replying: answering mid-body would reset the
                // connection and the client would see a transport error instead of the status.
                let mut length = 0usize;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        length = value.trim().parse().unwrap_or(0);
                    }
                }
                let mut body = vec![0u8; length];
                let _ = reader.read_exact(&mut body);
                let _ = reader.get_mut().write_all(
                    format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n")
                        .as_bytes(),
                );
            }
        });
        (base, requests)
    }

    /// A real HTTPS object endpoint plus a plain loopback capability endpoint. The control client
    /// sees only the capability document; the object client spends it on a separate TLS
    /// connection without any client identity.
    async fn accepting_report_endpoints(
    ) -> (String, reqwest::Client, Arc<AtomicUsize>, Arc<AtomicUsize>) {
        use rcgen::{
            BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, SanType,
        };
        use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca = ca_params.self_signed(&ca_key).unwrap();

        let server_key = KeyPair::generate().unwrap();
        let mut server_params = CertificateParams::default();
        server_params
            .subject_alt_names
            .push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server = server_params.signed_by(&server_key, &ca, &ca_key).unwrap();
        let server_config = tokio_rustls::rustls::ServerConfig::builder_with_provider(Arc::new(
            updated::tls::crypto_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![server.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key.serialize_der())),
        )
        .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        let object_url = format!("https://{}/report", listener.local_addr().unwrap());
        let object_writes = Arc::new(AtomicUsize::new(0));
        let counted_writes = Arc::clone(&object_writes);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let acceptor = acceptor.clone();
                let counted_writes = Arc::clone(&counted_writes);
                tokio::spawn(async move {
                    let Ok(mut stream) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut headers = Vec::new();
                    while !headers.ends_with(b"\r\n\r\n") && headers.len() < 64 * 1024 {
                        let mut byte = [0u8; 1];
                        if stream.read_exact(&mut byte).await.is_err() {
                            return;
                        }
                        headers.push(byte[0]);
                    }
                    let text = String::from_utf8_lossy(&headers);
                    if !text.starts_with("POST /report ") {
                        return;
                    }
                    let length = text
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .and_then(|value| value.trim().parse::<usize>().ok())
                        })
                        .unwrap_or(0);
                    let mut body = vec![0u8; length];
                    if stream.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    counted_writes.fetch_add(1, Ordering::SeqCst);
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 0\r\nconnection: close\r\n\r\n",
                        )
                        .await;
                });
            }
        });

        let capability = serde_json::to_vec(&updated_contracts::dataflow::UploadCapability {
            schema: updated_contracts::dataflow::UploadCapability::SCHEMA,
            url: object_url,
            fields: updated_contracts::dataflow::testing::presigned_post_fields(
                "routing/private/reports/node-1.json",
            ),
        })
        .unwrap();
        let control_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let control_base = format!("http://{}", control_listener.local_addr().unwrap());
        let control_requests = Arc::new(AtomicUsize::new(0));
        let counted_requests = Arc::clone(&control_requests);
        std::thread::spawn(move || {
            for stream in control_listener.incoming() {
                let Ok(stream) = stream else { return };
                counted_requests.fetch_add(1, Ordering::SeqCst);
                let mut reader = BufReader::new(stream);
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    capability.len()
                );
                let stream = reader.get_mut();
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(&capability);
            }
        });
        // Exercise the production anonymous-object TLS constructor. Building a second reqwest
        // policy here used reqwest's implicit rustls provider; under the all-features Windows build
        // that drifted from the explicitly selected aws-lc/FIPS provider used by the test server
        // and every real agent client, so the TLS handshake never reached the endpoint.
        let ca_dir = tempfile::tempdir().unwrap();
        let ca_path = ca_dir.path().join("ca.pem");
        std::fs::write(&ca_path, ca.pem()).unwrap();
        let object_client = updated::tls::anonymous_object_client_with_ca(&ca_path).unwrap();
        (control_base, object_client, control_requests, object_writes)
    }

    /// One report attempt against `base`, with a fresh signing key so the envelope is real.
    async fn report(base: &str, refusal: &mut Refusal, backoff: Duration) {
        report_with_object_client(base, &reqwest::Client::new(), refusal, backoff).await;
    }

    async fn report_with_object_client(
        base: &str,
        object_client: &reqwest::Client,
        refusal: &mut Refusal,
        backoff: Duration,
    ) {
        let key =
            updated::csr::key_pem_to_pkcs8_der(&updated::csr::generate_key().unwrap()).unwrap();
        let control_client = reqwest::Client::new();
        let directory = tempfile::tempdir().unwrap();
        let paths = updated::config::Paths::resolve(directory.path(), directory.path());
        let digest = "a".repeat(64);
        write_reconciliation(&paths, "1.0.0", &digest, &digest, &digest);
        report_running_state(
            &ReportChannel {
                control_client: &control_client,
                object_client,
                control_base: Some(base),
                node: Some("node-1"),
                signing_key: Some(&key),
                refusal_backoff: backoff,
            },
            &RunningState {
                deployment: "deployment",
                assignment_sha256: &digest,
                version: "1.0.0",
                archive_sha256: &digest,
                provider_set_sha256: &digest,
                healthy: false,
                updating: false,
                rejected: false,
                fingerprint: None,
                paths: &paths,
                manifest_sha256: "",
            },
            refusal,
            &mut OutputPublisher::default(),
        )
        .await;
    }

    fn write_reconciliation(
        paths: &updated::config::Paths,
        version: &str,
        archive_sha256: &str,
        provider_set_sha256: &str,
        manifest_sha256: &str,
    ) {
        use updated_contracts::reconciler::{
            HostAction, LastReconciliation, MutationOperation, Reason, ReconciledRelease,
            ReconcilerIdentity, ReconciliationTransition, SuccessfulMutation,
        };
        let release = ReconciledRelease::new(
            version.into(),
            manifest_sha256.into(),
            archive_sha256.into(),
        )
        .unwrap();
        let transition = ReconciliationTransition::new(release.clone(), release);
        let reconciler_release =
            ReconciledRelease::new("1.0.0".into(), archive_sha256.into(), archive_sha256.into())
                .unwrap();
        let record = LastReconciliation::new(
            MutationOperation::Apply,
            Reason::Restart,
            updated_contracts::reconciler::attempt::CONVERGE.into(),
            transition,
            ReconcilerIdentity::new(
                provider_set_sha256.into(),
                "system".into(),
                reconciler_release,
            )
            .unwrap(),
            SuccessfulMutation::new(false, HostAction::None, None).unwrap(),
            1,
        )
        .unwrap();
        std::fs::create_dir_all(paths.last_reconciliation.parent().unwrap()).unwrap();
        updated::reconciler::write_last_reconciliation(&paths.last_reconciliation, &record)
            .unwrap();
    }

    /// A 403 is a standing verdict on this node's identity: the writer must stop hammering it every
    /// cycle. This protects a deleted, revoked, or malformed identity from producing one futile
    /// request and warning per second forever on a demo cadence.
    #[tokio::test]
    async fn a_refused_report_backs_off_instead_of_reporting_every_cycle() {
        let (base, requests) = report_endpoint("403 Forbidden");
        let mut refusal = Refusal::default();
        for _ in 0..5 {
            report(&base, &mut refusal, Duration::from_secs(3600)).await;
        }
        assert_eq!(
            requests.load(Ordering::SeqCst),
            1,
            "only the first cycle of a refusal episode reaches the endpoint"
        );
    }

    /// The backoff is a pace, not a surrender: the node keeps trying at the slow cadence, so an
    /// identity completed later recovers without a restart.
    #[tokio::test]
    async fn a_refused_node_keeps_retrying_at_the_backoff_cadence() {
        let (base, requests) = report_endpoint("403 Forbidden");
        let mut refusal = Refusal::default();
        for _ in 0..3 {
            report(&base, &mut refusal, Duration::ZERO).await;
        }
        assert_eq!(requests.load(Ordering::SeqCst), 3);
    }

    /// An accepting endpoint is never paced, and acceptance re-arms the single warning so a later
    /// refusal is still reported.
    #[tokio::test]
    async fn an_accepted_report_leaves_the_cadence_alone() {
        let (base, object_client, requests, object_writes) = accepting_report_endpoints().await;
        let mut refusal = Refusal {
            retry_after: Some(std::time::Instant::now()),
        };
        for _ in 0..3 {
            report_with_object_client(
                &base,
                &object_client,
                &mut refusal,
                Duration::from_secs(3600),
            )
            .await;
        }
        assert_eq!(requests.load(Ordering::SeqCst), 3);
        assert_eq!(object_writes.load(Ordering::SeqCst), 3);
        assert!(refusal.retry_after.is_none());
    }

    #[tokio::test]
    async fn unchanged_outputs_are_reput_before_every_report() {
        let (base, object_client, control_requests, object_writes) =
            accepting_report_endpoints().await;
        let directory = tempfile::tempdir().unwrap();
        let paths = updated::config::Paths::resolve(directory.path(), directory.path());
        let manifest = "c".repeat(64);
        let output_path = paths.reconciler_output_snapshot(&manifest);
        std::fs::create_dir_all(output_path.parent().unwrap()).unwrap();
        let snapshot = FileSnapshot {
            files: BTreeMap::from([(
                "endpoint".into(),
                updated_contracts::dataflow::FileValue::from_bytes(b"db.internal:5432").unwrap(),
            )]),
        };
        std::fs::write(output_path, serde_json::to_vec(&snapshot).unwrap()).unwrap();
        let key =
            updated::csr::key_pem_to_pkcs8_der(&updated::csr::generate_key().unwrap()).unwrap();
        let control_client = reqwest::Client::new();
        let channel = ReportChannel {
            control_client: &control_client,
            object_client: &object_client,
            control_base: Some(&base),
            node: Some("node-1"),
            signing_key: Some(&key),
            refusal_backoff: Duration::from_secs(60),
        };
        let assignment_sha256 = "a".repeat(64);
        let archive_sha256 = "b".repeat(64);
        write_reconciliation(&paths, "1.0.0", &archive_sha256, &archive_sha256, &manifest);
        let state = RunningState {
            deployment: "database",
            assignment_sha256: &assignment_sha256,
            version: "1.0.0",
            archive_sha256: &archive_sha256,
            provider_set_sha256: &archive_sha256,
            healthy: true,
            updating: false,
            rejected: false,
            fingerprint: None,
            paths: &paths,
            manifest_sha256: &manifest,
        };
        let mut refusal = Refusal::default();
        let mut outputs = OutputPublisher::default();

        report_running_state(&channel, &state, &mut refusal, &mut outputs).await;
        let output_sha256 = updated_contracts::digest::sha256_bytes(
            &outputs
                .current
                .as_ref()
                .unwrap()
                .publication
                .to_bounded_body()
                .unwrap(),
        );
        report_running_state(&channel, &state, &mut refusal, &mut outputs).await;

        assert_eq!(
            updated_contracts::digest::sha256_bytes(
                &outputs
                    .current
                    .as_ref()
                    .unwrap()
                    .publication
                    .to_bounded_body()
                    .unwrap()
            ),
            output_sha256,
            "unchanged bytes keep one content identity"
        );
        assert_eq!(
            control_requests.load(Ordering::SeqCst),
            4,
            "each cycle requests output and report capabilities"
        );
        assert_eq!(
            object_writes.load(Ordering::SeqCst),
            4,
            "each cycle repairs the output object before writing its report"
        );
    }

    /// Anything other than a refusal keeps the ordinary cadence: a 5xx or an unreachable gateway is
    /// transient, and the node's freshness budget depends on retrying it next cycle.
    #[tokio::test]
    async fn a_transient_failure_is_not_a_refusal() {
        let (base, requests) = report_endpoint("503 Service Unavailable");
        let mut refusal = Refusal::default();
        for _ in 0..3 {
            report(&base, &mut refusal, Duration::from_secs(3600)).await;
        }
        assert_eq!(requests.load(Ordering::SeqCst), 3);
        assert!(refusal.retry_after.is_none());
    }

    #[test]
    fn a_refusal_episode_warns_exactly_once_and_re_arms_on_acceptance() {
        let now = Instant::now();
        let mut refusal = Refusal::default();
        assert!(refusal.admits(now));
        assert!(refusal.refused(now, Duration::from_secs(60)));
        assert!(!refusal.admits(now));
        assert!(refusal.admits(now + Duration::from_secs(60)));
        assert!(
            !refusal.refused(now, Duration::from_secs(60)),
            "a continuing refusal does not warn again"
        );
        refusal.accepted();
        assert!(refusal.admits(now));
        assert!(
            refusal.refused(now, Duration::from_secs(60)),
            "a new episode after an accepted report warns again"
        );
    }
}
