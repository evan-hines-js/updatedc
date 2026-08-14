//! Best-effort rollout telemetry: the node writes its running state to the report
//! location signed into its current assignment, so the control plane — which can never
//! reach the node — can read rollout progress out of shared storage.
//!
//! This is driven entirely by the *current* assignment each cycle: a new assignment
//! that adds `report_url` starts the heartbeat, one that drops it stops the heartbeat,
//! with no persistent telemetry state to reconcile. Every failure path here is a
//! logged no-op — a node that cannot report keeps updating and serving exactly as if
//! telemetry were never configured.

use std::time::{Duration, Instant};

use updated::config::Routing;
use updated_contracts::telemetry::{
    report_url as telemetry_report_url, sign_report, NodeReport, OutputManifest,
    MAX_OUTPUT_MANIFEST_BYTES,
};

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
    /// secret, or resolved input — one `maxUnavailable` batch at a time.
    pub assignment_sha256: &'a str,
    /// The version actually answering, empty before the first install completes.
    pub version: &'a str,
    /// The SHA-256 of the archive that version was installed from, empty alongside `version`.
    pub archive_sha256: &'a str,
    /// Settled: acted on the assignment and healthy. Never true mid-rollout.
    pub healthy: bool,
    /// An update transaction is in flight: this node committed an update whose confirmation window
    /// has not closed. It is the OTHER half of an unsettled report — the half that says the
    /// transaction genuinely ran, told apart from an ordinary readiness failure — and only this
    /// writer can tell them apart, so it is reported rather than guessed at by a reader.
    pub updating: bool,
    /// This node has DURABLY REJECTED the release its assignment names: the assignment's own
    /// application archive is in the node's rejection record, which is written by content hash when
    /// a candidate fails and never expires. Only this node knows it — the record covers a candidate
    /// that failed its ACTIVATION as well as one that failed its confirmation window, and the first
    /// runs no update transaction at all, so no observer of the report stream can infer it.
    pub rejected: bool,
    /// Latest successful opaque node-state fingerprint, when one is currently publishable.
    pub fingerprint: Option<&'a updated_contracts::telemetry::Fingerprint>,
    /// Where installed archives live, and the manifest digest identifying the running one — the
    /// two inputs [`load_outputs`] needs. The outputs themselves are read here, not by the caller,
    /// so the rule that only a settled report carries them is enforced in exactly one place.
    pub install_root: &'a std::path::Path,
    pub manifest_sha256: &'a str,
}

/// Read and validate the running archive's bounded output manifest. A missing file means the
/// reconciler emitted no outputs; malformed or oversized data is omitted rather than weakening
/// the health report itself.
pub fn load_outputs(
    install_root: &std::path::Path,
    archive_sha256: &str,
) -> Option<OutputManifest> {
    if archive_sha256.is_empty() {
        return None;
    }
    let path = crate::update::reconciler_output_path(install_root, archive_sha256);
    let metadata = std::fs::metadata(&path).ok()?;
    // The size bound is the *envelope* bound worked backwards (see
    // `MAX_OUTPUT_MANIFEST_BYTES`): a manifest larger than this signs into a report no hop on the
    // publish path would accept, and since outputs ride only on healthy reports, attaching it
    // would silently drain a healthy node forever. Omitting the outputs keeps the node published.
    if !metadata.is_file() || metadata.len() > MAX_OUTPUT_MANIFEST_BYTES as u64 {
        crate::warn("reconciler output manifest is not a bounded regular file; omitting outputs");
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let manifest: OutputManifest = match serde_json::from_slice(&bytes) {
        Ok(manifest) => manifest,
        Err(error) => {
            crate::warn(&format!(
                "decoding reconciler output manifest failed ({error}); omitting outputs"
            ));
            return None;
        }
    };
    if let Err(error) = manifest.validate() {
        crate::warn(&format!(
            "invalid reconciler output manifest ({error}); omitting outputs"
        ));
        return None;
    }
    Some(manifest)
}

/// The report endpoint's standing refusal of this node, and when reporting may next be attempted.
///
/// A `403` there is a verdict about identity, not a transient failure: the gateway admits a report
/// only from a node whose `UpdateAgent` is an enrolled member of the repository presenting the
/// public key that name is pinned to. It fails OPEN on every indefinite condition (an apiserver
/// blip, a 5xx, throttling), so a refusal means the node genuinely may not write its own report and
/// will keep not being able to until its identity itself changes.
///
/// An offline-provisioned `kind: manual` node is the deliberate case: it never enrolls, so it never
/// has a pinned key, and the control plane classifies it as blind by design (see
/// `updatec::rollout::NodeEvidence::Blind`) — it is staged on what was published to it rather than
/// on evidence. Its reports are refused for the life of the machine. Reporting rides the update
/// cadence, so re-PUTting a refused report every cycle is one futile request and one warning per
/// cycle — once a second on a demo cadence — forever.
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

/// Write the node's running state to its report location. Strictly best-effort: any
/// error (no report URL, no derivable identity, network failure, non-success status)
/// is logged and swallowed so reporting can never disrupt the update loop.
///
/// `backoff` is how long a refused node stays quiet before trying again (see [`Refusal`]).
pub async fn report_running_state(
    client: &reqwest::Client,
    report_url: Option<&str>,
    node: Option<&str>,
    state: &RunningState<'_>,
    signing_key: Option<&[u8]>,
    refusal: &mut Refusal,
    backoff: Duration,
) {
    let (Some(report_url), Some(node)) = (report_url, node) else {
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
    let Some(key) = signing_key else {
        crate::warn("no telemetry signing key available; skipping the rollout heartbeat");
        return;
    };
    let mut report = NodeReport::new(
        node,
        state.deployment,
        state.assignment_sha256,
        state.version,
        state.archive_sha256,
        state.healthy,
    );
    report.updating = state.updating;
    report.rejected = state.rejected;
    report.fingerprint = state.fingerprint.cloned();
    // Outputs describe what the running archive settled on, so an unsettled node has none to
    // publish — and no reason to pay the read. One gate, at the one place that attaches them.
    report.outputs = state
        .healthy
        .then(|| load_outputs(state.install_root, state.manifest_sha256))
        .flatten();
    // Signed with the node's per-node key so the throttle and the health proxy can verify authenticity
    // end-to-end, rather than trusting the write hop.
    let body = match sign_report(&report, key).and_then(|envelope| {
        serde_json::to_vec(&envelope).map_err(|e| format!("encoding rollout telemetry: {e}"))
    }) {
        Ok(body) => body,
        Err(error) => {
            crate::warn(&format!(
                "preparing rollout telemetry failed ({error}); continuing"
            ));
            return;
        }
    };
    let target = telemetry_report_url(report_url, node);
    let result = client
        .put(&target)
        .timeout(Duration::from_secs(5))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await;
    match result {
        Ok(response) if response.status().is_success() => refusal.accepted(),
        Ok(response) if response.status() == reqwest::StatusCode::FORBIDDEN => {
            if refusal.refused(Instant::now(), backoff) {
                crate::warn(&format!(
                    "rollout telemetry to {target} was refused (403): this node is not an enrolled \
                     member of its repository presenting its pinned key, so the control plane \
                     cannot verify anything it reports and stages it blind. Reporting backs off to \
                     one attempt every {}s and recovers on its own if the identity is completed.",
                    backoff.as_secs()
                ));
            }
        }
        Ok(response) => crate::warn(&format!(
            "rollout telemetry to {target} returned {}; continuing",
            response.status()
        )),
        Err(error) => crate::warn(&format!(
            "rollout telemetry to {target} failed ({error}); continuing"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

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
        let identity = "a".repeat(64);
        let path = crate::update::reconciler_output_path(root.path(), &identity);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let manifest = OutputManifest {
            schema: OutputManifest::SCHEMA,
            values: BTreeMap::from([(
                "endpoint".into(),
                updated_contracts::telemetry::OutputValue::String {
                    value: "https://vault-0:8200".into(),
                },
            )]),
        };
        std::fs::write(&path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        assert_eq!(load_outputs(root.path(), &identity), Some(manifest));
        assert_eq!(load_outputs(root.path(), &"b".repeat(64)), None);

        std::fs::write(path, vec![b'x'; MAX_OUTPUT_MANIFEST_BYTES + 1]).unwrap();
        assert_eq!(load_outputs(root.path(), &identity), None);
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

    /// One report attempt against `base`, with a fresh signing key so the envelope is real.
    async fn report(base: &str, refusal: &mut Refusal, backoff: Duration) {
        let key =
            updated::csr::key_pem_to_pkcs8_der(&updated::csr::generate_key().unwrap()).unwrap();
        report_running_state(
            &reqwest::Client::new(),
            Some(base),
            Some("node-1"),
            &RunningState {
                deployment: "deployment",
                assignment_sha256: "assignment",
                version: "1.0.0",
                archive_sha256: "archive",
                healthy: false,
                updating: false,
                rejected: false,
                fingerprint: None,
                install_root: std::path::Path::new("/nonexistent"),
                manifest_sha256: "",
            },
            Some(&key),
            refusal,
            backoff,
        )
        .await;
    }

    /// A 403 is a standing verdict on this node's identity: the writer must stop hammering it every
    /// cycle. A `kind: manual` node — deliberately blind, never enrolled, never pinned — is refused
    /// for the life of the machine, which on the demo cadence was one futile request and one warning
    /// per second, forever.
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
        let (base, requests) = report_endpoint("200 OK");
        let mut refusal = Refusal {
            retry_after: Some(std::time::Instant::now()),
        };
        for _ in 0..3 {
            report(&base, &mut refusal, Duration::from_secs(3600)).await;
        }
        assert_eq!(requests.load(Ordering::SeqCst), 3);
        assert!(refusal.retry_after.is_none());
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
