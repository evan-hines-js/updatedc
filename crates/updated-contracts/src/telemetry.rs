//! Node → control-plane rollout telemetry.
//!
//! The control plane can never reach a node, so completion feedback flows the other
//! way through shared storage: a node writes a small [`NodeReport`] to the report
//! location signed into its assignment,
//! and the control plane reads it back out of the same object store it publishes to.
//! Reporting is strictly best-effort — a node that cannot write its report keeps
//! running, and a control plane that finds no report rolls without completion gating.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// How old a healthy report may be before a reader treats it as not-ready / not-settled. Shared by
/// every consumer (the control-plane rollout throttle AND the healthproxy) so they agree on when a
/// node that stopped heart-beating drops out — a node that goes silent must age out of "settled" in
/// the same bounded time it ages out of load-balancer rotation.
///
/// The window is a *reader-side* judgment and deliberately not derived from anything the node says:
/// a node that could widen its own window would, once compromised or dead, hold itself in rotation
/// for as long as it liked. Instead the writer's cadence is bounded by the window —
/// [`MAX_CHECK_INTERVAL_SECONDS`] is derived from it, and every assignment is validated against
/// that — so the two cannot drift apart and a merely-slow re-report never flaps.
pub const REPORT_FRESHNESS: Duration = Duration::from_secs(60);

/// How much later than its assigned check interval a node's heartbeat can land: the supervisor
/// spreads each next check by this much, so consecutive reports are up to 1.2x the interval apart.
/// Public because the supervisor schedules against it — the spread a node actually applies and the
/// spread [`MAX_CHECK_INTERVAL_SECONDS`] budgets for are then the same number, not two literals
/// that agree today.
pub const REPORT_CADENCE_JITTER_PERCENT: u32 = 20;

/// The largest `check_interval_seconds` a signed assignment may carry.
///
/// A node writes its report at the bottom of its check loop, so its report cadence *is* its check
/// interval (plus jitter) — and THREE such gaps must fit inside [`REPORT_FRESHNESS`]. Two of them
/// because a report write is best-effort and never retried, so one lost write must not drain a
/// healthy node out of rotation or un-settle it mid-rollout. The third is the allowance for
/// everything between the write and the read, none of which is free: the upload itself, propagation
/// through the object store, and the reader's own poll interval — the healthproxy polls on its own
/// clock, so a report can already be a full poll old before anyone looks at it. Budgeting only the
/// two gaps makes "one lost write still leaves the node fresh" true solely on a machine where all
/// of that costs zero, which is to say false.
///
/// A slower interval publishes a node that is stale by construction: routinely older than the one
/// window [`NodeReport::is_fresh`], the healthproxy's last-known-good cache, and the rollout
/// throttle all judge it against, so it drops out of the load balancer for part of every cycle
/// while being perfectly healthy.
///
/// Derived from the window rather than written beside it, and enforced in
/// [`crate::assignment::ManagedRuntime::validate`], so the cadence a publisher may assign and the
/// age every reader enforces cannot diverge. Every other duration in the contract answers to the
/// generic [`crate::assignment::MAX_INTERVAL_SECONDS`] ceiling instead.
pub const MAX_CHECK_INTERVAL_SECONDS: u64 =
    REPORT_FRESHNESS.as_secs() * 100 / (3 * (100 + REPORT_CADENCE_JITTER_PERCENT as u64));

/// How far ahead of the reader's clock a report may be stamped and still be usable. Writer and
/// reader are different machines, so a small disagreement is normal; anything beyond it is either a
/// badly-skewed RTC or a node buying itself unbounded freshness. Without this bound a single report
/// stamped in the future ages to zero forever, and a dead or compromised node stays "settled" and in
/// load-balancer rotation permanently — the freshness window is the only thing that ages a silent
/// node out.
pub const REPORT_MAX_SKEW: Duration = Duration::from_secs(60);

/// Milliseconds since the Unix epoch, the shared clock a node stamps its report with and a
/// reader ages it against. Wall-clock (not `Instant`) because writer and reader are different
/// processes; a clock that cannot be read reads as `0`, which [`NodeReport::is_fresh`] treats as
/// "no usable clock" and refuses every report against — the fail-closed direction.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// The namespace, under a report base, that every node report lives in. A store that accepts
/// report writes must serve this namespace back: the writer and every reader derive their path
/// from this one name, so a store that knows only its write half returns 404 to every consumer.
pub const REPORT_NAMESPACE: &str = "telemetry";

/// The relative object key, under a report base, a node writes its report to. Keyed by
/// node identity so the control plane can attribute a report to the agent it selected.
pub fn report_object_key(node: &str) -> String {
    format!("{REPORT_NAMESPACE}/{node}.json")
}

/// The absolute URL of a node's report under a base location: `<base>/telemetry/<node>.json`,
/// tolerant of a trailing slash on the base. The single place a report base and a node identity
/// become one fetchable/writable URL — shared by the agent that writes its report and any reader
/// (the health proxy) that fetches it, so the two can never drift.
pub fn report_url(base: &str, node: &str) -> String {
    format!("{}/{}", base.trim_end_matches('/'), report_object_key(node))
}

/// The request path a node `PUT`s its report to, relative to the report base.
pub const REPORT_PATH_PREFIX: &str = "/telemetry/";

#[test]
fn the_report_path_prefix_is_the_report_namespace() {
    assert_eq!(REPORT_PATH_PREFIX, format!("/{REPORT_NAMESPACE}/"));
}

/// Recover the node identity from a report request path (`/telemetry/<node>.json`),
/// rejecting traversal or unsafe characters. Shared by every control plane so the write
/// path is validated identically wherever a `report_url` happens to point.
pub fn node_from_path(request_path: &str) -> Option<&str> {
    let node = request_path
        .strip_prefix(REPORT_PATH_PREFIX)?
        .strip_suffix(".json")?;
    is_valid_node(node).then_some(node)
}

/// The segment that separates a routing-assignment prefix from the node it addresses. The control
/// plane publishes each node's assignment at exactly `<prefix>/agents/<node>.json`.
pub const ASSIGNMENT_AGENTS_SEGMENT: &str = "/agents/";

/// The segment that separates a routing-assignment prefix from the content-addressed deployment
/// document the node's assignment points at: `<prefix>/configs/<id>.json`.
pub const ASSIGNMENT_CONFIGS_SEGMENT: &str = "/configs/";

/// The routing-assignment target a node's document is published at, `<prefix>/agents/<node>.json`,
/// tolerant of stray slashes on the prefix. The one writer of that layout — every control plane
/// that signs assignments names them with this, and [`split_assignment_path`] is the only reader —
/// so what is signed, what is served, and what a node believes is its own identity cannot drift.
pub fn assignment_object_key(prefix: &str, node: &str) -> String {
    format!(
        "{}{ASSIGNMENT_AGENTS_SEGMENT}{node}.json",
        prefix.trim_matches('/')
    )
}

/// The deployment-document target an assignment references, `<prefix>/configs/<id>.json`, where
/// `id` is the SHA-256 of the exact published bytes. Same layout ownership as
/// [`assignment_object_key`].
pub fn config_object_key(prefix: &str, id: &str) -> String {
    format!(
        "{}{ASSIGNMENT_CONFIGS_SEGMENT}{id}.json",
        prefix.trim_matches('/')
    )
}

/// Split a routing-assignment target path (`<prefix>/agents/<node>.json`) into its prefix and the
/// node it addresses, rejecting anything that is not a valid node identity. The one reader of the
/// layout [`assignment_object_key`] writes: the identity a node reports under, the identity an
/// enrollment bundle's assignment must name, and the prefix a publisher derives sibling keys from
/// are all the same fact, and must be read the same way.
pub fn split_assignment_path(assignment: &str) -> Option<(&str, &str)> {
    let (prefix, node) = assignment
        .strip_suffix(".json")?
        .rsplit_once(ASSIGNMENT_AGENTS_SEGMENT)?;
    (!prefix.is_empty() && is_valid_node(node)).then_some((prefix, node))
}

/// The one grammar a node identity must satisfy. Traversal safety is the shared component check
/// ([`crate::path::is_safe_component`]); on top of that a report node is a URL segment and a clean
/// identity, so it additionally forbids `.` (any dot, not just `.`/`..`) and the URL-significant
/// `% ? #`.
///
/// This is the predicate, not a copy of it: [`node_from_path`] gates the write path on it, and any
/// component that *configures* node identities (the health proxy's member inventory) validates
/// against the same function at startup. A name only one side accepts is a node whose report can
/// never be stored where the other side looks for it — drained from rotation forever behind a log
/// line indistinguishable from a genuinely unhealthy node — so there is exactly one definition.
///
/// Length is deliberately unbounded here: the identity is bounded downstream by the object key and
/// URL it forms, and no hop imposes a shorter limit than those.
pub fn is_valid_node(node: &str) -> bool {
    crate::path::is_safe_component(node) && !node.contains(['.', '%', '?', '#'])
}

/// An opaque measurement of node state produced by the signed reconciler's `fingerprint` phase.
/// Neither updatedc nor a consumer interprets the output: the exact stdout bytes are SHA-256 hashed.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Fingerprint {
    /// SHA-256 of the signed reconciler artifact that defines how node state is measured.
    pub definition_sha256: String,
    /// SHA-256 of the exact stdout bytes emitted by one successful fingerprint invocation.
    pub output_sha256: String,
}

/// The one bound on a published report, stated in the units it actually crosses the wire in: the
/// bytes of the signed DSSE envelope. Every hop enforces exactly this number — the gateway's and
/// the dev CDN's request-body limits on the write, the healthproxy's bounded read on the way back —
/// so there is no size a node may sign that some hop then refuses.
///
/// This matters because a rejected write is silent and permanent in effect: report writes are
/// best-effort and never retried, and outputs ride only on *healthy* reports, so a node whose
/// healthy report is too large keeps publishing nothing while its last unhealthy report stands, and
/// it is drained from rotation forever while being perfectly healthy. The writer-side bound is
/// therefore derived from this one ([`MAX_OUTPUT_MANIFEST_BYTES`]) rather than written beside it.
pub const MAX_REPORT_ENVELOPE_BYTES: usize = 64 * 1024;

/// What one signed envelope costs on top of the output manifest it carries, worst case: base64
/// expands the whole report payload by 4/3 with padding, and on top of that sit the envelope's JSON
/// scaffolding, the payload type, the base64 signature, and every report field that is
/// not the manifest (node and deployment identities, two digests, the timestamp, the fingerprint).
/// Reserved generously — the cost of reserving too much is a slightly smaller manifest allowance,
/// the cost of reserving too little is a node that can never publish.
const REPORT_ENVELOPE_OVERHEAD_BYTES: usize = 8 * 1024;

/// The largest output manifest a node may attach to a report — the writer-side bound, derived so
/// the WORST-CASE signed envelope for a manifest of exactly this size still fits
/// [`MAX_REPORT_ENVELOPE_BYTES`] after base64 expansion and envelope overhead. Enforced by
/// `supervisor::telemetry::load_outputs` before a manifest is ever attached, and asserted against
/// a real signed envelope by this module's tests, so the two bounds cannot drift into agreeing on
/// a number while disagreeing on its units.
pub const MAX_OUTPUT_MANIFEST_BYTES: usize =
    (MAX_REPORT_ENVELOPE_BYTES - REPORT_ENVELOPE_OVERHEAD_BYTES) * 3 / 4;

/// Small, typed dataflow values emitted by a reconciler for dependent groups. The manifest is
/// carried inside the node's signed report, so its producer identity, deployment, running archive,
/// health, and freshness are authenticated together. Secret values never appear here; only the
/// reference already understood by the authenticated secret-delivery path does.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutputManifest {
    pub schema: u32,
    pub values: BTreeMap<String, OutputValue>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum OutputValue {
    String { value: String },
    SecretRef { secret: String, key: String },
}

impl OutputManifest {
    pub const SCHEMA: u32 = 1;
    pub const MAX_VALUES: usize = 64;
    pub const MAX_STRING_BYTES: usize = 4 * 1024;

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != Self::SCHEMA || self.values.len() > Self::MAX_VALUES {
            return Err("node output manifest schema or value count is invalid".into());
        }
        for (name, value) in &self.values {
            if !crate::path::is_safe_component(name) || name.len() > 128 {
                return Err("node output name is invalid".into());
            }
            match value {
                OutputValue::String { value }
                    if value.len() <= Self::MAX_STRING_BYTES && !value.contains('\0') => {}
                OutputValue::SecretRef { secret, key }
                    if !secret.is_empty()
                        && secret.len() <= 253
                        && !key.is_empty()
                        && key.len() <= 253 => {}
                _ => return Err("node output value is invalid".into()),
            }
        }
        Ok(())
    }
}

impl Fingerprint {
    pub fn from_output(
        definition_sha256: impl Into<String>,
        output: &[u8],
    ) -> Result<Self, String> {
        use aws_lc_rs::digest::{digest, SHA256};
        let fingerprint = Self {
            definition_sha256: definition_sha256.into(),
            output_sha256: hex::encode(digest(&SHA256, output).as_ref()),
        };
        fingerprint
            .is_wellformed()
            .then_some(fingerprint)
            .ok_or_else(|| "fingerprint definition is not a SHA-256".into())
    }

    pub fn is_wellformed(&self) -> bool {
        crate::is_sha256_hex(&self.definition_sha256) && crate::is_sha256_hex(&self.output_sha256)
    }
}

/// A node's self-reported running state, signed by the node's own per-node key.
///
/// Authenticity IS load-bearing: a report is consumed only through
/// [`report_is_authentic_and_fresh`], which requires the signature to verify against the key the
/// control plane pinned at enrollment. Without that, a compromised gateway or anyone who can write
/// the shared bucket could forge a healthy report and drive a rollout past unhealthy peers, or hold
/// a drained node in load-balancer rotation. Every failure — missing, unsigned, forged, stale, or
/// attributed to another node — fails closed: the member is treated as not-yet-settled and keeps
/// its throttle slot, and as not-ready for routing.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NodeReport {
    pub schema: u32,
    /// The node identity this report is for (matches the selected `UpdateAgent`).
    pub node: String,
    /// The deployment identity the node currently has assigned
    /// selected by the control plane.
    pub deployment: String,
    /// SHA-256 (hex) of the exact signed assignment document the node is acting on — the same
    /// digest the control plane published it under.
    ///
    /// [`NodeReport::deployment`] is a NAME, and an operator can change everything a deployment
    /// does (its archive digest, arguments, secrets) while keeping it; the control plane changes
    /// resolved dependency inputs under an unchanged name by itself. This is the content, so a
    /// reader can tell "settled on the deployment currently desired" from "settled on an older
    /// body of the same name" — which is what makes staged, `maxUnavailable`-bounded rollout work
    /// for a change that does not rename anything. Empty only before the node has resolved its
    /// first assignment.
    pub assignment_sha256: String,
    /// The semantic version the node is *actually running* right now, independent of what it
    /// was assigned — after a rollback or ordered-fallback descent this is the version that
    /// really answered, not the desired one. It is the control plane's authoritative source
    /// of a node's running version, so no consumer ever has to probe the managed app (which
    /// may speak any protocol, or none). Empty only before the first install completes.
    pub version: String,
    /// The SHA-256 (hex) of the archive the running release was installed from — the
    /// `archive_sha256` of the committed head in the node's own installed state.
    ///
    /// A version is a *name*; this is the content. Signing it makes the report say which exact
    /// bytes are executing, so a reader can join a running node straight to whatever it knows
    /// about that digest (provenance, an attestation, a policy decision) without trusting a
    /// version string or re-deriving the assignment the node was given. It is the running
    /// digest, not the assigned one: after a rollback or an ordered-fallback descent it names
    /// the predecessor that really answered.
    ///
    /// Empty only before the first install completes, matching [`NodeReport::version`]. Any
    /// other non-`is_sha256_hex` value is malformed and fails the trust gate closed.
    pub archive_sha256: String,
    /// Whether the node has *settled* on that deployment: it has finished acting on the
    /// assignment (installed and confirmed it, or attempted and rolled back from it) and
    /// its running app is healthy. A node with an unconfirmed update still in flight reports
    /// `false` — so the control plane never mistakes "received" for "done".
    ///
    /// It is not a claim that the node installed what the assignment names: a node that resolved a
    /// new assignment but could not fetch its archive has nothing in flight and a healthy app, so
    /// it reports settled on that assignment while still running the old bytes.
    /// [`NodeReport::archive_sha256`] is what says which bytes are executing.
    pub healthy: bool,
    /// Whether an update TRANSACTION is in flight: the node committed an update whose
    /// confirmation window has not closed yet.
    ///
    /// This is the half of `healthy == false` that says the transaction genuinely RAN. The two
    /// meanings are not interchangeable — a report is also unsettled when the running app simply
    /// fails a readiness probe, with no update anywhere near it — and a reader that infers "an
    /// update was attempted" from `!healthy` alone mints rollback evidence out of an ordinary
    /// readiness blip. Never true together with [`NodeReport::healthy`]: settled means the
    /// confirmation window is closed.
    pub updating: bool,
    /// Milliseconds since the Unix epoch when the node wrote this report (see [`now_ms`]). A
    /// reader ages the report against this so a node that dies without writing a not-ready
    /// report cannot stay trusted forever — a stale report fails closed.
    pub reported_at_ms: u64,
    /// Opaque node-state fingerprint. Absent before the first successful observation or when the
    /// bounded observation failed or was cancelled for a deployment.
    #[serde(deserialize_with = "crate::required_option")]
    pub fingerprint: Option<Fingerprint>,
    /// Versioned reconciler outputs. Absent when the running artifact has not emitted any. Outputs
    /// are usable only through the same authenticity/freshness/health/deployment gate as the rest
    /// of this report.
    #[serde(deserialize_with = "crate::required_option")]
    pub outputs: Option<OutputManifest>,
}

impl NodeReport {
    pub const SCHEMA: u32 = 6;

    /// A report of a node that is NOT mid-transaction. [`NodeReport::updating`] is set by the one
    /// writer that knows (the supervisor's heartbeat, from its own unconfirmed-update journal);
    /// every other constructor is describing a settled or merely not-ready node.
    pub fn new(
        node: impl Into<String>,
        deployment: impl Into<String>,
        assignment_sha256: impl Into<String>,
        version: impl Into<String>,
        archive_sha256: impl Into<String>,
        healthy: bool,
    ) -> Self {
        Self {
            schema: Self::SCHEMA,
            node: node.into(),
            deployment: deployment.into(),
            assignment_sha256: assignment_sha256.into(),
            version: version.into(),
            archive_sha256: archive_sha256.into(),
            healthy,
            updating: false,
            reported_at_ms: now_ms(),
            fingerprint: None,
            outputs: None,
        }
    }

    /// Whether this report is a shape a reader may act on.
    ///
    /// The schema first: a record of a version this build does not know is not a report it may
    /// interpret, whatever the rest of it says. It is checked HERE, in the one predicate both the
    /// write gate ([`accept_report_envelope`]) and the read gate ([`report_is_authentic_and_fresh`])
    /// run, because the two must agree. A skewed record the writer accepts and every reader then
    /// discards strands the node: it reads as silent to the rollout throttle and drains out of the
    /// load balancer, with a 200 telling the writer all is well.
    ///
    /// Then the fields. [`NodeReport::archive_sha256`] must be a SHA-256 hex digest, or empty for a
    /// node that has not completed its first install. Anything else is a malformed record — a
    /// truncated, re-encoded, or hand-written digest — and a reader that joined on it would
    /// attribute a running node to bytes it cannot name.
    ///
    /// `updating` and `healthy` are mutually exclusive by construction (settled means no
    /// transaction is outstanding), so a record claiming both is malformed: it would otherwise be
    /// one signed report asserting simultaneously that a rollout has completed and that the
    /// transaction behind it is still in flight.
    pub fn is_wellformed(&self) -> bool {
        self.schema == Self::SCHEMA
            && !self.node.is_empty()
            && !self.deployment.is_empty()
            && self.reported_at_ms > 0
            && (self.version.is_empty() == self.archive_sha256.is_empty())
            && (!self.healthy || !self.archive_sha256.is_empty())
            && !(self.healthy && self.updating)
            && (self.archive_sha256.is_empty() || crate::is_sha256_hex(&self.archive_sha256))
            && (self.assignment_sha256.is_empty() || crate::is_sha256_hex(&self.assignment_sha256))
            && self
                .fingerprint
                .as_ref()
                .is_none_or(Fingerprint::is_wellformed)
            && self
                .outputs
                .as_ref()
                .is_none_or(|outputs| outputs.validate().is_ok())
    }

    /// Whether this report is inside the shared freshness window as seen from `now_ms`.
    ///
    /// Bounded in BOTH directions. Backwards is the obvious one: a node that stops writing ages out
    /// of "settled" and out of rotation. Forwards matters just as much — with only a backwards
    /// bound, a report stamped in the future subtracts to age zero and stays fresh forever, so one
    /// such report from a node with a skewed clock (or one whose key an attacker holds) pins it
    /// healthy and settled permanently. A reader with no usable clock (`now_ms == 0`, see
    /// [`now_ms`]) accepts nothing, which is the fail-closed direction.
    pub fn is_fresh(&self, now_ms: u64) -> bool {
        now_ms != 0
            && self.reported_at_ms <= now_ms.saturating_add(REPORT_MAX_SKEW.as_millis() as u64)
            && now_ms.saturating_sub(self.reported_at_ms) <= REPORT_FRESHNESS.as_millis() as u64
    }
}

/// The DSSE `payloadType` a node report is signed under. Bound into the pre-authentication encoding,
/// so an envelope of some other kind — even one this node legitimately signed — cannot be replayed as
/// a health report.
pub const REPORT_PAYLOAD_TYPE: &str = "application/vnd.updated.node-report+json";

/// A DSSE envelope: the signed payload, its type, and the signatures over the pre-authentication
/// encoding of both.
///
/// The report travels as the envelope's payload rather than as a struct with a `signature` field
/// beside it. That is deliberate: the exact signed bytes are carried verbatim, so a verifier never
/// has to re-serialize a parsed record and hope it reproduces what was signed. Any consumer in any
/// language re-verifies the same bytes, which is what makes a report retained today still
/// re-verifiable years from now.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    /// Standard base64 of the payload bytes.
    pub payload: String,
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    pub signatures: Vec<Signature>,
}

impl Envelope {
    /// The most signatures a report envelope may carry. A node signs with exactly one key, so this
    /// is generous; it exists because verification is the expensive step and the count is otherwise
    /// attacker-chosen — a body full of bogus signatures with the valid one last would cost a full
    /// ECDSA verify each, on every read, for every consumer.
    pub const MAX_SIGNATURES: usize = 4;
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    /// Standard base64 of the ASN.1 DER ECDSA signature.
    pub sig: String,
}

/// The DSSE pre-authentication encoding — the exact bytes a signature commits to:
/// `DSSEv1 <len(type)> <type> <len(payload)> <payload>`.
///
/// Binding the length and the type in front of the payload is what stops a payload from being
/// reinterpreted as a different kind of document, or two fields from being slid into one another.
pub fn pae(payload: &[u8], payload_type: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + payload_type.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

/// Sign a report into a DSSE envelope with a node's private key (PKCS#8 DER — the aws-lc-rs form of
/// the rcgen-minted ECDSA P-256 key that also certifies the node's mTLS leaf).
pub fn sign_report(report: &NodeReport, pkcs8_der: &[u8]) -> Result<Envelope, String> {
    use aws_lc_rs::signature::{EcdsaKeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
    use base64::Engine as _;

    let payload =
        serde_json::to_vec(report).map_err(|e| format!("encoding telemetry report: {e}"))?;
    let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8_der)
        .map_err(|e| format!("loading telemetry signing key: {e}"))?;
    let rng = aws_lc_rs::rand::SystemRandom::new();
    let signature = key
        .sign(&rng, &pae(&payload, REPORT_PAYLOAD_TYPE))
        .map_err(|e| format!("signing telemetry report: {e}"))?;

    let b64 = base64::engine::general_purpose::STANDARD;
    Ok(Envelope {
        payload: b64.encode(&payload),
        payload_type: REPORT_PAYLOAD_TYPE.to_string(),
        signatures: vec![Signature {
            sig: b64.encode(signature.as_ref()),
        }],
    })
}

/// The one write-side acceptance gate for a report envelope: the rule every hop that *stores* a
/// report applies before it stores it.
///
/// Returns the decoded report only when the body is an envelope of the report payload type, carries
/// no more than [`Envelope::MAX_SIGNATURES`] signatures, decodes to a report that is well formed
/// (which includes carrying this build's [`NodeReport::SCHEMA`] — the same predicate every reader
/// applies, so a record no reader can use is never stored), and names `node` — the node the caller
/// is filing it under. The signature is deliberately NOT
/// verified here, and this is the only function that decodes a payload without checking it: a writer
/// hop authorizes by the transport identity that presented the bytes, and the signature is
/// end-to-end evidence for the consumers that later read them back, every one of which must go
/// through [`report_is_authentic_and_fresh`] instead.
///
/// It lives here, beside the envelope types, because the production gateway and the dev CDN both
/// enforce it and must enforce the *same* thing: maintained as two copies, a tightening on one side
/// silently makes the test path accept what production refuses, or the reverse.
pub fn accept_report_envelope(body: &[u8], node: &str) -> Option<NodeReport> {
    let envelope: Envelope = serde_json::from_slice(body).ok()?;
    if envelope.payload_type != REPORT_PAYLOAD_TYPE
        || envelope.signatures.len() > Envelope::MAX_SIGNATURES
    {
        return None;
    }
    use base64::Engine as _;
    let payload = base64::engine::general_purpose::STANDARD
        .decode(&envelope.payload)
        .ok()?;
    let report: NodeReport = serde_json::from_slice(&payload).ok()?;
    (report.node == node && report.is_wellformed()).then_some(report)
}

/// Whether `point` is a well-formed uncompressed SEC1 P-256 point: `0x04` followed by two 32-byte
/// coordinates, and not the all-zero encoding. Shape only — proving a point is on the curve is the
/// verifier's job; this exists so a malformed *pin* is refused as a configuration error rather than
/// silently behaving like a node whose every report is forged.
///
/// Public because the shape must be enforced where a pin is *configured*, not only where it is
/// used: a pin that reaches [`report_is_authentic_and_fresh`] malformed drains its node forever
/// with a log line indistinguishable from a genuinely unhealthy one. Every consumer validates
/// against this one rule, so the boundary check and the verification check cannot drift.
pub fn is_uncompressed_p256_point(point: &[u8]) -> bool {
    point.len() == 65 && point[0] == 4 && point[1..].iter().any(|byte| *byte != 0)
}

/// The one trust gate for consuming a node report.
///
/// Returns the report ONLY when the envelope is authentic and usable, so a caller structurally cannot
/// read a node's state without having verified it — the previous shape (a bool beside a separately
/// parsed struct) let a caller forget. A report is usable only when the envelope's `payloadType` is a
/// node report, a signature verifies against that node's pinned enrollment key over the PAE, the
/// payload parses, the schema is one this build understands, the running digest is well-formed, it
/// names the expected node, and it is inside the shared freshness window.
///
/// Rollout admission and load-balancer membership both call this, so attribution, replay resistance,
/// and signature policy cannot drift between control-plane consumers. Health and deployment matching
/// remain consumer-specific decisions made only after this gate succeeds.
///
/// The schema is checked explicitly even though it is signed: a signature proves the *node* wrote that
/// value, not that this build agrees with what it means.
pub fn report_is_authentic_and_fresh(
    envelope: &Envelope,
    expected_node: &str,
    public_key_point: &[u8],
    now_ms: u64,
) -> Option<NodeReport> {
    use aws_lc_rs::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_ASN1};
    use base64::Engine as _;

    if envelope.payload_type != REPORT_PAYLOAD_TYPE
        || envelope.signatures.len() > Envelope::MAX_SIGNATURES
    {
        return None;
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let payload = b64.decode(&envelope.payload).ok()?;
    let pae = pae(&payload, REPORT_PAYLOAD_TYPE);

    // The pinned key must be a well-formed uncompressed P-256 point. An empty key would make every signature
    // unverifiable (the fail-closed default rather than "no key, no check"), but so would a truncated key, a
    // stray PEM header, or a config typo — and those are indistinguishable from a forged report unless the
    // shape is checked. The pin arrives from operator config, which is exactly where such a mistake happens.
    let verified = is_uncompressed_p256_point(public_key_point)
        && envelope.signatures.iter().any(|signature| {
            b64.decode(&signature.sig).is_ok_and(|sig| {
                UnparsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, public_key_point)
                    .verify(&pae, &sig)
                    .is_ok()
            })
        });
    if !verified {
        return None;
    }

    let report: NodeReport = serde_json::from_slice(&payload).ok()?;
    let usable = report.is_wellformed() && report.node == expected_node && report.is_fresh(now_ms);

    usable.then_some(report)
}

/// The report an envelope CLAIMS to carry, decoded without verifying any signature or freshness.
///
/// For OBSERVABILITY only, never a trust decision: [`report_is_authentic_and_fresh`] remains the
/// one gate anything acting on a report goes through. This exists so a metric can say WHY a node
/// was drained — "its report aged out" versus "its report is unusable" — which requires reading a
/// timestamp off a document the gate has already refused.
pub fn unverified_report(envelope: &Envelope) -> Option<NodeReport> {
    use base64::Engine as _;
    if envelope.payload_type != REPORT_PAYLOAD_TYPE {
        return None;
    }
    let payload = base64::engine::general_purpose::STANDARD
        .decode(&envelope.payload)
        .ok()?;
    serde_json::from_slice(&payload).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};
    use base64::Engine as _;

    /// SHA-256 of the empty input, and of `abc` — two well-formed digests that differ.
    const DIGEST: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const OTHER_DIGEST: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn b64() -> base64::engine::general_purpose::GeneralPurpose {
        base64::engine::general_purpose::STANDARD
    }

    /// A keypair plus the raw uncompressed public point the control plane pins at enrollment.
    fn keypair() -> (Vec<u8>, Vec<u8>) {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
        (pkcs8.as_ref().to_vec(), key.public_key().as_ref().to_vec())
    }

    fn report() -> NodeReport {
        NodeReport::new("agent-9", "deploy-2", OTHER_DIGEST, "2.0.0", DIGEST, true)
    }

    /// A report the node genuinely signed *after* `mutate` ran. Signing last is the point: it isolates
    /// what the gate refuses on policy grounds from what it refuses because a signature broke.
    fn signed(mutate: impl FnOnce(&mut NodeReport)) -> (Envelope, Vec<u8>) {
        let (pkcs8, point) = keypair();
        let mut report = report();
        mutate(&mut report);
        (sign_report(&report, &pkcs8).unwrap(), point)
    }

    #[test]
    fn a_genuine_envelope_verifies_and_yields_the_report() {
        let (envelope, point) = signed(|_| {});
        let report = report_is_authentic_and_fresh(&envelope, "agent-9", &point, now_ms())
            .expect("a genuine envelope must verify");

        assert_eq!(report.node, "agent-9");
        assert_eq!(report.version, "2.0.0");
        assert_eq!(report.archive_sha256, DIGEST);
        assert!(report.healthy);
        assert_eq!(envelope.payload_type, REPORT_PAYLOAD_TYPE);
    }

    #[test]
    fn a_fingerprint_is_signed_as_two_opaque_content_digests() {
        let (envelope, point) = signed(|report| {
            report.fingerprint = Some(Fingerprint {
                definition_sha256: DIGEST.into(),
                output_sha256: OTHER_DIGEST.into(),
            });
        });

        let report = report_is_authentic_and_fresh(&envelope, "agent-9", &point, now_ms())
            .expect("a well-formed signed fingerprint must verify");
        assert_eq!(
            report.fingerprint,
            Some(Fingerprint {
                definition_sha256: DIGEST.into(),
                output_sha256: OTHER_DIGEST.into(),
            })
        );

        let (malformed, point) = signed(|report| {
            report.fingerprint = Some(Fingerprint {
                definition_sha256: DIGEST.into(),
                output_sha256: "not-a-digest".into(),
            });
        });
        assert!(report_is_authentic_and_fresh(&malformed, "agent-9", &point, now_ms()).is_none());
    }

    /// The writer-side allowance and the reader-side body limit must be the SAME bound, not the
    /// same number in two different units. A manifest of exactly [`MAX_OUTPUT_MANIFEST_BYTES`],
    /// attached to a report whose every other field is at its worst-case length, must sign into an
    /// envelope that still fits [`MAX_REPORT_ENVELOPE_BYTES`] after base64 expansion — otherwise a
    /// perfectly healthy node publishes nothing (writes are best-effort and never retried, and
    /// outputs ride only on healthy reports) and is drained from rotation forever.
    #[test]
    fn the_worst_case_envelope_for_a_max_size_manifest_fits_the_body_limit() {
        let size = |manifest: &OutputManifest| serde_json::to_vec(manifest).unwrap().len();
        let mut manifest = OutputManifest {
            schema: OutputManifest::SCHEMA,
            values: BTreeMap::new(),
        };
        // Fill to the cap with maximum-length values, then top the last one up so the manifest is
        // exactly at the bound rather than merely near it.
        for index in 0.. {
            let mut candidate = manifest.clone();
            candidate.values.insert(
                format!("output-{index:03}"),
                OutputValue::String {
                    value: "x".repeat(OutputManifest::MAX_STRING_BYTES),
                },
            );
            if size(&candidate) > MAX_OUTPUT_MANIFEST_BYTES {
                break;
            }
            manifest = candidate;
        }
        let name = "output-top".to_string();
        let mut probe = manifest.clone();
        probe.values.insert(
            name.clone(),
            OutputValue::String {
                value: String::new(),
            },
        );
        let fill = MAX_OUTPUT_MANIFEST_BYTES - size(&probe);
        manifest.values.insert(
            name,
            OutputValue::String {
                value: "x".repeat(fill),
            },
        );
        assert_eq!(size(&manifest), MAX_OUTPUT_MANIFEST_BYTES);
        manifest
            .validate()
            .expect("a manifest at the byte cap must be a valid one a node can actually attach");

        // Worst case around it: the longest identities and every optional field present.
        let mut report = NodeReport::new(
            "n".repeat(253),
            "d".repeat(253),
            OTHER_DIGEST,
            "1.2.3-rc.1+build.9999",
            DIGEST,
            true,
        );
        report.fingerprint = Some(Fingerprint {
            definition_sha256: DIGEST.into(),
            output_sha256: OTHER_DIGEST.into(),
        });
        report.outputs = Some(manifest);
        let (pkcs8, _) = keypair();
        let envelope = serde_json::to_vec(&sign_report(&report, &pkcs8).unwrap()).unwrap();
        assert!(
            envelope.len() <= MAX_REPORT_ENVELOPE_BYTES,
            "a max-size manifest signs into a {}-byte envelope, past the {MAX_REPORT_ENVELOPE_BYTES}-byte limit every reader enforces",
            envelope.len()
        );
    }

    #[test]
    fn typed_outputs_are_bounded_and_covered_by_the_report_signature() {
        let (envelope, point) = signed(|report| {
            report.outputs = Some(OutputManifest {
                schema: OutputManifest::SCHEMA,
                values: BTreeMap::from([
                    (
                        "leader-address".into(),
                        OutputValue::String {
                            value: "https://vault-0:8200".into(),
                        },
                    ),
                    (
                        "join-token".into(),
                        OutputValue::SecretRef {
                            secret: "vault-bootstrap".into(),
                            key: "join-token".into(),
                        },
                    ),
                ]),
            });
        });
        let report = report_is_authentic_and_fresh(&envelope, "agent-9", &point, now_ms())
            .expect("signed typed outputs must verify");
        assert_eq!(report.outputs.unwrap().values.len(), 2);

        let (oversized, point) = signed(|report| {
            report.outputs = Some(OutputManifest {
                schema: OutputManifest::SCHEMA,
                values: BTreeMap::from([(
                    "value".into(),
                    OutputValue::String {
                        value: "x".repeat(OutputManifest::MAX_STRING_BYTES + 1),
                    },
                )]),
            });
        });
        assert!(report_is_authentic_and_fresh(&oversized, "agent-9", &point, now_ms()).is_none());
    }

    #[test]
    fn the_pae_binds_the_type_and_the_lengths() {
        // The exact bytes DSSE specifies. Pinned because every other implementation — including
        // Draupnir's Elixir verifier — must produce this byte-for-byte or nothing interoperates.
        assert_eq!(
            pae(b"hi", "t/x"),
            b"DSSEv1 3 t/x 2 hi".to_vec(),
            "the PAE must be DSSEv1 <len(type)> <type> <len(payload)> <payload>"
        );
    }

    #[test]
    fn a_tampered_payload_or_a_wrong_key_never_verifies() {
        let (envelope, point) = signed(|_| {});

        // Re-point the report at other bytes after signing — the forgery a signature exists to catch.
        let mut forged = envelope.clone();
        let mut inner: NodeReport =
            serde_json::from_slice(&b64().decode(&envelope.payload).unwrap()).unwrap();
        inner.archive_sha256 = OTHER_DIGEST.into();
        forged.payload = b64().encode(serde_json::to_vec(&inner).unwrap());
        assert!(
            report_is_authentic_and_fresh(&forged, "agent-9", &point, now_ms()).is_none(),
            "a re-pointed payload must not verify"
        );

        let (_, other_point) = keypair();
        assert!(
            report_is_authentic_and_fresh(&envelope, "agent-9", &other_point, now_ms()).is_none(),
            "another node's key must not verify this report"
        );

        // A malformed pin is refused on shape, so a configuration mistake is not mistaken for a node
        // whose every report is forged. Empty, truncated, wrong tag, and all-zero all fail closed.
        for bad in [
            vec![],
            vec![4u8; 10],
            {
                let mut compressed = vec![2u8];
                compressed.extend_from_slice(&[7u8; 64]);
                compressed
            },
            {
                let mut zeroed = vec![4u8];
                zeroed.extend_from_slice(&[0u8; 64]);
                zeroed
            },
        ] {
            assert!(
                report_is_authentic_and_fresh(&envelope, "agent-9", &bad, now_ms()).is_none(),
                "a malformed pinned key must fail closed: {bad:?}"
            );
        }
    }

    #[test]
    fn an_envelope_of_another_type_cannot_be_replayed_as_a_health_report() {
        // The type is bound into the PAE, so this is refused twice over: by the explicit type check and
        // because a signature over a different type could not match anyway.
        let (envelope, point) = signed(|_| {});
        let mut mistyped = envelope;
        mistyped.payload_type = "application/vnd.updated.something-else+json".into();

        assert!(report_is_authentic_and_fresh(&mistyped, "agent-9", &point, now_ms()).is_none());
    }

    #[test]
    fn the_gate_refuses_a_misattributed_stale_or_unknown_record() {
        let (envelope, point) = signed(|_| {});

        assert!(
            report_is_authentic_and_fresh(&envelope, "another-agent", &point, now_ms()).is_none(),
            "a report must not be credited to a node it does not name"
        );

        let stamped = report_is_authentic_and_fresh(&envelope, "agent-9", &point, now_ms())
            .unwrap()
            .reported_at_ms;
        let too_late = stamped + REPORT_FRESHNESS.as_millis() as u64 + 1;
        assert!(
            report_is_authentic_and_fresh(&envelope, "agent-9", &point, too_late).is_none(),
            "a stale report must fail closed"
        );

        // A genuinely signed record whose field meanings this build does not know.
        let (future, future_point) = signed(|r| r.schema = NodeReport::SCHEMA + 1);
        assert!(
            report_is_authentic_and_fresh(&future, "agent-9", &future_point, now_ms()).is_none(),
            "an unknown schema must fail closed even when authentic"
        );
    }

    /// The two reasons a report is unsettled are carried separately, because a reader cannot
    /// recover them from `healthy` alone: an update transaction in flight is evidence a rollout
    /// ran, an ordinary readiness failure is not, and the control plane's rollback verdict is
    /// built on the first meaning. Claiming BOTH settled and mid-transaction is a contradiction
    /// no supervisor can produce, so it fails the gate closed rather than being interpreted.
    #[test]
    fn a_transaction_in_flight_is_reported_apart_from_readiness_and_never_beside_settled() {
        let (unsettled, point) = signed(|r| {
            r.healthy = false;
            r.updating = true;
        });
        let report = report_is_authentic_and_fresh(&unsettled, "agent-9", &point, now_ms())
            .expect("an unsettled report with a transaction in flight is well-formed");
        assert!(!report.healthy && report.updating);

        let (blip, point) = signed(|r| {
            r.healthy = false;
            r.updating = false;
        });
        let report = report_is_authentic_and_fresh(&blip, "agent-9", &point, now_ms())
            .expect("so is an unsettled report with no update anywhere near it");
        assert!(!report.healthy && !report.updating);

        let (contradictory, point) = signed(|r| r.updating = true);
        assert!(
            report_is_authentic_and_fresh(&contradictory, "agent-9", &point, now_ms()).is_none(),
            "settled means the confirmation window is closed; a record claiming both is malformed"
        );
    }

    #[test]
    fn a_future_stamped_report_ages_out_instead_of_staying_fresh_forever() {
        // The attack the forward bound exists for: one report stamped far ahead subtracts to age
        // zero under a backwards-only check and pins the node healthy and settled permanently.
        let (envelope, point) = signed(|r| r.reported_at_ms = u64::MAX);
        assert!(
            report_is_authentic_and_fresh(&envelope, "agent-9", &point, now_ms()).is_none(),
            "a report from the far future must fail closed, not read as age zero"
        );

        // A small disagreement between two machines' clocks is normal and still usable.
        let (skewed, point) = signed(|r| {
            r.reported_at_ms = now_ms() + REPORT_MAX_SKEW.as_millis() as u64 / 2;
        });
        assert!(
            report_is_authentic_and_fresh(&skewed, "agent-9", &point, now_ms()).is_some(),
            "ordinary clock skew must not reject a live node"
        );
    }

    #[test]
    fn a_reader_with_no_usable_clock_accepts_nothing() {
        // `now_ms()` reads 0 when the host clock cannot be read. Under a plain subtraction that
        // makes every report age zero — fresh forever, the fail-OPEN direction.
        let (envelope, point) = signed(|_| {});
        assert!(report_is_authentic_and_fresh(&envelope, "agent-9", &point, 0).is_none());
    }

    /// The one write-side gate both storing hops call. It must accept a genuine envelope filed under
    /// its own node and refuse everything a stored record could strand a reader with.
    #[test]
    fn the_write_gate_accepts_only_a_wellformed_envelope_filed_under_its_own_node() {
        let (pkcs8, _) = keypair();
        let envelope = sign_report(&report(), &pkcs8).unwrap();
        let body = serde_json::to_vec(&envelope).unwrap();

        assert_eq!(
            accept_report_envelope(&body, "agent-9").map(|report| report.node),
            Some("agent-9".to_string())
        );
        assert!(
            accept_report_envelope(&body, "agent-8").is_none(),
            "a report must not be storable under another node's name"
        );
        assert!(accept_report_envelope(b"not json", "agent-9").is_none());

        // Wrong payload type: an envelope this node legitimately signed for something else.
        let mut retyped = envelope.clone();
        retyped.payload_type = "application/vnd.updated.something-else+json".into();
        assert!(
            accept_report_envelope(&serde_json::to_vec(&retyped).unwrap(), "agent-9").is_none()
        );

        // A stuffed signature list is refused at the door, not left for every reader to pay for.
        let mut stuffed = envelope.clone();
        stuffed.signatures = std::iter::repeat_n(
            Signature {
                sig: b64().encode([0u8; 72]),
            },
            Envelope::MAX_SIGNATURES + 1,
        )
        .collect();
        assert!(
            accept_report_envelope(&serde_json::to_vec(&stuffed).unwrap(), "agent-9").is_none()
        );

        // A payload that parses but is not well formed: the reader-side shape gate, applied on write.
        let malformed = sign_report(
            &{
                let mut report = report();
                report.archive_sha256 = "deadbeef".into();
                report
            },
            &pkcs8,
        )
        .unwrap();
        assert!(
            accept_report_envelope(&serde_json::to_vec(&malformed).unwrap(), "agent-9").is_none()
        );

        // A schema every reader will discard. Storing it answered 200 while the rollout throttle
        // and the health proxy both dropped the record, so a node mid-fleet-upgrade read as silent
        // and drained out of rotation permanently — the exact stranding this gate exists to refuse
        // at the door, where the writer still learns about it.
        let skewed = sign_report(
            &{
                let mut report = report();
                report.schema = NodeReport::SCHEMA + 1;
                report
            },
            &pkcs8,
        )
        .unwrap();
        assert!(
            accept_report_envelope(&serde_json::to_vec(&skewed).unwrap(), "agent-9").is_none(),
            "the write gate must enforce the schema every reader enforces"
        );
    }

    #[test]
    fn an_envelope_stuffed_with_signatures_is_refused_before_any_verification() {
        let (pkcs8, point) = keypair();
        let mut envelope = sign_report(&report(), &pkcs8).unwrap();
        let genuine = envelope.signatures[0].clone();
        envelope.signatures = (0..Envelope::MAX_SIGNATURES)
            .map(|_| Signature {
                sig: b64().encode([0u8; 72]),
            })
            .chain(std::iter::once(genuine))
            .collect();
        assert!(
            report_is_authentic_and_fresh(&envelope, "agent-9", &point, now_ms()).is_none(),
            "an attacker-chosen signature count must not buy unbounded ECDSA verifications"
        );
    }

    #[test]
    fn the_gate_refuses_a_malformed_running_digest_even_when_signed() {
        for malformed in [
            "deadbeef".to_string(),
            DIGEST[..63].to_string(),
            format!("{DIGEST}0"),
            "z".repeat(64),
            format!("sha256:{DIGEST}"),
        ] {
            let (envelope, point) = signed(|r| r.archive_sha256 = malformed.clone());
            assert!(
                report_is_authentic_and_fresh(&envelope, "agent-9", &point, now_ms()).is_none(),
                "a digest a reader cannot join on must fail the gate: {malformed}"
            );
        }
    }

    #[test]
    fn a_node_before_its_first_install_reports_no_digest_and_still_passes_the_gate() {
        // Empty version and digest are the honest pre-install state, not a malformed record. Refusing it
        // would strand a fresh node outside the rollout's view entirely.
        let (envelope, point) = signed(|r| {
            r.version = String::new();
            r.archive_sha256 = String::new();
            r.healthy = false;
        });

        let report = report_is_authentic_and_fresh(&envelope, "agent-9", &point, now_ms()).unwrap();
        assert!(report.version.is_empty());
        assert!(report.archive_sha256.is_empty());
    }

    #[test]
    fn garbage_base64_and_bodies_fail_closed_rather_than_panicking() {
        let (envelope, point) = signed(|_| {});

        let mut bad_payload = envelope.clone();
        bad_payload.payload = "!!!not base64!!!".into();
        assert!(report_is_authentic_and_fresh(&bad_payload, "agent-9", &point, now_ms()).is_none());

        let mut bad_sig = envelope.clone();
        bad_sig.signatures[0].sig = "!!!".into();
        assert!(report_is_authentic_and_fresh(&bad_sig, "agent-9", &point, now_ms()).is_none());

        let mut no_sigs = envelope.clone();
        no_sigs.signatures.clear();
        assert!(report_is_authentic_and_fresh(&no_sigs, "agent-9", &point, now_ms()).is_none());

        // A valid signature over a payload that is not a report.
        let mut not_a_report = envelope;
        not_a_report.payload = b64().encode(b"{}");
        assert!(
            report_is_authentic_and_fresh(&not_a_report, "agent-9", &point, now_ms()).is_none()
        );
    }

    #[test]
    fn the_envelope_round_trips_and_rejects_unknown_fields() {
        let (envelope, _) = signed(|_| {});
        let json = serde_json::to_string(&envelope).unwrap();
        assert_eq!(serde_json::from_str::<Envelope>(&json).unwrap(), envelope);
        assert!(
            json.contains("\"payloadType\""),
            "DSSE spells it payloadType"
        );
        assert!(serde_json::from_str::<Envelope>(
            r#"{"payload":"e30=","payloadType":"t","signatures":[],"extra":1}"#
        )
        .is_err());
    }

    #[test]
    fn report_key_is_namespaced_by_node() {
        assert_eq!(report_object_key("agent-7"), "telemetry/agent-7.json");
    }

    #[test]
    fn the_assignment_layout_round_trips_and_rejects_foreign_paths() {
        assert_eq!(
            assignment_object_key("/assignments/", "agent-7"),
            "assignments/agents/agent-7.json"
        );
        assert_eq!(
            config_object_key("assignments", &"a".repeat(64)),
            format!("assignments/configs/{}.json", "a".repeat(64))
        );
        assert_eq!(
            split_assignment_path(&assignment_object_key("assignments", "agent-7")),
            Some(("assignments", "agent-7"))
        );
        // No prefix, no node identity, and no `.json` are each not this layout.
        assert_eq!(split_assignment_path("/agents/agent-7.json"), None);
        assert_eq!(split_assignment_path("assignments/agents/.json"), None);
        assert_eq!(split_assignment_path("assignments/agents/agent-7"), None);
        assert_eq!(
            split_assignment_path("assignments/configs/agent-7.json"),
            None
        );
    }

    #[test]
    fn report_url_joins_base_and_key_without_a_double_slash() {
        // The writer (agent) and every reader (health proxy) resolve a report URL through here, so
        // a trailing slash on the base must not produce `//` either way.
        assert_eq!(
            report_url("https://cdn/", "agent-1"),
            "https://cdn/telemetry/agent-1.json"
        );
        assert_eq!(
            report_url("https://cdn", "agent-1"),
            "https://cdn/telemetry/agent-1.json"
        );
    }

    #[test]
    fn node_recovers_from_its_report_path() {
        assert_eq!(node_from_path("/telemetry/agent-7.json"), Some("agent-7"));
        // The key a node writes and the path it PUTs are the two halves of one contract.
        assert_eq!(
            node_from_path(&format!("/{}", report_object_key("agent-7"))),
            Some("agent-7")
        );
    }

    #[test]
    fn node_path_rejects_traversal_and_unsafe_names() {
        for path in [
            "/telemetry/../secret.json",
            "/telemetry/a/b.json",
            "/telemetry/.json",
            "/telemetry/agent-7.txt",
            "/other/agent-7.json",
        ] {
            assert_eq!(node_from_path(path), None, "{path}");
        }
    }
}
