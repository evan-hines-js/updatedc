//! Node → control-plane rollout telemetry.
//!
//! The control plane can never reach a node, so completion feedback flows the other
//! way through shared storage: a node obtains an exact short-lived S3 POST capability and uploads a
//! small signed [`NodeReport`] to its own private object. The controller projects those raw objects
//! into canonical fleet report shards, and readers fetch that fixed-width shard set.
//! Reporting is strictly best-effort — a node that cannot write its report keeps
//! running, and a control plane that finds no report rolls without completion gating.

// This module DEFINES the report gates that `clippy.toml` bans elsewhere. The one owning
// composition and this module's tests receive narrow exemptions at their call sites below; the
// rest of this production module remains under the same enforcement as every consumer, so adding
// a second verification or acceptance path here cannot silently bypass the shared gate.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::key::P256PublicKey;

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

/// How much later than its assigned check interval a node's heartbeat can land: the agent
/// spreads each next check by this much, so consecutive reports are up to 1.2x the interval apart.
/// Public because the agent schedules against it — the spread a node actually applies and the
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

/// Namespace containing the controller's healthproxy-compatible fleet projection.
pub const REPORT_NAMESPACE: &str = "telemetry";

/// Stable index object every reader fetches first. It names one layout generation and the exact
/// number of shards in that generation; readers never guess layout from local configuration.
pub const FLEET_INDEX_OBJECT_KEY: &str = "telemetry/fleet.json";
#[cfg(test)]
const FLEET_INDEX_BASENAME: &str = "fleet";

/// The stable fleet-index URL below a health CDN base.
pub fn fleet_index_url(base: &str) -> String {
    format!("{}/{}", base.trim_end_matches('/'), FLEET_INDEX_OBJECT_KEY)
}

/// Hard ceiling for the runtime shard-count knob. The operator may choose any value from 1 through
/// this limit without changing wire format; the index advertises the active count and a change
/// causes the next flush to rebalance the whole fleet into a new generation.
///
/// Private: a caller reaches it only by asking [`FleetShardLimit::new`] (or the parser above it) to
/// accept a value, so a shard count that has crossed a module boundary has necessarily crossed this
/// check — there is no way to re-implement the range test against the raw number.
const MAX_FLEET_REPORT_SHARDS: usize = 64;

/// Shared bound on concurrent fleet-shard I/O. Writers and readers use the same fan-out ceiling,
/// so raising the shard-count knob does not create a second, component-specific memory multiplier.
pub const FLEET_SHARD_IO_CONCURRENCY: usize = 16;

/// The one configuration surface for the serialized fleet-report ceiling.
pub const FLEET_REPORT_MAX_SHARDS_ENV: &str = "UPDATED_FLEET_REPORT_MAX_SHARDS";

/// A shard ceiling that has passed the one shared range check. Writers and the rebalancer accept
/// this type instead of a raw integer, so no caller can invent a second interpretation of the
/// operator's memory knob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FleetShardLimit(u16);

impl FleetShardLimit {
    pub fn new(shards: usize) -> Result<Self, String> {
        if !(1..=MAX_FLEET_REPORT_SHARDS).contains(&shards) {
            return Err(format!(
                "{FLEET_REPORT_MAX_SHARDS_ENV} must be between 1 and {MAX_FLEET_REPORT_SHARDS}"
            ));
        }
        Ok(Self(
            u16::try_from(shards).expect("the absolute shard bound fits u16"),
        ))
    }

    pub fn get(self) -> usize {
        usize::from(self.0)
    }
}

/// Default for [`FLEET_REPORT_MAX_SHARDS_ENV`]. Four 16 MiB shards preserve the monolith's old
/// 64 MiB total byte ceiling while removing its one-object contention point.
pub const DEFAULT_FLEET_REPORT_MAX_SHARDS: FleetShardLimit = FleetShardLimit(4);

/// Parse the shard-count knob once, including its default and absolute safety bound. Both the
/// production gateway and the local server use this function so the same setting cannot mean two
/// different report-byte ceilings.
pub fn parse_fleet_report_max_shards(value: Option<&str>) -> Result<FleetShardLimit, String> {
    let shards = match value {
        Some(value) => value.parse::<usize>().map_err(|error| {
            format!("{FLEET_REPORT_MAX_SHARDS_ENV} must be an integer: {error}")
        })?,
        None => return Ok(DEFAULT_FLEET_REPORT_MAX_SHARDS),
    };
    FleetShardLimit::new(shards)
}

/// Exact byte ceiling for one fetched or stored fleet-report shard. Together with
/// `UPDATED_FLEET_REPORT_MAX_SHARDS`, this gives an operator an explicit upper bound on active
/// pending and stored serialized report bytes: `max_shards × 16 MiB`, plus the small index.
pub const MAX_FLEET_REPORT_SHARD_BYTES: usize = 16 * 1024 * 1024;

/// The index is fixed-size control metadata, never a place report data can accumulate.
pub const MAX_FLEET_INDEX_BYTES: usize = 4 * 1024;

/// Obsolete projection generations remain readable across an index race, then are eligible for
/// deletion. Two freshness windows outlive any useful report read while bounding orphaned storage.
pub const FLEET_GENERATION_RETENTION: Duration =
    Duration::from_secs(REPORT_FRESHNESS.as_secs() * 2);

/// The segment that separates a routing-assignment prefix from the node it addresses. The control
/// plane publishes each node's assignment at exactly `<prefix>/agents/<node>.json`.
///
/// Private, like its sibling below: publishing the raw segment would re-open the door the accessors
/// close, letting a caller format its own `<prefix>/agents/<node>.json` — a second speller of the
/// layout, which is exactly what [`assignment_object_key`] and [`split_assignment_path`] exist to
/// make impossible.
const ASSIGNMENT_AGENTS_SEGMENT: &str = "/agents/";

/// The segment that separates a routing-assignment prefix from the content-addressed deployment
/// document the node's assignment points at: `<prefix>/configs/<id>.json`.
const ASSIGNMENT_CONFIGS_SEGMENT: &str = "/configs/";

/// The digest that stands for a node wherever its name itself cannot appear.
///
/// A node name is operator-chosen and variable-length, so anything that needs a fixed-width, safe,
/// collision-free stand-in for it uses this: the private object keys for a node's reports and
/// outputs, its enrollment generation prefix, and the `registrationSha256` an enrolled agent is
/// pinned to.
///
/// One function because these are one fact. The gateway *writes* an agent's registration digest and
/// the control plane *checks* it; the dataflow scanner *derives* a report key and the sweeper
/// *matches* it. Spelled out separately — as `sha256_bytes(node.as_bytes())`, eight times — a change
/// to the convention would have moved the writers and left the readers looking in the old place,
/// which reads as a node that silently never reports rather than as a mistake.
pub fn node_object_digest(node: &str) -> String {
    crate::digest::sha256_bytes(node.as_bytes())
}

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
    (!prefix.is_empty() && crate::identity::is_dns_subdomain(node)).then_some((prefix, node))
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
/// bytes of the signed DSSE envelope. Health reports never carry dataflow values; secret-bearing
/// snapshots use the authenticated dataflow API instead.
pub const MAX_REPORT_ENVELOPE_BYTES: usize = 64 * 1024;

impl Fingerprint {
    pub fn from_output(
        definition_sha256: impl Into<String>,
        output: &[u8],
    ) -> Result<Self, String> {
        let fingerprint = Self {
            definition_sha256: definition_sha256.into(),
            output_sha256: crate::digest::sha256_bytes(output),
        };
        fingerprint
            .is_wellformed()
            .then_some(fingerprint)
            .ok_or_else(|| "fingerprint definition is not a SHA-256".into())
    }

    pub fn is_wellformed(&self) -> bool {
        crate::is_canonical_sha256(&self.definition_sha256)
            && crate::is_canonical_sha256(&self.output_sha256)
    }
}

/// A node's self-reported running state, signed by the node's own per-node key.
///
/// Authenticity IS load-bearing: a report is consumed only through
/// [`authenticate_report`], which requires the signature to verify against the key the
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
    /// other non-`is_canonical_sha256` value is malformed and fails the trust gate closed.
    pub archive_sha256: String,
    /// SHA-256 of the signed provider-set document whose reconciler is actually installed.
    /// Application bytes and their lifecycle provider are one deployed unit; reporting both keeps
    /// a provider-only assignment from looking settled while the node still runs the old hooks.
    /// Empty only before the first install, alongside [`NodeReport::archive_sha256`].
    pub provider_set_sha256: String,
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
    ///
    /// No VERDICT reads it. The regression evidence is [`NodeReport::rejected`], which the node
    /// states outright instead of leaving a sequence for a reader to catch. This remains the half
    /// of `healthy == false` that says a transaction genuinely ran, which `is_wellformed` enforces
    /// (never true together with `healthy`).
    pub updating: bool,
    /// Whether this node has DURABLY REJECTED the release its assignment names: the archive
    /// [`NodeReport::assignment_sha256`] resolves to is in the node's rejection record, written by
    /// content hash when a candidate failed and kept for good.
    ///
    /// This is the node stating a TERMINAL fact about itself, and it is the only honest source for
    /// it. The control plane cannot infer it: a rejection is recorded for a candidate that failed
    /// its ACTIVATION as well as for one that failed its confirmation window, and the first —
    /// a release that cannot start at all, the most ordinary bad release there is — runs no update
    /// transaction, so it leaves no report sequence to observe. Inferring it from a sequence also
    /// required catching a transient (`updating`) as it went past, which a control plane that was
    /// restarting, had just changed leader, or was simply slow that second never saw again: the
    /// node never retries rejected bytes, so a missed sequence was missed for ever, and the group
    /// containing it stayed "rolling" — holding its set's concurrency slot against every sibling —
    /// with no exit but an operator retargeting it by hand.
    ///
    /// It is a fact about BYTES, so it is stable across reboots and reports: the record never
    /// expires, and corrected bytes have a new digest, which is the same rule the fleet-wide halt
    /// enforces.
    ///
    pub rejected: bool,
    /// Milliseconds since the Unix epoch when the node wrote this report (see [`now_ms`]). A
    /// reader ages the report against this so a node that dies without writing a not-ready
    /// report cannot stay trusted forever — a stale report fails closed.
    pub reported_at_ms: u64,
    /// Opaque node-state fingerprint. Absent before the first successful observation or when the
    /// bounded observation failed or was cancelled for a deployment.
    #[serde(deserialize_with = "crate::required_option")]
    pub fingerprint: Option<Fingerprint>,
    /// SHA-256 of the exact output-publication bytes successfully written before this report.
    /// The publication lives in a separate private object, so signing its exact content identity
    /// is what prevents an untrusted object store from substituting different dependency values.
    /// Absent when the node is unhealthy, has no declared outputs, or could not publish them.
    #[serde(deserialize_with = "crate::required_option")]
    pub output_sha256: Option<String>,
    /// Platform-owned evidence for the latest successful state-changing reconciler invocation.
    /// The node persists this before accepting the invocation, then signs it into every heartbeat.
    #[serde(deserialize_with = "crate::required_option")]
    pub reconciliation: Option<crate::reconciler::LastReconciliation>,
}

impl NodeReport {
    pub const SCHEMA: u32 = 12;

    /// A report of a node that is NOT mid-transaction and claims no rejection.
    /// [`NodeReport::updating`] and [`NodeReport::rejected`] are set by the one writer that knows
    /// (the agent's heartbeat, from its own unconfirmed-update journal and its own rejection
    /// record); every other constructor is describing a settled or merely not-ready node.
    pub fn new(
        node: impl Into<String>,
        deployment: impl Into<String>,
        assignment_sha256: impl Into<String>,
        version: impl Into<String>,
        archive_sha256: impl Into<String>,
        provider_set_sha256: impl Into<String>,
        healthy: bool,
    ) -> Self {
        Self {
            schema: Self::SCHEMA,
            node: node.into(),
            deployment: deployment.into(),
            assignment_sha256: assignment_sha256.into(),
            version: version.into(),
            archive_sha256: archive_sha256.into(),
            provider_set_sha256: provider_set_sha256.into(),
            healthy,
            updating: false,
            rejected: false,
            reported_at_ms: now_ms(),
            fingerprint: None,
            output_sha256: None,
            reconciliation: None,
        }
    }

    /// Whether this report is a shape a reader may act on.
    ///
    /// The schema first: a record of a version this build does not know is not a report it may
    /// interpret, whatever the rest of it says. It is checked HERE, in the one predicate both the
    /// storage gate ([`accept_stored_report`]) and the read gate ([`authenticate_report`])
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
        self.shape_error().is_none()
    }

    /// The diagnostic form of [`Self::is_wellformed`]. Private so callers still have one public
    /// structural predicate; the producer uses the reason only to make a fail-closed omission
    /// actionable instead of logging an opaque "malformed" warning.
    fn shape_error(&self) -> Option<&'static str> {
        if self.schema != Self::SCHEMA {
            return Some("unknown schema");
        }
        if !crate::identity::is_dns_subdomain(&self.node) {
            return Some("invalid node identity");
        }
        if !crate::identity::is_segment(&self.deployment) {
            return Some("invalid deployment identity");
        }
        if self.reported_at_ms == 0 {
            return Some("missing report timestamp");
        }
        if self.version.is_empty() != self.archive_sha256.is_empty() {
            return Some("version and archive identity are incomplete");
        }
        if !self.version.is_empty() && !crate::identity::is_release_version(&self.version) {
            return Some("invalid release version");
        }
        if self.archive_sha256.is_empty() != self.provider_set_sha256.is_empty() {
            return Some("archive and provider-set identity are incomplete");
        }
        if self.healthy && self.archive_sha256.is_empty() {
            return Some("healthy report has no installed release");
        }
        if self.healthy && self.updating {
            return Some("report is both healthy and updating");
        }
        if !self.archive_sha256.is_empty() && !crate::is_canonical_sha256(&self.archive_sha256) {
            return Some("invalid archive digest");
        }
        if !self.provider_set_sha256.is_empty()
            && !crate::is_canonical_sha256(&self.provider_set_sha256)
        {
            return Some("invalid provider-set digest");
        }
        if !self.assignment_sha256.is_empty()
            && !crate::is_canonical_sha256(&self.assignment_sha256)
        {
            return Some("invalid assignment digest");
        }
        if self
            .fingerprint
            .as_ref()
            .is_some_and(|fingerprint| !fingerprint.is_wellformed())
        {
            return Some("invalid fingerprint");
        }
        if self
            .output_sha256
            .as_deref()
            .is_some_and(|digest| !crate::is_canonical_sha256(digest))
        {
            return Some("invalid output digest");
        }
        if !self.healthy && (self.fingerprint.is_some() || self.output_sha256.is_some()) {
            return Some("unhealthy report carries healthy-only evidence");
        }
        match &self.reconciliation {
            None if self.version.is_empty() => None,
            None => Some("installed release has no reconciliation evidence"),
            Some(_) if self.version.is_empty() => {
                Some("reconciliation evidence has no installed release")
            }
            Some(record)
                if record.candidate().version() != self.version
                    || record.candidate().archive_sha256() != self.archive_sha256
                    || record.reconciler().provider_set_sha256() != self.provider_set_sha256 =>
            {
                Some("reconciliation evidence names a different release")
            }
            Some(_) => None,
        }
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

    /// Whether this report proves convergence to one exact desired-state unit.
    ///
    /// Health alone describes the release that is actually serving and deliberately remains true
    /// after a successful rollback. Convergence additionally binds the signed assignment, the
    /// application archive, and its provider set, and excludes a standing rejection of that
    /// assignment. Rollout settlement and dataflow admission share this predicate so neither can
    /// mistake a healthy predecessor for the desired release.
    pub fn is_converged_to(
        &self,
        assignment_sha256: &str,
        archive_sha256: &str,
        provider_set_sha256: &str,
    ) -> bool {
        self.is_wellformed()
            && self.healthy
            && !self.rejected
            && self.assignment_sha256 == assignment_sha256
            && self.archive_sha256 == archive_sha256
            && self.provider_set_sha256 == provider_set_sha256
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

/// The one node-report producer boundary.
///
/// Validates the same report shape every write and trust gate consumes, signs the exact JSON
/// payload with the node's private key (PKCS#8 DER), and encodes the envelope under the same byte
/// ceiling every reader enforces. Keeping all three operations inseparable prevents callers from
/// publishing a signed report no consumer can use or forgetting the wire bound after signing.
pub fn encode_signed_report(report: &NodeReport, pkcs8_der: &[u8]) -> Result<Vec<u8>, String> {
    if let Some(error) = report.shape_error() {
        return Err(format!("refusing to sign a malformed node report: {error}"));
    }
    encode_report_envelope(&sign_report_envelope(report, pkcs8_der)?)
}

/// Cryptographic primitive behind [`encode_signed_report`]. Private so production callers cannot
/// bypass the shared report-shape and wire-size invariants. Tests use it only to construct
/// authentic malformed inputs for fail-closed consumer coverage.
fn sign_report_envelope(report: &NodeReport, pkcs8_der: &[u8]) -> Result<Envelope, String> {
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

fn encode_report_envelope(envelope: &Envelope) -> Result<Vec<u8>, String> {
    crate::bounded::encode(envelope, "node report envelope", MAX_REPORT_ENVELOPE_BYTES)
}

/// The durable object-store timestamp attached to raw report bytes.
///
/// Fleet eviction uses storage order, not an untrusted payload timestamp or the instant a
/// controller happened to restart and reread an object. The private field prevents callers from
/// confusing an arbitrary integer with that ordering evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReportStoredAt(u64);

impl ReportStoredAt {
    /// Convert an object store's Unix-millisecond timestamp. Pre-epoch metadata is not a valid
    /// ordering instant for this protocol and is rejected instead of silently clamped.
    pub fn from_unix_millis(value: i64) -> Option<Self> {
        u64::try_from(value).ok().map(Self)
    }
}

/// The one fleet-admission gate for a stored report envelope.
///
/// Returns an opaque accepted report only when the body fits [`MAX_REPORT_ENVELOPE_BYTES`], is an envelope
/// of the report payload type, carries one to [`Envelope::MAX_SIGNATURES`] signatures, and decodes
/// to a report that is well formed
/// (which includes the exact current schema — the same fail-closed predicate every reader applies,
/// so a record no reader can use is never stored), and names `node` — the node the caller
/// is filing it under. The signature is deliberately NOT
/// verified here, and this is the only function that decodes a payload without checking it: a writer
/// hop authorizes by the transport identity that presented the bytes, and the signature is
/// end-to-end evidence for the consumers that later read them back, every one of which must go
/// through [`authenticate_report`] instead.
///
/// It lives here, beside the envelope types, because every production ingestion/projection path
/// and every fixture must enforce the *same* thing. Maintained as copies, a tightening in one path
/// would silently make another accept a report no consumer can use.
pub fn accept_stored_report(
    body: &[u8],
    node: &str,
    stored_at: ReportStoredAt,
) -> Option<AcceptedReport> {
    let envelope: Envelope =
        crate::bounded::decode(body, "node report envelope", MAX_REPORT_ENVELOPE_BYTES).ok()?;
    let payload = decode_report_payload(&envelope)?;
    parse_attributed_payload(&payload, node).map(|_| AcceptedReport {
        node: node.to_string(),
        envelope,
        stored_at_ms: stored_at.0,
    })
}

/// The one envelope decoder shared by storage admission, shard recovery, and cryptographic
/// authentication. Every trusted path therefore agrees on payload type, signature cardinality,
/// and base64 spelling.
fn decode_report_payload(envelope: &Envelope) -> Option<Vec<u8>> {
    if envelope.payload_type != REPORT_PAYLOAD_TYPE
        || envelope.signatures.is_empty()
        || envelope.signatures.len() > Envelope::MAX_SIGNATURES
    {
        return None;
    }
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(&envelope.payload)
        .ok()
}

/// The one report parser and attribution gate. Authentication calls it only after signature
/// verification, so forged payloads cannot spend JSON parsing work; storage admission and shard
/// recovery use the identical interpretation without pretending to establish authenticity.
fn parse_attributed_payload(payload: &[u8], node: &str) -> Option<NodeReport> {
    let report = serde_json::from_slice::<NodeReport>(payload).ok()?;
    (crate::identity::is_dns_subdomain(node) && report.node == node && report.is_wellformed())
        .then_some(report)
}

/// Proof that a report passed [`accept_stored_report`].
///
/// The fields are intentionally private: writers cannot construct or alter this value and
/// [`FleetReports::record`] accepts no raw envelope. Consequently every report entering a fleet
/// generation has exactly one validation path, and the envelope parsed by the gate is the envelope
/// stored by the writer rather than a second parse of the same request body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedReport {
    node: String,
    envelope: Envelope,
    /// When the object store durably recorded these exact bytes.
    ///
    /// A property of the acceptance, never of the moment someone asks. [`FleetReports`] evicts by
    /// this value. It therefore survives controller restarts and cannot collapse "evict the
    /// stalest" into "evict whichever node sorts first" when a cache is rebuilt.
    stored_at_ms: u64,
}

impl AcceptedReport {
    /// Consume the proof and return the exact envelope parsed by the shared acceptance gate.
    ///
    /// Caches that need to retain the raw signed envelope use this instead of reparsing the
    /// untrusted request body after validation. Construction remains private, so obtaining an
    /// envelope this way is itself proof that the one write-side gate accepted it.
    pub fn into_envelope(self) -> Envelope {
        self.envelope
    }

    /// The node these bytes are attributed to, as the gate confirmed it.
    pub fn node(&self) -> &str {
        &self.node
    }

    fn into_stored(self) -> (String, StoredReport) {
        (
            self.node,
            StoredReport {
                envelope: self.envelope,
                stored_at_ms: self.stored_at_ms,
            },
        )
    }
}

/// An authenticated report whose perishable fields remain sealed behind the shared freshness gate.
///
/// The inner [`NodeReport`] is intentionally private. Authentication alone is not authority to
/// read current health, deployment, or output state: those claims expire. A holder can obtain the
/// full report only through [`AuthenticReport::fresh`], or read the one nonperishable claim through
/// [`AuthenticReport::rejected_assignment`]. This makes the trust distinction a type boundary rather
/// than a warning every cache and consumer has to remember.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticReport(NodeReport);

impl AuthenticReport {
    /// The full report, only while it is inside the one shared freshness window.
    pub fn fresh(&self, now_ms: u64) -> Option<NodeReport> {
        self.0.is_fresh(now_ms).then(|| self.0.clone())
    }

    /// The report's one durable claim: the exact signed assignment this node permanently
    /// rejected. A negative statement is current report state, not durable evidence, and therefore
    /// has no value in this stale-safe API.
    pub fn rejected_assignment(&self) -> Option<&str> {
        self.0.rejected.then_some(&self.0.assignment_sha256)
    }
}

/// The one trust gate for consuming a node report.
///
/// The envelope is authentic, attributed to this node, and of a schema this build understands, but
/// it may be of any age. The returned [`AuthenticReport`] enforces the only two legal ways to read
/// it, so caching an authenticity verdict cannot accidentally turn stale health into current state.
///
/// One claim in a report is not perishable — [`NodeReport::rejected`], which is a statement about
/// BYTES: this node durably refused this release, a record that never expires and that the node
/// never revisits. Requiring freshness there made one contained node going quiet for longer than
/// [`REPORT_FRESHNESS`] — a rejection restarts the app and often reboots the host, so this is the
/// ordinary case — drop the fleet's evidence below its threshold, clear the halt for that pass, and
/// admit another batch onto the proven-bad body, one blip at a time.
///
/// The schema is checked explicitly even though it is signed: a signature proves the *node* wrote
/// that value, not that this build agrees with what it means.
pub fn authenticate_report(
    envelope: &Envelope,
    expected_node: &str,
    public_key: &P256PublicKey,
) -> Option<AuthenticReport> {
    use base64::Engine as _;

    let payload = decode_report_payload(envelope)?;
    let b64 = base64::engine::general_purpose::STANDARD;
    let pae = pae(&payload, REPORT_PAYLOAD_TYPE);

    // The pin cannot be malformed here: [`P256PublicKey`] is the only shape this takes and its
    // constructors are the only way to make one, so a truncated key, a stray PEM header, or a
    // config typo was already refused where the operator configured it. That matters because such a
    // pin fails every signature and is indistinguishable in the logs from a genuinely forged report.
    let verified = envelope.signatures.iter().any(|signature| {
        b64.decode(&signature.sig)
            .is_ok_and(|sig| public_key.verify_asn1(&pae, &sig))
    });
    if !verified {
        return None;
    }

    Some(AuthenticReport(parse_attributed_payload(
        &payload,
        expected_node,
    )?))
}

/// Whether the report an envelope CLAIMS to carry is stale, decoded without verifying a signature.
///
/// For OBSERVABILITY only, never a trust decision: [`authenticate_report`] remains the
/// one gate anything acting on a report goes through. Deliberately returns only the one permitted
/// observation instead of a full [`NodeReport`]; unverified health, deployment and rejection fields
/// therefore cannot escape this boundary and accidentally become control-plane input later.
/// `None` means the envelope did not even contain a parseable report.
pub fn report_staleness_for_observability(envelope: &Envelope, now_ms: u64) -> Option<bool> {
    use base64::Engine as _;
    if envelope.payload_type != REPORT_PAYLOAD_TYPE {
        return None;
    }
    let payload = base64::engine::general_purpose::STANDARD
        .decode(&envelope.payload)
        .ok()?;
    serde_json::from_slice::<NodeReport>(&payload)
        .ok()
        .map(|report| !report.is_fresh(now_ms))
}

/// The index readers use to discover one complete fleet generation. Its fields are private and it
/// is not `Serialize`: only [`FleetReports::rebalance`] can publish an index, so there is one way to
/// produce a layout and changing the shard-count knob always runs through the same rebalancer.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetIndex {
    schema: u32,
    generation: String,
    max_shards: u16,
    #[serde(deserialize_with = "crate::required_option")]
    rebalance_to: Option<u16>,
}

impl FleetIndex {
    const SCHEMA: u32 = 1;

    /// Parse the bounded stable index. One schema admits one exact shape, and generation names are
    /// fixed-width lowercase hex so derived object keys cannot escape their namespace.
    pub fn parse(body: &[u8]) -> Option<Self> {
        let index: Self =
            crate::bounded::decode(body, "fleet report index", MAX_FLEET_INDEX_BYTES).ok()?;
        let generation_ok = index.generation.len() == 32
            && index
                .generation
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        (index.schema == Self::SCHEMA
            && generation_ok
            && (1..=MAX_FLEET_REPORT_SHARDS).contains(&usize::from(index.max_shards))
            && index.rebalance_to.is_none_or(|target| {
                target != index.max_shards
                    && (1..=MAX_FLEET_REPORT_SHARDS).contains(&usize::from(target))
            }))
        .then_some(index)
    }

    /// Produce the one immutable transition marker that freezes steady-state writes before a full
    /// rebalance reads this generation. A marker is never cancelled or retargeted: every replica
    /// that sees one helps finish it, which makes rolling configuration changes serializable.
    pub fn begin_rebalance(&self, target: FleetShardLimit) -> Result<(Self, Vec<u8>), String> {
        if self.rebalance_to.is_some() {
            return Err("the fleet generation is already marked for rebalance".into());
        }
        if self.max_shards == target.0 {
            return Err("the fleet generation already has the requested shard limit".into());
        }
        let mut transition = self.clone();
        transition.rebalance_to = Some(target.0);
        let body = transition.encode()?;
        Ok((transition, body))
    }

    /// Immutable shard locations for this exact generation, in canonical order.
    pub fn shard_locations(&self) -> impl ExactSizeIterator<Item = FleetShardLocation> + '_ {
        (0..self.max_shards).map(|shard| FleetShardLocation {
            generation: self.generation.clone(),
            shard,
            max_shards: self.max_shards,
        })
    }

    /// Canonical, deduplicated shard locations containing `nodes`. A reader that needs only a
    /// configured subset of the fleet must not download unrelated shards; full rebalance and
    /// repair continue to use [`Self::shard_locations`].
    pub fn shard_locations_for<'a>(
        &self,
        nodes: impl IntoIterator<Item = &'a str>,
    ) -> Vec<FleetShardLocation> {
        let max_shards = usize::from(self.max_shards);
        let wanted: BTreeSet<u16> = nodes
            .into_iter()
            .map(|node| {
                u16::try_from(FleetReports::shard_for(node, max_shards))
                    .expect("the absolute shard bound fits u16")
            })
            .collect();
        self.shard_locations()
            .filter(|location| wanted.contains(&location.shard))
            .collect()
    }

    fn encode(&self) -> Result<Vec<u8>, String> {
        #[derive(Serialize)]
        struct Document<'a> {
            schema: u32,
            generation: &'a str,
            max_shards: u16,
            rebalance_to: Option<u16>,
        }
        // Under the same ceiling the reader decodes with. This was a `debug_assert!`, which is
        // compiled out of the release binaries that actually ship: an index past the ceiling would
        // have been written happily and then refused by every healthproxy that fetched it. The
        // index is the DISCOVERY document — no readable index means no shards are found at all, so
        // the whole fleet reads as absent rather than as one oversized object.
        crate::bounded::encode(
            &Document {
                schema: self.schema,
                generation: &self.generation,
                max_shards: self.max_shards,
                rebalance_to: self.rebalance_to,
            },
            "fleet report index",
            MAX_FLEET_INDEX_BYTES,
        )
    }
}

/// One CAS-updated shard named by a [`FleetIndex`]. Readers use this value for both its derived
/// location and the generation/index binding checked inside the shard body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FleetShardLocation {
    generation: String,
    shard: u16,
    max_shards: u16,
}

impl FleetShardLocation {
    pub fn object_key(&self) -> String {
        format!(
            "{REPORT_NAMESPACE}/fleet/{}/{:04x}.json",
            self.generation, self.shard
        )
    }

    pub fn url(&self, base: &str) -> String {
        format!("{}/{}", base.trim_end_matches('/'), self.object_key())
    }
}

/// One encoded shard of a generation: where it lives and the exact bytes stored there.
pub type EncodedShard = (FleetShardLocation, Vec<u8>);

/// One fully encoded generation produced by [`FleetReports::rebalance`]. Consuming it yields the
/// stable index bytes, every initial shard body, and the number of oldest entries evicted to stay
/// inside the operator's exact `max_shards × MAX_FLEET_REPORT_SHARD_BYTES` serialized budget.
pub struct FleetGeneration {
    index: FleetIndex,
    index_body: Vec<u8>,
    shards: Vec<EncodedShard>,
    evicted: usize,
}

impl FleetGeneration {
    pub fn into_parts(self) -> (FleetIndex, Vec<u8>, Vec<EncodedShard>, usize) {
        (self.index, self.index_body, self.shards, self.evicted)
    }
}

/// In-memory fleet reports: every node's most recently accepted envelope, keyed by node identity.
/// Stored bytes are always a generation of bounded shards referenced by [`FLEET_INDEX_OBJECT_KEY`];
/// this aggregate is never serialized directly.
///
/// This is TRANSPORT, not authority. Each envelope is consumed only through
/// [`authenticate_report`] against its node's pinned key. Reordering or dropping an entry
/// only drains a node; forging one still requires its private key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FleetReports {
    reports: BTreeMap<String, StoredReport>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredReport {
    stored_at_ms: u64,
    envelope: Envelope,
}

impl FleetReports {
    const SHARD_SCHEMA: u32 = 1;

    /// Parse one shard only when its bounded body agrees with the generation and position named by
    /// the index. Entries that could not have passed the shared write gate are dropped individually
    /// as storage corruption rather than poisoning the rest of the shard.
    pub fn parse_shard(body: &[u8], location: &FleetShardLocation) -> Option<Self> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Document {
            schema: u32,
            generation: String,
            shard: u16,
            reports: BTreeMap<String, serde_json::Value>,
        }

        let document: Document =
            crate::bounded::decode(body, "fleet report shard", MAX_FLEET_REPORT_SHARD_BYTES)
                .ok()?;
        if document.schema != Self::SHARD_SCHEMA
            || document.generation != location.generation
            || document.shard != location.shard
        {
            return None;
        }
        let reports = document
            .reports
            .into_iter()
            .filter_map(|(node, value)| {
                let stored: StoredReport = serde_json::from_value(value).ok()?;
                (serde_json::to_vec(&stored.envelope)
                    .is_ok_and(|body| body.len() <= MAX_REPORT_ENVELOPE_BYTES)
                    && decode_report_payload(&stored.envelope)
                        .and_then(|payload| parse_attributed_payload(&payload, &node))
                        .is_some()
                    && Self::shard_for(&node, usize::from(location.max_shards))
                        == usize::from(location.shard))
                .then_some((node, stored))
            })
            .collect();
        Some(Self { reports })
    }

    /// Record a report produced by the shared storage gate. Durable object-store order, never an
    /// unverified payload timestamp or controller process age, decides which report is evicted.
    pub fn record(&mut self, accepted: AcceptedReport) {
        let (node, stored) = accepted.into_stored();
        self.reports.insert(node, stored);
    }

    /// Overlay a later accepted/read set onto this one. Object-store CAS decides replica ordering;
    /// payload timestamps do not act as a second concurrency mechanism.
    pub fn overlay(&mut self, newer: Self) {
        self.reports.extend(newer.reports);
    }

    /// Remove one node's envelope for consumption. Readers ask only for their configured fleet, so
    /// unknown stored nodes never escape the transport aggregate.
    pub fn remove(&mut self, node: &str) -> Option<Envelope> {
        self.reports.remove(node).map(|stored| stored.envelope)
    }

    pub fn is_empty(&self) -> bool {
        self.reports.is_empty()
    }

    /// Deterministically rebalance the entire fleet into exactly `max_shards` bounded objects and a
    /// new generation. A node's SHA-256 identity chooses its shard, which makes steady-state writes
    /// touch only shards carrying this flush's nodes; changing the knob rehashes the full fleet.
    pub fn rebalance(self, max_shards: FleetShardLimit) -> Result<FleetGeneration, String> {
        let max_shards = max_shards.get();
        use aws_lc_rs::rand::SecureRandom as _;
        let mut random = [0u8; 16];
        aws_lc_rs::rand::SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| "generating a fleet report generation ID".to_string())?;
        let generation = hex::encode(random);

        let mut bins: Vec<BTreeMap<String, StoredReport>> =
            (0..max_shards).map(|_| BTreeMap::new()).collect();
        for (node, stored) in self.reports {
            let shard = Self::shard_for(&node, max_shards);
            bins[shard].insert(node, stored);
        }

        let index = FleetIndex {
            schema: FleetIndex::SCHEMA,
            generation: generation.clone(),
            max_shards: u16::try_from(max_shards).expect("the absolute shard bound fits u16"),
            rebalance_to: None,
        };
        let index_body = index.encode()?;

        let mut evicted = 0;
        let mut shards = Vec::with_capacity(max_shards);
        for (reports, location) in bins.into_iter().zip(index.shard_locations()) {
            let (body, removed) = Self::encode_shard(reports, &location);
            evicted += removed;
            shards.push((location, body));
        }
        Ok(FleetGeneration {
            index,
            index_body,
            shards,
            evicted,
        })
    }

    /// Split a buffered batch by the current layout. This is the only steady-state placement path;
    /// it uses the same hash function as full rebalance, so a node can never acquire two homes.
    pub fn into_shard_updates(self, index: &FleetIndex) -> Vec<FleetShardUpdate> {
        let shard_count = usize::from(index.max_shards);
        let locations: Vec<_> = index.shard_locations().collect();
        let mut updates: BTreeMap<u16, FleetReports> = BTreeMap::new();
        for (node, stored) in self.reports {
            let shard = u16::try_from(Self::shard_for(&node, shard_count))
                .expect("the absolute shard bound fits u16");
            updates
                .entry(shard)
                .or_default()
                .reports
                .insert(node, stored);
        }
        updates
            .into_iter()
            .map(|(shard, reports)| FleetShardUpdate {
                location: locations[usize::from(shard)].clone(),
                reports,
            })
            .collect()
    }

    fn shard_for(node: &str, shard_count: usize) -> usize {
        // The placement rule is wire-visible: writer and reader must land a node on the same
        // shard, so it is defined on the canonical digest spelling every other identity uses —
        // the leading 64 bits, read big-endian out of the first sixteen hex characters.
        let digest = node_object_digest(node);
        let prefix = u64::from_str_radix(&digest[..16], 16).expect("sixteen hex characters");
        let divisor = u64::try_from(shard_count).expect("the absolute shard bound fits u64");
        usize::try_from(prefix % divisor).expect("a shard index fits usize")
    }

    fn entry_len(node: &str, stored: &StoredReport) -> usize {
        serde_json::to_vec(node)
            .expect("a string always encodes")
            .len()
            + 1
            + serde_json::to_vec(stored)
                .expect("a stored report of integers and strings always encodes")
                .len()
    }

    fn encode_shard(
        mut reports: BTreeMap<String, StoredReport>,
        location: &FleetShardLocation,
    ) -> (Vec<u8>, usize) {
        #[derive(Serialize)]
        struct Document<'a> {
            schema: u32,
            generation: &'a str,
            shard: u16,
            reports: &'a BTreeMap<String, StoredReport>,
        }

        let empty = BTreeMap::new();
        let base_len = serde_json::to_vec(&Document {
            schema: Self::SHARD_SCHEMA,
            generation: &location.generation,
            shard: location.shard,
            reports: &empty,
        })
        .expect("a fleet shard header always encodes")
        .len();
        let mut entries: Vec<(u64, String, usize)> = reports
            .iter()
            .map(|(node, stored)| {
                (
                    stored.stored_at_ms,
                    node.clone(),
                    Self::entry_len(node, stored),
                )
            })
            .collect();
        let mut encoded_len = base_len
            + entries.iter().map(|(_, _, len)| len).sum::<usize>()
            + entries.len().saturating_sub(1);
        entries.sort_by(|left, right| (left.0, left.1.as_str()).cmp(&(right.0, right.1.as_str())));

        let mut evicted = 0;
        for (_, node, entry_len) in entries {
            if encoded_len <= MAX_FLEET_REPORT_SHARD_BYTES {
                break;
            }
            let entries_before = reports.len();
            reports.remove(&node);
            encoded_len -= entry_len + usize::from(entries_before > 1);
            evicted += 1;
        }
        let body = serde_json::to_vec(&Document {
            schema: Self::SHARD_SCHEMA,
            generation: &location.generation,
            shard: location.shard,
            reports: &reports,
        })
        .expect("a fleet shard always encodes");
        debug_assert_eq!(body.len(), encoded_len);
        (body, evicted)
    }
}

/// The buffered reports assigned to one current-generation shard. Its fields are private so a
/// writer cannot choose a different placement or a second encoding path.
#[derive(Clone)]
pub struct FleetShardUpdate {
    location: FleetShardLocation,
    reports: FleetReports,
}

impl FleetShardUpdate {
    pub fn location(&self) -> &FleetShardLocation {
        &self.location
    }

    /// Merge this accepted batch over the currently stored shard (or repair an unusable shard) and
    /// return the one canonical bounded encoding plus its capacity-eviction count.
    pub fn merge(&self, current: Option<&[u8]>) -> (Vec<u8>, usize) {
        let mut reports = current
            .and_then(|body| FleetReports::parse_shard(body, &self.location))
            .unwrap_or_default();
        reports.overlay(self.reports.clone());
        FleetReports::encode_shard(reports.reports, &self.location)
    }
}

/// The bounded ingress form of [`FleetReports`]. It applies the same identity hash, exact encoded
/// entry accounting, per-shard byte ceiling, and receiver-acceptance eviction order as persisted
/// shards. A gateway therefore cannot exceed its configured serialized report budget in the gap
/// before a flush and cannot disagree with the writer about which entries fit.
pub struct FleetReportBuffer {
    reports: FleetReports,
    max_shards: FleetShardLimit,
    shards: Vec<BufferedFleetShard>,
}

struct BufferedFleetShard {
    encoded_len: usize,
    eviction_order: BTreeSet<(u64, String)>,
}

impl FleetReportBuffer {
    /// The only constructor: the shard ceiling is the operator's, never a default this type picks.
    /// This is the ingress half of an accounting the persisted layout owns the other half of, and a
    /// buffer that silently substituted [`DEFAULT_FLEET_REPORT_MAX_SHARDS`] is exactly how the two
    /// halves get to disagree about which entries fit.
    pub fn new(max_shards: FleetShardLimit) -> Self {
        let accounting_index = FleetIndex {
            schema: FleetIndex::SCHEMA,
            generation: "0".repeat(32),
            max_shards: max_shards.0,
            rebalance_to: None,
        };
        let shards = accounting_index
            .shard_locations()
            .map(|location| {
                let (empty, evicted) = FleetReports::encode_shard(BTreeMap::new(), &location);
                debug_assert_eq!(evicted, 0);
                BufferedFleetShard {
                    encoded_len: empty.len(),
                    eviction_order: BTreeSet::new(),
                }
            })
            .collect();
        Self {
            reports: FleetReports::default(),
            max_shards,
            shards,
        }
    }

    /// Record one accepted report and return the number evicted from its shard to preserve the
    /// exact encoded-body ceiling. At most one existing node is replaced, but a maximum-sized new
    /// value can evict multiple older small entries.
    pub fn record(&mut self, accepted: AcceptedReport) -> usize {
        let (node, stored) = accepted.into_stored();
        let shard_index = FleetReports::shard_for(&node, self.max_shards.get());
        let shard = &mut self.shards[shard_index];
        let entries_before = shard.eviction_order.len();
        if let Some(previous) = self.reports.reports.insert(node.clone(), stored.clone()) {
            shard.encoded_len -= FleetReports::entry_len(&node, &previous);
            shard
                .eviction_order
                .remove(&(previous.stored_at_ms, node.clone()));
        } else if entries_before > 0 {
            shard.encoded_len += 1;
        }
        shard.encoded_len += FleetReports::entry_len(&node, &stored);
        shard.eviction_order.insert((stored.stored_at_ms, node));

        let mut evicted = 0;
        while shard.encoded_len > MAX_FLEET_REPORT_SHARD_BYTES {
            let (_, oldest) = shard
                .eviction_order
                .pop_first()
                .expect("an overfull shard contains an entry");
            let entries_before = shard.eviction_order.len() + 1;
            let removed = self
                .reports
                .reports
                .remove(&oldest)
                .expect("eviction order and report map stay in lockstep");
            shard.encoded_len -=
                FleetReports::entry_len(&oldest, &removed) + usize::from(entries_before > 1);
            evicted += 1;
        }
        evicted
    }

    /// Take the bounded batch while retaining its configured shard budget for the next arrivals.
    pub fn drain(&mut self) -> FleetReports {
        let reports = std::mem::take(&mut self.reports);
        *self = Self::new(self.max_shards);
        reports
    }
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

    fn shard_limit(value: usize) -> FleetShardLimit {
        FleetShardLimit::new(value).unwrap()
    }

    fn stored_at(value: i64) -> ReportStoredAt {
        ReportStoredAt::from_unix_millis(value).unwrap()
    }

    /// Test assertion shorthand. Production has one public authentication gate and freshness is
    /// always opened through the capability it returns.
    fn fresh_report_fixture(
        envelope: &Envelope,
        expected_node: &str,
        public_key: &P256PublicKey,
        now_ms: u64,
    ) -> Option<NodeReport> {
        authenticate_report(envelope, expected_node, public_key)
            .and_then(|report| report.fresh(now_ms))
    }

    /// Test shorthand for the fleet-admission gate with a deterministic durable-store instant.
    fn accept_report_fixture(body: &[u8], node: &str) -> Option<AcceptedReport> {
        accept_stored_report(body, node, stored_at(1))
    }

    /// A keypair plus the public key the control plane pins at enrollment.
    fn keypair() -> (Vec<u8>, P256PublicKey) {
        let rng = aws_lc_rs::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref()).unwrap();
        let public = P256PublicKey::from_point(key.public_key().as_ref()).unwrap();
        (pkcs8.as_ref().to_vec(), public)
    }

    fn report() -> NodeReport {
        let mut report = NodeReport::new(
            "agent-9",
            "deploy-2",
            OTHER_DIGEST,
            "2.0.0",
            DIGEST,
            DIGEST,
            true,
        );
        report.reconciliation = Some(reconciliation());
        report
    }

    fn encoded_envelope(report: &NodeReport, pkcs8: &[u8]) -> Envelope {
        let bytes = encode_signed_report(report, pkcs8).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// A well-formed report produced through the only public producer boundary.
    fn signed(mutate: impl FnOnce(&mut NodeReport)) -> (Envelope, P256PublicKey) {
        let (pkcs8, public) = keypair();
        let mut report = report();
        mutate(&mut report);
        (encoded_envelope(&report, &pkcs8), public)
    }

    /// An authentic malformed input for fail-closed consumer tests. Product code cannot call the
    /// private signing primitive and therefore cannot create this state.
    fn signed_unchecked(mutate: impl FnOnce(&mut NodeReport)) -> (Envelope, P256PublicKey) {
        let (pkcs8, public) = keypair();
        let mut report = report();
        mutate(&mut report);
        (sign_report_envelope(&report, &pkcs8).unwrap(), public)
    }

    /// Sign an intentionally untyped report payload. Invalid contract values cannot be constructed
    /// through the Rust types, so negative wire tests mutate JSON before signing it.
    fn signed_json(mutate: impl FnOnce(&mut serde_json::Value)) -> (Envelope, P256PublicKey) {
        let (pkcs8, public) = keypair();
        let mut value = serde_json::to_value(report()).unwrap();
        mutate(&mut value);
        let payload = serde_json::to_vec(&value).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &pkcs8).unwrap();
        let signature = key
            .sign(
                &aws_lc_rs::rand::SystemRandom::new(),
                &pae(&payload, REPORT_PAYLOAD_TYPE),
            )
            .unwrap();
        (
            Envelope {
                payload: b64().encode(payload),
                payload_type: REPORT_PAYLOAD_TYPE.into(),
                signatures: vec![Signature {
                    sig: b64().encode(signature.as_ref()),
                }],
            },
            public,
        )
    }

    fn reconciliation() -> crate::reconciler::LastReconciliation {
        let transition = crate::reconciler::ReconciliationTransition::new(
            crate::reconciler::ReconciledRelease::new("2.0.0".into(), DIGEST.into(), DIGEST.into())
                .unwrap(),
            crate::reconciler::ReconciledRelease::new(
                "1.0.0".into(),
                OTHER_DIGEST.into(),
                OTHER_DIGEST.into(),
            )
            .unwrap(),
        );
        let reconciler_release = crate::reconciler::ReconciledRelease::new(
            "3.0.0".into(),
            DIGEST.into(),
            OTHER_DIGEST.into(),
        )
        .unwrap();
        crate::reconciler::LastReconciliation::new(
            crate::reconciler::MutationOperation::Apply,
            crate::reconciler::Reason::Update,
            "a".repeat(64),
            transition,
            crate::reconciler::ReconcilerIdentity::new(
                DIGEST.into(),
                "system".into(),
                reconciler_release,
            )
            .unwrap(),
            crate::reconciler::SuccessfulMutation::new(
                true,
                crate::reconciler::HostAction::Reboot,
                Some("kernel changed".into()),
            )
            .unwrap(),
            1,
        )
        .unwrap()
    }

    fn accepted(node: &str, envelope: &Envelope) -> AcceptedReport {
        let body = serde_json::to_vec(envelope).unwrap();
        accept_report_fixture(&body, node).unwrap()
    }

    #[test]
    fn every_non_current_schema_is_refused() {
        for schema in [NodeReport::SCHEMA - 1, NodeReport::SCHEMA + 1] {
            let (envelope, point) = signed_unchecked(|report| report.schema = schema);
            assert!(
                fresh_report_fixture(&envelope, "agent-9", &point, now_ms()).is_none(),
                "schema {schema} must be refused"
            );
        }
        let (envelope, point) = signed(|_| {});
        assert!(fresh_report_fixture(&envelope, "agent-9", &point, now_ms()).is_some());
    }

    #[test]
    fn a_genuine_envelope_verifies_and_yields_the_report() {
        let (envelope, point) = signed(|_| {});
        let report = fresh_report_fixture(&envelope, "agent-9", &point, now_ms())
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

        let report = fresh_report_fixture(&envelope, "agent-9", &point, now_ms())
            .expect("a well-formed signed fingerprint must verify");
        assert_eq!(
            report.fingerprint,
            Some(Fingerprint {
                definition_sha256: DIGEST.into(),
                output_sha256: OTHER_DIGEST.into(),
            })
        );

        let (malformed, point) = signed_unchecked(|report| {
            report.fingerprint = Some(Fingerprint {
                definition_sha256: DIGEST.into(),
                output_sha256: "not-a-digest".into(),
            });
        });
        assert!(fresh_report_fixture(&malformed, "agent-9", &point, now_ms()).is_none());
    }

    #[test]
    fn only_a_settled_healthy_report_can_attest_observations_or_outputs() {
        for mutate in [
            (|report: &mut NodeReport| {
                report.healthy = false;
                report.fingerprint = Some(Fingerprint {
                    definition_sha256: DIGEST.into(),
                    output_sha256: OTHER_DIGEST.into(),
                });
            }) as fn(&mut NodeReport),
            |report: &mut NodeReport| {
                report.healthy = false;
                report.output_sha256 = Some(DIGEST.into());
            },
        ] {
            let (envelope, point) = signed_unchecked(mutate);
            assert!(fresh_report_fixture(&envelope, "agent-9", &point, now_ms()).is_none());
        }
    }

    #[test]
    fn a_restored_healthy_predecessor_can_attest_the_rejected_assignment() {
        let (envelope, point) = signed(|report| report.rejected = true);
        let report = fresh_report_fixture(&envelope, "agent-9", &point, now_ms())
            .expect("a rollback reports both the restored release health and the rejection");
        assert!(report.healthy);
        assert!(report.rejected);
        assert!(!report.is_converged_to(OTHER_DIGEST, DIGEST, DIGEST));
    }

    #[test]
    fn exact_convergence_has_one_assignment_release_and_provider_predicate() {
        let report = report();
        assert!(report.is_converged_to(OTHER_DIGEST, DIGEST, DIGEST));
        assert!(!report.is_converged_to(DIGEST, DIGEST, DIGEST));
        assert!(!report.is_converged_to(OTHER_DIGEST, OTHER_DIGEST, DIGEST));
        assert!(!report.is_converged_to(OTHER_DIGEST, DIGEST, OTHER_DIGEST));

        let mut unhealthy = report.clone();
        unhealthy.healthy = false;
        assert!(!unhealthy.is_converged_to(OTHER_DIGEST, DIGEST, DIGEST));

        let mut rejected = report;
        rejected.rejected = true;
        assert!(!rejected.is_converged_to(OTHER_DIGEST, DIGEST, DIGEST));
    }

    #[test]
    fn reconciliation_audit_evidence_is_validated_inside_the_signed_report() {
        let (envelope, point) = signed(|report| {
            report.reconciliation = Some(reconciliation());
        });
        let verified = fresh_report_fixture(&envelope, "agent-9", &point, now_ms())
            .expect("valid audit evidence remains inside the signed report");
        assert_eq!(
            verified
                .reconciliation
                .expect("the report contains audit evidence")
                .result()
                .host_action(),
            crate::reconciler::HostAction::Reboot
        );

        let (malformed, point) = signed_json(|report| {
            report["reconciliation"]["result"]["message"] = serde_json::json!("invalid\nmessage");
        });
        assert!(fresh_report_fixture(&malformed, "agent-9", &point, now_ms()).is_none());
    }

    #[test]
    fn an_installed_report_must_bind_reconciliation_to_its_running_bytes_and_provider_set() {
        for mutate in [
            (|report: &mut serde_json::Value| {
                report["reconciliation"] = serde_json::Value::Null;
            }) as fn(&mut serde_json::Value),
            |report| {
                report["reconciliation"]["candidate"]["archiveSha256"] =
                    serde_json::json!(OTHER_DIGEST);
            },
            |report| {
                report["reconciliation"]["reconciler"]["providerSetSha256"] =
                    serde_json::json!(OTHER_DIGEST);
            },
        ] {
            let (envelope, point) = signed_json(mutate);
            assert!(fresh_report_fixture(&envelope, "agent-9", &point, now_ms()).is_none());
        }
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
            fresh_report_fixture(&forged, "agent-9", &point, now_ms()).is_none(),
            "a re-pointed payload must not verify"
        );

        let (_, other_key) = keypair();
        assert!(
            fresh_report_fixture(&envelope, "agent-9", &other_key, now_ms()).is_none(),
            "another node's key must not verify this report"
        );
        // A malformed pin cannot reach this gate at all: `P256PublicKey` is the only shape it
        // accepts, and `crate::key` is where every way of making one is proven to refuse a
        // truncated, wrongly tagged, zeroed, or off-curve point.
    }

    #[test]
    fn an_envelope_of_another_type_cannot_be_replayed_as_a_health_report() {
        // The type is bound into the PAE, so this is refused twice over: by the explicit type check and
        // because a signature over a different type could not match anyway.
        let (envelope, point) = signed(|_| {});
        let mut mistyped = envelope;
        mistyped.payload_type = "application/vnd.updated.something-else+json".into();

        assert!(fresh_report_fixture(&mistyped, "agent-9", &point, now_ms()).is_none());
    }

    #[test]
    fn the_gate_refuses_a_misattributed_stale_or_unknown_record() {
        let (envelope, point) = signed(|_| {});

        assert!(
            fresh_report_fixture(&envelope, "another-agent", &point, now_ms()).is_none(),
            "a report must not be credited to a node it does not name"
        );

        let fresh = fresh_report_fixture(&envelope, "agent-9", &point, now_ms()).unwrap();
        let assignment_sha256 = fresh.assignment_sha256.clone();
        let too_late = fresh.reported_at_ms + REPORT_FRESHNESS.as_millis() as u64 + 1;
        assert!(
            fresh_report_fixture(&envelope, "agent-9", &point, too_late).is_none(),
            "a stale report must fail closed"
        );
        let authentic = authenticate_report(&envelope, "agent-9", &point).unwrap();
        assert!(
            authentic.fresh(too_late).is_none(),
            "the cached authenticity capability must enforce the identical freshness gate"
        );
        assert_eq!(
            authentic.rejected_assignment(),
            None,
            "a stale negative statement is not durable evidence"
        );
        let (rejected, rejected_point) = signed(|report| report.rejected = true);
        let authentic_rejection =
            authenticate_report(&rejected, "agent-9", &rejected_point).unwrap();
        assert_eq!(
            authentic_rejection.rejected_assignment(),
            Some(assignment_sha256.as_str()),
            "the positive rejection is the only claim authentication may expose without freshness"
        );

        // A genuinely signed record whose field meanings this build does not know.
        let (future, future_point) = signed_unchecked(|r| r.schema = NodeReport::SCHEMA + 1);
        assert!(
            fresh_report_fixture(&future, "agent-9", &future_point, now_ms()).is_none(),
            "an unknown schema must fail closed even when authentic"
        );
    }

    /// The two reasons a report is unsettled are carried separately, because a reader cannot
    /// recover them from `healthy` alone: an update transaction in flight is evidence a rollout
    /// ran, an ordinary readiness failure is not, and the control plane's rollback verdict is
    /// built on the first meaning. Claiming BOTH settled and mid-transaction is a contradiction
    /// no agent can produce, so it fails the gate closed rather than being interpreted.
    #[test]
    fn a_transaction_in_flight_is_reported_apart_from_readiness_and_never_beside_settled() {
        let (unsettled, point) = signed(|r| {
            r.healthy = false;
            r.updating = true;
        });
        let report = fresh_report_fixture(&unsettled, "agent-9", &point, now_ms())
            .expect("an unsettled report with a transaction in flight is well-formed");
        assert!(!report.healthy && report.updating);

        let (blip, point) = signed(|r| {
            r.healthy = false;
            r.updating = false;
        });
        let report = fresh_report_fixture(&blip, "agent-9", &point, now_ms())
            .expect("so is an unsettled report with no update anywhere near it");
        assert!(!report.healthy && !report.updating);

        let (contradictory, point) = signed_unchecked(|r| r.updating = true);
        assert!(
            fresh_report_fixture(&contradictory, "agent-9", &point, now_ms()).is_none(),
            "settled means the confirmation window is closed; a record claiming both is malformed"
        );
    }

    #[test]
    fn a_future_stamped_report_ages_out_instead_of_staying_fresh_forever() {
        // The attack the forward bound exists for: one report stamped far ahead subtracts to age
        // zero under a backwards-only check and pins the node healthy and settled permanently.
        let (envelope, point) = signed(|r| r.reported_at_ms = u64::MAX);
        assert!(
            fresh_report_fixture(&envelope, "agent-9", &point, now_ms()).is_none(),
            "a report from the far future must fail closed, not read as age zero"
        );

        // A small disagreement between two machines' clocks is normal and still usable.
        let (skewed, point) = signed(|r| {
            r.reported_at_ms = now_ms() + REPORT_MAX_SKEW.as_millis() as u64 / 2;
        });
        assert!(
            fresh_report_fixture(&skewed, "agent-9", &point, now_ms()).is_some(),
            "ordinary clock skew must not reject a live node"
        );
    }

    #[test]
    fn a_reader_with_no_usable_clock_accepts_nothing() {
        // `now_ms()` reads 0 when the host clock cannot be read. Under a plain subtraction that
        // makes every report age zero — fresh forever, the fail-OPEN direction.
        let (envelope, point) = signed(|_| {});
        assert!(fresh_report_fixture(&envelope, "agent-9", &point, 0).is_none());
    }

    /// The one write-side gate both storing hops call. It must accept a genuine envelope filed under
    /// its own node and refuse everything a stored record could strand a reader with.
    #[test]
    fn the_write_gate_accepts_only_a_wellformed_envelope_filed_under_its_own_node() {
        let (pkcs8, _) = keypair();
        let body = encode_signed_report(&report(), &pkcs8).unwrap();
        let envelope: Envelope = serde_json::from_slice(&body).unwrap();

        assert_eq!(
            accept_report_fixture(&body, "agent-9").map(|report| report.node),
            Some("agent-9".to_string())
        );
        assert!(
            accept_report_fixture(&body, "agent-8").is_none(),
            "a report must not be storable under another node's name"
        );
        assert!(accept_report_fixture(b"not json", "agent-9").is_none());
        let mut padded = body.clone();
        padded.resize(MAX_REPORT_ENVELOPE_BYTES + 1, b' ');
        assert!(
            accept_report_fixture(&padded, "agent-9").is_none(),
            "the shared write gate owns the envelope byte bound"
        );

        // Wrong payload type: an envelope this node legitimately signed for something else.
        let mut retyped = envelope.clone();
        retyped.payload_type = "application/vnd.updated.something-else+json".into();
        assert!(accept_report_fixture(&serde_json::to_vec(&retyped).unwrap(), "agent-9").is_none());

        // A stuffed signature list is refused at the door, not left for every reader to pay for.
        let mut stuffed = envelope.clone();
        stuffed.signatures = std::iter::repeat_n(
            Signature {
                sig: b64().encode([0u8; 72]),
            },
            Envelope::MAX_SIGNATURES + 1,
        )
        .collect();
        assert!(accept_report_fixture(&serde_json::to_vec(&stuffed).unwrap(), "agent-9").is_none());

        let mut unsigned = envelope.clone();
        unsigned.signatures.clear();
        assert!(
            accept_report_fixture(&serde_json::to_vec(&unsigned).unwrap(), "agent-9").is_none(),
            "an envelope no reader can authenticate must be refused before storage"
        );

        // A payload that parses but is not well formed: the reader-side shape gate, applied on write.
        let malformed = sign_report_envelope(
            &{
                let mut report = report();
                report.archive_sha256 = "deadbeef".into();
                report
            },
            &pkcs8,
        )
        .unwrap();
        assert!(
            accept_report_fixture(&serde_json::to_vec(&malformed).unwrap(), "agent-9").is_none()
        );

        // A schema every reader will discard. Storing it answered 200 while the rollout throttle
        // and the health proxy both dropped the record, so a node mid-fleet-upgrade read as silent
        // and drained out of rotation permanently — the exact stranding this gate exists to refuse
        // at the door, where the writer still learns about it.
        let skewed = sign_report_envelope(
            &{
                let mut report = report();
                report.schema = NodeReport::SCHEMA + 1;
                report
            },
            &pkcs8,
        )
        .unwrap();
        assert!(
            accept_report_fixture(&serde_json::to_vec(&skewed).unwrap(), "agent-9").is_none(),
            "the write gate must enforce the schema every reader enforces"
        );
    }

    #[test]
    fn an_envelope_stuffed_with_signatures_is_refused_before_any_verification() {
        let (pkcs8, point) = keypair();
        let mut envelope = encoded_envelope(&report(), &pkcs8);
        let genuine = envelope.signatures[0].clone();
        envelope.signatures = (0..Envelope::MAX_SIGNATURES)
            .map(|_| Signature {
                sig: b64().encode([0u8; 72]),
            })
            .chain(std::iter::once(genuine))
            .collect();
        assert!(
            fresh_report_fixture(&envelope, "agent-9", &point, now_ms()).is_none(),
            "an attacker-chosen signature count must not buy unbounded ECDSA verifications"
        );
    }

    #[test]
    fn the_gate_refuses_malformed_content_digests_even_when_signed() {
        for malformed in [
            "deadbeef".to_string(),
            DIGEST[..63].to_string(),
            format!("{DIGEST}0"),
            DIGEST.to_ascii_uppercase(),
            "z".repeat(64),
            format!("sha256:{DIGEST}"),
        ] {
            let (envelope, point) = signed_unchecked(|r| r.archive_sha256 = malformed.clone());
            assert!(
                fresh_report_fixture(&envelope, "agent-9", &point, now_ms()).is_none(),
                "a digest a reader cannot join on must fail the gate: {malformed}"
            );
        }
        let (envelope, point) = signed_unchecked(|r| r.provider_set_sha256 = "not-a-digest".into());
        assert!(
            fresh_report_fixture(&envelope, "agent-9", &point, now_ms()).is_none(),
            "the provider half of the running identity must fail closed too"
        );
        for malformed in ["deadbeef".to_string(), "A".repeat(64), "z".repeat(64)] {
            let (envelope, point) = signed_unchecked(|r| r.output_sha256 = Some(malformed.clone()));
            assert!(
                fresh_report_fixture(&envelope, "agent-9", &point, now_ms()).is_none(),
                "an output identity not produced by the exact-byte hasher must fail closed: {malformed}"
            );
        }
    }

    #[test]
    fn report_names_are_bounded_by_the_same_grammars_as_their_producers() {
        for deployment in [
            "nested/deployment".to_string(),
            "a".repeat(crate::identity::MAX_SEGMENT_BYTES + 1),
        ] {
            let (envelope, point) =
                signed_unchecked(|report| report.deployment = deployment.clone());
            assert!(
                fresh_report_fixture(&envelope, "agent-9", &point, now_ms()).is_none(),
                "invalid deployment identity must fail closed: {deployment:?}"
            );
        }
        for version in [
            "latest".to_string(),
            format!(
                "1.0.0+{}",
                "a".repeat(crate::identity::MAX_RELEASE_VERSION_BYTES)
            ),
        ] {
            let (envelope, point) = signed_unchecked(|report| report.version = version.clone());
            assert!(
                fresh_report_fixture(&envelope, "agent-9", &point, now_ms()).is_none(),
                "invalid release version must fail closed: {version:?}"
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
            r.provider_set_sha256 = String::new();
            r.reconciliation = None;
            r.healthy = false;
        });

        let report = fresh_report_fixture(&envelope, "agent-9", &point, now_ms()).unwrap();
        assert!(report.version.is_empty());
        assert!(report.archive_sha256.is_empty());
        assert!(report.provider_set_sha256.is_empty());
    }

    #[test]
    fn garbage_base64_and_bodies_fail_closed_rather_than_panicking() {
        let (envelope, point) = signed(|_| {});

        let mut bad_payload = envelope.clone();
        bad_payload.payload = "!!!not base64!!!".into();
        assert!(fresh_report_fixture(&bad_payload, "agent-9", &point, now_ms()).is_none());

        let mut bad_sig = envelope.clone();
        bad_sig.signatures[0].sig = "!!!".into();
        assert!(fresh_report_fixture(&bad_sig, "agent-9", &point, now_ms()).is_none());

        let mut no_sigs = envelope.clone();
        no_sigs.signatures.clear();
        assert!(fresh_report_fixture(&no_sigs, "agent-9", &point, now_ms()).is_none());

        // A valid signature over a payload that is not a report.
        let mut not_a_report = envelope;
        not_a_report.payload = b64().encode(b"{}");
        assert!(fresh_report_fixture(&not_a_report, "agent-9", &point, now_ms()).is_none());
    }

    /// The producer and the consumer of a report envelope share one ceiling.
    #[test]
    fn an_envelope_is_encoded_under_the_ceiling_its_readers_enforce() {
        let (pkcs8, _) = keypair();
        let bytes = encode_signed_report(&report(), &pkcs8).expect("a real report fits");
        let envelope: Envelope = serde_json::from_slice(&bytes).unwrap();
        assert!(bytes.len() <= MAX_REPORT_ENVELOPE_BYTES);
        assert!(
            accept_report_fixture(&bytes, "agent-9").is_some(),
            "what the producer emits is exactly what the one acceptance gate takes"
        );

        // An envelope past the ceiling fails at the node instead of being dropped by every reader.
        let mut bloated = envelope.clone();
        bloated.payload = "A".repeat(MAX_REPORT_ENVELOPE_BYTES + 1);
        let error = encode_report_envelope(&bloated).expect_err("over the ceiling");
        assert!(error.contains("node report envelope"), "{error}");
    }

    #[test]
    fn the_producer_refuses_every_report_the_shared_shape_gate_refuses() {
        let (pkcs8, _) = keypair();
        let mut malformed = report();
        malformed.archive_sha256 = "deadbeef".into();

        assert!(!malformed.is_wellformed());
        assert_eq!(
            encode_signed_report(&malformed, &pkcs8).unwrap_err(),
            "refusing to sign a malformed node report: invalid archive digest"
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

    /// Last accepted report per node, overlay semantics, and the full storage round trip:
    /// rebalance into an index plus its initial shards, then recover the identical fleet by
    /// walking exactly what a reader walks — parse the index, parse each named shard.
    #[test]
    fn the_fleet_round_trips_through_its_index_and_shards() {
        let (pkcs8, _) = keypair();
        let sign_at = |node: &str, at: u64| {
            let mut report = report();
            report.node = node.to_string();
            report.reported_at_ms = at;
            encoded_envelope(&report, &pkcs8)
        };

        let mut reports = FleetReports::default();
        let future = sign_at("a", u64::MAX);
        reports.record(accepted("a", &future));
        let correction = sign_at("a", 50);
        reports.record(accepted("a", &correction));
        assert_eq!(
            reports.clone().remove("a"),
            Some(correction.clone()),
            "an untrusted future timestamp must not pin an unusable report"
        );

        // The flusher's conditional read-merge-write overlays the accepted batch on the stored
        // fleet. Payload timestamps do not act as a second concurrency mechanism.
        let mut stored = FleetReports::default();
        let stored_a = sign_at("a", 200);
        let stored_b = sign_at("b", 200);
        let stored_c = sign_at("c", 300);
        stored.record(accepted("a", &stored_a));
        stored.record(accepted("b", &stored_b));
        stored.record(accepted("c", &stored_c));
        stored.overlay(reports);
        assert_eq!(stored.clone().remove("a"), Some(correction.clone()));

        let (index, index_body, shards, evicted) = stored
            .rebalance(shard_limit(2))
            .expect("a small fleet rebalances")
            .into_parts();
        assert_eq!(evicted, 0);
        assert_eq!(
            FleetIndex::parse(&index_body),
            Some(index.clone()),
            "the published index bytes name the generation that was built"
        );
        assert_eq!(index.shard_locations().len(), 2);
        let locations: Vec<_> = index.shard_locations().collect();
        assert_eq!(
            index.shard_locations_for(["a", "a"]),
            vec![locations[FleetReports::shard_for("a", 2)].clone()],
            "subset readers fetch one canonical shard once"
        );
        assert_eq!(index.max_shards, shard_limit(2).0);
        assert_eq!(index.rebalance_to, None);
        assert_eq!(shards.len(), 2);

        // Locations derived from the index and locations the writer stored under are one set,
        // and every key stays inside the fleet namespace under the reserved basename.
        let mut recovered = FleetReports::default();
        for (location, body) in &shards {
            assert!(index.shard_locations().any(|derived| derived == *location));
            assert!(location
                .object_key()
                .starts_with(&format!("{REPORT_NAMESPACE}/{FLEET_INDEX_BASENAME}/")));
            assert_eq!(
                location.url("https://cdn/"),
                format!("https://cdn/{}", location.object_key())
            );
            recovered
                .overlay(FleetReports::parse_shard(body, location).expect("a stored shard parses"));
        }
        assert_eq!(recovered.remove("a"), Some(correction));
        assert_eq!(recovered.remove("b"), Some(stored_b));
        assert_eq!(recovered.remove("c"), Some(stored_c));
        assert!(recovered.is_empty(), "nothing beyond what was recorded");
    }

    #[test]
    fn durable_store_order_survives_projection_recovery() {
        let (envelope, _) = signed(|_| {});
        let body = serde_json::to_vec(&envelope).unwrap();
        let mut fleet = FleetReports::default();
        fleet.record(
            accept_stored_report(&body, "agent-9", stored_at(42))
                .expect("a valid stored report is admitted"),
        );

        let (index, _, shards, _) = fleet.rebalance(shard_limit(1)).unwrap().into_parts();
        let stored_at_in = |body: &[u8]| {
            serde_json::from_slice::<serde_json::Value>(body).unwrap()["reports"]["agent-9"]
                ["stored_at_ms"]
                .as_u64()
                .unwrap()
        };
        assert_eq!(stored_at_in(&shards[0].1), 42);

        // Rebuild the aggregate exactly as a fresh process does, then publish a new generation.
        // The generation changes; the durable object ordering evidence must not.
        let recovered = FleetReports::parse_shard(&shards[0].1, &shards[0].0).unwrap();
        let (_, _, republished, _) = recovered.rebalance(shard_limit(1)).unwrap().into_parts();
        assert_eq!(stored_at_in(&republished[0].1), 42);
        assert_eq!(index.max_shards, shard_limit(1).0);
    }

    #[test]
    fn steady_state_updates_only_the_canonical_shard_and_preserve_the_index() {
        let (pkcs8, _) = keypair();
        let sign_at = |node: &str, at: u64| {
            let mut report = report();
            report.node = node.into();
            report.reported_at_ms = at;
            encoded_envelope(&report, &pkcs8)
        };
        let original_a = sign_at("a", 1);
        let original_b = sign_at("b", 1);
        let mut fleet = FleetReports::default();
        fleet.record(accepted("a", &original_a));
        fleet.record(accepted("b", &original_b));
        let (index, index_body, shards, _) = fleet.rebalance(shard_limit(2)).unwrap().into_parts();
        let mut stored: BTreeMap<String, (FleetShardLocation, Vec<u8>)> = shards
            .into_iter()
            .map(|(location, body)| (location.object_key(), (location, body)))
            .collect();

        let replacement = sign_at("a", 2);
        let mut pending = FleetReports::default();
        pending.record(accepted("a", &replacement));
        let updates = pending.into_shard_updates(&index);
        assert_eq!(updates.len(), 1, "one node has exactly one shard home");
        for update in updates {
            let key = update.location().object_key();
            let current = stored.get(&key).map(|(_, body)| body.as_slice());
            let (body, evicted) = update.merge(current);
            assert_eq!(evicted, 0);
            stored.insert(key, (update.location().clone(), body));
        }

        assert_eq!(FleetIndex::parse(&index_body), Some(index.clone()));
        let mut recovered = FleetReports::default();
        for (location, body) in stored.values() {
            recovered.overlay(FleetReports::parse_shard(body, location).unwrap());
        }
        assert_eq!(recovered.remove("a"), Some(replacement));
        assert_eq!(recovered.remove("b"), Some(original_b));
    }

    #[test]
    fn a_rebalance_marker_keeps_the_old_layout_readable_and_has_one_encoding() {
        let fleet = FleetReports::default();
        let (index, _, _, _) = fleet.rebalance(shard_limit(2)).unwrap().into_parts();
        let old_locations: Vec<_> = index.shard_locations().collect();
        let (transition, body) = index.begin_rebalance(shard_limit(1)).unwrap();
        assert_eq!(FleetIndex::parse(&body), Some(transition.clone()));
        assert_eq!(transition.rebalance_to, Some(shard_limit(1).0));
        assert_eq!(transition.max_shards, shard_limit(2).0);
        assert_eq!(
            transition.shard_locations().collect::<Vec<_>>(),
            old_locations
        );

        assert!(transition.begin_rebalance(shard_limit(2)).is_err());
        assert!(index.begin_rebalance(shard_limit(2)).is_err());
    }

    #[test]
    fn index_and_shard_parsing_fail_closed_on_schema_identity_and_bounds() {
        let (envelope, _) = signed(|_| {});
        let mut fleet = FleetReports::default();
        fleet.record(accepted("agent-9", &envelope));
        let (index, index_body, shards, _) = fleet.rebalance(shard_limit(1)).unwrap().into_parts();
        let location = index.shard_locations().next().unwrap();
        let (stored_location, body) = &shards[0];
        assert_eq!(*stored_location, location);

        // The index: garbage, a future schema, a malformed generation, and an impossible shard
        // count are each not a layout a reader may act on.
        assert_eq!(FleetIndex::parse(b"not json"), None);
        let tamper_index = |mutate: &dyn Fn(&mut serde_json::Value)| {
            let mut value: serde_json::Value = serde_json::from_slice(&index_body).unwrap();
            mutate(&mut value);
            FleetIndex::parse(&serde_json::to_vec(&value).unwrap())
        };
        assert_eq!(tamper_index(&|v| v["schema"] = 2.into()), None);
        assert_eq!(tamper_index(&|v| v["generation"] = "short".into()), None);
        assert_eq!(
            tamper_index(&|v| v["generation"] = "G".repeat(32).into()),
            None,
            "generation names are lowercase hex or they could escape their key namespace"
        );
        assert_eq!(tamper_index(&|v| v["max_shards"] = 0.into()), None);
        assert_eq!(
            tamper_index(&|v| { v["max_shards"] = (MAX_FLEET_REPORT_SHARDS as u64 + 1).into() }),
            None
        );
        assert_eq!(tamper_index(&|v| v["rebalance_to"] = 0.into()), None);
        assert_eq!(tamper_index(&|v| v["rebalance_to"] = 1.into()), None);
        assert!(tamper_index(&|v| v["rebalance_to"] = 2.into()).is_some());
        assert_eq!(
            tamper_index(&|v| {
                v.as_object_mut().unwrap().remove("rebalance_to");
            }),
            None,
            "the stable index carries an explicit null transition, never an omitted old shape"
        );
        assert_eq!(
            tamper_index(&|v| v["future_field"] = true.into()),
            None,
            "one schema admits exactly one index shape"
        );
        let mut oversized_index = index_body.clone();
        oversized_index.resize(MAX_FLEET_INDEX_BYTES + 1, b' ');
        assert_eq!(FleetIndex::parse(&oversized_index), None);

        // The shard: it must agree with the exact generation and position the index named —
        // a body served from another generation or slot is not this shard.
        let other_fleet = {
            let mut other = FleetReports::default();
            other.record(accepted("agent-9", &envelope));
            other
        };
        let (_, _, other_shards, _) = other_fleet.rebalance(shard_limit(1)).unwrap().into_parts();
        assert_eq!(
            FleetReports::parse_shard(&other_shards[0].1, &location),
            None,
            "a shard from another generation must not satisfy this index"
        );
        let mut oversized_shard = body.clone();
        oversized_shard.resize(MAX_FLEET_REPORT_SHARD_BYTES + 1, b' ');
        assert_eq!(FleetReports::parse_shard(&oversized_shard, &location), None);

        // Entries a write gate could never have produced are dropped individually as storage
        // corruption, never poisoning the rest of the shard.
        let mut value: serde_json::Value = serde_json::from_slice(body).unwrap();
        let mut unknown_shard_field = value.clone();
        unknown_shard_field["future_field"] = true.into();
        assert_eq!(
            FleetReports::parse_shard(
                &serde_json::to_vec(&unknown_shard_field).unwrap(),
                &location
            ),
            None,
            "one schema admits exactly one shard shape"
        );
        let mut missing_reports = value.clone();
        missing_reports.as_object_mut().unwrap().remove("reports");
        assert_eq!(
            FleetReports::parse_shard(&serde_json::to_vec(&missing_reports).unwrap(), &location),
            None,
            "an empty shard is encoded as an explicit empty report map, not a second shape"
        );
        let entries = value["reports"].as_object_mut().unwrap();
        let stored = entries["agent-9"].clone();
        entries.insert("../escape".into(), stored.clone());
        entries.insert(FLEET_INDEX_BASENAME.into(), stored.clone());
        let mut oversized = stored;
        oversized["envelope"]["payload"] = "A".repeat(MAX_REPORT_ENVELOPE_BYTES).into();
        entries.insert("oversized".into(), oversized);
        entries.insert(
            "malformed".into(),
            serde_json::json!({"stored_at_ms": "not an integer"}),
        );
        let tampered = serde_json::to_vec(&value).unwrap();
        let mut parsed = FleetReports::parse_shard(&tampered, &location).unwrap();
        assert_eq!(parsed.remove("agent-9"), Some(envelope));
        assert!(parsed.remove("oversized").is_none());
        assert!(parsed.is_empty());
    }

    #[test]
    fn an_authentic_report_filed_in_the_wrong_shard_is_dropped() {
        let (envelope, _) = signed(|_| {});
        let mut fleet = FleetReports::default();
        fleet.record(accepted("agent-9", &envelope));
        let (_, _, shards, _) = fleet.rebalance(shard_limit(2)).unwrap().into_parts();
        let canonical = FleetReports::shard_for("agent-9", 2);
        let stored: serde_json::Value = serde_json::from_slice(&shards[canonical].1).unwrap();
        let entry = stored["reports"]["agent-9"].clone();

        let wrong = 1 - canonical;
        let (location, body) = &shards[wrong];
        let mut misplaced: serde_json::Value = serde_json::from_slice(body).unwrap();
        misplaced["reports"]["agent-9"] = entry;
        let parsed =
            FleetReports::parse_shard(&serde_json::to_vec(&misplaced).unwrap(), location).unwrap();

        assert!(
            parsed.is_empty(),
            "a valid envelope has exactly one home in its indexed generation"
        );
    }

    /// A shard that cannot fit its byte ceiling sheds entries in receiver acceptance order, never
    /// by a node-controlled payload timestamp, and what remains is a well-formed bounded shard.
    #[test]
    fn an_overfull_shard_evicts_the_stalest_entries_and_stays_readable() {
        let (envelope, _) = signed(|_| {});
        let mut seed = FleetReports::default();
        seed.record(accepted("agent-9", &envelope));
        let (index, _, _, _) = seed.rebalance(shard_limit(1)).unwrap().into_parts();
        let location = index.shard_locations().next().unwrap();

        // Nine ~2.7 MiB envelopes overflow the 16 MiB ceiling. Their claimed stamps run opposite
        // their receiver acceptance order: if eviction trusted the payload, the newest accepted
        // records would be removed first.
        let big_envelope = |claimed_stamp: u64| {
            let report = format!(
                r#"{{"reported_at_ms":{claimed_stamp},"padding":"{}"}}"#,
                "p".repeat(2 * 1024 * 1024)
            );
            Envelope {
                payload: b64().encode(report.as_bytes()),
                payload_type: REPORT_PAYLOAD_TYPE.into(),
                signatures: Vec::new(),
            }
        };
        let reports: BTreeMap<String, StoredReport> = (1..=9u64)
            .map(|stored_at_ms| {
                (
                    format!("agent-{stored_at_ms}"),
                    StoredReport {
                        stored_at_ms,
                        envelope: big_envelope(10 - stored_at_ms),
                    },
                )
            })
            .collect();
        let (body, evicted) = FleetReports::encode_shard(reports.clone(), &location);
        assert!(evicted > 0, "nine ~2.7 MiB entries cannot fit 16 MiB");
        assert!(body.len() <= MAX_FLEET_REPORT_SHARD_BYTES);

        // Exactly the oldest receiver stamps went despite their newest claimed timestamps.
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let survivors: Vec<&String> = value["reports"].as_object().unwrap().keys().collect();
        assert!(!survivors.is_empty(), "eviction trims, it does not empty");
        for stamp in 1..=evicted as u64 {
            assert!(
                !value["reports"]
                    .as_object()
                    .unwrap()
                    .contains_key(&format!("agent-{stamp}")),
                "the {evicted} oldest stamps are the ones evicted"
            );
        }

        let mut buffer = FleetReportBuffer::new(shard_limit(1));
        let mut buffer_evicted = 0;
        for (node, stored) in reports {
            buffer_evicted += buffer.record(AcceptedReport {
                node,
                envelope: stored.envelope,
                stored_at_ms: stored.stored_at_ms,
            });
        }
        assert_eq!(
            buffer_evicted, evicted,
            "pending and persisted forms apply the same exact byte budget"
        );
        let (_, _, shards, rebalance_evicted) = buffer
            .drain()
            .rebalance(shard_limit(1))
            .unwrap()
            .into_parts();
        assert_eq!(
            rebalance_evicted, 0,
            "a bounded pending batch needs no second capacity policy at flush time"
        );
        assert!(shards[0].1.len() <= MAX_FLEET_REPORT_SHARD_BYTES);
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
    fn fleet_index_url_joins_without_a_double_slash() {
        assert_eq!(
            fleet_index_url("https://cdn/"),
            "https://cdn/telemetry/fleet.json"
        );
    }

    #[test]
    fn the_shard_limit_knob_has_one_parser_and_exact_bounds() {
        assert_eq!(
            parse_fleet_report_max_shards(None),
            Ok(DEFAULT_FLEET_REPORT_MAX_SHARDS)
        );
        assert_eq!(parse_fleet_report_max_shards(Some("1")), Ok(shard_limit(1)));
        assert_eq!(
            parse_fleet_report_max_shards(Some(&MAX_FLEET_REPORT_SHARDS.to_string())),
            Ok(shard_limit(MAX_FLEET_REPORT_SHARDS))
        );
        for invalid in ["", "0", " 4", "4 ", "1.0", "65"] {
            assert!(
                parse_fleet_report_max_shards(Some(invalid)).is_err(),
                "{invalid:?} must not silently select another report-byte budget"
            );
        }
    }

    #[test]
    fn reports_consume_the_shared_kubernetes_identity_grammar() {
        assert!(report().is_wellformed());
        let mut malformed = report();
        malformed.node = "Agent-7".into();
        assert!(
            !malformed.is_wellformed(),
            "the report gate must consume the shared node grammar"
        );
    }

    #[test]
    fn fleet_index_has_the_projection_namespace() {
        assert_eq!(
            FLEET_INDEX_OBJECT_KEY,
            format!("{REPORT_NAMESPACE}/{FLEET_INDEX_BASENAME}.json")
        );
    }
}
