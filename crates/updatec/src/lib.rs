//! Environment-neutral desired-state compiler for `updated`, hosted on Kubernetes.
//!
//! Custom `UpdateAgent` resources represent agents anywhere. Group selectors determine
//! which exact config bundle each minimal agent document references.

use std::collections::{BTreeMap, BTreeSet};

use kube::CustomResource;
use object_store::ObjectStoreExt;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use updated_contracts::artifact::TargetReference as ExactTarget;
use updated_contracts::assignment::RepositoryAssignment as DesiredDeployment;
use updated_contracts::enrollment::EnrollmentBundle;

pub mod admission;
pub mod alerts;

/// Stable condition names and reasons shared by condition producers and exact consumers.
/// Keeping the wire contract here prevents a controller wording refactor from silently disabling
/// admission, monitoring, or campaign assertions that depend on a semantic verdict.
pub mod status_contract {
    pub const READY_CONDITION: &str = "Ready";
    pub const ROLLOUT_STUCK_CONDITION: &str = "RolloutStuck";
    pub const REPORTS_STALE_CONDITION: &str = "ReportsStale";
    pub const DEPLOYMENT_HALTED_CONDITION: &str = "DeploymentHalted";
    pub const RECONCILE_FAILING_CONDITION: &str = "ReconcileFailing";
    pub const ROOT_RENEWAL_CONDITION: &str = "RootRenewal";
    pub const RELEASE_ADMISSION_CONDITION: &str = "ReleaseAdmission";
    pub const ENROLLMENT_CAPACITY_CONDITION: &str = "EnrollmentCapacity";
    pub const CONDITION_TRUE: &str = "True";
    pub const CONDITION_FALSE: &str = "False";
    pub const REJECTED_REASON: &str = "Rejected";
    pub const REGRESSION_EVIDENCE_REASON: &str = "RegressionEvidence";

    /// Assemble the one Kubernetes condition wire shape from an observed verdict.
    ///
    /// Alert projections, ordinary status writers, and subscription delivery all provide their
    /// own clock because they observe transitions at different boundaries. They do not get to
    /// restate how a boolean verdict maps onto the Kubernetes condition fields: keeping that here
    /// makes `True`/`False`, generation binding, and transition stamping one invariant.
    pub(crate) fn condition(
        condition_type: &str,
        active: bool,
        observed_generation: Option<i64>,
        reason: &str,
        message: impl Into<String>,
        last_transition_time: impl Into<String>,
    ) -> super::ResourceCondition {
        super::ResourceCondition {
            condition_type: condition_type.into(),
            status: if active {
                CONDITION_TRUE
            } else {
                CONDITION_FALSE
            }
            .into(),
            reason: reason.into(),
            message: message.into(),
            observed_generation,
            last_transition_time: last_transition_time.into(),
        }
    }
}
pub mod crd;
pub(crate) mod dataflow;
pub(crate) mod domain;
pub mod env;
pub mod evidence;
pub mod gateway;
pub(crate) mod input_data;
pub mod join;
pub mod metrics;
pub mod publisher;
pub(crate) mod rollout;
pub mod runtime;
pub mod served;
pub mod subscription;
#[cfg(test)]
pub(crate) mod test_support;
pub(crate) mod webhook;
pub mod window;

pub use window::{CalendarEntry, RolloutWindow, Weekday};

/// The operator-selected consequence of an authoritative Draupnir verdict. These are enums rather
/// than booleans so the generated CRD is self-documenting and cannot accumulate two inverse knobs
/// for the same decision.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum AdmissionAction {
    Allow,
    Block,
}

/// One namespaced release-admission policy. A repository either references exactly one of these or
/// has no external admission gate; there are no environment-variable or per-group override paths.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "updated.dev",
    version = "v1alpha1",
    kind = "UpdateAdmissionPolicy",
    plural = "updateadmissionpolicies",
    namespaced,
    shortname = "uap",
    printcolumn = r#"{"name":"URL","type":"string","jsonPath":".spec.webhook.url"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAdmissionPolicySpec {
    pub webhook: AdmissionWebhookSpec,
    pub actions: AdmissionActions,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionWebhookSpec {
    /// Absolute HTTP(S) endpoint implementing updatedc's versioned release-admission contract.
    /// At most every 30 seconds (and immediately for a previously unseen subject), the controller
    /// POSTs the complete active subject set. The idempotent request is both event notification and
    /// verdict refresh; there is no second event or admission endpoint.
    pub url: String,
    /// Secret in the same namespace whose `key` entry authenticates the exact REQUEST bytes with
    /// HMAC-SHA256 (`X-Updated-Signature: sha256=<hex>`). Caller authentication only: the response
    /// is authenticated by [`Self::decision_public_key`] instead.
    pub secret_ref: LocalSecretReference,
    /// Draupnir's admission public key, pinned here the way a release-signing root is pinned:
    /// hex of an uncompressed P-256 point (65 bytes, `04`-prefixed), the same encoding
    /// [`AgentIdentity::public_key`] uses, so the fleet has exactly one public-key encoding.
    ///
    /// The decision is an authoritative compliance assertion that gates deployment, so it is signed
    /// ASYMMETRICALLY over the exact response body bytes and verified against this pin. A shared
    /// HMAC could not serve here: this control plane holds that key, so it could mint its own
    /// verdict, and no third party could ever verify what Draupnir decided. Because the signed
    /// document is byte-identical to the enforced one, Draupnir's retained attestation — which
    /// embeds the digest of these bytes — cannot silently disagree with what was enforced.
    ///
    /// There is no unsigned or symmetric fallback: a policy that cannot verify a decision has no
    /// safe reading, so this is required and a malformed pin fails closed.
    pub decision_public_key: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AdmissionActions {
    /// What to do when Draupnir has information and declares the subject noncompliant.
    pub non_compliant: AdmissionAction,
    /// What to do when Draupnir authoritatively says it has no information for the subject.
    /// Transport failure, a missing verdict, and `Pending` are not `NoInformation`; they always
    /// hold movement until an authoritative response arrives.
    pub no_information: AdmissionAction,
}

#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "updated.dev",
    version = "v1alpha1",
    kind = "UpdateGroup",
    plural = "updategroups",
    namespaced,
    shortname = "upg",
    status = "UpdateGroupStatus",
    printcolumn = r#"{"name":"Repository","type":"string","jsonPath":".spec.repositoryRef.name"}"#,
    printcolumn = r#"{"name":"Agents","type":"integer","jsonPath":".status.matchedAgents"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type == 'Ready')].status"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct UpdateGroupSpec {
    pub repository_ref: LocalObjectReference,
    pub selector: LabelSelector,
    /// Namespace-local prerequisite groups which must be settled before this group can roll.
    /// These are opaque ordering edges; updatedc never interprets deployment semantics.
    #[serde(default)]
    pub depends_on: Vec<String>,
    /// Named lifecycle inputs sourced from signed outputs of prerequisite groups.
    #[serde(default)]
    pub inputs: BTreeMap<String, GroupOutputReference>,
    pub deployment: DeploymentSpec,
    /// Maximum unavailable agents while this group changes deployment. This is group rollout
    /// policy, deliberately outside `deployment` so changing it does not change the signed
    /// assignment identity. Defaults to one; zero is rejected during reconciliation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub max_unavailable: Option<usize>,
    /// The operator's explicit statement that [`deployment`](Self::deployment) is an EMERGENCY
    /// CORRECTION: admit it now, without waiting for the governing
    /// [`UpdateGroupSet`]'s rollout schedule (its windows and its calendar).
    ///
    /// The schedule, and ONLY the schedule, is bypassed. The set's concurrency limit still applies:
    /// an emergency correction to a settled group waits for one of the set's `maxConcurrent` slots
    /// exactly as an ordinary retarget does, so declaring an emergency across many groups at once
    /// still rolls them `maxConcurrent` at a time rather than changing the whole fleet
    /// simultaneously. (A group whose rollout is already in flight holds the slot it claimed, so
    /// retargeting it needs no new one — that is true of any retarget, emergency or not.) This
    /// group's `maxUnavailable` staging, its resolved inputs, and its prerequisites all still apply
    /// too.
    ///
    /// Intent is STATED here rather than inferred from telemetry, and that is the whole point. The
    /// control plane cannot tell an emergency rollback from an ordinary forward change by looking at
    /// node health: a group carrying one chronically unhealthy node (a failing downstream
    /// dependency, an expired licence) would be permanently window-exempt, while the failure an
    /// operator most needs to escape a window for — a release that bricks the agent itself — emits
    /// no telemetry at all and so looks like nothing is wrong. Both cases are answered by the
    /// operator saying so.
    ///
    /// It stays in force until it is cleared, and it is loudly visible while it is: the governing
    /// set lists the group in `status.emergency`, and `updatectl deploy` writes this field
    /// explicitly on every publish, so the next ordinary deploy of this group clears it.
    #[serde(default)]
    pub emergency_correction: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GroupOutputReference {
    pub group: String,
    pub output: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentSpec {
    pub name: String,
    pub release_repository: ReleaseRepositorySpec,
    pub application: TargetSpec,
    /// Signed opt-in to first-install ordered fallback (see
    /// [`updated_contracts::assignment::RepositoryAssignment::ordered_install_fallback`]). Defaults
    /// off so a group only descends versions when the publisher explicitly allows it.
    #[serde(default)]
    pub ordered_install_fallback: bool,
    pub provider_set: TargetSpec,
    pub runtime: RuntimeSpec,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseRepositorySpec {
    pub metadata_url: String,
    pub targets_url: String,
    /// Exact JSON bytes of the pinned TUF root. A string keeps the Kubernetes API
    /// structural while preserving TUF's intentionally extensible document.
    pub root_json: String,
}

/// The CRD spelling of [`updated_contracts::assignment::ManagedRuntime`].
///
/// It is a near-twin, not a full one, and the difference is the point. This side is a Kubernetes
/// object: deserialized from apiserver JSON, versioned by the CRD's own `v1alpha1`, and free to gain
/// an optional field whenever an operator needs one. The contract side is the SIGNED, node-facing
/// document, governed by [`updated_contracts::assignment::RepositoryAssignment::SCHEMA`], where any
/// shape change — even an added optional field — strands every not-yet-upgraded node behind a parse
/// error. Two things with genuinely different evolution rules get two types.
///
/// What this type must never contain is a second DEFINITION of a value the node acts on. It used to:
/// `repository`, `storage` and `timeouts` were declared here as field-for-field copies of the
/// contract structs, and a copy drifts. Adding a field to the contract failed to compile, but adding
/// one *here* did not — an operator could set it in YAML and it would silently never reach a node —
/// and nothing at all caught a mis-wired mapping between two `u64` fields. Those three are now the
/// contract's own types, carried across whole. There is one declaration of each, so there is nothing
/// left to drift against and no field mapping to get wrong.
///
/// What remains is genuinely this side's own: `product`, `channel`, and an `installRoot` the
/// contract holds as a `PathBuf`. `TryFrom<DeploymentSpec> for DesiredDeployment` destructures every
/// spec exhaustively, so a field added to either side is a compile error until both agree.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeSpec {
    pub product: String,
    pub channel: String,
    pub install_root: String,
    pub repository: updated_contracts::assignment::ManagedRepositoryLimits,
    pub storage: updated_contracts::assignment::ManagedStorage,
    pub timeouts: updated_contracts::assignment::ManagedTimeouts,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct TargetSpec {
    pub path: String,
    pub sha256: String,
}

impl TryFrom<DeploymentSpec> for DesiredDeployment {
    type Error = String;

    /// Every field is DESTRUCTURED, never read by dotted access.
    ///
    /// That is the whole drift guard, and it closes the direction a field-by-field copy leaves
    /// open. Adding a field to the contract already failed to compile here (the struct literal
    /// below would be missing it). Adding one to the *spec* did not: `value.runtime.timeouts.x`
    /// simply never mentions it, so an operator could set a field in YAML that silently never
    /// reached a node. A non-exhaustive destructuring pattern is a compile error, so now neither
    /// side can gain a field the other does not.
    fn try_from(value: DeploymentSpec) -> Result<Self, Self::Error> {
        let DeploymentSpec {
            name,
            release_repository:
                ReleaseRepositorySpec {
                    metadata_url,
                    targets_url,
                    root_json,
                },
            application,
            ordered_install_fallback,
            provider_set,
            runtime:
                RuntimeSpec {
                    product,
                    channel,
                    install_root,
                    repository,
                    storage,
                    timeouts,
                },
        } = value;
        let release_root = serde_json::from_str(&root_json)
            .map_err(|error| format!("releaseRepository.rootJson is invalid JSON: {error}"))?;
        let desired = Self {
            schema: updated_contracts::assignment::RepositoryAssignment::SCHEMA,
            deployment: name,
            metadata_url,
            targets_url,
            application: application.into(),
            ordered_install_fallback,
            provider_set: provider_set.into(),
            release_root,
            runtime: updated_contracts::assignment::ManagedRuntime {
                product,
                channel,
                install_root: install_root.into(),
                // The operator does not choose a node's inputs: they are resolved from the group's
                // own subscriptions, so the signed document starts empty here.
                inputs: updated_contracts::dataflow::InputSelection::default(),
                // Carried, not copied: these three are the contract's own types, so there is no
                // field mapping to get wrong and no second declaration to fall behind.
                repository,
                storage,
                timeouts,
            },
        };
        desired.validate()?;
        Ok(desired)
    }
}

impl From<TargetSpec> for ExactTarget {
    fn from(value: TargetSpec) -> Self {
        let TargetSpec { path, sha256 } = value;
        Self { path, sha256 }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelector {
    #[serde(default)]
    pub match_labels: BTreeMap<String, String>,
}

/// A dynamically managed load-balancer projection. This is the sole topology input for
/// `updated-healthproxy`: the operator derives its inventory from matching [`UpdateAgent`]s and
/// owns the workload and its least-privilege RBAC for the lifetime of this object.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "updated.dev",
    version = "v1alpha1",
    kind = "UpdateBackend",
    plural = "updatebackends",
    namespaced,
    shortname = "upb",
    status = "UpdateBackendStatus",
    printcolumn = r#"{"name":"Repository","type":"string","jsonPath":".spec.repositoryRef.name"}"#,
    printcolumn = r#"{"name":"Agents","type":"integer","jsonPath":".status.matchedAgents"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type == 'Ready')].status"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct UpdateBackendSpec {
    pub repository_ref: LocalObjectReference,
    /// Selects `UpdateAgent.spec.labels`. An empty selector is refused rather than interpreted as
    /// the whole fleet.
    pub selector: LabelSelector,
    /// Public base URL from which healthproxy reads this repository's signed telemetry projection.
    pub health_base: String,
    pub target: BackendTarget,
    #[serde(default = "default_backend_interval_seconds")]
    #[schemars(range(min = "BACKEND_POLL_SECONDS_MIN", max = "BACKEND_INTERVAL_SECONDS_MAX"))]
    pub interval_seconds: u64,
    #[serde(default = "default_backend_health_timeout_seconds")]
    #[schemars(range(
        min = "BACKEND_POLL_SECONDS_MIN",
        max = "BACKEND_HEALTH_TIMEOUT_SECONDS_MAX"
    ))]
    pub health_timeout_seconds: u64,
}

/// The poll bounds an `UpdateBackend` must satisfy, stated once. The `schemars(range(...))`
/// attributes above render them into the shipped CRD, so the apiserver refuses an out-of-range
/// value up front, and `runtime::validate_backend` refuses one that reaches the controller anyway
/// (an older CRD in the cluster, a hand-written object). Two enforcement points that disagree give
/// an operator a CR the apiserver accepts and every reconcile then fails with `InvalidPollPlan`, so
/// both read these — including the message that quotes them back.
pub const BACKEND_POLL_SECONDS_MIN: u64 = 1;
/// The slowest poll a backend may be given, DERIVED from the telemetry freshness window rather
/// than written beside it.
///
/// `spec.intervalSeconds` reaches the healthproxy verbatim as `HEALTHPROXY_INTERVAL_SECS` and
/// becomes its per-cycle sleep, so it is the reader half of the budget
/// [`updated_contracts::telemetry::MAX_CHECK_INTERVAL_SECONDS`] derives for the writer: of the
/// three gaps that must fit inside [`updated_contracts::telemetry::REPORT_FRESHNESS`], one is
/// spent on "the reader's own poll interval". Taking the same number keeps both halves of that
/// budget answerable to the one window.
///
/// The literal 300 that stood here admitted intervals five times the window. Two things break past
/// it, and neither is visible in steady state. A report is routinely older than
/// `NodeReport::is_fresh` accepts by the time the reader looks at it; and — the reason this is a
/// bound rather than a warning — `LastKnownGood::STALENESS` IS `REPORT_FRESHNESS`, so the entry
/// stored on cycle N-1 has already expired when cycle N runs. The last-known-good cache is then
/// inert by construction, and a single failed fetch (one CDN 5xx) programs every member of the
/// backend not-ready in one cycle: the whole healthy fleet drained out of the load balancer, which
/// is exactly what that cache exists to prevent ("a checker-side outage is not evidence a node is
/// down"). At this bound the bridge spans at least three consecutive failed cycles.
pub const BACKEND_INTERVAL_SECONDS_MAX: u64 =
    updated_contracts::telemetry::MAX_CHECK_INTERVAL_SECONDS;
/// Three whole poll cycles must fit inside the staleness window the healthproxy's last-known-good
/// cache uses, so a reader outage spanning several cycles still cannot drain a healthy fleet.
const _: () = assert!(
    BACKEND_INTERVAL_SECONDS_MAX * 3 <= updated_contracts::telemetry::REPORT_FRESHNESS.as_secs()
);
pub const BACKEND_HEALTH_TIMEOUT_SECONDS_MAX: u64 = 30;

fn default_backend_interval_seconds() -> u64 {
    2
}

fn default_backend_health_timeout_seconds() -> u64 {
    2
}

/// One structurally valid Kubernetes object for both load-balancer integrations. Reconciliation
/// enforces the discriminator strictly: fields belonging to the other kind are rejected, so there
/// is still exactly one valid configuration shape without relying on CRD `oneOf` constructs that
/// Kubernetes cannot make structural.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct BackendTarget {
    pub kind: BackendTargetKind,
    /// Selectorless Service in the `UpdateBackend` namespace. Cross-namespace traffic mutation is
    /// deliberately not supported; it would require namespace-wide operator credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port_name: Option<String>,
    /// HAProxy Runtime API TCP sockets as `host:port`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub enum BackendTargetKind {
    #[serde(rename = "endpointSlice")]
    EndpointSlice,
    #[serde(rename = "haProxy")]
    HAProxy,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateBackendStatus {
    pub observed_generation: Option<i64>,
    pub matched_agents: Option<u32>,
    pub workload: Option<String>,
    #[serde(default)]
    pub conditions: Vec<ResourceCondition>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateGroupStatus {
    pub observed_generation: Option<i64>,
    pub matched_agents: Option<u32>,
    pub published_digest: Option<String>,
    /// How many of this group's agents the operator is holding (`UpdateAgent.spec.hold`). A
    /// forgotten hold must be a visible condition, not a mystery, so the count is projected here
    /// on every reconcile, from the planner's own membership ([`rollout::GroupNodes::held`]) — the
    /// group this pass's labels select, never the group the last publication routed the node to.
    /// Serialized even when `None`: this status travels as a merge patch, and
    /// the explicit null is what deletes a stale count when a writer (quarantine, failure) cannot
    /// compute one.
    pub held_agents: Option<u32>,
    #[serde(default)]
    pub conditions: Vec<ResourceCondition>,
}

/// A blast-radius throttle over a set of [`UpdateGroup`]s. Membership is label-based
/// like everything else: `selector` matches `UpdateGroup` **metadata labels** (not agent
/// labels) within the repository named by `repositoryRef`, so a set can gather any number of
/// that repository's member groups. The control plane rolls no
/// more than [`Self::effective_max_concurrent`] members at once, holding the rest on
/// their last-admitted deployment until an in-flight member settles (all its agents
/// report the desired deployment, healthy). A member "settles" only through the node
/// telemetry the control plane reads out of storage. Deployments require a report URL;
/// unverifiable or missing telemetry fails closed.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "updated.dev",
    version = "v1alpha1",
    kind = "UpdateGroupSet",
    plural = "updategroupsets",
    namespaced,
    shortname = "upgs",
    status = "UpdateGroupSetStatus",
    printcolumn = r#"{"name":"Members","type":"integer","jsonPath":".status.memberCount"}"#,
    printcolumn = r#"{"name":"MaxConcurrent","type":"integer","jsonPath":".status.maxConcurrent"}"#,
    printcolumn = r#"{"name":"Rolling","type":"integer","jsonPath":".status.rollingCount"}"#,
    printcolumn = r#"{"name":"Frozen","type":"string","jsonPath":".status.frozen"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct UpdateGroupSetSpec {
    /// The repository whose groups this set governs. A set is reconciled and has its status
    /// written by exactly that repository's controller; selectors never cross repository
    /// boundaries, even when another repository uses the same group labels in this namespace.
    pub repository_ref: LocalObjectReference,
    /// Selects member `UpdateGroup`s by their Kubernetes metadata labels.
    pub selector: LabelSelector,
    /// Maximum member groups allowed to roll at once. Defaults to `members - 1`, so at
    /// least one member always holds a known-good release. Clamped to `1..=members-1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrent: Option<u32>,
    /// UTC windows during which this set may admit new rollouts. Empty means always open.
    /// When non-empty, the set freezes (admits nothing new) whenever "now" (UTC) falls
    /// outside every window; members already rolling keep settling. See [`RolloutWindow`]
    /// for the schedule model, including weekly and every-other-week ("every other Sunday")
    /// recurrences and past-midnight time spans.
    #[serde(default)]
    pub rollout_windows: Vec<RolloutWindow>,
    /// One-off dated maintenance windows: absolute UTC dates with a time range, e.g.
    /// `{ date: "2026-08-25", start: "06:00", end: "09:00" }`. Edit the CRD to change them
    /// — the operator re-reads every reconcile. The set may roll only inside a listed
    /// window; once every entry is in the past the calendar "runs out" and stops gating
    /// (falls back to open). Combined with [`rollout_windows`](Self::rollout_windows) by
    /// intersection: when both are set, the set must satisfy both. See [`CalendarEntry`].
    #[serde(default)]
    pub calendar: Vec<CalendarEntry>,
    /// How many distinct nodes must independently prove a staged deployment bad — attempt it and
    /// roll themselves back, as their signed reports already show — before the deployment is
    /// HALTED: no further node is moved to it, anywhere in the fleet, until a deployment with a
    /// different identity is staged. Defaults to one.
    ///
    /// The verdict is FLEET-WIDE per deployment identity — a body proven bad must not reach a
    /// sibling set, or a group no set governs, through a second door — so the effective threshold
    /// for an identity is the TIGHTEST `maxRegressions` among all sets whose members name it
    /// (default one when none does). The halt is a planner verdict recomputed from evidence each
    /// reconcile, never stored state, and republishing the identical body cannot clear it —
    /// corrected bytes have a new digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub max_regressions: Option<u32>,
    /// What happens to this set's groups, beyond the fleet-wide halt, when the regression verdict
    /// fires on a deployment they are staging. `halt` (the default) stops admission and leaves
    /// every node where it is — nodes that attempted the bad release already rolled themselves
    /// back, and nodes that settled healthy on it stay on it. `rollback` additionally rebases each
    /// affected group onto the deployment its rollout was staging away from, so the nodes that
    /// settled on the proven-bad body are staged back too (bounded by `maxUnavailable`, exactly
    /// like the forward direction).
    ///
    /// The rollback response is deliberately conservative in three ways. It fires only once every
    /// node whose evidence triggered the halt is OBSERVABLY RECOVERED — an authentic, fresh report
    /// that is healthy and still claims the rejection — because a node whose own rollback failed
    /// is a machine in an unknown state, not proof that reverting the rest of the fleet is safe;
    /// until then the halt alone stands. It requires a predecessor to exist (a group whose FIRST
    /// deployment regressed has nowhere to go and stays halted). And a group governed by several
    /// sets rolls back only when every one of them says `rollback` — automatic movement needs
    /// unanimous operator intent, a freeze does not.
    ///
    /// Rolling back consumes the very evidence the halt is recomputed from (the rejecting nodes
    /// are reassigned the predecessor, so their reports stop naming the bad assignment), so the
    /// response also records a durable VETO of the deployment identity in the admitted-state
    /// document: the proven-bad body stays refused across controller restarts, until no group
    /// names it any more. The exit is the same as for a halt — publish corrected bytes, which have
    /// a new digest.
    #[serde(default)]
    pub on_regression: RegressionResponse,
    /// How long a member group may sit in `staging` with no node newly settled before the
    /// `RolloutStuck` condition is raised on it. Defaults to 3600 seconds. Alerting policy only —
    /// it gates nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub stuck_after_seconds: Option<u64>,
}

impl UpdateGroupSetSpec {
    /// Resolve the effective concurrency for a set of `members` groups: the configured
    /// `max_concurrent`, else the `members - 1` default, clamped to `1..=members-1`.
    /// (A one-member set is not a real case, so the `members == 1` degenerate is not
    /// specially codified beyond the floor of 1.)
    pub fn effective_max_concurrent(&self, members: usize) -> usize {
        let ceiling = members.saturating_sub(1).max(1);
        let requested = self.max_concurrent.map(|n| n as usize).unwrap_or(ceiling);
        requested.clamp(1, ceiling)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateGroupSetStatus {
    pub observed_generation: Option<i64>,
    pub member_count: Option<u32>,
    pub max_concurrent: Option<u32>,
    pub rolling_count: Option<u32>,
    /// True when the set is outside all its rollout windows: no new rollouts are being
    /// admitted (in-flight members still settle). Absent/false when open or window-less.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub frozen: Option<bool>,
    /// True when the set's dated calendar has run out (every approved window is past): it has
    /// stopped gating and now admits at any hour. Surfaced so "silently expired" is distinguishable
    /// from "actively inside an approved window." Absent/false for a set with no calendar or one
    /// still active or pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub calendar_exhausted: Option<bool>,
    /// Member groups currently admitted to roll (desired != settled).
    #[serde(default)]
    pub rolling: Vec<String>,
    /// Member groups settled on their desired deployment: every agent whose reports can be
    /// verified reports it, healthy. Agents with no pinned public key are excluded from the
    /// judgement rather than assumed healthy — a group carrying any of them is listed here only as
    /// "settled as far as anything can be observed".
    #[serde(default)]
    pub settled: Vec<String>,
    /// Member groups whose rollout ENDED IN FAILURE: their nodes attempted the admitted deployment
    /// and durably rejected it (rolling back to what they were running), and nothing is still moving
    /// toward it. They hold no concurrency slot — there is nothing in flight to protect — and they
    /// are never listed as settled, so nothing gated on them opens and no progress count includes
    /// them. The exit is a deployment with a different identity: corrected bytes have a new digest.
    #[serde(default)]
    pub failed: Vec<String>,
    /// Member groups no evidence can ever come from: they select no agent, or EVERY agent they
    /// select has no pinned public key (offline-provisioned, never enrolled). They hold no
    /// concurrency slot and will never settle, so anything gated on them waits forever — which is
    /// why they are surfaced rather than folded into `rolling`.
    #[serde(default)]
    pub unobservable: Vec<String>,
    /// Member groups also claimed by another set, safely rolled up (admitted only when
    /// every governing set has a slot).
    #[serde(default)]
    pub shared: Vec<String>,
    /// Member groups whose spec declares
    /// [`emergency_correction`](UpdateGroupSpec::emergency_correction): their desired deployment is
    /// admitted without waiting for this set's schedule. Listed for as long as the flag is set, so
    /// an emergency override is never silently permanent.
    #[serde(default)]
    pub emergency: Vec<String>,
    /// Deployments HALTED for this set by the regression verdict: enough distinct nodes proved
    /// each one bad (attempted it and rolled themselves back). No further node is moved to a
    /// halted deployment in any member group; nodes already on it are left where they are. An
    /// array, not a map, so a JSON merge patch replaces it wholesale and a cleared halt cannot
    /// linger.
    #[serde(default)]
    pub halted: Vec<HaltedDeployment>,
    #[serde(default)]
    pub conditions: Vec<ResourceCondition>,
}

/// One deployment the regression verdict has halted for a set, with the evidence that halted it.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct HaltedDeployment {
    /// The deployment's operator-facing name.
    pub deployment: String,
    /// Distinct nodes whose signed reports prove they attempted this deployment and rolled back.
    pub evidence: u32,
    /// Whether an `onRegression: rollback` response has consumed this halt: the affected groups
    /// were rebased onto their predecessors and the identity carries a durable veto, so it stays
    /// refused even though the rejecting nodes — reassigned to the predecessor — no longer state
    /// the rejection in their reports.
    #[serde(default)]
    pub rolled_back: bool,
}

/// What a set does, beyond the fleet-wide halt, when the regression verdict fires on a deployment
/// its groups are staging. See `UpdateGroupSetSpec::on_regression` for the full contract.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RegressionResponse {
    /// Stop admitting anyone to the proven-bad deployment; leave every node where it is.
    #[default]
    Halt,
    /// Additionally rebase each affected group onto the deployment it was staging away from, once
    /// every rejecting node's own rollback is observably complete and healthy.
    Rollback,
}

/// The durable record of a deployment identity an `onRegression: rollback` response has consumed
/// the evidence for. Persisted in the admitted-state document, because the response reassigns the
/// rejecting nodes to the predecessor — after which their reports no longer state the rejection —
/// and a verdict recomputed from reports alone would re-admit the proven-bad body on the next
/// leader change. Pruned when no group's desired or admitted deployments name the identity.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VetoedDeployment {
    /// The deployment's operator-facing name, for the status projection.
    pub deployment: String,
    /// Distinct nodes whose evidence triggered the response, frozen at the moment it fired.
    pub evidence: u32,
}

#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "updated.dev",
    version = "v1alpha1",
    kind = "UpdateAgent",
    plural = "updateagents",
    namespaced,
    shortname = "upa",
    status = "UpdateAgentStatus",
    printcolumn = r#"{"name":"Repository","type":"string","jsonPath":".spec.repositoryRef.name"}"#,
    printcolumn = r#"{"name":"Selected","type":"string","jsonPath":".status.selectedGroup"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type == 'Ready')].status"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAgentSpec {
    pub repository_ref: LocalObjectReference,
    pub identity: AgentIdentity,
    /// Control-plane labels for this agent. The represented agent may run anywhere and
    /// does not need to be a Kubernetes Node, Pod, or workload.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// Host a load balancer uses to reach this agent's managed service: one IP literal or DNS name,
    /// never a URL or `host:port`. The [`UpdateBackend`] target owns the service port, so there is
    /// one port authority rather than an ignored per-agent spelling. It is optional because not
    /// every managed machine serves traffic; an [`UpdateBackend`] selecting an uncordoned agent
    /// without a valid host and pinned key projects that identity as explicitly drained and reports
    /// the degraded inventory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_address: Option<String>,
    /// Freeze this node on exactly the body its recorded assignment names — a hardware swap is
    /// scheduled, do not move it. A held node keeps its group membership for accounting but is
    /// excluded from admission: it neither advances to a staged deployment nor releases a rollout
    /// slot, and its recorded body is republished verbatim. If that body can no longer be resolved,
    /// planning fails closed for this node exactly as the quarantine carry-forward does — a hold
    /// can never silently become a move. Clearing it returns the node to normal admission on the
    /// next reconcile.
    #[serde(default)]
    pub hold: bool,
    /// Take this node out of load-balancer rotation gracefully, without stopping the application.
    /// A cordoned identity is projected through every matching [`UpdateBackend`]'s trusted
    /// inventory as an explicit drain, regardless of its report. The application keeps running,
    /// the node keeps reporting, and the agent stays unaware. Rollout accounting treats it as
    /// absent (like a departed node), so a cordon neither eats the group's availability budget nor
    /// wedges an in-flight rollout. Orthogonal to [`hold`](Self::hold): a node can be held but
    /// serving, or cordoned but updatable.
    #[serde(default)]
    pub cordon: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AgentIdentity {
    pub kind: AgentIdentityKind,
    /// Present only for controller-created dynamic inventory. It is the stable digest of the
    /// validated enrollment name and makes retries resolve to the same agent.
    pub registration_sha256: Option<String>,
    /// The node's pinned public key (hex uncompressed EC point) — set from the CSR at online
    /// enrollment or supplied by the operator for a manual identity. It is the same key that
    /// certifies the node's mTLS leaf. Rollout planning verifies the node's *signed* telemetry
    /// against this, so a report is attributable end-to-end (node → planner), not merely
    /// authenticated on the write hop. `None` only while a reserved identity has not enrolled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

impl AgentIdentity {
    /// Whether this identity has the one valid field shape for its kind and node name.
    ///
    /// A manual identity carries the public key the operator provisioned but no online-registration
    /// digest. A reserved identity carries neither until enrollment. An enrolled identity carries
    /// both, with the same canonical SHA-256 and P-256 encodings the enrollment and telemetry paths
    /// use. Keeping this rule here prevents callers from inventing subtly different meanings for an
    /// identity kind.
    /// The registration digest is not merely shaped like SHA-256:
    /// enrollment defines it as the digest of the validated node name, so accepting any other
    /// value would create a second, forgeable meaning for the field.
    pub fn is_well_formed_for(&self, node: &str) -> bool {
        let public_key_is_valid = || {
            self.public_key.as_deref().is_some_and(|encoded| {
                updated_contracts::key::P256PublicKey::parse_hex(encoded).is_ok()
            })
        };
        match self.kind {
            AgentIdentityKind::Manual => {
                self.registration_sha256.is_none() && public_key_is_valid()
            }
            AgentIdentityKind::Reserved => {
                self.registration_sha256.is_none() && self.public_key.is_none()
            }
            AgentIdentityKind::Enrolled => {
                self.registration_sha256.as_deref().is_some_and(|digest| {
                    digest == updated_contracts::telemetry::node_object_digest(node)
                }) && public_key_is_valid()
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AgentIdentityKind {
    /// Offline provisioning: the operator declares the agent, pins the public half of its
    /// provisioned node key, and copies its content-addressed S3 enrollment object out of band. The
    /// machine never talks to `/enroll`, and this identity is NEVER completable over the shared
    /// fleet bootstrap certificate. Its signed reports and mTLS requests use the same pinned key as
    /// every enrolled node; only the initial delivery path differs.
    Manual,
    /// The operator reserved this exact name for a machine that will enroll dynamically, and
    /// deferred the identity to the node's own CSR. This is the ONLY shape `/enroll` may complete
    /// in place, because the enrollment credential is the fleet-wide bootstrap certificate every
    /// node already holds: whoever presents it first claims the name and the labels attached to it.
    /// Reserving is therefore an explicit statement that any fleet member may claim this name —
    /// never something a plain declared agent falls into by default.
    Reserved,
    /// A node that has enrolled: its CSR public key is pinned and its registration digest is set.
    Enrolled,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateAgentStatus {
    pub observed_generation: Option<i64>,
    pub selected_group: Option<String>,
    pub assignment_path: Option<String>,
    pub published_digest: Option<String>,
    /// SHA-256 of this node's exact currently published signed assignment document.
    /// Informational only: the gateway independently resolves the assignment through TUF and
    /// never treats status as data-plane authority.
    pub assignment_sha256: Option<String>,
    /// Repository-relative S3 key of this agent's current content-addressed enrollment bundle.
    /// The gateway authorizes this exact object for live enrollment; an operator may copy the same
    /// object out of band for a manual identity. No gateway response carries its bytes.
    pub enrollment_object_key: Option<String>,
    /// The version the node last reported it is actually running, from its rollout telemetry.
    /// This is the control plane's authoritative view of a node's running version — no
    /// consumer probes the managed app, so it works for any app kind (a Rust service, a real
    /// Jenkins, anything). `None` until the node has reported at least once.
    pub reported_version: Option<String>,
    /// Whether the node last reported itself settled and healthy on its assignment.
    pub reported_ready: Option<bool>,
    /// The latest successful state-changing reconciler invocation, durably bound and signed by the
    /// node. This exposes change, immutable release identities, and any requested host action
    /// without trusting script logs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reconciliation: Option<ReconciliationStatus>,
    /// Mirror of `spec.hold`, written as an explicit bool every reconcile (a merge patch that
    /// omitted it would leave a cleared hold reading `true` forever). Surfaced so a forgotten hold
    /// is a visible condition, not a mystery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<bool>,
    /// Mirror of `spec.cordon`, written as an explicit bool for the same merge-patch reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cordoned: Option<bool>,
    #[serde(default)]
    pub conditions: Vec<ResourceCondition>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReconciledReleaseStatus {
    pub version: String,
    pub manifest_sha256: String,
    pub archive_sha256: String,
}

impl From<&updated_contracts::reconciler::ReconciledRelease> for ReconciledReleaseStatus {
    fn from(release: &updated_contracts::reconciler::ReconciledRelease) -> Self {
        Self {
            version: release.version().into(),
            manifest_sha256: release.manifest_sha256().into(),
            archive_sha256: release.archive_sha256().into(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReconcilerStatus {
    pub provider_set_sha256: String,
    pub product: String,
    pub release: ReconciledReleaseStatus,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationStatus {
    pub operation: String,
    pub reason: String,
    pub attempt_id: String,
    pub candidate: ReconciledReleaseStatus,
    pub predecessor: ReconciledReleaseStatus,
    pub reconciler: ReconcilerStatus,
    pub changed: bool,
    pub host_action: String,
    pub message: Option<String>,
    pub completed_at_ms: u64,
}

impl From<&updated_contracts::reconciler::LastReconciliation> for ReconciliationStatus {
    fn from(record: &updated_contracts::reconciler::LastReconciliation) -> Self {
        Self {
            operation: record.operation().as_str().into(),
            reason: record.reason().as_str().into(),
            attempt_id: record.attempt_id().into(),
            candidate: record.candidate().into(),
            predecessor: record.predecessor().into(),
            reconciler: ReconcilerStatus {
                provider_set_sha256: record.reconciler().provider_set_sha256().into(),
                product: record.reconciler().product().into(),
                release: record.reconciler().release().into(),
            },
            changed: record.result().changed(),
            host_action: record.result().host_action().as_str().into(),
            message: record.result().message().map(str::to_owned),
            completed_at_ms: record.completed_at_ms(),
        }
    }
}

#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "updated.dev",
    version = "v1alpha1",
    kind = "UpdateRepository",
    plural = "updaterepositories",
    namespaced,
    shortname = "upr",
    status = "UpdateRepositoryStatus",
    printcolumn = r#"{"name":"Agents","type":"integer","jsonPath":".status.agentCount"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type == 'Ready')].status"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRepositorySpec {
    /// Deployment selected when no named group matches an agent.
    pub default_deployment: DeploymentSpec,
    /// Secret in the same namespace containing active and standby root keys (`root.pk8` and
    /// `root.next.pk8`) plus targets, snapshot, and timestamp private keys. The controller never
    /// stores private keys in CRD status.
    pub signing_secret_ref: LocalSecretReference,
    /// Trusted labels applied to dynamic registrations. Enrollment is authenticated by mutual
    /// TLS at the gateway (a cert-manager-issued server cert + fleet client CA, mounted), so
    /// there is no shared secret here.
    pub enrollment: EnrollmentSpec,
    /// Object store that holds this managed repository. The controller derives the repository's
    /// key prefix from its Kubernetes namespace and name; operators cannot select or retarget it.
    pub s3: RepositoryStorage,
    /// Prefix below the TUF targets namespace at which assignments are published.
    #[serde(default = "default_assignment_prefix")]
    pub assignment_prefix: String,
    /// Exact maximum number of bounded ConfigMaps used for the durable rollout-state document.
    /// The controller atomically rebalances the entire document when this changes. Two slots are
    /// used so a process death can never expose a partially rewritten state; a live rebalance may
    /// transiently hold the old width plus the new width, and reclaims the old slot afterwards.
    #[serde(default = "default_state_max_shards")]
    #[schemars(range(min = 1, max = "crate::runtime::MAX_ADMITTED_STATE_SHARDS"))]
    pub state_max_shards: u8,
    /// Optional namespace-local release-admission policy. Presence enables the one Draupnir
    /// integration path; absence disables external admission. Policy behavior lives only in the
    /// referenced CRD, never in environment variables or group-level overrides.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_policy_ref: Option<LocalObjectReference>,
}

fn default_state_max_shards() -> u8 {
    8
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentSpec {
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
pub struct LocalSecretReference {
    #[schemars(length(min = 1))]
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct LocalObjectReference {
    pub name: String,
}

/// This status is always written as a JSON MERGE PATCH, where an explicit `null` DELETES the field
/// instead of leaving it alone. A writer that has nothing to say about a field must therefore OMIT
/// it, which is what `skip_serializing_if` is doing on every optional field a later reader depends
/// on: the failure path knows neither the agent count nor the published digest, and serializing its
/// `None` erased the count `gateway::at_enrollment_capacity` reads — uncapping `/enroll` from the
/// first failed reconcile until the next successful one.
#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRepositoryStatus {
    pub observed_generation: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_count: Option<u32>,
    /// SHA-256 of the `root.json` this control plane publishes — the fleet's trust anchor, recorded
    /// in etcd where only the control plane can write it.
    ///
    /// The object store is a distribution channel, not a trust boundary: anyone able to write its
    /// prefix can replace `root.json`. Enrollment therefore pins the root it hands a node against
    /// THIS value before verifying anything else. `None` until the first publish, and enrollment
    /// refuses to serve a bundle until then.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing_root_sha256: Option<String>,
    /// Storage coordinates this controller bound before it added the external-artifact finalizer
    /// or published the first object. The status subresource is controller-owned, so deletion uses
    /// this record rather than reconstructing an irreversible target from mutable access settings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_ownership: Option<RepositoryStorageOwnership>,
    #[serde(default)]
    pub conditions: Vec<ResourceCondition>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceCondition {
    #[serde(rename = "type")]
    pub condition_type: String,
    pub status: String,
    pub reason: String,
    pub message: String,
    pub observed_generation: Option<i64>,
    pub last_transition_time: String,
}

/// A generic webhook that is notified when a repository publishes a new generation. This is how
/// external change-tracking systems (compliance engines, audit stores, chat notifiers) subscribe to
/// updates without polling S3 or depending on bucket event notifications: the publisher pushes.
///
/// Delivery is at-least-once and rides the controller's single-writer reconcile. Each subscription
/// carries a per-repository high-water mark in its status; every reconcile the controller delivers
/// one event per generation from that mark up to the currently published version, advancing the
/// mark on each success. A subscriber that was down is caught up on the next tick; nothing is
/// skipped and, because the mark only moves forward on a delivered POST, nothing is lost.
#[derive(CustomResource, Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[kube(
    group = "updated.dev",
    version = "v1alpha1",
    kind = "UpdateSubscription",
    plural = "updatesubscriptions",
    namespaced,
    shortname = "usub",
    status = "UpdateSubscriptionStatus",
    printcolumn = r#"{"name":"URL","type":"string","jsonPath":".spec.webhook.url"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type == 'Ready')].status"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSubscriptionSpec {
    /// Where update events are delivered.
    pub webhook: WebhookSpec,
    /// Restrict this subscription to one repository. Omit to be notified for every
    /// `UpdateRepository` in the namespace (each tracked independently in status).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_ref: Option<LocalObjectReference>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct WebhookSpec {
    /// Absolute `http(s)` URL the controller `POST`s each update event to as JSON.
    pub url: String,
    /// Secret in the same namespace whose `key` entry is the HMAC-SHA256 secret used to sign the
    /// request body. The signature rides `X-Updated-Signature: sha256=<hex>` so the subscriber can
    /// authenticate the event and reject a forged one. Omit for an unsigned POST over TLS.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<LocalSecretReference>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateSubscriptionStatus {
    pub observed_generation: Option<i64>,
    /// Highest generation successfully delivered, per repository (repository name → version). One
    /// entry per repository this subscription covers; the controller delivers versions above each
    /// mark. Per-repository because each repository has its own independent generation counter.
    #[serde(default)]
    pub delivered_versions: BTreeMap<String, u64>,
    /// RFC 3339 time of the most recent successful delivery, for operator visibility.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_delivery_time: Option<String>,
    /// RFC 3339 time this subscription was last ATTEMPTED — success or failure alike, and never
    /// stamped by a deferral. It is the delivery cursor: each pass serves the least recently
    /// attempted subscriptions first, so a slow subscriber early in name order can no longer
    /// consume the whole budget every pass and starve the ones behind it. Persisted here rather
    /// than in the controller so it survives a leader change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_time: Option<String>,
    #[serde(default)]
    pub conditions: Vec<ResourceCondition>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct S3Destination {
    pub bucket: String,
    #[serde(default)]
    pub prefix: String,
    pub region: String,
    /// Optional Secret containing standard AWS_ACCESS_KEY_ID and
    /// AWS_SECRET_ACCESS_KEY entries. When absent, workload identity is used.
    pub credentials_secret_ref: Option<LocalSecretReference>,
    pub endpoint: Option<String>,
    /// Public HTTPS S3-compatible endpoint placed in short-lived object capabilities. Omit for AWS
    /// S3 or when `endpoint` is already public HTTPS. An internal HTTP endpoint must provide this:
    /// payload proxying is not a fallback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_endpoint: Option<String>,
}

/// Storage configuration accepted by a managed [`UpdateRepository`]. Unlike the generic
/// [`S3Destination`] used by `updatectl`, it intentionally has no prefix: the controller assigns
/// one canonical, non-overlapping key space from the repository's Kubernetes identity.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryStorage {
    #[schemars(length(min = 1))]
    pub bucket: String,
    #[schemars(length(min = 1))]
    pub region: String,
    /// Optional Secret containing standard AWS_ACCESS_KEY_ID and
    /// AWS_SECRET_ACCESS_KEY entries. When absent, workload identity is used.
    pub credentials_secret_ref: Option<LocalSecretReference>,
    #[schemars(length(min = 1))]
    pub endpoint: Option<String>,
    /// Public HTTPS S3-compatible endpoint placed in short-lived object capabilities. Omit for AWS
    /// S3 or when `endpoint` is already public HTTPS. An internal HTTP endpoint must provide this:
    /// payload proxying is not a fallback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1))]
    pub public_endpoint: Option<String>,
}

/// Controller-owned identity of the object-store key space a repository is allowed to delete.
/// Secret contents and the public download endpoint are deliberately absent: they may rotate and
/// do not change which physical keys the finalizer owns. The Secret REFERENCE is included because
/// selecting another credential identity can select another cloud account and therefore another
/// physical bucket even when endpoint and bucket strings remain equal.
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryStorageOwnership {
    pub bucket: String,
    pub prefix: String,
    pub region: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials_secret_ref: Option<LocalSecretReference>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
}

impl From<&S3Destination> for RepositoryStorageOwnership {
    fn from(destination: &S3Destination) -> Self {
        Self {
            bucket: destination.bucket.clone(),
            prefix: destination.prefix.clone(),
            region: destination.region.clone(),
            credentials_secret_ref: destination.credentials_secret_ref.clone(),
            endpoint: destination.endpoint.clone(),
        }
    }
}

impl RepositoryStorageOwnership {
    pub(crate) fn destination_with_access(&self, access: &RepositoryStorage) -> S3Destination {
        S3Destination {
            bucket: self.bucket.clone(),
            prefix: self.prefix.clone(),
            region: self.region.clone(),
            credentials_secret_ref: self.credentials_secret_ref.clone(),
            endpoint: self.endpoint.clone(),
            public_endpoint: access.public_endpoint.clone(),
        }
    }
}

fn default_assignment_prefix() -> String {
    "assignments".into()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationTarget {
    pub path: String,
    pub bytes: Vec<u8>,
    pub sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationPlan {
    /// Config documents contain desired deployments; agent documents contain exact config
    /// target references.
    pub targets: Vec<PublicationTarget>,
    pub node_groups: BTreeMap<String, String>,
    /// Node → the identity of the deployment this generation publishes for it. Recorded here, by
    /// the one function that decides what a node is handed, so the next generation can tell which
    /// nodes have already been advanced without asking telemetry that ages out mid-update.
    pub node_assignments: BTreeMap<String, String>,
    pub digest: String,
}

/// An `UpdateGroup` after Kubernetes metadata has been combined with its spec.
#[derive(Clone, Debug)]
pub struct ResolvedGroup {
    pub name: String,
    pub match_labels: BTreeMap<String, String>,
    pub depends_on: Vec<String>,
    pub inputs: BTreeMap<String, GroupOutputReference>,
    /// Sensitive resolved bytes retained only inside this reconciliation so the controller can
    /// write the private keyed-blinded S3 publication before publishing its non-secret exact-byte
    /// commitment. `None` means unresolved when bindings exist; groups with no bindings are ready
    /// without a private object.
    pub input_snapshot: Option<updated_contracts::dataflow::FileSnapshot>,
    pub deployment: DesiredDeployment,
    pub max_unavailable: usize,
    /// [`UpdateGroupSpec::emergency_correction`] — the operator's stated intent that `deployment`
    /// is an emergency correction, which exempts its admission from the governing set's schedule.
    pub emergency_correction: bool,
}

impl ResolvedGroup {
    pub fn inputs_ready(&self) -> bool {
        self.inputs.is_empty() || self.input_snapshot.is_some()
    }
}

#[derive(Clone, Debug)]
pub struct ResolvedNode {
    pub name: String,
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum PlanError {
    EmptySelector(String),
    DuplicateGroup(String),
    ReservedGroupName,
    /// The planned generation would publish no assignment for a node that already has one.
    RoutingLoss(Vec<String>),
    /// A node carried forward on its last routing has no deployment body the control plane can
    /// still resolve, so where it actually stands is unknown and nothing may be published for it.
    UnknownPlacement {
        node: String,
        group: String,
    },
    DuplicateNode(String),
    MissingDependency {
        group: String,
        dependency: String,
    },
    DependencyCycle(Vec<String>),
    InvalidDependencyInput {
        group: String,
        input: String,
    },
    /// More dependency inputs than the signed file snapshot admits, so the group's resolved
    /// `runtime.inputs` could never be published.
    TooManyDependencyInputs {
        group: String,
        inputs: usize,
    },
    AmbiguousNode {
        node: String,
        groups: Vec<String>,
    },
    InvalidNodeName,
    InvalidPrefix,
    InvalidDeployment(String),
    NodeDeploymentMismatch,
    Serialize(String),
}

/// Whether a name may be a key of a signed file snapshot — the grammar dependency inputs must
/// satisfy, asked of the contract itself rather than restated here.
///
/// A dependency input name becomes a key of `deployment.runtime.inputs`, which
/// `RepositoryAssignment::validate` runs through `FileSnapshot::validate` at publication time.
/// Admitting an input name against the weaker traversal rule alone let an over-long one (the
/// manifest bounds names at 128 bytes) through admission and detonate later: nothing is written
/// into `runtime.inputs` until the producer reports healthy, and from that moment every reconcile
/// for the whole repository failed to build a publication at all — no group ever got another
/// generation, and no new agent could enroll. One grammar, checked where the name is accepted.
fn is_output_name(name: &str) -> bool {
    updated_contracts::dataflow::FileSnapshot {
        files: BTreeMap::from([(
            name.to_string(),
            updated_contracts::dataflow::FileValue::from_bytes(b"")
                .expect("an empty file is contract-valid"),
        )]),
    }
    .validate()
    .is_ok()
}

/// Validate the group dependency graph before planning a new publication. Invalid desired state
/// fails the whole generation closed, preserving the last published assignments.
///
/// A QUARANTINED group is present-but-frozen, not missing: the resource exists, it simply cannot be
/// planned this pass. Reading it as missing made one typo'd digest abort publication for the entire
/// repository — the exact fleet-wide stall quarantine exists to prevent ("rather than aborting
/// publication for every other resource"). Its dependents resolve no inputs from it, so they stay
/// un-admitted and carry their current routing forward, which is what a frozen prerequisite should
/// do.
///
/// The skip keys on the FULL quarantined set, not on the subset that has a durable pin (`held`): a
/// group created with a typo'd digest was never admitted, so it has no pin at all, and that is the
/// most likely way this state is ever reached.
pub(crate) fn validate_dependency_graph(
    groups: &BTreeMap<String, ResolvedGroup>,
    quarantined: &BTreeSet<String>,
) -> Result<(), PlanError> {
    fn visit(
        name: &str,
        groups: &BTreeMap<String, ResolvedGroup>,
        quarantined: &BTreeSet<String>,
        state: &mut BTreeMap<String, u8>,
        stack: &mut Vec<String>,
    ) -> Result<(), PlanError> {
        match state.get(name).copied() {
            Some(2) => return Ok(()),
            Some(1) => {
                let start = stack.iter().position(|entry| entry == name).unwrap_or(0);
                let mut cycle = stack[start..].to_vec();
                cycle.push(name.to_string());
                return Err(PlanError::DependencyCycle(cycle));
            }
            _ => {}
        }
        state.insert(name.to_string(), 1);
        stack.push(name.to_string());
        for dependency in &groups[name].depends_on {
            if quarantined.contains(dependency) {
                continue;
            }
            if !groups.contains_key(dependency) {
                return Err(PlanError::MissingDependency {
                    group: name.to_string(),
                    dependency: dependency.clone(),
                });
            }
            visit(dependency, groups, quarantined, state, stack)?;
        }
        // The resolved input COUNT is bounded by the signed manifest exactly as each input NAME is.
        // `resolve_one` replaces `runtime.inputs` wholesale with one value per declared input, so a
        // group declaring more than the manifest admits parses fine at admission and detonates the
        // moment its producer first reports healthy: `deployment_identity` returns None from then
        // on and every reconcile for the whole repository fails to build a publication.
        if groups[name].inputs.len() > updated_contracts::dataflow::FileSnapshot::MAX_FILES {
            return Err(PlanError::TooManyDependencyInputs {
                group: name.to_string(),
                inputs: groups[name].inputs.len(),
            });
        }
        for (input, reference) in &groups[name].inputs {
            if !is_output_name(input)
                || !is_output_name(&reference.output)
                || !groups[name].depends_on.contains(&reference.group)
            {
                return Err(PlanError::InvalidDependencyInput {
                    group: name.to_string(),
                    input: input.clone(),
                });
            }
        }
        stack.pop();
        state.insert(name.to_string(), 2);
        Ok(())
    }

    let mut state = BTreeMap::new();
    let mut stack = Vec::new();
    for name in groups.keys() {
        visit(name, groups, quarantined, &mut state, &mut stack)?;
    }
    Ok(())
}

/// Every group whose dependency wiring cannot be planned, with the human-readable reason — the
/// PER-GROUP reading of exactly what [`validate_dependency_graph`] enforces. A malformed input
/// name, a reference to a group outside `dependsOn`, a dependency that does not exist, and
/// membership in a dependency cycle are all facts about specific groups, and the operator-facing
/// response to each is the same as for an invalid deployment: QUARANTINE those groups (their
/// nodes hold what they run) and keep planning everyone else. Surfacing them as a plan error
/// instead made one bad edit to one group fail every reconcile for the whole repository, forever
/// — a fleet-wide control-plane outage with a per-group cause. The graph validation itself stays
/// in the pure planner as the backstop invariant; this classifier is what keeps it from ever
/// firing in the operator.
pub(crate) fn dependency_violations(
    groups: &BTreeMap<String, ResolvedGroup>,
    quarantined: &BTreeSet<String>,
) -> BTreeMap<String, String> {
    let mut violations: BTreeMap<String, String> = BTreeMap::new();
    for (name, group) in groups {
        if group.inputs.len() > updated_contracts::dataflow::FileSnapshot::MAX_FILES {
            violations.insert(
                name.clone(),
                format!(
                    "This group declares {} dependency inputs; a signed file snapshot admits at most {}.",
                    group.inputs.len(),
                    updated_contracts::dataflow::FileSnapshot::MAX_FILES
                ),
            );
            continue;
        }
        if let Some((input, reference)) = group.inputs.iter().find(|(input, reference)| {
            !is_output_name(input)
                || !is_output_name(&reference.output)
                || !group.depends_on.contains(&reference.group)
        }) {
            violations.insert(
                name.clone(),
                format!(
                    "This group's input {input:?} is invalid: its name and referenced output must \
                     satisfy the output grammar, and its group {:?} must be listed in dependsOn.",
                    reference.group
                ),
            );
            continue;
        }
        if let Some(dependency) = group.depends_on.iter().find(|dependency| {
            !quarantined.contains(*dependency) && !groups.contains_key(*dependency)
        }) {
            violations.insert(
                name.clone(),
                format!("This group depends on {dependency:?}, which does not exist."),
            );
        }
    }
    // Cycles, on whatever remains: each pass of the graph validation reports one cycle; every
    // member is quarantined and the walk repeats until the remainder is acyclic. Bounded by the
    // group count — each pass removes at least one group.
    loop {
        let mut remaining = groups.clone();
        remaining.retain(|name, _| !violations.contains_key(name));
        let mut skip: BTreeSet<String> = quarantined.clone();
        skip.extend(violations.keys().cloned());
        match validate_dependency_graph(&remaining, &skip) {
            Ok(()) => break,
            Err(PlanError::DependencyCycle(cycle)) => {
                let display = cycle.join(" -> ");
                for member in cycle {
                    violations.entry(member).or_insert_with(|| {
                        format!("This group is part of a dependency cycle: {display}.")
                    });
                }
            }
            // Local shapes and dangling dependencies were classified above; the only error the
            // remainder can still raise is a cycle. A new variant reaching here is a missed
            // classification, and quarantining nothing for it would resurrect the fleet-wide
            // failure this exists to prevent — so it is a bug to fix, loudly.
            Err(other) => {
                unreachable!("dependency violation not classified per-group: {other:?}")
            }
        }
    }
    violations
}

/// The pseudo-group a node that matched no `UpdateGroup` routes to; it receives the repository's
/// `default_deployment` directly and is never throttled. Reserved: a real `UpdateGroup` claiming
/// this name would have its own throttled, gated rollout silently replaced by that fleet-wide
/// switch, so [`resolve_node_groups`] refuses it outright.
pub const DEFAULT_GROUP: &str = "default";

/// Resolve selectors before rollout admission without constructing a throwaway publication.
pub(crate) fn resolve_node_groups(
    groups: impl IntoIterator<Item = ResolvedGroup>,
    nodes: impl IntoIterator<Item = ResolvedNode>,
) -> Result<BTreeMap<String, String>, PlanError> {
    let mut indexed = BTreeMap::new();
    for group in groups {
        let name = group.name.clone();
        if group.match_labels.is_empty() {
            return Err(PlanError::EmptySelector(name));
        }
        if name == DEFAULT_GROUP {
            return Err(PlanError::ReservedGroupName);
        }
        if indexed.insert(name.clone(), group).is_some() {
            return Err(PlanError::DuplicateGroup(name));
        }
    }
    let mut node_groups = BTreeMap::new();
    for node in nodes {
        let name = node.name;
        if !updated_contracts::identity::is_dns_subdomain(&name) || node_groups.contains_key(&name)
        {
            return if node_groups.contains_key(&name) {
                Err(PlanError::DuplicateNode(name))
            } else {
                Err(PlanError::InvalidNodeName)
            };
        }
        let matches: Vec<_> = indexed
            .iter()
            .filter(|(_, group)| selector_matches(&group.match_labels, &node.labels))
            .map(|(name, _)| name.clone())
            .collect();
        let selected = match matches.as_slice() {
            [] => DEFAULT_GROUP.to_string(),
            [only] => only.clone(),
            _ => {
                return Err(PlanError::AmbiguousNode {
                    node: name,
                    groups: matches,
                });
            }
        };
        node_groups.insert(name, selected);
    }
    Ok(node_groups)
}

impl std::fmt::Display for PlanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for PlanError {}

/// Compile the deterministic, all-or-nothing publication selected by rollout admission.
/// Config targets are content-addressed, so nodes held on the same deployment share one target
/// without conflating deployment choice with group membership.
pub(crate) fn build_publication_plan(
    repository: &UpdateRepositorySpec,
    node_groups: BTreeMap<String, String>,
    node_deployments: BTreeMap<String, DesiredDeployment>,
) -> Result<PublicationPlan, PlanError> {
    let prefix = repository.assignment_prefix.trim_matches('/');
    // The object-key prefix must be a confined relative path — the one shared traversal guard, so a
    // prefix can never climb out of the repository key space (`is_confined_relative` also rejects an
    // empty prefix).
    if !updated_contracts::path::is_confined_relative(prefix) {
        return Err(PlanError::InvalidPrefix);
    }
    if node_groups.keys().ne(node_deployments.keys()) {
        return Err(PlanError::NodeDeploymentMismatch);
    }
    let mut targets = Vec::new();
    let mut references: BTreeMap<String, ExactTarget> = BTreeMap::new();
    let mut node_assignments = BTreeMap::new();
    // One canonicalization per node, and no more: serializing a deployment validates it and hashing
    // it is what gives it its identity, so both the shared config target (one per DISTINCT body,
    // however many nodes hold it) and this node's own assignment document are derived from that
    // single pass rather than the body being re-serialized to look its own identity back up.
    for (node, deployment) in &node_deployments {
        let (bytes, id) = deployment
            .publication()
            .map_err(PlanError::InvalidDeployment)?;
        if !references.contains_key(&id) {
            let config = target(
                updated_contracts::telemetry::config_object_key(prefix, &id),
                bytes,
            );
            references.insert(
                id.clone(),
                ExactTarget {
                    path: config.path.clone(),
                    sha256: config.sha256.clone(),
                },
            );
            targets.push(config);
        }
        let assignment = updated_contracts::artifact::AgentDocument {
            schema: 1,
            config: references[&id].clone(),
        };
        let bytes = assignment.to_bounded_json().map_err(PlanError::Serialize)?;
        targets.push(target(
            updated_contracts::telemetry::assignment_object_key(prefix, node),
            bytes,
        ));
        node_assignments.insert(node.clone(), id);
    }
    targets.sort_by(|a, b| a.path.cmp(&b.path));
    let digest = publication_digest(&targets);
    Ok(PublicationPlan {
        targets,
        node_groups,
        node_assignments,
        digest,
    })
}

pub(crate) fn selector_matches(
    expected: &BTreeMap<String, String>,
    labels: &BTreeMap<String, String>,
) -> bool {
    expected
        .iter()
        .all(|(key, value)| labels.get(key) == Some(value))
}

/// The content identity of a deployment: the SHA-256 of the exact bytes published as its
/// `configs/<id>.json` target, which is the digest a node reports back once it is acting on it.
///
/// This, not the operator-chosen `deployment` NAME, is what "settled on the desired deployment"
/// means. An operator can change a deployment's archive, arguments, or secrets without renaming it,
/// and the control plane rewrites resolved dependency inputs under an unchanged name by itself;
/// comparing names would call every one of those changes "already settled" and roll them to the
/// whole group at once, with no `maxUnavailable` staging at all.
///
/// An invalid deployment has no identity — `None` — and can never match a report.
pub(crate) fn deployment_identity(value: &DesiredDeployment) -> Option<String> {
    value.publication().ok().map(|(_, identity)| identity)
}

fn target(path: String, bytes: Vec<u8>) -> PublicationTarget {
    let sha256 = updated_contracts::digest::sha256_bytes(&bytes);
    PublicationTarget {
        path,
        bytes,
        sha256,
    }
}

fn publication_digest(targets: &[PublicationTarget]) -> String {
    let mut digest = updated_contracts::digest::Sha256Hasher::new();
    for target in targets {
        digest.update(target.path.as_bytes());
        digest.update(&[0]);
        digest.update(&target.bytes);
        digest.update(&[0]);
    }
    digest.finish_hex()
}

/// Join a store `prefix` with a `relative` object path into a normalized object key, dropping any
/// empty segment (an empty prefix, or one with surrounding slashes). The single place this
/// prefix+relative join is expressed, shared by the gateway's content handlers, the operator's
/// publication and telemetry reads, and `updatectl`'s reads back out of the same bucket.
pub fn object_key(prefix: &str, relative: &str) -> object_store::path::Path {
    object_store::path::Path::from(
        [prefix.trim_matches('/'), relative]
            .into_iter()
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join("/"),
    )
}

/// Whether `object` belongs to `root` rather than merely sharing its byte prefix.
///
/// S3 list requests use byte prefixes: asking for `tenant/repository` may also return
/// `tenant/repository-old`. Every destructive namespace walk goes through this boundary check so
/// one repository can never retire a sibling repository's objects.
pub(crate) fn object_in_namespace(
    root: &object_store::path::Path,
    object: &object_store::path::Path,
) -> bool {
    object == root
        || object
            .as_ref()
            .strip_prefix(root.as_ref())
            .is_some_and(|rest| rest.starts_with('/'))
}

/// Total wall-clock budget for best-effort object-store garbage collection and private namespace
/// scans. All such walks stream their results; this budget additionally prevents a slow or hostile
/// backend from monopolizing the repository reconciler indefinitely.
pub(crate) const OBJECT_STORE_MAINTENANCE_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(30);

/// Upper bound on any single repository object the control plane reads back into memory: a signed
/// metadata document, an assignment, a managed configuration, or a node report. All are small, and
/// all are bounded at *write* time (the gateway caps request bodies) — but the bucket is not
/// exclusively ours, so a direct writer must not be able to make a reconcile or an `/enroll`
/// response allocate without limit. Generous relative to any legitimate document.
pub const OBJECT_BYTES_LIMIT: u64 = 8 * 1024 * 1024;

const _: () =
    assert!(updated_contracts::enrollment::MAX_DOCUMENT_BYTES as u64 == OBJECT_BYTES_LIMIT);

/// Collect an object-store result without trusting its declared size as the allocation bound.
/// Metadata rejects an honestly oversized object before reading it; the running byte count also
/// rejects a backend that streams more than it declared. This is the one collection path for every
/// control-plane object read, including the gateway's versioned fleet-document merge.
pub(crate) async fn collect_object_bounded(
    result: object_store::GetResult,
    key: &object_store::path::Path,
    limit: u64,
) -> Result<(object_store::ObjectMeta, Vec<u8>), object_store::Error> {
    use futures::StreamExt as _;

    let meta = result.meta.clone();
    if meta.size > limit {
        return Err(object_store::Error::Generic {
            store: "updatec",
            source: format!(
                "object {key} is {} bytes, over the {limit}-byte limit",
                meta.size
            )
            .into(),
        });
    }
    let capacity = usize::try_from(meta.size.min(limit)).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    let mut stream = result.into_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        let next_len = u64::try_from(bytes.len())
            .unwrap_or(u64::MAX)
            .saturating_add(u64::try_from(chunk.len()).unwrap_or(u64::MAX));
        if next_len > limit {
            return Err(object_store::Error::Generic {
                store: "updatec",
                source: format!("object {key} streamed more than the {limit}-byte limit").into(),
            });
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok((meta, bytes))
}

/// Read one object through [`collect_object_bounded`]. The convenience wrapper deliberately adds
/// no second collection implementation: callers that do not need version metadata discard it.
pub async fn read_object_bounded(
    store: &dyn object_store::ObjectStore,
    key: &object_store::path::Path,
    limit: u64,
) -> Result<Vec<u8>, object_store::Error> {
    let result = store.get(key).await?;
    collect_object_bounded(result, key, limit)
        .await
        .map(|(_, bytes)| bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bounded_object_collection_does_not_trust_declared_size() {
        use axum::body::Bytes;
        use futures::stream;
        use object_store::{Attributes, GetResult, GetResultPayload, ObjectMeta};

        let key = object_store::path::Path::from("lying-object");
        let result = GetResult {
            payload: GetResultPayload::Stream(Box::pin(stream::iter([Ok(Bytes::from_static(
                b"too large",
            ))]))),
            meta: ObjectMeta {
                location: key.clone(),
                last_modified: chrono::Utc::now(),
                size: 1,
                e_tag: None,
                version: None,
            },
            range: 0..1,
            attributes: Attributes::new(),
            extensions: Default::default(),
        };

        let error = collect_object_bounded(result, &key, 4)
            .await
            .expect_err("the running byte count must enforce the bound");
        assert!(error.to_string().contains("streamed more"), "{error}");
    }

    fn group_set(max_concurrent: Option<u32>) -> UpdateGroupSetSpec {
        UpdateGroupSetSpec {
            repository_ref: LocalObjectReference {
                name: "default".into(),
            },
            selector: LabelSelector::default(),
            max_concurrent,
            rollout_windows: vec![],
            calendar: vec![],
            on_regression: RegressionResponse::default(),
            max_regressions: None,
            stuck_after_seconds: None,
        }
    }

    #[test]
    fn object_key_normalizes_prefix_and_drops_empties() {
        // Only prefixes the S3 store actually accepts: it requires an already-normalized,
        // non-empty, confined prefix, so a `/p/` case here would prove nothing about any reachable
        // input.
        assert_eq!(
            object_key("routing", "metadata").as_ref(),
            "routing/metadata"
        );
        assert_eq!(
            object_key("a/b", "metadata/root.json").as_ref(),
            "a/b/metadata/root.json"
        );
        // An empty sub-path must not leave a trailing slash.
        assert_eq!(object_key("a/b", "").as_ref(), "a/b");
    }

    #[test]
    fn object_namespace_membership_is_segment_aware() {
        let root = object_key("tenant", "routing");
        assert!(object_in_namespace(&root, &root));
        assert!(object_in_namespace(
            &root,
            &object_key("tenant/routing", "metadata/root.json")
        ));
        assert!(!object_in_namespace(
            &root,
            &object_key("tenant", "routing-old/metadata/root.json")
        ));
        assert!(!object_in_namespace(
            &root,
            &object_key("tenant", "routing2")
        ));
    }

    #[test]
    fn default_concurrency_holds_one_member_back() {
        // A pair (2 members) defaults to 1 — never both at once.
        assert_eq!(group_set(None).effective_max_concurrent(2), 1);
        // Larger cohorts keep exactly one in reserve by default.
        assert_eq!(group_set(None).effective_max_concurrent(5), 4);
        assert_eq!(group_set(None).effective_max_concurrent(100), 99);
    }

    #[test]
    fn explicit_concurrency_is_clamped_below_member_count() {
        assert_eq!(group_set(Some(2)).effective_max_concurrent(5), 2);
        // Can never admit every member: clamped to members - 1.
        assert_eq!(group_set(Some(10)).effective_max_concurrent(5), 4);
        // Never zero, even if asked.
        assert_eq!(group_set(Some(0)).effective_max_concurrent(5), 1);
    }

    fn deployment(id: &str) -> DesiredDeployment {
        DesiredDeployment {
            schema: updated_contracts::assignment::RepositoryAssignment::SCHEMA,
            deployment: id.into(),
            metadata_url: "https://cdn.example/tuf/metadata/".into(),
            targets_url: "https://cdn.example/tuf/targets/".into(),
            application: ExactTarget {
                path: "app".into(),
                sha256: "1".repeat(64),
            },
            ordered_install_fallback: false,
            provider_set: ExactTarget {
                path: "providers".into(),
                sha256: "2".repeat(64),
            },
            release_root: serde_json::json!({"signed": {}, "signatures": []}),
            runtime: managed_runtime(),
        }
    }

    /// The managed runtime a nominal [`DeploymentSpec`] resolves to.
    ///
    /// Derived from [`runtime_spec`] through the real `TryFrom` conversion rather than written out
    /// a second time: the CRD spec and the signed contract carry the same policy in two type
    /// systems, and two hand-written fixtures for one nominal value are two fixtures that can
    /// disagree. This way the fixture also exercises the conversion every deployment goes through.
    pub(crate) fn managed_runtime() -> updated_contracts::assignment::ManagedRuntime {
        DesiredDeployment::try_from(deployment_spec("fixture"))
            .expect("the nominal deployment spec is valid")
            .runtime
    }

    /// The one nominal CRD runtime spec, built from the one nominal managed runtime.
    ///
    /// The three policy structs are the contract's own types now, so they are moved across rather
    /// than restated — there is no second set of nominal limits in this workspace to fall out of
    /// step with `updated_contracts::assignment::testing::runtime`.
    pub(crate) fn runtime_spec() -> RuntimeSpec {
        let updated_contracts::assignment::ManagedRuntime {
            product,
            channel,
            repository,
            storage,
            timeouts,
            install_root: _,
            inputs: _,
        } = updated_contracts::assignment::testing::runtime();
        RuntimeSpec {
            product,
            channel,
            install_root: "/opt/app".into(),
            repository,
            storage,
            timeouts,
        }
    }

    pub(crate) fn deployment_spec(id: &str) -> DeploymentSpec {
        DeploymentSpec {
            name: id.into(),
            release_repository: ReleaseRepositorySpec {
                metadata_url: "https://cdn.example/tuf/metadata/".into(),
                targets_url: "https://cdn.example/tuf/targets/".into(),
                root_json: serde_json::json!({"signed": {}, "signatures": []}).to_string(),
            },
            application: TargetSpec {
                path: "app".into(),
                sha256: "1".repeat(64),
            },
            ordered_install_fallback: false,
            provider_set: TargetSpec {
                path: "providers".into(),
                sha256: "2".repeat(64),
            },
            runtime: runtime_spec(),
        }
    }

    fn group(name: &str, labels: &[(&str, &str)]) -> ResolvedGroup {
        ResolvedGroup {
            name: name.into(),
            match_labels: labels
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
            depends_on: vec![],
            inputs: BTreeMap::new(),
            input_snapshot: None,
            deployment: deployment(name),
            max_unavailable: 1,
            emergency_correction: false,
        }
    }

    /// One bad edit quarantines exactly the groups it names — never the fleet. Each violation
    /// class (input outside dependsOn, dangling dependency, cycle membership) maps to its own
    /// groups, the healthy sibling stays plannable, and the remainder passes the pure planner's
    /// backstop validation, so `plan_reconcile` can no longer fail on wiring an operator can fix
    /// per group.
    #[test]
    fn dependency_violations_are_classified_per_group_and_spare_the_rest() {
        let mut cyclic_a = group("cycle-a", &[("g", "a")]);
        cyclic_a.depends_on = vec!["cycle-b".into()];
        let mut cyclic_b = group("cycle-b", &[("g", "b")]);
        cyclic_b.depends_on = vec!["cycle-a".into()];
        let mut dangling = group("dangling", &[("g", "d")]);
        dangling.depends_on = vec!["never-created".into()];
        let mut unwired = group("unwired", &[("g", "u")]);
        unwired.inputs = BTreeMap::from([(
            "upstream".to_string(),
            GroupOutputReference {
                group: "healthy".into(),
                output: "endpoint".into(),
            },
        )]);
        // The reference names a real group — but one this group does not depend on.
        let healthy = group("healthy", &[("g", "h")]);
        let groups = BTreeMap::from([
            ("cycle-a".to_string(), cyclic_a),
            ("cycle-b".to_string(), cyclic_b),
            ("dangling".to_string(), dangling),
            ("unwired".to_string(), unwired),
            ("healthy".to_string(), healthy),
        ]);

        let violations = dependency_violations(&groups, &BTreeSet::new());
        assert_eq!(
            violations.keys().collect::<Vec<_>>(),
            ["cycle-a", "cycle-b", "dangling", "unwired"],
            "every broken group is named, the healthy one is not"
        );
        // The survivors pass the pure planner's own gate: quarantining these groups is exactly
        // what keeps `plan_reconcile` from ever failing on dependency wiring.
        let mut remaining = groups.clone();
        remaining.retain(|name, _| !violations.contains_key(name));
        let skip: BTreeSet<String> = violations.keys().cloned().collect();
        assert!(validate_dependency_graph(&remaining, &skip).is_ok());

        // A dependency on an already-quarantined group is NOT a violation: the planner skips it,
        // holding the dependent rather than punishing it for its prerequisite's spec.
        let mut waiting = group("waiting", &[("g", "w")]);
        waiting.depends_on = vec!["broken-elsewhere".into()];
        let groups = BTreeMap::from([("waiting".to_string(), waiting)]);
        let quarantined = BTreeSet::from(["broken-elsewhere".to_string()]);
        assert!(dependency_violations(&groups, &quarantined).is_empty());
    }

    fn node(name: &str, labels: &[(&str, &str)]) -> ResolvedNode {
        ResolvedNode {
            name: name.into(),
            labels: labels
                .iter()
                .map(|(k, v)| ((*k).into(), (*v).into()))
                .collect(),
        }
    }

    /// A `kube::Client` answered by `handler` instead of by a socket: request method, path and body
    /// in, response status and body out.
    ///
    /// Everything this crate does to the cluster goes through a `kube::Api`, so the gates that
    /// matter most — which Secret may be served to a node, which subscription gets told it was
    /// deferred, whether a failed store rebuild keeps the working one — are only reachable in a
    /// test through a client. This is that client, and it records nothing itself: a handler that
    /// wants to assert on the traffic closes over its own log.
    pub(crate) fn apiserver<H>(handler: H) -> kube::Client
    where
        H: Fn(&axum::http::Method, &str, Vec<u8>) -> (axum::http::StatusCode, serde_json::Value)
            + Send
            + Sync
            + 'static,
    {
        use http_body_util::BodyExt;
        let handler = std::sync::Arc::new(handler);
        kube::Client::new(
            tower::service_fn(move |request: axum::http::Request<kube::client::Body>| {
                let handler = handler.clone();
                async move {
                    let (parts, body) = request.into_parts();
                    let bytes = body.collect().await.expect("request body").to_bytes();
                    let (status, response) =
                        handler(&parts.method, parts.uri.path(), bytes.to_vec());
                    Ok::<_, std::convert::Infallible>(
                        axum::http::Response::builder()
                            .status(status)
                            .header("content-type", "application/json")
                            .body(kube::client::Body::from(response.to_string().into_bytes()))
                            .expect("well-formed response"),
                    )
                }
            }),
            "default",
        )
    }

    /// The one nominal object destination. Fixtures that care about the bucket or prefix override
    /// those two fields; nothing else about a destination varies between them, and writing the rest
    /// out again is how three fixtures came to disagree about what "nominal" meant.
    pub(crate) fn s3_destination() -> S3Destination {
        S3Destination {
            bucket: "updates".into(),
            prefix: String::new(),
            region: "us-east-1".into(),
            credentials_secret_ref: None,
            endpoint: None,
            public_endpoint: None,
        }
    }

    pub(crate) fn repository_storage() -> RepositoryStorage {
        RepositoryStorage {
            bucket: "updates".into(),
            region: "us-east-1".into(),
            credentials_secret_ref: None,
            endpoint: None,
            public_endpoint: None,
        }
    }

    /// The one nominal repository spec. Every fixture in this crate starts here and overrides only
    /// what its test is actually about.
    pub(crate) fn repository() -> UpdateRepositorySpec {
        UpdateRepositorySpec {
            default_deployment: deployment_spec("default"),
            signing_secret_ref: LocalSecretReference {
                name: "tuf-signing-keys".into(),
            },
            enrollment: EnrollmentSpec {
                labels: BTreeMap::new(),
            },
            s3: repository_storage(),
            assignment_prefix: "assignments".into(),
            state_max_shards: 8,
            admission_policy_ref: None,
        }
    }

    #[test]
    fn agent_documents_point_to_the_exact_selected_config_bundle() {
        let node_groups =
            BTreeMap::from([("a".into(), "edge".into()), ("b".into(), "default".into())]);
        let node_deployments = BTreeMap::from([
            ("a".into(), deployment("edge")),
            ("b".into(), deployment("default")),
        ]);
        let plan = build_publication_plan(&repository(), node_groups, node_deployments).unwrap();
        assert_eq!(plan.node_groups["a"], "edge");
        assert_eq!(plan.node_groups["b"], "default");
        let node = plan
            .targets
            .iter()
            .find(|t| t.path == "assignments/agents/a.json")
            .unwrap();
        let assignment: updated_contracts::artifact::AgentDocument =
            serde_json::from_slice(&node.bytes).unwrap();
        let config = plan
            .targets
            .iter()
            .find(|target| target.path == assignment.config.path)
            .unwrap();
        assert_eq!(assignment.config.sha256, config.sha256);
        assert_ne!(node.bytes, config.bytes);
    }

    #[test]
    fn a_group_may_not_claim_the_reserved_default_name() {
        // `default` is the sentinel for "matched no group", and the domain planner overwrites every
        // node routed to it with the repository's unthrottled default deployment. A real group
        // wearing that name would have its throttled, health-gated rollout silently replaced.
        let error = resolve_node_groups(
            [group("default", &[("tier", "default")])],
            [node("node", &[("tier", "default")])],
        )
        .unwrap_err();
        assert_eq!(error, PlanError::ReservedGroupName);
    }

    #[test]
    fn overlapping_non_default_groups_fail_closed() {
        let error = resolve_node_groups(
            [
                group("a", &[("role", "edge")]),
                group("b", &[("role", "edge")]),
            ],
            [node("node", &[("role", "edge")])],
        )
        .unwrap_err();
        assert_eq!(
            error,
            PlanError::AmbiguousNode {
                node: "node".into(),
                groups: vec!["a".into(), "b".into()]
            }
        );
    }

    #[test]
    fn rollout_planning_uses_the_one_shared_node_name_grammar() {
        for invalid in ["NODE-0", "node_0", "node..0"] {
            assert_eq!(
                resolve_node_groups(
                    [group("edge", &[("role", "edge")])],
                    [node(invalid, &[("role", "edge")])],
                ),
                Err(PlanError::InvalidNodeName),
                "{invalid:?} must not enter rollout planning"
            );
        }
        assert_eq!(
            resolve_node_groups(
                [group("edge", &[("role", "edge")])],
                [node("rack-1.node-0", &[("role", "edge")])],
            )
            .unwrap()["rack-1.node-0"],
            "edge"
        );
    }

    #[test]
    fn dependency_graph_rejects_missing_groups_and_cycles() {
        let mut groups = BTreeMap::from([
            ("a".into(), group("a", &[("role", "a")])),
            ("b".into(), group("b", &[("role", "b")])),
        ]);
        groups.get_mut("b").unwrap().depends_on = vec!["missing".into()];
        assert_eq!(
            validate_dependency_graph(&groups, &BTreeSet::new()),
            Err(PlanError::MissingDependency {
                group: "b".into(),
                dependency: "missing".into(),
            })
        );

        groups.get_mut("a").unwrap().depends_on = vec!["b".into()];
        groups.get_mut("b").unwrap().depends_on = vec!["a".into()];
        assert_eq!(
            validate_dependency_graph(&groups, &BTreeSet::new()),
            Err(PlanError::DependencyCycle(vec![
                "a".into(),
                "b".into(),
                "a".into(),
            ]))
        );

        groups.get_mut("a").unwrap().depends_on.clear();
        groups.get_mut("b").unwrap().depends_on.clear();
        groups.get_mut("b").unwrap().inputs.insert(
            "leader".into(),
            GroupOutputReference {
                group: "a".into(),
                output: "endpoint".into(),
            },
        );
        assert_eq!(
            validate_dependency_graph(&groups, &BTreeSet::new()),
            Err(PlanError::InvalidDependencyInput {
                group: "b".into(),
                input: "leader".into(),
            })
        );
    }

    /// An input name is a published output filename, which the shared snapshot contract bounds at
    /// 128 bytes.
    /// Admitting one against the traversal rule alone accepted an over-long name here and detonated
    /// hours later: `resolve_one` writes it into `runtime.inputs` the moment the producer reports
    /// healthy, and from then on every reconcile for the whole repository failed to build a
    /// publication at all — no group got another generation and no agent could enroll.
    #[test]
    fn a_dependency_input_name_the_signed_contract_refuses_is_rejected_at_admission() {
        let mut groups = BTreeMap::from([
            ("a".into(), group("a", &[("role", "a")])),
            ("b".into(), group("b", &[("role", "b")])),
        ]);
        groups.get_mut("b").unwrap().depends_on = vec!["a".into()];
        let over_long = "x".repeat(129);
        groups.get_mut("b").unwrap().inputs.insert(
            over_long.clone(),
            GroupOutputReference {
                group: "a".into(),
                output: "endpoint".into(),
            },
        );
        assert_eq!(
            validate_dependency_graph(&groups, &BTreeSet::new()),
            Err(PlanError::InvalidDependencyInput {
                group: "b".into(),
                input: over_long.clone(),
            })
        );
        assert!(!is_output_name(&over_long));
        assert!(is_output_name(&"x".repeat(128)));
        assert!(is_output_name("endpoint"));
        assert!(!is_output_name(""));
        assert!(!is_output_name("a/b"));
    }

    /// The manifest bounds the input COUNT at 64 as firmly as it bounds each name at 128 bytes, and
    /// 65 distinct names may all reference one producer's single output. Admitting the count only
    /// when `ManagedRuntime::validate` sees the RESOLVED map time-bombed on the producer first
    /// reporting healthy: `deployment_identity` returned None from then on and
    /// `build_publication_plan` failed repository-wide, every pass.
    #[test]
    fn more_dependency_inputs_than_the_signed_manifest_admits_are_rejected_at_admission() {
        let mut groups = BTreeMap::from([
            ("a".into(), group("a", &[("role", "a")])),
            ("b".into(), group("b", &[("role", "b")])),
        ]);
        groups.get_mut("b").unwrap().depends_on = vec!["a".into()];
        let limit = updated_contracts::dataflow::FileSnapshot::MAX_FILES;
        for index in 0..limit {
            groups.get_mut("b").unwrap().inputs.insert(
                format!("peer{index}"),
                GroupOutputReference {
                    group: "a".into(),
                    output: "endpoint".into(),
                },
            );
        }
        assert_eq!(validate_dependency_graph(&groups, &BTreeSet::new()), Ok(()));

        groups.get_mut("b").unwrap().inputs.insert(
            format!("peer{limit}"),
            GroupOutputReference {
                group: "a".into(),
                output: "endpoint".into(),
            },
        );
        assert_eq!(
            validate_dependency_graph(&groups, &BTreeSet::new()),
            Err(PlanError::TooManyDependencyInputs {
                group: "b".into(),
                inputs: limit + 1,
            })
        );
    }

    /// A quarantined group is present-but-frozen, not missing. Reading it as missing let one typo'd
    /// digest in one `UpdateGroup` that another group depends on abort publication for the ENTIRE
    /// repository: no generation signed at all, so every group stopped receiving updates and no
    /// agent could enroll until an operator fixed the typo.
    #[test]
    fn a_dependency_that_is_only_quarantined_does_not_abort_the_whole_generation() {
        let mut groups = BTreeMap::from([("join".into(), group("join", &[("role", "join")]))]);
        groups.get_mut("join").unwrap().depends_on = vec!["initialize".into()];
        assert_eq!(
            validate_dependency_graph(&groups, &BTreeSet::new()),
            Err(PlanError::MissingDependency {
                group: "join".into(),
                dependency: "initialize".into(),
            })
        );

        // Quarantine is keyed on the group being quarantined, NOT on it having a durable pin: the
        // likeliest way to reach this state is an operator CREATING a group with a typo'd digest,
        // which was never admitted and therefore has no pin to hold.
        let quarantined = BTreeSet::from(["initialize".to_string()]);
        assert_eq!(validate_dependency_graph(&groups, &quarantined), Ok(()));
    }

    #[test]
    fn node_group_resolution_uses_the_shared_safe_component_invariant() {
        for name in ["", ".", "..", "a/b", "a\\b", "a:b", "a\0b"] {
            let mut invalid = node("placeholder", &[("role", "edge")]);
            invalid.name = name.into();
            assert_eq!(
                resolve_node_groups([group("edge", &[("role", "edge")])], [invalid]),
                Err(PlanError::InvalidNodeName),
                "{name:?} must not enter assignment path construction"
            );
        }
    }

    #[test]
    fn output_is_deterministic_across_input_order() {
        let mappings =
            BTreeMap::from([("a".into(), "edge".into()), ("b".into(), "default".into())]);
        let deployments = BTreeMap::from([
            ("a".into(), deployment("edge")),
            ("b".into(), deployment("default")),
        ]);
        let first =
            build_publication_plan(&repository(), mappings.clone(), deployments.clone()).unwrap();
        let second = build_publication_plan(
            &repository(),
            mappings.into_iter().rev().collect(),
            deployments.into_iter().rev().collect(),
        )
        .unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn thousand_nodes_share_one_content_addressed_config() {
        let mappings: BTreeMap<String, String> = (0..1_000)
            .map(|index| (format!("node-{index:04}"), "edge".into()))
            .collect();
        let deployments = mappings
            .keys()
            .map(|node| (node.clone(), deployment("edge")))
            .collect();

        let first = build_publication_plan(&repository(), mappings.clone(), deployments).unwrap();
        let second = build_publication_plan(
            &repository(),
            mappings.into_iter().rev().collect(),
            first
                .node_groups
                .keys()
                .rev()
                .map(|node| (node.clone(), deployment("edge")))
                .collect(),
        )
        .unwrap();

        assert_eq!(first, second);
        assert_eq!(first.node_groups.len(), 1_000);
        assert_eq!(first.targets.len(), 1_001);
        assert_eq!(
            first
                .targets
                .iter()
                .filter(|target| target.path.contains("/configs/"))
                .count(),
            1
        );
    }
}
