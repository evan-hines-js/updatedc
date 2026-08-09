//! Environment-neutral desired-state compiler for `updated`, hosted on Kubernetes.
//!
//! Custom `UpdateAgent` resources represent agents anywhere. Group selectors determine
//! which exact config bundle each minimal agent document references.

use std::collections::{BTreeMap, BTreeSet};

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use updated_contracts::artifact::TargetReference as ExactTarget;
use updated_contracts::assignment::RepositoryAssignment as DesiredDeployment;
use updated_contracts::enrollment::{EnrollmentBundle, InitialSignedConfiguration};

pub mod alerts;
pub(crate) mod domain;
pub mod evidence;
pub mod gateway;
pub mod join;
pub mod metrics;
pub mod publisher;
pub(crate) mod rollout;
pub mod runtime;
pub mod served;
pub mod subscription;
pub mod window;

pub use window::{CalendarEntry, RolloutWindow, Weekday};

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
    /// Telemetry write location signed into each agent's assignment. Rollout safety requires
    /// attributable node feedback, so every deployment must provide it.
    pub report_url: String,
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

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeSpec {
    #[serde(default)]
    pub mode: RuntimeModeSpec,
    pub product: String,
    pub channel: String,
    pub install_root: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub secrets: Vec<SecretReferenceSpec>,
    pub repository: RepositoryLimitsSpec,
    pub storage: StorageSpec,
    pub timeouts: TimeoutsSpec,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretReferenceSpec {
    pub environment: String,
    /// Secret in the control-plane namespace, which the gateway serves to the assigned node at
    /// `/v1/node/secrets` ONLY if it carries the label `updated.dev/fleet-distributable: "true"`.
    /// Writing this field needs `update` on `updategroups.updated.dev`, which does not imply `get`
    /// on Secrets, so the opt-in deliberately lives on the Secret: naming one here is a request,
    /// never a grant. The control plane's own key material (signing keys, object-store credentials,
    /// cert-manager-issued certificates, and the enrollment Secrets it owns) is refused whatever it
    /// is labelled.
    pub secret: String,
    pub key: String,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeModeSpec {
    #[default]
    Managed,
    ProviderManaged,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryLimitsSpec {
    pub metadata_limit: u64,
    pub target_limit: u64,
    pub transport_timeout_seconds: u64,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StorageSpec {
    pub inactive_releases: usize,
    pub inactive_providers: usize,
    pub inactive_supervisors: usize,
    pub inactive_bytes: u64,
    pub inactive_repository_caches: usize,
}
#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TimeoutsSpec {
    pub check_interval_seconds: u64,
    pub health_grace_seconds: u64,
    pub health_successes: u32,
    pub health_interval_seconds: u64,
    pub refresh_retry_seconds: u64,
    pub confirmation_window_seconds: u64,
    pub supervisor_check_interval_seconds: u64,
    /// Upper bound (seconds) on the managed drain hold; `None` or `0` = no hold (stop immediately),
    /// `Some(n)` = wait up to `n`. Never an indefinite wait. See
    /// [`updated_contracts::assignment::ManagedTimeouts::drain_hold_seconds`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain_hold_seconds: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct TargetSpec {
    pub path: String,
    pub sha256: String,
}

impl TryFrom<DeploymentSpec> for DesiredDeployment {
    type Error = String;

    fn try_from(value: DeploymentSpec) -> Result<Self, Self::Error> {
        let release_root = serde_json::from_str(&value.release_repository.root_json)
            .map_err(|error| format!("releaseRepository.rootJson is invalid JSON: {error}"))?;
        let desired = Self {
            schema: updated_contracts::assignment::RepositoryAssignment::SCHEMA,
            deployment: value.name,
            metadata_url: value.release_repository.metadata_url,
            targets_url: value.release_repository.targets_url,
            report_url: Some(value.report_url),
            application: ExactTarget {
                path: value.application.path,
                sha256: value.application.sha256,
            },
            ordered_install_fallback: value.ordered_install_fallback,
            provider_set: ExactTarget {
                path: value.provider_set.path,
                sha256: value.provider_set.sha256,
            },
            release_root,
            runtime: updated_contracts::assignment::ManagedRuntime {
                mode: match value.runtime.mode {
                    RuntimeModeSpec::Managed => updated_contracts::assignment::RuntimeMode::Managed,
                    RuntimeModeSpec::ProviderManaged => {
                        updated_contracts::assignment::RuntimeMode::ProviderManaged
                    }
                },
                product: value.runtime.product,
                channel: value.runtime.channel,
                install_root: value.runtime.install_root.into(),
                args: value.runtime.args,
                secrets: value
                    .runtime
                    .secrets
                    .into_iter()
                    .map(|reference| updated_contracts::assignment::SecretReference {
                        environment: reference.environment,
                        secret: reference.secret,
                        key: reference.key,
                    })
                    .collect(),
                inputs: BTreeMap::new(),
                repository: updated_contracts::assignment::ManagedRepositoryLimits {
                    metadata_limit: value.runtime.repository.metadata_limit,
                    target_limit: value.runtime.repository.target_limit,
                    transport_timeout_seconds: value.runtime.repository.transport_timeout_seconds,
                },
                storage: updated_contracts::assignment::ManagedStorage {
                    inactive_releases: value.runtime.storage.inactive_releases,
                    inactive_providers: value.runtime.storage.inactive_providers,
                    inactive_supervisors: value.runtime.storage.inactive_supervisors,
                    inactive_bytes: value.runtime.storage.inactive_bytes,
                    inactive_repository_caches: value.runtime.storage.inactive_repository_caches,
                },
                timeouts: updated_contracts::assignment::ManagedTimeouts {
                    check_interval_seconds: value.runtime.timeouts.check_interval_seconds,
                    health_grace_seconds: value.runtime.timeouts.health_grace_seconds,
                    health_successes: value.runtime.timeouts.health_successes,
                    health_interval_seconds: value.runtime.timeouts.health_interval_seconds,
                    refresh_retry_seconds: value.runtime.timeouts.refresh_retry_seconds,
                    confirmation_window_seconds: value.runtime.timeouts.confirmation_window_seconds,
                    supervisor_check_interval_seconds: value
                        .runtime
                        .timeouts
                        .supervisor_check_interval_seconds,
                    drain_hold_seconds: value.runtime.timeouts.drain_hold_seconds,
                },
            },
        };
        desired.validate()?;
        Ok(desired)
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LabelSelector {
    #[serde(default)]
    pub match_labels: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateGroupStatus {
    pub observed_generation: Option<i64>,
    pub matched_agents: Option<u32>,
    pub published_digest: Option<String>,
    /// How many of this group's agents the operator is holding (`UpdateAgent.spec.hold`). A
    /// forgotten hold must be a visible condition, not a mystery, so the count is projected here
    /// on every reconcile. Serialized even when `None`: this status travels as a merge patch, and
    /// the explicit null is what deletes a stale count when a writer (quarantine, failure) cannot
    /// compute one.
    pub held_agents: Option<u32>,
    #[serde(default)]
    pub conditions: Vec<ResourceCondition>,
}

/// A blast-radius throttle over a set of [`UpdateGroup`]s. Membership is label-based
/// like everything else: `selector` matches `UpdateGroup` **metadata labels** (not agent
/// labels), so a set can gather any number of member groups. The control plane rolls no
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
    /// A cordoned node is published to the healthproxy's endpoint projection as drained regardless
    /// of its report — the same drained state a stale report produces — while the application
    /// keeps running, the node keeps reporting, and the supervisor stays entirely unaware. Rollout
    /// accounting treats it as absent (like a departed node) rather than unhealthy, so a cordon
    /// neither eats the group's availability budget nor wedges an in-flight rollout. Orthogonal to
    /// [`hold`](Self::hold): a node can be held but serving, or cordoned but updatable.
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
    /// The node's pinned public key (hex uncompressed EC point), set at enrollment from its CSR —
    /// the same key that certifies its mTLS leaf. Rollout planning verifies the node's *signed*
    /// telemetry against this, so a report is attributable end-to-end (node → planner), not merely
    /// authenticated on the write hop. `None` for a manual or pre-signing agent, whose reports then
    /// fail verification and so fail closed: the planner treats such a node as BLIND (see
    /// `rollout::NodeEvidence`) — never counted healthy, never counted as holding its group back —
    /// and stages it on what was published to it, so its group stays throttled and stays
    /// updatable without any unverifiable report ever being believed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AgentIdentityKind {
    /// Offline provisioning: the operator declares the agent and exports its immutable enrollment
    /// Secret out of band. The machine never talks to `/enroll`, so this identity is NEVER
    /// completable over the shared fleet bootstrap certificate.
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
    pub enrollment_secret_ref: Option<LocalSecretReference>,
    /// The version the node last reported it is actually running, from its rollout telemetry.
    /// This is the control plane's authoritative view of a node's running version — no
    /// consumer probes the managed app, so it works for any app kind (a Rust service, a real
    /// Magnolia CMS, anything). `None` until the node has reported at least once.
    pub reported_version: Option<String>,
    /// Whether the node last reported itself settled and healthy on its assignment.
    pub reported_ready: Option<bool>,
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
    /// Secret in the same namespace containing root, targets, snapshot, and timestamp
    /// private keys. The controller never stores private keys in CRD status.
    pub signing_secret_ref: LocalSecretReference,
    /// Trusted labels applied to dynamic registrations. Enrollment is authenticated by mutual
    /// TLS at the gateway (a cert-manager-issued server cert + fleet client CA, mounted), so
    /// there is no shared secret here.
    pub enrollment: EnrollmentSpec,
    pub s3: S3Destination,
    /// Prefix below the TUF targets namespace at which assignments are published.
    #[serde(default = "default_assignment_prefix")]
    pub assignment_prefix: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct EnrollmentSpec {
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
pub struct LocalSecretReference {
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

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
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
    /// Computed each reconcile after authentic producer reports are resolved.
    pub inputs_ready: bool,
    pub deployment: DesiredDeployment,
    pub max_unavailable: usize,
    /// [`UpdateGroupSpec::emergency_correction`] — the operator's stated intent that `deployment`
    /// is an emergency correction, which exempts its admission from the governing set's schedule.
    pub emergency_correction: bool,
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
    /// More dependency inputs than the signed output manifest admits, so the group's resolved
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

/// Whether a name may be a key of a signed output manifest — the grammar dependency inputs must
/// satisfy, asked of the contract itself rather than restated here.
///
/// A dependency input name becomes a key of `deployment.runtime.inputs`, which
/// `RepositoryAssignment::validate` runs through `OutputManifest::validate` at publication time.
/// Admitting an input name against the weaker traversal rule alone let an over-long one (the
/// manifest bounds names at 128 bytes) through admission and detonate later: nothing is written
/// into `runtime.inputs` until the producer reports healthy, and from that moment every reconcile
/// for the whole repository failed to build a publication at all — no group ever got another
/// generation, and no new agent could enroll. One grammar, checked where the name is accepted.
fn is_output_name(name: &str) -> bool {
    updated_contracts::telemetry::OutputManifest {
        schema: updated_contracts::telemetry::OutputManifest::SCHEMA,
        values: BTreeMap::from([(
            name.to_string(),
            updated_contracts::telemetry::OutputValue::String {
                value: String::new(),
            },
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
        if groups[name].inputs.len() > updated_contracts::telemetry::OutputManifest::MAX_VALUES {
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

/// The pseudo-group a node that matched no `UpdateGroup` routes to; it receives the repository's
/// `default_deployment` directly and is never throttled. Reserved: a real `UpdateGroup` claiming
/// this name would have its own throttled, gated rollout silently replaced by that fleet-wide
/// switch, so [`resolve_node_groups`] refuses it outright.
pub const DEFAULT_GROUP: &str = "default";

/// Whether this node could ever report — i.e. whether its name survives a round trip through the
/// telemetry path grammar, which is stricter than the traversal rule placement gates on: a report
/// is a URL segment, so it additionally forbids `.`, `%`, `?` and `#`.
///
/// Asked of the grammar itself rather than restated, so the name a node is admitted under and the
/// name the gateway recovers from `/telemetry/<node>.json` can never drift apart. A node admitted
/// under a name only one of the two accepts is placed, published, and enrolled, and then has every
/// report it ever sends refused with a 404 — permanently Silent, spending its group's
/// `maxUnavailable` forever.
pub(crate) fn node_name_is_reportable(name: &str) -> bool {
    let path = format!(
        "{}{name}.json",
        updated_contracts::telemetry::REPORT_PATH_PREFIX
    );
    updated_contracts::telemetry::node_from_path(&path) == Some(name)
}

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
        if !updated_contracts::path::is_safe_component(&name) || node_groups.contains_key(&name) {
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
    let mut references = BTreeMap::new();
    for deployment in node_deployments.values() {
        let bytes = canonical_json(deployment)?;
        let id = updated::hash::sha256_bytes(&bytes);
        if references.contains_key(&id) {
            continue;
        }
        let config = target(
            updated_contracts::telemetry::config_object_key(prefix, &id),
            bytes,
        );
        references.insert(
            id,
            ExactTarget {
                path: config.path.clone(),
                sha256: config.sha256.clone(),
            },
        );
        targets.push(config);
    }
    let mut node_assignments = BTreeMap::new();
    for (node, deployment) in &node_deployments {
        let id = updated::hash::sha256_bytes(&canonical_json(deployment)?);
        let assignment = updated_contracts::artifact::AgentDocument {
            schema: 1,
            config: references[&id].clone(),
        };
        let bytes = serde_json::to_vec(&assignment)
            .map_err(|error| PlanError::Serialize(error.to_string()))?;
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
    canonical_json(value)
        .ok()
        .map(|bytes| updated::hash::sha256_bytes(&bytes))
}

fn canonical_json(value: &DesiredDeployment) -> Result<Vec<u8>, PlanError> {
    value.validate().map_err(PlanError::InvalidDeployment)?;
    serde_json::to_vec(value).map_err(|error| PlanError::Serialize(error.to_string()))
}

fn target(path: String, bytes: Vec<u8>) -> PublicationTarget {
    let sha256 = updated::hash::sha256_bytes(&bytes);
    PublicationTarget {
        path,
        bytes,
        sha256,
    }
}

fn publication_digest(targets: &[PublicationTarget]) -> String {
    let mut digest = updated::hash::Sha256Hasher::new();
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

/// Upper bound on any single repository object the control plane reads back into memory: a signed
/// metadata document, an assignment, a managed configuration, or a node report. All are small, and
/// all are bounded at *write* time (the gateway caps request bodies) — but the bucket is not
/// exclusively ours, so a direct writer must not be able to make a reconcile or an `/enroll`
/// response allocate without limit. Generous relative to any legitimate document.
pub(crate) const OBJECT_BYTES_LIMIT: u64 = 8 * 1024 * 1024;

// The projection's shared wire bound is the same ceiling, so the writer's read-compare probe and
// the healthproxy's fetch accept exactly the same documents.
const _: () =
    assert!(updated_contracts::endpoints::MAX_PROJECTION_BYTES as u64 == OBJECT_BYTES_LIMIT);

/// Read one object fully into memory, refusing anything larger than [`OBJECT_BYTES_LIMIT`]. The
/// size is checked from the store's own metadata before a byte is buffered, so an oversized object
/// costs a `head`-equivalent rather than the allocation. The single bounded read every
/// control-plane object load goes through, so the `/enroll` resolution path and the rollout
/// telemetry read cannot drift apart on it.
pub(crate) async fn read_object_bounded(
    store: &dyn object_store::ObjectStore,
    key: &object_store::path::Path,
) -> Result<Vec<u8>, object_store::Error> {
    let result = store.get(key).await?;
    if result.meta.size > OBJECT_BYTES_LIMIT {
        return Err(object_store::Error::Generic {
            store: "updatec",
            source: format!(
                "object {key} is {} bytes, over the {OBJECT_BYTES_LIMIT}-byte limit",
                result.meta.size
            )
            .into(),
        });
    }
    Ok(result.bytes().await?.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn group_set(max_concurrent: Option<u32>) -> UpdateGroupSetSpec {
        UpdateGroupSetSpec {
            selector: LabelSelector::default(),
            max_concurrent,
            rollout_windows: vec![],
            calendar: vec![],
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
            report_url: Some("https://control.example/v1/telemetry".into()),
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

    pub(crate) fn managed_runtime() -> updated_contracts::assignment::ManagedRuntime {
        updated_contracts::assignment::ManagedRuntime {
            mode: updated_contracts::assignment::RuntimeMode::Managed,
            product: "app".into(),
            channel: "stable".into(),
            install_root: "/opt/app".into(),
            args: vec![],
            secrets: vec![],
            inputs: BTreeMap::new(),
            repository: updated_contracts::assignment::ManagedRepositoryLimits {
                metadata_limit: 1_048_576,
                target_limit: 536_870_912,
                transport_timeout_seconds: 30,
            },
            storage: updated_contracts::assignment::ManagedStorage {
                inactive_releases: 2,
                inactive_providers: 2,
                inactive_supervisors: 2,
                inactive_bytes: 1_073_741_824,
                inactive_repository_caches: 2,
            },
            timeouts: updated_contracts::assignment::ManagedTimeouts {
                check_interval_seconds: 15,
                health_grace_seconds: 30,
                health_successes: 2,
                health_interval_seconds: 1,
                refresh_retry_seconds: 5,
                confirmation_window_seconds: 120,
                supervisor_check_interval_seconds: 3600,
                drain_hold_seconds: Some(0),
            },
        }
    }

    pub(crate) fn runtime_spec() -> RuntimeSpec {
        RuntimeSpec {
            mode: RuntimeModeSpec::Managed,
            product: "app".into(),
            channel: "stable".into(),
            install_root: "/opt/app".into(),
            args: vec![],
            secrets: vec![],
            repository: RepositoryLimitsSpec {
                metadata_limit: 1_048_576,
                target_limit: 536_870_912,
                transport_timeout_seconds: 30,
            },
            storage: StorageSpec {
                inactive_releases: 2,
                inactive_providers: 2,
                inactive_supervisors: 2,
                inactive_bytes: 1_073_741_824,
                inactive_repository_caches: 2,
            },
            timeouts: TimeoutsSpec {
                check_interval_seconds: 15,
                health_grace_seconds: 30,
                health_successes: 2,
                health_interval_seconds: 1,
                refresh_retry_seconds: 5,
                confirmation_window_seconds: 120,
                supervisor_check_interval_seconds: 3600,
                drain_hold_seconds: Some(0),
            },
        }
    }

    pub(crate) fn deployment_spec(id: &str) -> DeploymentSpec {
        DeploymentSpec {
            name: id.into(),
            report_url: "https://control.example/v1/telemetry".into(),
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
            inputs_ready: true,
            deployment: deployment(name),
            max_unavailable: 1,
            emergency_correction: false,
        }
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

    pub(crate) fn repository() -> UpdateRepositorySpec {
        UpdateRepositorySpec {
            default_deployment: deployment_spec("default"),
            signing_secret_ref: LocalSecretReference {
                name: "tuf-signing-keys".into(),
            },
            enrollment: EnrollmentSpec {
                labels: BTreeMap::new(),
            },
            s3: S3Destination {
                bucket: "updates".into(),
                prefix: String::new(),
                region: "us-east-1".into(),
                credentials_secret_ref: None,
                endpoint: None,
            },
            assignment_prefix: "assignments".into(),
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

    /// An input name is a key of the SIGNED output manifest, which bounds names at 128 bytes.
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
        let limit = updated_contracts::telemetry::OutputManifest::MAX_VALUES;
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

    /// Placement and telemetry must agree on what a node may be called. A dot is a legal Kubernetes
    /// name and passes the traversal rule, but the gateway recovers the node from
    /// `/telemetry/<node>.json` and refuses one — so such an agent would be placed, published and
    /// enrolled, and then 404 on every report for the life of the machine: permanently Silent,
    /// spending its group's `maxUnavailable` and blocking every dependent group.
    #[test]
    fn a_node_name_the_telemetry_path_refuses_is_not_reportable() {
        assert!(node_name_is_reportable("web-prod-01"));
        assert!(node_name_is_reportable("v1_2_3"));
        assert!(!node_name_is_reportable("web.prod"));
        assert!(!node_name_is_reportable("web%prod"));
        assert!(!node_name_is_reportable("web?prod"));
        assert!(!node_name_is_reportable("web#prod"));
        assert!(!node_name_is_reportable("../escape"));
        assert!(!node_name_is_reportable(""));
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
