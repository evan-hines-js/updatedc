//! Environment-neutral desired-state compiler for `updated`, hosted on Kubernetes.
//!
//! Custom `UpdateAgent` resources represent agents anywhere. Group selectors determine
//! which exact config bundle each minimal agent document references.

use std::collections::BTreeMap;

use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use updated::config::{
    RepositoryAssignment as DesiredDeployment, TargetReference as ExactTarget,
};
pub use updated::enrollment::{EnrollmentBundle, InitialSignedConfiguration};

pub(crate) mod domain;
pub mod gateway;
pub mod join;
pub mod publisher;
pub(crate) mod rollout;
pub mod runtime;
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
    pub deployment: DeploymentSpec,
    /// Maximum unavailable agents while this group changes deployment. This is group rollout
    /// policy, deliberately outside `deployment` so changing it does not change the signed
    /// assignment identity. Defaults to one; zero is rejected during reconciliation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub max_unavailable: Option<usize>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentSpec {
    pub name: String,
    pub release_repository: ReleaseRepositorySpec,
    pub application: TargetSpec,
    /// Signed opt-in to first-install ordered fallback (see
    /// [`updated::config::RepositoryAssignment::ordered_install_fallback`]). Defaults
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
    pub product: String,
    pub channel: String,
    pub install_root: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub health_checks: Vec<HealthCheckSpec>,
    pub repository: RepositoryLimitsSpec,
    pub storage: StorageSpec,
    pub timeouts: TimeoutsSpec,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum HealthCheckKindSpec {
    Startup,
    Readiness,
    Liveness,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HealthCheckSpec {
    pub kind: HealthCheckKindSpec,
    pub url: String,
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
    pub retry_after_seconds: u64,
    pub refresh_retry_seconds: u64,
    pub confirmation_window_seconds: u64,
    pub supervisor_check_interval_seconds: u64,
    /// Upper bound (seconds) on the managed drain hold; `None` = wait indefinitely for the
    /// intermediary's drain acknowledgement (only sound when externally managed). See
    /// [`updated::config::ManagedTimeouts::drain_hold_seconds`].
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
            schema: 2,
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
            runtime: updated::config::ManagedRuntime {
                product: value.runtime.product,
                channel: value.runtime.channel,
                install_root: value.runtime.install_root.into(),
                args: value.runtime.args,
                health_checks: value
                    .runtime
                    .health_checks
                    .into_iter()
                    .map(|check| updated::config::ManagedHealthCheck {
                        kind: match check.kind {
                            HealthCheckKindSpec::Startup => {
                                updated::config::HealthCheckKind::Startup
                            }
                            HealthCheckKindSpec::Readiness => {
                                updated::config::HealthCheckKind::Readiness
                            }
                            HealthCheckKindSpec::Liveness => {
                                updated::config::HealthCheckKind::Liveness
                            }
                        },
                        url: check.url,
                    })
                    .collect(),
                repository: updated::config::ManagedRepositoryLimits {
                    metadata_limit: value.runtime.repository.metadata_limit,
                    target_limit: value.runtime.repository.target_limit,
                    transport_timeout_seconds: value.runtime.repository.transport_timeout_seconds,
                },
                storage: updated::config::ManagedStorage {
                    inactive_releases: value.runtime.storage.inactive_releases,
                    inactive_providers: value.runtime.storage.inactive_providers,
                    inactive_supervisors: value.runtime.storage.inactive_supervisors,
                    inactive_bytes: value.runtime.storage.inactive_bytes,
                    inactive_repository_caches: value.runtime.storage.inactive_repository_caches,
                },
                timeouts: updated::config::ManagedTimeouts {
                    check_interval_seconds: value.runtime.timeouts.check_interval_seconds,
                    health_grace_seconds: value.runtime.timeouts.health_grace_seconds,
                    health_successes: value.runtime.timeouts.health_successes,
                    health_interval_seconds: value.runtime.timeouts.health_interval_seconds,
                    retry_after_seconds: value.runtime.timeouts.retry_after_seconds,
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
    /// Member groups settled on their desired deployment (all agents report it, healthy).
    #[serde(default)]
    pub settled: Vec<String>,
    /// Member groups also claimed by another set, safely rolled up (admitted only when
    /// every governing set has a slot).
    #[serde(default)]
    pub shared: Vec<String>,
    #[serde(default)]
    pub conditions: Vec<ResourceCondition>,
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
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AgentIdentity {
    pub kind: AgentIdentityKind,
    /// Present only for controller-created dynamic inventory. It binds retries to the
    /// nonce generated and durably stored by that installation.
    pub registration_sha256: Option<String>,
    /// The node's pinned public key (hex uncompressed EC point), set at enrollment from its CSR —
    /// the same key that certifies its mTLS leaf. Rollout planning verifies the node's *signed*
    /// telemetry against this, so a report is attributable end-to-end (node → planner), not merely
    /// authenticated on the write hop. `None` for a manual or pre-signing agent, whose reports then
    /// fail verification and so fail closed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AgentIdentityKind {
    Manual,
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

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRepositoryStatus {
    pub observed_generation: Option<i64>,
    pub published_digest: Option<String>,
    pub agent_count: Option<u32>,
    #[serde(default)]
    pub conditions: Vec<ResourceCondition>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
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
    pub digest: String,
}

/// An `UpdateGroup` after Kubernetes metadata has been combined with its spec.
#[derive(Clone, Debug)]
pub struct ResolvedGroup {
    pub name: String,
    pub match_labels: BTreeMap<String, String>,
    pub deployment: DesiredDeployment,
    pub max_unavailable: usize,
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
    DuplicateNode(String),
    AmbiguousNode { node: String, groups: Vec<String> },
    InvalidNodeName,
    InvalidPrefix,
    InvalidDeployment(String),
    NodeDeploymentMismatch,
    Serialize(String),
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
        if indexed.insert(name.clone(), group).is_some() {
            return Err(PlanError::DuplicateGroup(name));
        }
    }
    let mut node_groups = BTreeMap::new();
    for node in nodes {
        let name = node.name;
        if name.is_empty()
            || name.contains(['/', '\\', ':'])
            || name.chars().any(char::is_control)
            || node_groups.contains_key(&name)
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
            [] => "default".to_string(),
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
    if prefix.is_empty()
        || prefix
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || prefix.contains(['\\', ':'])
        || prefix.chars().any(char::is_control)
    {
        return Err(PlanError::InvalidPrefix);
    }
    if node_groups.keys().ne(node_deployments.keys()) {
        return Err(PlanError::NodeDeploymentMismatch);
    }
    let mut targets = Vec::new();
    let mut references = BTreeMap::new();
    for deployment in node_deployments.values() {
        let bytes = canonical_json(deployment)?;
        let id = hex_digest(&bytes);
        if references.contains_key(&id) {
            continue;
        }
        let config = target(format!("{prefix}/configs/{id}.json"), bytes);
        references.insert(
            id,
            ExactTarget {
                path: config.path.clone(),
                sha256: config.sha256.clone(),
            },
        );
        targets.push(config);
    }
    for (node, deployment) in &node_deployments {
        let id = hex_digest(&canonical_json(deployment)?);
        let assignment = updated::config::AgentDocument {
            schema: 1,
            config: references[&id].clone(),
            status: None,
        };
        let bytes = serde_json::to_vec(&assignment)
            .map_err(|error| PlanError::Serialize(error.to_string()))?;
        targets.push(target(format!("{prefix}/agents/{node}.json"), bytes));
    }
    targets.sort_by(|a, b| a.path.cmp(&b.path));
    let digest = publication_digest(&targets);
    Ok(PublicationPlan {
        targets,
        node_groups,
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

fn canonical_json(value: &DesiredDeployment) -> Result<Vec<u8>, PlanError> {
    value.validate().map_err(PlanError::InvalidDeployment)?;
    serde_json::to_vec(value).map_err(|error| PlanError::Serialize(error.to_string()))
}

fn target(path: String, bytes: Vec<u8>) -> PublicationTarget {
    let sha256 = hex_digest(&bytes);
    PublicationTarget {
        path,
        bytes,
        sha256,
    }
}

fn publication_digest(targets: &[PublicationTarget]) -> String {
    let mut digest = Sha256::new();
    for target in targets {
        digest.update(target.path.as_bytes());
        digest.update([0]);
        digest.update(&target.bytes);
        digest.update([0]);
    }
    format!("{:x}", digest.finalize())
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Join a store `prefix` with a `relative` object path into a normalized object key, dropping any
/// empty segment (an empty prefix, or one with surrounding slashes). The single place this
/// prefix+relative join is expressed, shared by the gateway's content handlers and the operator's
/// publication and telemetry reads.
pub(crate) fn object_key(prefix: &str, relative: &str) -> object_store::path::Path {
    object_store::path::Path::from(
        [prefix.trim_matches('/'), relative]
            .into_iter()
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join("/"),
    )
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
        }
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
            schema: 2,
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

    fn managed_runtime() -> updated::config::ManagedRuntime {
        updated::config::ManagedRuntime {
            product: "app".into(),
            channel: "stable".into(),
            install_root: "/opt/app".into(),
            args: vec![],
            health_checks: vec![updated::config::ManagedHealthCheck {
                kind: updated::config::HealthCheckKind::Readiness,
                url: "http://127.0.0.1:8080/health".into(),
            }],
            repository: updated::config::ManagedRepositoryLimits {
                metadata_limit: 1_048_576,
                target_limit: 536_870_912,
                transport_timeout_seconds: 30,
            },
            storage: updated::config::ManagedStorage {
                inactive_releases: 2,
                inactive_providers: 2,
                inactive_supervisors: 2,
                inactive_bytes: 1_073_741_824,
                inactive_repository_caches: 2,
            },
            timeouts: updated::config::ManagedTimeouts {
                check_interval_seconds: 60,
                health_grace_seconds: 30,
                health_successes: 2,
                health_interval_seconds: 1,
                retry_after_seconds: 60,
                refresh_retry_seconds: 5,
                confirmation_window_seconds: 120,
                supervisor_check_interval_seconds: 3600,
                drain_hold_seconds: Some(0),
            },
        }
    }

    fn runtime_spec() -> RuntimeSpec {
        RuntimeSpec {
            product: "app".into(),
            channel: "stable".into(),
            install_root: "/opt/app".into(),
            args: vec![],
            health_checks: vec![HealthCheckSpec {
                kind: HealthCheckKindSpec::Readiness,
                url: "http://127.0.0.1:8080/health".into(),
            }],
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
                check_interval_seconds: 60,
                health_grace_seconds: 30,
                health_successes: 2,
                health_interval_seconds: 1,
                retry_after_seconds: 60,
                refresh_retry_seconds: 5,
                confirmation_window_seconds: 120,
                supervisor_check_interval_seconds: 3600,
                drain_hold_seconds: Some(0),
            },
        }
    }

    fn deployment_spec(id: &str) -> DeploymentSpec {
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
            deployment: deployment(name),
            max_unavailable: 1,
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

    fn repository() -> UpdateRepositorySpec {
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
        let assignment: updated::config::AgentDocument =
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
}
