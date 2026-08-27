//! The node reconciler protocol vocabulary.
//!
//! Every release carries one signed node reconciler, invoked as ordinary argv
//! (the published contract a third-party author writes against is
//! `docs/node-reconciler-protocol.md`).
//! The protocol has exactly four operations and four reserved
//! attempt identities, and this module is their single definition: the agent that
//! *invokes* a reconciler, and every reconciler implementation in this workspace that
//! *answers* one, name them from here. A second spelling of `healthcheck` — a reconciler
//! that answers `verify` while the agent asks for `healthcheck` — is exactly the
//! silent drift this module exists to make impossible.

use std::ffi::OsStr;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// The reconciler protocol implemented by this build.
///
/// Version one includes a dedicated, agent-owned result channel. State-changing operations must
/// describe their outcome there; process exit status remains reserved for a reconciler that could
/// not produce a valid answer at all.
pub const PROTOCOL: &str = "1";

/// Maximum encoded size of one reconciler result.
pub const MAX_RESULT_BYTES: usize = 16 * 1024;
pub const MAX_RESULT_MESSAGE_BYTES: usize = 4 * 1024;
/// Maximum times the platform will invoke one mutation when the reconciler keeps returning
/// `retry`. The attempt identity and arguments remain identical across all invocations.
pub const MAX_MUTATION_ATTEMPTS: u32 = 5;

/// A platform action requested after a successful state-changing operation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HostAction {
    #[default]
    None,
    Reboot,
}

impl HostAction {
    const ALL: [Self; 2] = [Self::None, Self::Reboot];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Reboot => "reboot",
        }
    }
}

impl Serialize for HostAction {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for HostAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::ALL
            .into_iter()
            .find(|action| action.as_str() == value)
            .ok_or_else(|| serde::de::Error::custom(format!("unknown host action {value:?}")))
    }
}

/// The successful semantic result of a state-changing operation.
///
/// This is also the only result shape durable reconciliation evidence can contain. A retry is a
/// request to invoke the same attempt again, not a completed reconciliation, so it has a different
/// type and cannot leak into an audit record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuccessfulMutation(SuccessfulMutationWire);

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SuccessfulMutationWire {
    changed: bool,
    host_action: HostAction,
    message: Option<String>,
}

impl Serialize for SuccessfulMutation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SuccessfulMutation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = SuccessfulMutationWire::deserialize(deserializer)?;
        Self::new(wire.changed, wire.host_action, wire.message).map_err(serde::de::Error::custom)
    }
}

impl SuccessfulMutation {
    pub fn new(
        changed: bool,
        host_action: HostAction,
        message: Option<String>,
    ) -> Result<Self, String> {
        let result = Self(SuccessfulMutationWire {
            changed,
            host_action,
            message,
        });
        result.validate()?;
        Ok(result)
    }

    fn validate(&self) -> Result<(), String> {
        validate_message(self.0.message.as_deref())
    }

    pub const fn changed(&self) -> bool {
        self.0.changed
    }

    pub const fn host_action(&self) -> HostAction {
        self.0.host_action
    }

    pub fn message(&self) -> Option<&str> {
        self.0.message.as_deref()
    }
}

/// A bounded request to repeat the same mutation attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RetryRequest {
    after_seconds: u64,
    message: Option<String>,
}

impl RetryRequest {
    fn new(after_seconds: u64, message: Option<String>) -> Result<Self, String> {
        if !(ResultDocument::MIN_RETRY_AFTER_SECONDS..=ResultDocument::MAX_RETRY_AFTER_SECONDS)
            .contains(&after_seconds)
        {
            return Err("a retry result requires a bounded delay".into());
        }
        validate_message(message.as_deref())?;
        Ok(Self {
            after_seconds,
            message,
        })
    }

    pub const fn after_seconds(&self) -> u64 {
        self.after_seconds
    }

    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }
}

/// The only two meanings a valid mutation result can have.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MutationResolution {
    Succeeded(SuccessfulMutation),
    Retry(RetryRequest),
}

/// The semantic result document produced by `apply` or `rollback`.
///
/// The wire shape is a tagged union rather than a bag of optional fields: a successful answer has a
/// host action and no retry delay; a retry has a delay and no host action or `changed` claim. Those
/// combinations are impossible to construct or deserialize instead of being conventions every
/// producer and consumer must independently remember.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResultDocument(MutationResolution);

#[derive(Deserialize, Serialize)]
#[serde(
    tag = "status",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum ResultDocumentWire {
    Succeeded {
        schema: u32,
        changed: bool,
        host_action: HostAction,
        message: Option<String>,
    },
    Retry {
        schema: u32,
        retry_after_seconds: u64,
        message: Option<String>,
    },
}

impl Serialize for ResultDocument {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match &self.0 {
            MutationResolution::Succeeded(result) => ResultDocumentWire::Succeeded {
                schema: Self::SCHEMA,
                changed: result.changed(),
                host_action: result.host_action(),
                message: result.0.message.clone(),
            },
            MutationResolution::Retry(retry) => ResultDocumentWire::Retry {
                schema: Self::SCHEMA,
                retry_after_seconds: retry.after_seconds(),
                message: retry.message.clone(),
            },
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ResultDocument {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ResultDocumentWire::deserialize(deserializer)?;
        Self::from_wire(wire).map_err(serde::de::Error::custom)
    }
}

fn validate_message(message: Option<&str>) -> Result<(), String> {
    if message.is_some_and(|message| {
        message.len() > MAX_RESULT_MESSAGE_BYTES || message.chars().any(char::is_control)
    }) {
        return Err("reconciler result message is oversized or contains control characters".into());
    }
    Ok(())
}

impl ResultDocument {
    pub const SCHEMA: u32 = 1;
    pub const MIN_RETRY_AFTER_SECONDS: u64 = 1;
    pub const MAX_RETRY_AFTER_SECONDS: u64 = 60 * 60;

    pub fn succeeded(
        changed: bool,
        host_action: HostAction,
        message: Option<String>,
    ) -> Result<Self, String> {
        SuccessfulMutation::new(changed, host_action, message)
            .map(MutationResolution::Succeeded)
            .map(Self)
    }

    pub fn retry(retry_after_seconds: u64, message: Option<String>) -> Result<Self, String> {
        RetryRequest::new(retry_after_seconds, message)
            .map(MutationResolution::Retry)
            .map(Self)
    }

    pub fn into_resolution(self) -> MutationResolution {
        self.0
    }

    fn from_wire(wire: ResultDocumentWire) -> Result<Self, String> {
        match wire {
            ResultDocumentWire::Succeeded {
                schema,
                changed,
                host_action,
                message,
            } => {
                Self::validate_schema(schema)?;
                Self::succeeded(changed, host_action, message)
            }
            ResultDocumentWire::Retry {
                schema,
                retry_after_seconds,
                message,
            } => {
                Self::validate_schema(schema)?;
                Self::retry(retry_after_seconds, message)
            }
        }
    }

    fn validate_schema(schema: u32) -> Result<(), String> {
        if schema != Self::SCHEMA {
            return Err(format!("unsupported reconciler result schema {}", schema));
        }
        Ok(())
    }

    pub fn from_bounded_json(bytes: &[u8]) -> Result<Self, String> {
        crate::bounded::decode(bytes, "reconciler result", MAX_RESULT_BYTES)
    }

    pub fn to_bounded_json(&self) -> Result<Vec<u8>, String> {
        crate::bounded::encode(self, "reconciler result", MAX_RESULT_BYTES)
    }
}

/// The four public reconciler operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Operation {
    /// Idempotently converge machine state to the candidate.
    Apply,
    /// Make one bounded readiness observation. This — and only this — is the readiness gate:
    /// exit zero means healthy.
    Healthcheck,
    /// Idempotently restore or compensate toward the predecessor.
    Rollback,
    /// Make one bounded steady-state observation for fingerprinting.
    Inspect,
}

/// State-changing operations. Keeping this as a type prevents callers that require a semantic
/// result and durable audit record from accidentally invoking an observation operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MutationOperation {
    Apply,
    Rollback,
}

impl MutationOperation {
    pub const fn operation(self) -> Operation {
        match self {
            Self::Apply => Operation::Apply,
            Self::Rollback => Operation::Rollback,
        }
    }

    pub const fn as_str(self) -> &'static str {
        self.operation().as_str()
    }

    /// Enforce the complete mutation invocation grammar in one place, before execution and again
    /// when durable evidence is decoded.
    pub fn validate_invocation(self, reason: Reason, id: &str) -> Result<(), String> {
        let accepted = match (self, reason) {
            (Self::Apply, Reason::Install) => id == attempt::BOOT,
            (Self::Apply, Reason::Restart) => matches!(id, attempt::BOOT | attempt::CONVERGE),
            (Self::Apply, Reason::Update) => attempt::is_transaction_invocation(id),
            (Self::Rollback, Reason::Update) => attempt::is_compensation(id),
            (Self::Rollback, Reason::Install | Reason::Restart) => false,
        };
        if accepted {
            Ok(())
        } else {
            Err("invalid mutation operation, reason, and attempt combination".into())
        }
    }
}

/// Read-only operations. These never publish a result document, outputs, retries, or host actions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservationOperation {
    Healthcheck,
    Inspect,
}

impl ObservationOperation {
    pub const fn operation(self) -> Operation {
        match self {
            Self::Healthcheck => Operation::Healthcheck,
            Self::Inspect => Operation::Inspect,
        }
    }

    /// Enforce the observation invocation grammar beside the mutation grammar. A healthcheck is
    /// evidence for the operation whose attempt identity it carries; an inspect is the one
    /// periodic fingerprint observation. Keeping these combinations here prevents an invoker from
    /// giving a reserved observation ID transaction meaning, or from claiming a transaction probe
    /// is an ordinary restart.
    pub fn validate_invocation(self, reason: Reason, id: &str) -> Result<(), String> {
        let accepted = match (self, reason) {
            (Self::Healthcheck, Reason::Install) => id == attempt::BOOT,
            (Self::Healthcheck, Reason::Restart) => {
                matches!(id, attempt::BOOT | attempt::CONVERGE | attempt::PERIODIC)
            }
            (Self::Healthcheck, Reason::Update) => attempt::is_transaction_invocation(id),
            (Self::Inspect, Reason::Restart) => id == attempt::FINGERPRINT,
            (Self::Inspect, Reason::Install | Reason::Update) => false,
        };
        if accepted {
            Ok(())
        } else {
            Err("invalid observation operation, reason, and attempt combination".into())
        }
    }
}

impl Operation {
    pub const ALL: [Self; 4] = [
        Self::Apply,
        Self::Healthcheck,
        Self::Rollback,
        Self::Inspect,
    ];

    /// The wire spelling passed as the reconciler's first argument.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Apply => "apply",
            Self::Healthcheck => "healthcheck",
            Self::Rollback => "rollback",
            Self::Inspect => "inspect",
        }
    }

    /// Whether a successful invocation defines the release's advertised output files.
    ///
    /// Observations receive a fresh output directory too, but must never replace the durable
    /// output snapshot. Otherwise an ordinary healthcheck would erase the files emitted by the
    /// preceding apply and spuriously cascade empty dependency inputs through the fleet.
    pub const fn publishes_outputs(self) -> bool {
        self.mutation().is_some()
    }

    pub const fn mutation(self) -> Option<MutationOperation> {
        match self {
            Self::Apply => Some(MutationOperation::Apply),
            Self::Rollback => Some(MutationOperation::Rollback),
            Self::Healthcheck | Self::Inspect => None,
        }
    }

    pub const fn observation(self) -> Option<ObservationOperation> {
        match self {
            Self::Healthcheck => Some(ObservationOperation::Healthcheck),
            Self::Inspect => Some(ObservationOperation::Inspect),
            Self::Apply | Self::Rollback => None,
        }
    }

    /// The complete invocation grammar, called at the one command-preparation boundary before any
    /// reconciler process can run.
    pub fn validate_invocation(self, reason: Reason, id: &str) -> Result<(), String> {
        match (self.mutation(), self.observation()) {
            (Some(operation), None) => operation.validate_invocation(reason, id),
            (None, Some(operation)) => operation.validate_invocation(reason, id),
            _ => unreachable!("every operation belongs to exactly one typed class"),
        }
    }
}

/// An argv operation that is not one of the four.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownOperation(pub String);

impl fmt::Display for UnknownOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown reconciler operation {:?}", self.0)
    }
}

impl std::error::Error for UnknownOperation {}

impl FromStr for Operation {
    type Err = UnknownOperation;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|operation| operation.as_str() == value)
            .ok_or_else(|| UnknownOperation(value.to_string()))
    }
}

impl Serialize for Operation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Operation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

impl Serialize for MutationOperation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for MutationOperation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Operation::deserialize(deserializer)?
            .mutation()
            .ok_or_else(|| serde::de::Error::custom("operation is not state-changing"))
    }
}

impl fmt::Display for Operation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The `--reason` vocabulary: why the agent is asking for this convergence. Part of the published
/// grammar exactly like [`FLAGS`] and [`Operation`] — the agent emits these spellings and a
/// reconciler may branch on only these — so it lives here rather than privately in the invoker,
/// where a second speller (a conformance harness, a test fixture) could drift from it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// First convergence onto a release this node has not run before.
    Install,
    /// Re-converge onto the release already installed: a boot, a repair, or changed input files.
    Restart,
    /// A transaction moving between releases, in either direction.
    Update,
}

impl Reason {
    pub const ALL: [Self; 3] = [Self::Install, Self::Restart, Self::Update];

    /// The wire spelling passed after `--reason`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Restart => "restart",
            Self::Update => "update",
        }
    }
}

/// A `--reason` value that is not one of the three.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownReason(pub String);

impl fmt::Display for UnknownReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown reconciler reason {:?}", self.0)
    }
}

impl std::error::Error for UnknownReason {}

impl FromStr for Reason {
    type Err = UnknownReason;

    /// Matched against the vocabulary's own [`as_str`](Reason::as_str) rather than a second set of
    /// literals, so a reader cannot end up recognizing a spelling the writer no longer sends.
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|reason| reason.as_str() == value)
            .ok_or_else(|| UnknownReason(value.to_string()))
    }
}

impl Serialize for Reason {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Reason {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for Reason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The last state-changing reconciliation completed by the node.
///
/// This is platform-owned audit evidence: a reconciler describes the semantic result, while the
/// agent binds it to the operation, reason, attempt, immutable releases, and completion time before
/// it treats the invocation as successful.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconciledRelease(ReconciledReleaseWire);

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReconciledReleaseWire {
    version: String,
    manifest_sha256: String,
    archive_sha256: String,
}

impl Serialize for ReconciledRelease {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ReconciledRelease {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ReconciledReleaseWire::deserialize(deserializer)?;
        Self::new(wire.version, wire.manifest_sha256, wire.archive_sha256)
            .map_err(serde::de::Error::custom)
    }
}

impl ReconciledRelease {
    pub fn new(
        version: String,
        manifest_sha256: String,
        archive_sha256: String,
    ) -> Result<Self, String> {
        if !crate::identity::is_release_version(&version)
            || !crate::is_canonical_sha256(&manifest_sha256)
            || !crate::is_canonical_sha256(&archive_sha256)
        {
            return Err("invalid reconciled release identity".into());
        }
        Ok(Self(ReconciledReleaseWire {
            version,
            manifest_sha256,
            archive_sha256,
        }))
    }

    pub fn version(&self) -> &str {
        &self.0.version
    }

    pub fn manifest_sha256(&self) -> &str {
        &self.0.manifest_sha256
    }

    pub fn archive_sha256(&self) -> &str {
        &self.0.archive_sha256
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconcilerIdentity(ReconcilerIdentityWire);

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ReconcilerIdentityWire {
    provider_set_sha256: String,
    product: String,
    release: ReconciledRelease,
}

impl Serialize for ReconcilerIdentity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ReconcilerIdentity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = ReconcilerIdentityWire::deserialize(deserializer)?;
        Self::new(wire.provider_set_sha256, wire.product, wire.release)
            .map_err(serde::de::Error::custom)
    }
}

impl ReconcilerIdentity {
    pub fn new(
        provider_set_sha256: String,
        product: String,
        release: ReconciledRelease,
    ) -> Result<Self, String> {
        if !crate::is_canonical_sha256(&provider_set_sha256)
            || !crate::identity::is_segment(&product)
        {
            return Err("invalid reconciler identity".into());
        }
        Ok(Self(ReconcilerIdentityWire {
            provider_set_sha256,
            product,
            release,
        }))
    }

    pub fn provider_set_sha256(&self) -> &str {
        &self.0.provider_set_sha256
    }

    pub fn product(&self) -> &str {
        &self.0.product
    }

    pub const fn release(&self) -> &ReconciledRelease {
        &self.0.release
    }
}

/// The immutable release identities on both sides of one state-changing reconciliation.
///
/// Each identity is already valid by construction; grouping them prevents candidate/predecessor
/// ordering from becoming another long argument list at every audit-record call site.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconciliationTransition {
    candidate: ReconciledRelease,
    predecessor: ReconciledRelease,
}

impl ReconciliationTransition {
    pub fn new(candidate: ReconciledRelease, predecessor: ReconciledRelease) -> Self {
        Self {
            candidate,
            predecessor,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LastReconciliation(LastReconciliationWire);

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LastReconciliationWire {
    schema: u32,
    operation: MutationOperation,
    reason: Reason,
    attempt_id: String,
    candidate: ReconciledRelease,
    predecessor: ReconciledRelease,
    reconciler: ReconcilerIdentity,
    result: SuccessfulMutation,
    completed_at_ms: u64,
}

impl Serialize for LastReconciliation {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for LastReconciliation {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = LastReconciliationWire::deserialize(deserializer)?;
        if wire.schema != Self::SCHEMA {
            return Err(serde::de::Error::custom(format!(
                "unsupported last-reconciliation schema {}",
                wire.schema
            )));
        }
        let transition = ReconciliationTransition::new(wire.candidate, wire.predecessor);
        Self::new(
            wire.operation,
            wire.reason,
            wire.attempt_id,
            transition,
            wire.reconciler,
            wire.result,
            wire.completed_at_ms,
        )
        .map_err(serde::de::Error::custom)
    }
}

impl LastReconciliation {
    const SCHEMA: u32 = 1;
    pub const MAX_BYTES: usize = 32 * 1024;

    pub fn new(
        operation: MutationOperation,
        reason: Reason,
        attempt_id: String,
        transition: ReconciliationTransition,
        reconciler: ReconcilerIdentity,
        result: SuccessfulMutation,
        completed_at_ms: u64,
    ) -> Result<Self, String> {
        operation.validate_invocation(reason, &attempt_id)?;
        if completed_at_ms == 0 {
            return Err("last reconciliation has no completion time".into());
        }
        Ok(Self(LastReconciliationWire {
            schema: Self::SCHEMA,
            operation,
            reason,
            attempt_id,
            candidate: transition.candidate,
            predecessor: transition.predecessor,
            reconciler,
            result,
            completed_at_ms,
        }))
    }

    pub const fn operation(&self) -> MutationOperation {
        self.0.operation
    }

    pub const fn reason(&self) -> Reason {
        self.0.reason
    }

    pub fn attempt_id(&self) -> &str {
        &self.0.attempt_id
    }

    pub const fn candidate(&self) -> &ReconciledRelease {
        &self.0.candidate
    }

    pub const fn predecessor(&self) -> &ReconciledRelease {
        &self.0.predecessor
    }

    pub const fn reconciler(&self) -> &ReconcilerIdentity {
        &self.0.reconciler
    }

    pub const fn result(&self) -> &SuccessfulMutation {
        &self.0.result
    }

    pub const fn completed_at_ms(&self) -> u64 {
        self.0.completed_at_ms
    }

    pub fn into_result(self) -> SuccessfulMutation {
        self.0.result
    }

    pub fn from_bounded_json(bytes: &[u8]) -> Result<Self, String> {
        crate::bounded::decode(bytes, "last reconciliation", Self::MAX_BYTES)
    }

    pub fn to_bounded_json(&self) -> Result<Vec<u8>, String> {
        crate::bounded::encode(self, "last reconciliation", Self::MAX_BYTES)
    }
}

/// Every protocol flag the agent passes to a reconciler invocation, in argv order. This is the
/// published invocation grammar: [`Arguments::argv`] emits exactly these, and a reconciler may read
/// only these. Publisher-configured arguments are separated by `--` and are not part of it.
///
/// One list, so a flag the agent stops emitting cannot go on being parsed by a hook that then reads
/// a value nobody sends.
pub const FLAGS: &[&str] = &[
    "--protocol",
    "--attempt-id",
    "--reason",
    "--install-root",
    "--state-dir",
    "--candidate",
    "--candidate-version",
    "--output-dir",
    "--result-file",
    "--input-dir",
    "--predecessor",
    "--predecessor-version",
];

/// One invocation's values, named. [`Arguments::argv`] is the only place a value is bound to a
/// flag, and every invoker — the agent and the conformance harness — builds its argv from it.
///
/// The binding used to be positional: each invoker wrote its own `[&OsStr; FLAGS.len()]` array and
/// zipped it against [`FLAGS`], so only the LENGTH was checked. Inserting a flag mid-list and
/// appending its value still compiled, and every pairing after the insertion point shifted by one
/// — the hook receiving the install root as its `--reason` and a version string as a directory.
/// Naming the fields is what makes that unrepresentable: a new flag is a new field every invoker
/// must fill in, and moving one moves its value with it.
pub struct Arguments<'a> {
    pub protocol: &'a OsStr,
    pub attempt_id: &'a OsStr,
    pub reason: Reason,
    pub install_root: &'a OsStr,
    pub state_dir: &'a OsStr,
    /// The release to converge ONTO, in both directions: on a rollback this is the predecessor
    /// being restored and `predecessor` is the failed candidate.
    pub candidate: &'a OsStr,
    pub candidate_version: &'a OsStr,
    /// Empty directory owned by this invocation. A successful operation publishes exactly the
    /// bounded regular files the reconciler leaves here.
    pub output_dir: &'a OsStr,
    /// Fresh agent-owned path where `apply` and `rollback` must atomically publish one
    /// [`ResultDocument`]. Observation operations must leave it absent.
    pub result_file: &'a OsStr,
    /// Immutable directory containing exactly the named files selected by the signed assignment.
    pub input_dir: &'a OsStr,
    pub predecessor: &'a OsStr,
    pub predecessor_version: &'a OsStr,
}

impl<'a> Arguments<'a> {
    /// The protocol arguments in published argv order, each flag beside the value it names.
    ///
    /// The return type is sized by [`FLAGS`], so adding or removing a flag without changing this
    /// list fails to compile; `the_argv_builder_emits_the_published_flags_in_order` covers the
    /// remaining case, a reordering, which the lengths alone cannot see.
    pub fn argv(&self) -> [(&'static str, &'a OsStr); FLAGS.len()] {
        [
            ("--protocol", self.protocol),
            ("--attempt-id", self.attempt_id),
            ("--reason", OsStr::new(self.reason.as_str())),
            ("--install-root", self.install_root),
            ("--state-dir", self.state_dir),
            ("--candidate", self.candidate),
            ("--candidate-version", self.candidate_version),
            ("--output-dir", self.output_dir),
            ("--result-file", self.result_file),
            ("--input-dir", self.input_dir),
            ("--predecessor", self.predecessor),
            ("--predecessor-version", self.predecessor_version),
        ]
    }
}

/// The reserved `--attempt-id` values. A deployment carries the transaction's own token, so
/// a reconciler can tell a transaction step from an operation performed outside one; these four
/// name the operations that belong to no transaction. They are stable, deliberately recurring
/// names — reused on every boot and every probe — so they are never idempotency keys: an operation
/// invoked under a reserved identity does its full work on every invocation.
pub mod attempt {
    /// A boot or restart: the per-boot converge and the boot readiness gate.
    pub const BOOT: &str = "boot";
    /// The steady-state desired-state converge and its readiness gate.
    pub const CONVERGE: &str = "converge";
    /// The agent's steady-state readiness/liveness observation.
    pub const PERIODIC: &str = "periodic";
    /// The steady-state fingerprint observation.
    pub const FINGERPRINT: &str = "fingerprint";

    /// Every reserved non-transaction identity. Consumers iterate this catalog instead of
    /// maintaining a second list that can drift when the protocol grows.
    pub const ALL: [&str; 4] = [BOOT, CONVERGE, PERIODIC, FINGERPRINT];

    /// Whether `id` is one of the reserved non-transaction identities rather than a deployment
    /// transaction token.
    pub fn is_reserved(id: &str) -> bool {
        ALL.contains(&id)
    }

    /// Whether `id` names either direction of one deployment transaction. Every transactional
    /// operation and observation uses this predicate, so the forward/compensating grammar cannot
    /// drift between `apply`, `healthcheck`, and durable audit evidence.
    pub fn is_transaction_invocation(id: &str) -> bool {
        crate::is_canonical_sha256(id) || is_compensation(id)
    }

    /// Whether `id` is the derived compensating direction of one transaction. A `rollback`
    /// mutation accepts only this form; the predecessor's compensating `apply` uses it too.
    pub fn is_compensation(id: &str) -> bool {
        id.strip_suffix('r').is_some_and(crate::is_canonical_sha256)
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::*;

    /// The wire spellings are the published protocol: changing one silently breaks every
    /// reconciler in the field.
    #[test]
    fn the_four_operations_round_trip_their_published_spellings() {
        for (operation, spelling) in [
            (Operation::Apply, "apply"),
            (Operation::Healthcheck, "healthcheck"),
            (Operation::Rollback, "rollback"),
            (Operation::Inspect, "inspect"),
        ] {
            assert_eq!(operation.as_str(), spelling);
            assert_eq!(spelling.parse::<Operation>().unwrap(), operation);
            assert_eq!(serde_json::to_value(operation).unwrap(), spelling);
            assert_eq!(
                serde_json::from_value::<Operation>(spelling.into()).unwrap(),
                operation
            );
        }
    }

    #[test]
    fn every_protocol_enum_uses_its_canonical_spelling_for_json() {
        for action in HostAction::ALL {
            let encoded = serde_json::to_value(action).unwrap();
            assert_eq!(encoded, action.as_str());
            assert_eq!(
                serde_json::from_value::<HostAction>(encoded).unwrap(),
                action
            );
        }
        for reason in Reason::ALL {
            let encoded = serde_json::to_value(reason).unwrap();
            assert_eq!(encoded, reason.as_str());
            assert_eq!(serde_json::from_value::<Reason>(encoded).unwrap(), reason);
        }
        for operation in Operation::ALL.into_iter().filter_map(Operation::mutation) {
            let encoded = serde_json::to_value(operation).unwrap();
            assert_eq!(encoded, operation.as_str());
            assert_eq!(
                serde_json::from_value::<MutationOperation>(encoded).unwrap(),
                operation
            );
        }
        for operation in Operation::ALL
            .into_iter()
            .filter(|operation| operation.observation().is_some())
        {
            assert!(
                serde_json::from_value::<MutationOperation>(operation.as_str().into()).is_err()
            );
        }
    }

    #[test]
    fn only_state_changing_operations_publish_output_files() {
        assert!(Operation::Apply.publishes_outputs());
        assert!(Operation::Rollback.publishes_outputs());
        assert!(!Operation::Healthcheck.publishes_outputs());
        assert!(!Operation::Inspect.publishes_outputs());
    }

    #[test]
    fn every_operation_belongs_to_exactly_one_typed_class() {
        for operation in Operation::ALL {
            assert_ne!(
                operation.mutation().is_some(),
                operation.observation().is_some()
            );
            if let Some(mutation) = operation.mutation() {
                assert_eq!(mutation.operation(), operation);
            }
            if let Some(observation) = operation.observation() {
                assert_eq!(observation.operation(), operation);
            }
        }
    }

    #[test]
    fn result_documents_are_bounded_tagged_unions() {
        let succeeded = ResultDocument::succeeded(
            true,
            HostAction::Reboot,
            Some("kernel configuration changed".into()),
        )
        .unwrap();
        assert_eq!(
            ResultDocument::from_bounded_json(&succeeded.to_bounded_json().unwrap()).unwrap(),
            succeeded
        );
        let succeeded_json = serde_json::to_value(&succeeded).unwrap();
        assert!(succeeded_json.get("retryAfterSeconds").is_none());

        let retry = ResultDocument::retry(30, Some("package manager is locked".into())).unwrap();
        let retry_json = serde_json::to_value(&retry).unwrap();
        assert!(retry_json.get("changed").is_none());
        assert!(retry_json.get("hostAction").is_none());
        assert!(ResultDocument::retry(0, None).is_err());
        assert!(ResultDocument::retry(ResultDocument::MAX_RETRY_AFTER_SECONDS + 1, None).is_err());

        let maximum_message = "a".repeat(MAX_RESULT_MESSAGE_BYTES);
        assert!(
            ResultDocument::succeeded(false, HostAction::None, Some(maximum_message.clone()))
                .is_ok()
        );
        assert!(ResultDocument::retry(1, Some(maximum_message)).is_ok());

        let oversized_message = "a".repeat(MAX_RESULT_MESSAGE_BYTES + 1);
        assert!(ResultDocument::succeeded(
            false,
            HostAction::None,
            Some(oversized_message.clone())
        )
        .is_err());
        assert!(ResultDocument::retry(1, Some(oversized_message)).is_err());

        let contradictory = br#"{
            "schema": 1,
            "status": "retry",
            "retryAfterSeconds": 1,
            "hostAction": "none",
            "message": null
        }"#;
        assert!(ResultDocument::from_bounded_json(contradictory).is_err());

        for invalid in [
            serde_json::json!({
                "schema": 2,
                "status": "succeeded",
                "changed": false,
                "hostAction": "none",
                "message": null
            }),
            serde_json::json!({
                "schema": 1,
                "status": "retry",
                "retryAfterSeconds": 0,
                "message": null
            }),
            serde_json::json!({
                "schema": 1,
                "status": "succeeded",
                "changed": false,
                "hostAction": "none",
                "retryAfterSeconds": null,
                "message": null
            }),
            serde_json::json!({
                "schema": 1,
                "status": "succeeded",
                "changed": false,
                "hostAction": "none",
                "message": "two\nlines"
            }),
        ] {
            assert!(serde_json::from_value::<ResultDocument>(invalid).is_err());
        }
        assert!(
            serde_json::from_value::<SuccessfulMutation>(serde_json::json!({
                "changed": false,
                "hostAction": "none",
                "message": "two\nlines"
            }))
            .is_err()
        );
    }

    #[test]
    fn platform_audit_evidence_binds_a_success_to_both_immutable_releases() {
        let transition = ReconciliationTransition::new(
            ReconciledRelease::new("2.0.0".into(), "a".repeat(64), "c".repeat(64)).unwrap(),
            ReconciledRelease::new("1.0.0".into(), "b".repeat(64), "d".repeat(64)).unwrap(),
        );
        let reconciler = ReconcilerIdentity::new(
            "e".repeat(64),
            "system".into(),
            ReconciledRelease::new("3.0.0".into(), "f".repeat(64), "0".repeat(64)).unwrap(),
        )
        .unwrap();
        let result =
            SuccessfulMutation::new(true, HostAction::Reboot, Some("kernel changed".into()))
                .unwrap();
        let record = LastReconciliation::new(
            MutationOperation::Apply,
            Reason::Update,
            "a".repeat(64),
            transition.clone(),
            reconciler.clone(),
            result.clone(),
            1,
        )
        .unwrap();
        assert_eq!(
            LastReconciliation::from_bounded_json(&record.to_bounded_json().unwrap()).unwrap(),
            record
        );

        let mut encoded = serde_json::to_value(&record).unwrap();
        encoded["operation"] = serde_json::json!("inspect");
        assert!(serde_json::from_value::<LastReconciliation>(encoded.clone()).is_err());
        assert!(
            LastReconciliation::from_bounded_json(&serde_json::to_vec(&encoded).unwrap()).is_err()
        );

        for mutate in [
            (|value: &mut serde_json::Value| value["schema"] = serde_json::json!(2))
                as fn(&mut serde_json::Value),
            |value| value["completedAtMs"] = serde_json::json!(0),
            |value| value["candidate"]["archiveSha256"] = serde_json::json!("not-a-digest"),
            |value| {
                value["reconciler"]["providerSetSha256"] = serde_json::json!("not-a-digest");
            },
        ] {
            let mut invalid = serde_json::to_value(&record).unwrap();
            mutate(&mut invalid);
            assert!(serde_json::from_value::<LastReconciliation>(invalid).is_err());
        }

        assert!(
            ReconciledRelease::new("2.0.0".into(), "not-a-digest".into(), "c".repeat(64)).is_err()
        );
        assert!(ReconcilerIdentity::new(
            "not-a-digest".into(),
            "system".into(),
            record.reconciler().release().clone(),
        )
        .is_err());

        assert!(LastReconciliation::new(
            MutationOperation::Rollback,
            Reason::Update,
            "a".repeat(64),
            transition,
            reconciler,
            result,
            1,
        )
        .is_err());
    }

    #[test]
    fn a_retired_spelling_is_rejected_rather_than_silently_ignored() {
        for retired in ["verify", "periodic", "pre-start", "finalize", "drain"] {
            assert!(retired.parse::<Operation>().is_err());
        }
    }

    #[test]
    fn only_the_four_non_transaction_identities_are_reserved() {
        for id in attempt::ALL {
            assert!(attempt::is_reserved(id));
        }
        assert!(!attempt::is_reserved("a1b2c3"));
    }

    #[test]
    fn mutation_invocations_have_one_exact_grammar() {
        let transaction = "a".repeat(64);
        let compensation = format!("{transaction}r");
        for (operation, reason, attempt_id) in [
            (MutationOperation::Apply, Reason::Install, attempt::BOOT),
            (MutationOperation::Apply, Reason::Restart, attempt::BOOT),
            (MutationOperation::Apply, Reason::Restart, attempt::CONVERGE),
            (MutationOperation::Apply, Reason::Update, &transaction),
            (MutationOperation::Apply, Reason::Update, &compensation),
            (MutationOperation::Rollback, Reason::Update, &compensation),
        ] {
            assert!(
                operation.validate_invocation(reason, attempt_id).is_ok(),
                "valid mutation invocation was refused: {operation:?} {reason:?} {attempt_id}"
            );
        }
        for (operation, reason, attempt_id) in [
            (MutationOperation::Apply, Reason::Install, attempt::CONVERGE),
            (MutationOperation::Apply, Reason::Restart, &transaction),
            (MutationOperation::Apply, Reason::Update, attempt::BOOT),
            (MutationOperation::Rollback, Reason::Restart, &compensation),
            (MutationOperation::Rollback, Reason::Update, &transaction),
        ] {
            assert!(
                operation.validate_invocation(reason, attempt_id).is_err(),
                "invalid mutation invocation was accepted: {operation:?} {reason:?} {attempt_id}"
            );
        }
    }

    #[test]
    fn observation_invocations_have_one_exact_grammar() {
        let transaction = "a".repeat(64);
        let compensation = format!("{transaction}r");
        for (operation, reason, attempt_id) in [
            (
                ObservationOperation::Healthcheck,
                Reason::Install,
                attempt::BOOT,
            ),
            (
                ObservationOperation::Healthcheck,
                Reason::Restart,
                attempt::BOOT,
            ),
            (
                ObservationOperation::Healthcheck,
                Reason::Restart,
                attempt::CONVERGE,
            ),
            (
                ObservationOperation::Healthcheck,
                Reason::Restart,
                attempt::PERIODIC,
            ),
            (
                ObservationOperation::Healthcheck,
                Reason::Update,
                &transaction,
            ),
            (
                ObservationOperation::Healthcheck,
                Reason::Update,
                &compensation,
            ),
            (
                ObservationOperation::Inspect,
                Reason::Restart,
                attempt::FINGERPRINT,
            ),
        ] {
            assert!(
                operation.validate_invocation(reason, attempt_id).is_ok(),
                "valid observation invocation was refused: {operation:?} {reason:?} {attempt_id}"
            );
            assert!(
                operation
                    .operation()
                    .validate_invocation(reason, attempt_id)
                    .is_ok(),
                "the shared execution gate disagreed with the typed observation grammar"
            );
        }
        for (operation, reason, attempt_id) in [
            (
                ObservationOperation::Healthcheck,
                Reason::Install,
                attempt::PERIODIC,
            ),
            (
                ObservationOperation::Healthcheck,
                Reason::Restart,
                &transaction,
            ),
            (
                ObservationOperation::Healthcheck,
                Reason::Update,
                attempt::BOOT,
            ),
            (
                ObservationOperation::Inspect,
                Reason::Restart,
                attempt::PERIODIC,
            ),
            (
                ObservationOperation::Inspect,
                Reason::Install,
                attempt::FINGERPRINT,
            ),
            (ObservationOperation::Inspect, Reason::Update, &transaction),
        ] {
            assert!(
                operation.validate_invocation(reason, attempt_id).is_err(),
                "invalid observation invocation was accepted: {operation:?} {reason:?} {attempt_id}"
            );
            assert!(
                operation
                    .operation()
                    .validate_invocation(reason, attempt_id)
                    .is_err(),
                "the shared execution gate disagreed with the typed observation grammar"
            );
        }
    }

    #[test]
    fn the_three_reasons_round_trip_their_published_spellings() {
        for (reason, spelling) in [
            (Reason::Install, "install"),
            (Reason::Restart, "restart"),
            (Reason::Update, "update"),
        ] {
            assert_eq!(reason.as_str(), spelling);
            assert_eq!(spelling.parse::<Reason>().unwrap(), reason);
        }
        assert!("periodic".parse::<Reason>().is_err());
    }

    /// The values are bound to the flags in exactly one place. The invokers' arrays used to be
    /// positional, where inserting a flag mid-list shifted every later value onto the wrong flag
    /// with the lengths still matching; adding or removing a flag now fails to compile, and this
    /// covers the reordering that a length check cannot see.
    #[test]
    fn the_argv_builder_emits_the_published_flags_in_order() {
        let arguments = Arguments {
            protocol: OsStr::new(PROTOCOL),
            attempt_id: OsStr::new(attempt::BOOT),
            reason: Reason::Restart,
            install_root: OsStr::new("/install"),
            state_dir: OsStr::new("/state"),
            candidate: OsStr::new("/candidate"),
            candidate_version: OsStr::new("2.0.0"),
            output_dir: OsStr::new("/out"),
            result_file: OsStr::new("/result.json"),
            input_dir: OsStr::new("/in"),
            predecessor: OsStr::new("/predecessor"),
            predecessor_version: OsStr::new("1.0.0"),
        };
        let argv = arguments.argv();
        let flags: Vec<&str> = argv.iter().map(|(flag, _)| *flag).collect();
        assert_eq!(flags, FLAGS);
        assert_eq!(
            argv.iter()
                .map(|(_, value)| value.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            [
                "1",
                "boot",
                "restart",
                "/install",
                "/state",
                "/candidate",
                "2.0.0",
                "/out",
                "/result.json",
                "/in",
                "/predecessor",
                "1.0.0",
            ]
        );
    }

    /// The published protocol document, the artifact a third-party author writes their reconciler
    /// against. It is not generated from this module, so every vocabulary the agent actually emits
    /// is checked against it here.
    const PROTOCOL_DOCUMENT: &str = include_str!("../../../docs/node-reconciler-protocol.md");

    /// The flag list is the half most likely to drift — it is what [`Arguments`] is structured
    /// around — and it is also the half a hook parses literally. Deleting `--input-dir` from the
    /// doc's grammar block, or swapping two lines there, left the whole suite green while every
    /// author read an invocation the agent does not send.
    ///
    /// Offsets, not mere presence: order is part of the published grammar (`Arguments::argv` emits
    /// exactly this sequence), so the doc must name the flags in the same sequence.
    #[test]
    fn the_published_protocol_names_every_flag_in_argv_order() {
        let mut previous = 0;
        for flag in FLAGS {
            let at = PROTOCOL_DOCUMENT
                .find(&format!("\n  {flag} "))
                .unwrap_or_else(|| {
                    panic!("docs/node-reconciler-protocol.md's invocation grammar omits {flag}")
                });
            assert!(
                at > previous,
                "docs/node-reconciler-protocol.md lists {flag} out of argv order"
            );
            previous = at;
        }
    }

    /// The reserved identities are a published cross-organization contract; a reconciler author
    /// reading the doc must see every spelling the agent actually sends.
    #[test]
    fn the_published_protocol_names_every_reserved_identity() {
        for id in attempt::ALL {
            assert!(
                PROTOCOL_DOCUMENT.contains(&format!("`{id}`")),
                "docs/node-reconciler-protocol.md does not name the reserved attempt id `{id}`"
            );
        }
        // Backticked, like the identities above: the bare words appear in the doc for unrelated
        // reasons ("install root", "restarting", "self-update"), so a bare-substring check stayed
        // green with the whole `--reason` grammar deleted — the one state it exists to prevent.
        for reason in [Reason::Install, Reason::Restart, Reason::Update] {
            assert!(
                PROTOCOL_DOCUMENT.contains(&format!("`{reason}`")),
                "docs/node-reconciler-protocol.md does not name the reason `{reason}`"
            );
        }
    }
}
