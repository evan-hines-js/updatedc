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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum HostAction {
    #[default]
    None,
    Reboot,
}

impl HostAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Reboot => "reboot",
        }
    }
}

/// The semantic result of `apply` or `rollback`.
///
/// The process must still exit successfully. A missing, malformed, or contradictory result is a
/// reconciler failure; this prevents an accidental `exit 0` from committing machine state whose
/// meaning the platform never learned.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResultDocument {
    pub schema: u32,
    pub status: ResultStatus,
    pub changed: bool,
    pub host_action: HostAction,
    pub retry_after_seconds: Option<u64>,
    pub message: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum ResultStatus {
    Succeeded,
    Retry,
}

impl ResultStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Retry => "retry",
        }
    }
}

impl ResultDocument {
    pub const SCHEMA: u32 = 1;
    pub const MIN_RETRY_AFTER_SECONDS: u64 = 1;
    pub const MAX_RETRY_AFTER_SECONDS: u64 = 60 * 60;

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != Self::SCHEMA {
            return Err(format!(
                "unsupported reconciler result schema {}",
                self.schema
            ));
        }
        if self.message.as_ref().is_some_and(|message| {
            message.len() > MAX_RESULT_MESSAGE_BYTES || message.chars().any(char::is_control)
        }) {
            return Err(
                "reconciler result message is oversized or contains control characters".into(),
            );
        }
        match self.status {
            ResultStatus::Succeeded if self.retry_after_seconds.is_some() => {
                Err("a successful reconciler result cannot request a retry".into())
            }
            ResultStatus::Retry
                if self.host_action != HostAction::None
                    || !self.retry_after_seconds.is_some_and(|seconds| {
                        (Self::MIN_RETRY_AFTER_SECONDS..=Self::MAX_RETRY_AFTER_SECONDS)
                            .contains(&seconds)
                    }) =>
            {
                Err(
                    "a retry result requires a bounded delay and cannot request a host action"
                        .into(),
                )
            }
            _ => Ok(()),
        }
    }

    pub fn from_bounded_json(bytes: &[u8]) -> Result<Self, String> {
        let result: Self = crate::bounded::decode(bytes, "reconciler result", MAX_RESULT_BYTES)?;
        result.validate()?;
        Ok(result)
    }

    pub fn to_bounded_json(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        crate::bounded::encode(self, "reconciler result", MAX_RESULT_BYTES)
    }
}

/// The four public reconciler operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
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
}

impl Operation {
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
        match value {
            "apply" => Ok(Self::Apply),
            "healthcheck" => Ok(Self::Healthcheck),
            "rollback" => Ok(Self::Rollback),
            "inspect" => Ok(Self::Inspect),
            other => Err(UnknownOperation(other.to_string())),
        }
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum Reason {
    /// First convergence onto a release this node has not run before.
    Install,
    /// Re-converge onto the release already installed: a boot, a repair, or changed input files.
    Restart,
    /// A transaction moving between releases, in either direction.
    Update,
}

impl Reason {
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
        [Self::Install, Self::Restart, Self::Update]
            .into_iter()
            .find(|reason| reason.as_str() == value)
            .ok_or_else(|| UnknownReason(value.to_string()))
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
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReconciledRelease {
    pub version: String,
    pub manifest_sha256: String,
    pub archive_sha256: String,
}

impl ReconciledRelease {
    fn validate(&self, name: &str) -> Result<(), String> {
        if !crate::identity::is_release_version(&self.version)
            || !crate::is_canonical_sha256(&self.manifest_sha256)
            || !crate::is_canonical_sha256(&self.archive_sha256)
        {
            return Err(format!(
                "last reconciliation has an invalid {name} release identity"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReconcilerIdentity {
    pub provider_set_sha256: String,
    pub product: String,
    pub release: ReconciledRelease,
}

impl ReconcilerIdentity {
    fn validate(&self) -> Result<(), String> {
        if !crate::is_canonical_sha256(&self.provider_set_sha256)
            || !crate::identity::is_segment(&self.product)
        {
            return Err("last reconciliation has an invalid reconciler identity".into());
        }
        self.release.validate("reconciler")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LastReconciliation {
    pub schema: u32,
    pub operation: Operation,
    pub reason: Reason,
    pub attempt_id: String,
    pub candidate: ReconciledRelease,
    pub predecessor: ReconciledRelease,
    pub reconciler: ReconcilerIdentity,
    pub result: ResultDocument,
    pub completed_at_ms: u64,
}

impl LastReconciliation {
    pub const SCHEMA: u32 = 1;
    pub const MAX_BYTES: usize = 32 * 1024;

    pub fn validate(&self) -> Result<(), String> {
        if self.schema != Self::SCHEMA {
            return Err(format!(
                "unsupported last-reconciliation schema {}",
                self.schema
            ));
        }
        let valid_attempt = match self.operation.mutation() {
            Some(MutationOperation::Apply) => attempt::is_mutation(&self.attempt_id),
            Some(MutationOperation::Rollback) => attempt::is_compensation(&self.attempt_id),
            None => {
                return Err("last reconciliation must describe a state-changing operation".into())
            }
        };
        if !valid_attempt {
            return Err("last reconciliation has an invalid attempt id".into());
        }
        self.candidate.validate("candidate")?;
        self.predecessor.validate("predecessor")?;
        self.reconciler.validate()?;
        self.result.validate()?;
        if self.result.status != ResultStatus::Succeeded {
            return Err("last reconciliation cannot record an incomplete retry result".into());
        }
        if self.completed_at_ms == 0 {
            return Err("last reconciliation has no completion time".into());
        }
        Ok(())
    }

    pub fn from_bounded_json(bytes: &[u8]) -> Result<Self, String> {
        let record: Self = crate::bounded::decode(bytes, "last reconciliation", Self::MAX_BYTES)?;
        record.validate()?;
        Ok(record)
    }

    pub fn to_bounded_json(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
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

    /// Whether `id` can belong to a state-changing invocation: boot or steady convergence, a
    /// deployment transaction, or that transaction's compensating direction. Observation-only
    /// identities are deliberately excluded from durable reconciliation evidence.
    pub fn is_mutation(id: &str) -> bool {
        matches!(id, BOOT | CONVERGE) || crate::is_canonical_sha256(id) || is_compensation(id)
    }

    /// Whether `id` is the derived compensating direction of one transaction. A `rollback`
    /// mutation accepts only this form; the predecessor's compensating `apply` uses it too.
    pub fn is_compensation(id: &str) -> bool {
        id.strip_suffix('r').is_some_and(crate::is_canonical_sha256)
    }
}

#[cfg(test)]
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
        for operation in [
            Operation::Apply,
            Operation::Healthcheck,
            Operation::Rollback,
            Operation::Inspect,
        ] {
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
    fn result_documents_are_bounded_and_semantically_consistent() {
        let succeeded = ResultDocument {
            schema: ResultDocument::SCHEMA,
            status: ResultStatus::Succeeded,
            changed: true,
            host_action: HostAction::Reboot,
            retry_after_seconds: None,
            message: Some("kernel configuration changed".into()),
        };
        assert_eq!(
            ResultDocument::from_bounded_json(&succeeded.to_bounded_json().unwrap()).unwrap(),
            succeeded
        );

        let retry = ResultDocument {
            schema: ResultDocument::SCHEMA,
            status: ResultStatus::Retry,
            changed: false,
            host_action: HostAction::None,
            retry_after_seconds: Some(30),
            message: Some("package manager is locked".into()),
        };
        assert!(retry.validate().is_ok());

        let mut invalid = retry.clone();
        invalid.host_action = HostAction::Reboot;
        assert!(invalid.validate().is_err());
        invalid = succeeded;
        invalid.retry_after_seconds = Some(1);
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn platform_audit_evidence_binds_a_success_to_both_immutable_releases() {
        let record = LastReconciliation {
            schema: LastReconciliation::SCHEMA,
            operation: Operation::Apply,
            reason: Reason::Update,
            attempt_id: "a".repeat(64),
            candidate: ReconciledRelease {
                version: "2.0.0".into(),
                manifest_sha256: "a".repeat(64),
                archive_sha256: "c".repeat(64),
            },
            predecessor: ReconciledRelease {
                version: "1.0.0".into(),
                manifest_sha256: "b".repeat(64),
                archive_sha256: "d".repeat(64),
            },
            reconciler: ReconcilerIdentity {
                provider_set_sha256: "e".repeat(64),
                product: "system".into(),
                release: ReconciledRelease {
                    version: "3.0.0".into(),
                    manifest_sha256: "f".repeat(64),
                    archive_sha256: "0".repeat(64),
                },
            },
            result: ResultDocument {
                schema: ResultDocument::SCHEMA,
                status: ResultStatus::Succeeded,
                changed: true,
                host_action: HostAction::Reboot,
                retry_after_seconds: None,
                message: Some("kernel changed".into()),
            },
            completed_at_ms: 1,
        };
        assert_eq!(
            LastReconciliation::from_bounded_json(&record.to_bounded_json().unwrap()).unwrap(),
            record
        );

        let mut invalid = record;
        invalid.operation = Operation::Inspect;
        assert!(invalid.validate().is_err());

        invalid.operation = Operation::Rollback;
        invalid.attempt_id = "a".repeat(64);
        assert!(
            invalid.validate().is_err(),
            "rollback evidence must carry the transaction's compensating identity"
        );
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
    fn mutation_identities_have_one_exact_grammar() {
        let transaction = "a".repeat(64);
        assert!(attempt::is_mutation(attempt::BOOT));
        assert!(attempt::is_mutation(attempt::CONVERGE));
        assert!(attempt::is_mutation(&transaction));
        assert!(attempt::is_mutation(&format!("{transaction}r")));
        assert!(attempt::is_compensation(&format!("{transaction}r")));
        assert!(!attempt::is_compensation(&transaction));
        for observation_only in [attempt::PERIODIC, attempt::FINGERPRINT] {
            assert!(!attempt::is_mutation(observation_only));
        }
        for malformed in ["", "attempt", &"A".repeat(64), &format!("{transaction}rr")] {
            assert!(!attempt::is_mutation(malformed));
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
