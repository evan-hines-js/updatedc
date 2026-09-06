//! Wrap existing deployment procedures without taking ownership of their workloads.
use crate::helper::Context;
use serde::{Deserialize, Serialize};
use std::{
    io,
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    time::{Duration, Instant},
};
use updated_contracts::attention::Attention;
use updated_contracts::reconciler::{attempt, Operation, ResultDocument};

pub const CONFIG: &str = ".updated-execution.json";
pub const API: u32 = updated_contracts::helper::API;
pub const MAX_COMMAND_SECONDS: u64 = updated_contracts::helper::MAX_COMMAND_SECONDS;
pub const MAX_HEALTH_SECONDS: u64 = 20;
pub const MAX_INVOCATION_MILLIS: u64 = (2 * MAX_COMMAND_SECONDS + MAX_HEALTH_SECONDS + 5) * 1000;
pub const EXPECTED_DEFINITION_ENV: &str = "UPDATED_EXECUTION_SHA256";
pub fn check_api(api: u32) -> Result<(), String> {
    if api == API {
        Ok(())
    } else {
        Err(format!(
            "agent upgrade required: execution API {api} is unsupported"
        ))
    }
}
pub fn execution_for(payload: &Path, product: &str) -> io::Result<crate::state::ReconcilerRelease> {
    execution_from_bytes(&read_config_bytes(payload)?, product)
}
pub(crate) fn execution_from_bytes(
    bytes: &[u8],
    product: &str,
) -> io::Result<crate::state::ReconcilerRelease> {
    let config = parse_config(bytes)?;
    Ok(crate::state::ReconcilerRelease {
        definition_sha256: updated_contracts::digest::sha256_bytes(bytes),
        product: product.into(),
        api: config.schema,
        timeout_millis: package_info(&config).timeout_millis,
    })
}
pub(crate) const LIMIT: usize = 64 * 1024;
const RECORD_LIMIT: usize = updated_contracts::dataflow::MAX_DATAFLOW_BODY_BYTES
    + updated_contracts::reconciler::MAX_RESULT_BYTES
    + 4096;
fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Procedure {
    argv: Vec<String>,
    timeout_seconds: u64,
}
impl Procedure {
    fn validate(&self) -> io::Result<()> {
        updated_contracts::helper::validate_command(&self.argv, self.timeout_seconds)
            .map_err(invalid)
    }
}

#[derive(Deserialize)]
#[serde(tag = "policy", rename_all = "kebab-case", deny_unknown_fields)]
enum Replay {
    Safe {},
    Check { command: Procedure },
    Manual {},
}
impl Replay {
    fn validate(&self) -> io::Result<()> {
        if let Self::Check { command } = self {
            command.validate()?;
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(tag = "policy", rename_all = "kebab-case", deny_unknown_fields)]
enum Recovery {
    Manual {},
    Command { command: Procedure, replay: Replay },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    schema: u32,
    deploy: Procedure,
    health: Option<Procedure>,
    inspect: Option<Procedure>,
    replay: Replay,
    recovery: Recovery,
}
impl Config {
    fn validate(&self) -> io::Result<()> {
        if self.schema != API {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "agent upgrade required: unsupported execution API",
            ));
        }
        self.deploy
            .validate()
            .map_err(|e| invalid(format!("deploy: {e}")))?;
        if let Some(health) = &self.health {
            health
                .validate()
                .map_err(|e| invalid(format!("health: {e}")))?;
            if health.timeout_seconds > MAX_HEALTH_SECONDS {
                return Err(invalid(
                    "health.timeoutSeconds must be at most 20 to preserve report cadence",
                ));
            }
        }
        if let Some(inspect) = &self.inspect {
            inspect.validate()?;
        }
        self.replay
            .validate()
            .map_err(|e| invalid(format!("replay: {e}")))?;
        if let Recovery::Command { command, replay } = &self.recovery {
            command.validate()?;
            replay.validate()?;
        }
        Ok(())
    }
}

/// Publisher and checker validation. This describes execution bounds, never application resources.
pub struct PackageInfo {
    pub timeout_millis: u64,
    pub manual_recovery: bool,
    pub health_check: bool,
}

#[cfg(test)]
mod budget_tests {
    #[test]
    fn inspection_budget_includes_its_preceding_health_observation() {
        let config: super::Config = serde_json::from_value(serde_json::json!({
            "schema": super::API,
            "deploy": {"argv": ["app"], "timeoutSeconds": 5},
            "health": {"argv": ["health"], "timeoutSeconds": 20},
            "inspect": {"argv": ["inspect"], "timeoutSeconds": 100},
            "replay": {"policy": "safe"},
            "recovery": {"policy": "manual"}
        }))
        .unwrap();
        config.validate().unwrap();
        assert_eq!(super::package_info(&config).timeout_millis, 125_000);
    }
}
pub(crate) fn read_config_bytes(payload: &Path) -> io::Result<Vec<u8>> {
    foundation::file::read_bounded_regular(
        &payload.join(CONFIG),
        LIMIT,
        foundation::file::FinalSymlink::Refuse,
    )
}
fn read_config(payload: &Path) -> io::Result<(Config, Vec<u8>)> {
    let bytes = read_config_bytes(payload)?;
    Ok((parse_config(&bytes)?, bytes))
}
fn parse_config(bytes: &[u8]) -> io::Result<Config> {
    #[derive(Deserialize)]
    struct Header {
        schema: u32,
    }
    let header: Header =
        serde_json::from_slice(bytes).map_err(|_| invalid("invalid execution API header"))?;
    if header.schema == 0 {
        return Err(invalid("execution API must be positive"));
    }
    check_api(header.schema)
        .map_err(|message| io::Error::new(io::ErrorKind::Unsupported, message))?;
    let config: Config = serde_json::from_slice(bytes).map_err(|error| {
        invalid(format!(
            ".updated-execution.json: invalid configuration at line {}, column {}",
            error.line(),
            error.column()
        ))
    })?;
    config.validate()?;
    Ok(config)
}
pub fn inspect_package(payload: &Path) -> io::Result<PackageInfo> {
    Ok(package_info(&read_config(payload)?.0))
}
fn package_info(config: &Config) -> PackageInfo {
    let check_time = |replay: &Replay| match replay {
        Replay::Check { command } => command.timeout_seconds,
        _ => 0,
    };
    let health = config
        .health
        .as_ref()
        .map_or(0, |command| command.timeout_seconds);
    let deploy = config.deploy.timeout_seconds + check_time(&config.replay) + health;
    let recovery = match &config.recovery {
        Recovery::Command { command, replay } => command.timeout_seconds + check_time(replay),
        Recovery::Manual {} => 0,
    };
    PackageInfo {
        timeout_millis: (deploy.max(recovery).max(
            health
                + config
                    .inspect
                    .as_ref()
                    .map_or(0, |command| command.timeout_seconds),
        ) + 5)
            * 1000,
        manual_recovery: matches!(config.recovery, Recovery::Manual {}),
        health_check: config.health.is_some(),
    }
}

fn observe(context: &Context, config: &Config, definition: &str, id: &str) -> io::Result<bool> {
    if let Some(health) = &config.health {
        return Ok(observe_command(context, health, Operation::Healthcheck)? == Some(0));
    }
    // Without a custom probe, readiness attests completed execution, not ongoing workload health.
    let receipt: Option<Receipt> =
        read(&receipt_path(&context.state_dir, id, Operation::Converge))?;
    Ok(receipt.is_some_and(|receipt| {
        receipt.phase == Phase::Complete && receipt.definition == definition
    }))
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    Ready,
    Running,
    Complete,
    Failed,
    NeedsAttention,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Receipt {
    definition: String,
    inputs_sha256: String,
    attempt: String,
    transaction: Option<String>,
    phase: Phase,
    message: String,
    exit_code: Option<i32>,
    completion: Option<Completion>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    result: ResultDocument,
    outputs: updated_contracts::dataflow::FileSnapshot,
    boot_id: String,
}
impl Completion {
    fn capture(context: &Context) -> io::Result<Self> {
        let result = match foundation::file::read_bounded_regular(
            &context.result_file,
            updated_contracts::reconciler::MAX_RESULT_BYTES,
            foundation::file::FinalSymlink::Refuse,
        ) {
            Ok(bytes) => ResultDocument::from_bounded_json(&bytes).map_err(invalid)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => ResultDocument::succeeded(
                true,
                updated_contracts::reconciler::HostAction::None,
                None,
            )
            .map_err(invalid)?,
            Err(error) => return Err(error),
        };
        Ok(Self {
            result,
            outputs: crate::reconciler::snapshot_directory(&context.output_dir)?,
            boot_id: crate::helper::boot_identity()?,
        })
    }
    fn replay(&self, context: &Context) -> io::Result<()> {
        self.outputs.validate().map_err(invalid)?;
        for (name, value) in &self.outputs.files {
            foundation::durable::atomic_write(
                &context.output_dir.join(name),
                ".output-",
                &value.bytes().map_err(invalid)?,
            )?;
        }
        let result = match self.result.clone().into_resolution() {
            updated_contracts::reconciler::MutationResolution::Succeeded(success) => {
                ResultDocument::succeeded(
                    false,
                    if self.boot_id == crate::helper::boot_identity()? {
                        success.host_action()
                    } else {
                        updated_contracts::reconciler::HostAction::None
                    },
                    success.message().map(str::to_owned),
                )
                .map_err(invalid)?
            }
            _ => return Err(invalid("completed execution has a non-successful result")),
        };
        publish(context, result)
    }
}
fn replay_completion(context: &Context, receipt: Option<&Receipt>) -> io::Result<()> {
    match receipt.and_then(|receipt| receipt.completion.as_ref()) {
        Some(completion) => completion.replay(context),
        None => success(context, false), // Operator-verified completion has no invented outputs.
    }
}

/// The immutable payload directory's identity is stable across launches and independent of the
/// per-invocation exchange directory. Definitions are also bound to exact configuration bytes.
pub fn receipt_id(payload: &Path) -> io::Result<String> {
    let name = payload
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| invalid("invalid payload identity"))?;
    Ok(updated_contracts::digest::sha256_bytes(name.as_bytes()))
}

// Private receipt evidence only: this digest is never included in logs or fleet reports.
fn inputs_digest(context: &Context) -> io::Result<String> {
    let inputs = crate::reconciler::snapshot_directory(&context.input_dir)?;
    Ok(updated_contracts::digest::sha256_bytes(
        &serde_json::to_vec(&inputs).map_err(io::Error::other)?,
    ))
}

fn receipt_path(state: &Path, id: &str, operation: Operation) -> PathBuf {
    state
        .join("commands")
        .join(id)
        .join(format!("{}.json", operation.as_str()))
}
trait ExecutionRecord {
    fn validate_record(&self) -> io::Result<()>;
}
impl ExecutionRecord for Attention {
    fn validate_record(&self) -> io::Result<()> {
        self.validate().map_err(invalid)
    }
}
impl ExecutionRecord for Receipt {
    fn validate_record(&self) -> io::Result<()> {
        if !updated_contracts::is_canonical_sha256(&self.definition)
            || !updated_contracts::is_canonical_sha256(&self.inputs_sha256)
            || !(attempt::is_reserved(&self.attempt)
                || attempt::is_transaction_invocation(&self.attempt))
            || self
                .transaction
                .as_ref()
                .is_some_and(|id| !updated_contracts::is_canonical_sha256(id))
            || (!attempt::is_reserved(&self.attempt)
                && self.transaction.as_deref() != Some(self.attempt.trim_end_matches('r')))
            || self.message.len() > updated_contracts::reconciler::MAX_RESULT_MESSAGE_BYTES
        {
            return Err(invalid("invalid execution receipt identity"));
        }
        if let Some(completion) = &self.completion {
            if self.phase != Phase::Complete
                || !matches!(
                    completion.result.clone().into_resolution(),
                    updated_contracts::reconciler::MutationResolution::Succeeded(_)
                )
                || !updated_contracts::is_canonical_sha256(&completion.boot_id)
            {
                return Err(invalid("invalid completed execution evidence"));
            }
            completion.outputs.validate().map_err(invalid)?;
        }
        Ok(())
    }
}
fn read<T: serde::de::DeserializeOwned + ExecutionRecord>(path: &Path) -> io::Result<Option<T>> {
    match foundation::file::read_bounded_regular(
        path,
        RECORD_LIMIT,
        foundation::file::FinalSymlink::Refuse,
    ) {
        Ok(bytes) => {
            let record: T = serde_json::from_slice(&bytes)
                .map_err(|_| invalid("invalid command execution record"))?;
            record.validate_record()?;
            Ok(Some(record))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
fn write(path: &Path, value: &(impl Serialize + ExecutionRecord)) -> io::Result<()> {
    value.validate_record()?;
    std::fs::create_dir_all(foundation::durable::parent_dir(path))?;
    let bytes = serde_json::to_vec(value).map_err(io::Error::other)?;
    if bytes.len() > RECORD_LIMIT {
        return Err(invalid("execution record exceeds size limit"));
    }
    foundation::durable::atomic_write(path, ".commands-", &bytes)
}

fn attention_path(root: &Path) -> PathBuf {
    root.join("state/attention.json")
}
pub fn read_attention(root: &Path) -> io::Result<Option<Attention>> {
    let record: Option<Attention> = read(&attention_path(root))?;
    if let Some(record) = &record {
        record.validate().map_err(invalid)?;
    }
    Ok(record)
}
pub fn write_attention(root: &Path, record: &Attention) -> io::Result<()> {
    record.validate().map_err(invalid)?;
    write(&attention_path(root), record)
}

/// These local operator actions require the service to be stopped for a decision. Status is
/// read-only; resolution uses the same nonblocking installation lock as the agent.
pub fn control_dispatch() -> Option<ExitCode> {
    let mut args = std::env::args_os().skip(1);
    let action = args.next()?;
    if action != "command-status" && action != "command-resume" {
        return None;
    }
    let result = (|| {
        let root = PathBuf::from(
            args.next()
                .ok_or_else(|| invalid("an installation root is required"))?,
        );
        let decision = args.next();
        if args.next().is_some() {
            return Err(invalid("unexpected command control arguments"));
        }
        if action == "command-status" {
            if decision.is_some() {
                return Err(invalid("status takes only the installation root"));
            }
            println!(
                "{}",
                serde_json::to_string(&read_attention(&root)?).map_err(io::Error::other)?
            );
        } else {
            let decision = decision
                .as_deref()
                .and_then(|s| s.to_str())
                .ok_or_else(|| invalid("resume requires retry, complete, or recovered"))?;
            resolve(&root, decision)?;
        }
        Ok(())
    })();
    Some(match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("command adapter: {error}");
            ExitCode::FAILURE
        }
    })
}

pub fn resolve(root: &Path, decision: &str) -> io::Result<()> {
    if !["retry", "complete", "recovered"].contains(&decision) {
        return Err(invalid("decision must be retry, complete, or recovered"));
    }
    let paths = crate::config::Paths::resolve(root, root);
    let _lock = paths.lock_installation()?;
    let hold =
        read_attention(root)?.ok_or_else(|| invalid("this installation has no attention hold"))?;
    let state = paths.reconciler_state_dir(&hold.product);
    let path = receipt_path(&state, &hold.receipt, hold.operation.operation());
    let mut receipt: Receipt =
        read(&path)?.ok_or_else(|| invalid("this hold has no command adapter receipt"))?;
    let message = format!("operator decision: {decision}");
    let phase = if decision == "retry" {
        Phase::Ready
    } else {
        Phase::Complete
    };
    if receipt.attempt != hold.attempt
        || !(receipt.phase == Phase::NeedsAttention
            || (receipt.phase == phase && receipt.message == message))
    {
        return Err(invalid(
            "attention hold does not match the command receipt or recorded decision",
        ));
    }
    let forward = hold.attempt.strip_suffix('r').unwrap_or(&hold.attempt);
    if decision == "recovered" && !updated_contracts::is_canonical_sha256(forward) {
        return Err(invalid("recovered applies only to a transaction"));
    }
    // All decisions are validated before the first write. Repeating the same decision after a
    // crash completes the remaining writes and clears the hold last.
    receipt.message = message;
    receipt.phase = phase;
    write(&path, &receipt)?;
    if decision == "recovered" {
        receipt.attempt = format!("{forward}r");
        write(
            &receipt_path(&state, &hold.receipt, Operation::Rollback),
            &receipt,
        )?;
    }
    if hold.operation.operation() == Operation::Rollback && decision != "recovered" {
        let forward_path = receipt_path(&state, &hold.receipt, Operation::Converge);
        if let Some(mut forward_receipt) = read::<Receipt>(&forward_path)? {
            if forward_receipt.attempt == forward && forward_receipt.phase == Phase::NeedsAttention
            {
                forward_receipt.phase = Phase::Failed;
                forward_receipt.message = "operator authorized recovery decision".into();
                write(&forward_path, &forward_receipt)?;
            }
        }
    }
    foundation::durable::remove_path(&attention_path(root))
}

/// The native runtime is embedded in the distributed agent executable.
/// Normal agent and helper invocations are not intercepted.
pub fn dispatch() -> Option<ExitCode> {
    let operation = std::env::args_os()
        .nth(1)?
        .to_str()?
        .parse::<Operation>()
        .ok()?;
    let result = (|| {
        let context: Context = serde_json::from_str(
            &std::env::var(updated_contracts::helper::CONTEXT_ENV)
                .map_err(|_| invalid("command adapter requires an agent invocation"))?,
        )
        .map_err(|_| invalid("invalid adapter invocation context"))?;
        context.validate()?;
        if context.operation != operation {
            return Err(invalid("operation does not match invocation context"));
        }
        run(&context)
    })();
    Some(match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("command adapter: {error}");
            ExitCode::FAILURE
        }
    })
}

fn run(context: &Context) -> io::Result<()> {
    let (config, bytes) = read_config(&context.payload_root)?;
    let definition = updated_contracts::digest::sha256_bytes(&bytes);
    if std::env::var(EXPECTED_DEFINITION_ENV).is_ok_and(|expected| expected != definition) {
        return Err(invalid(
            "package execution definition differs from its transaction",
        ));
    }
    let id = receipt_id(&context.payload_root)?;
    if context.operation.observation().is_some() {
        if !observe(context, &config, &definition, &id)? {
            return Err(io::Error::other("health command failed"));
        }
        if context.operation == Operation::Inspect {
            if let Some(inspect) = &config.inspect {
                return if observe_command(context, inspect, Operation::Inspect)? == Some(0) {
                    Ok(())
                } else {
                    Err(io::Error::other("inspection failed"))
                };
            }
            // This describes observed readiness and the requested artifact, not a resource diff.
            println!(
                "payload={id}\n{}",
                if config.health.is_some() {
                    "health=ready"
                } else {
                    "execution=complete"
                }
            );
        }
        return Ok(());
    }
    let lock = crate::lock::InstanceLock::acquire(&context.state_dir.join("commands/.lock"));
    let _lock = match lock {
        Ok(lock) => lock,
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
            return publish(
                context,
                ResultDocument::retry(1, Some("another command owns this application".into()))
                    .map_err(invalid)?,
            )
        }
        Err(error) => return Err(error),
    };
    let path = receipt_path(&context.state_dir, &id, context.operation);
    let prior: Option<Receipt> = read(&path)?;
    if prior.as_ref().is_some_and(|r| r.definition != definition) {
        return Err(invalid(
            "deployment receipt does not match its immutable definition",
        ));
    }

    // The candidate's explicit recovery command owns restoration. Replay the predecessor's
    // output evidence without repeating an old deployment procedure. Readiness belongs to the
    // platform's bounded health gate: a one-shot probe here can catch a service still starting
    // and strand an otherwise successful rollback behind a permanent attention hold.
    if context.operation == Operation::Converge && attempt::is_compensation(&context.attempt_id) {
        return replay_completion(context, prior.as_ref());
    }

    let inputs_sha256 = inputs_digest(context)?;
    let inputs_changed = prior
        .as_ref()
        .is_some_and(|r| r.inputs_sha256 != inputs_sha256);
    if inputs_changed
        && prior
            .as_ref()
            .is_some_and(|r| !matches!(r.phase, Phase::Complete | Phase::Ready))
    {
        return attention(
            context,
            &path,
            &definition,
            "assigned inputs changed while command completion is uncertain",
        );
    }
    let same_attempt = prior
        .as_ref()
        .is_some_and(|r| r.attempt == context.attempt_id);
    if prior
        .as_ref()
        .is_some_and(|r| r.phase == Phase::NeedsAttention)
    {
        return attention(
            context,
            &path,
            &definition,
            "this command requires an explicit operator decision",
        );
    }
    if context.operation == Operation::Rollback {
        if same_attempt && prior.as_ref().is_some_and(|r| r.phase == Phase::Complete) {
            return replay_completion(context, prior.as_ref());
        }
        let forward: Option<Receipt> =
            read(&receipt_path(&context.state_dir, &id, Operation::Converge))?;
        if forward.as_ref().is_some_and(|r| r.definition != definition) {
            return Err(invalid(
                "recovery receipt does not match its immutable definition",
            ));
        }
        if forward
            .as_ref()
            .is_none_or(|r| r.transaction.as_deref() != context.attempt_id.strip_suffix('r'))
        {
            return success(context, false); // This transaction never authorized a deployment command.
        }
        if forward
            .as_ref()
            .is_some_and(|r| r.phase == Phase::NeedsAttention)
        {
            return attention(
                context,
                &path,
                &definition,
                "deployment outcome is unknown; automatic recovery is paused",
            );
        }
    }
    let (command, replay) = match context.operation {
        Operation::Converge => (&config.deploy, &config.replay),
        Operation::Rollback => match &config.recovery {
            Recovery::Command { command, replay } => (command, replay),
            Recovery::Manual {} => {
                return attention(
                    context,
                    &path,
                    &definition,
                    "deployment requires operator-managed recovery",
                )
            }
        },
        _ => unreachable!(),
    };
    let completed = prior.as_ref().is_some_and(|r| r.phase == Phase::Complete);
    // A receipt is evidence of a finished command, not proof of current application health.
    if context.operation == Operation::Converge
        && completed
        && !inputs_changed
        && (same_attempt || attempt::is_reserved(&context.attempt_id))
        && observe(context, &config, &definition, &id)?
    {
        return replay_completion(context, prior.as_ref());
    }
    let uncertain = prior.as_ref().is_some_and(|r| {
        r.phase != Phase::Ready && !(r.phase == Phase::Complete && inputs_changed)
    }) && (same_attempt
        || attempt::is_reserved(&context.attempt_id)
        || prior.as_ref().is_some_and(|r| r.phase != Phase::Complete));
    if uncertain {
        match replay {
            Replay::Safe {} => (),
            Replay::Manual {} => {
                return attention(
                    context,
                    &path,
                    &definition,
                    "repeating the deployment command is not authorized",
                )
            }
            Replay::Check { command } => {
                match observe_command(context, command, Operation::Healthcheck) {
                    Ok(Some(0)) => {
                        write(
                            &path,
                            &Receipt {
                                transaction: transaction_identity(
                                    prior.as_ref(),
                                    &context.attempt_id,
                                ),
                                definition,
                                inputs_sha256,
                                attempt: context.attempt_id.clone(),
                                phase: Phase::Complete,
                                message: "completion verified".into(),
                                exit_code: Some(0),
                                completion: None,
                            },
                        )?;
                        return success(context, false);
                    }
                    Ok(Some(10)) => (), // The application explicitly proves repeating is safe.
                    _ => {
                        return attention(
                            context,
                            &path,
                            &definition,
                            "completion check could not prove completion or safe repetition",
                        )
                    }
                }
            }
        }
    }
    let mut receipt = Receipt {
        transaction: transaction_identity(prior.as_ref(), &context.attempt_id),
        definition: definition.clone(),
        inputs_sha256,
        attempt: context.attempt_id.clone(),
        phase: Phase::Running,
        message: "command started".into(),
        exit_code: None,
        completion: None,
    };
    write(&path, &receipt)?; // Must survive a kill between spawn and command completion.
    let outcome = launch(context, command);
    match outcome {
        Ok(Some(0)) => {
            let completion = Completion::capture(context)?;
            match completion.result.clone().into_resolution() {
                updated_contracts::reconciler::MutationResolution::Succeeded(_) => {
                    receipt.phase = Phase::Complete;
                    receipt.exit_code = Some(0);
                    receipt.message = "command completed".into();
                    let result = completion.result.clone();
                    receipt.completion = Some(completion);
                    write(&path, &receipt)?;
                    publish(context, result)
                }
                updated_contracts::reconciler::MutationResolution::Retry(_) => {
                    receipt.phase = Phase::Ready; // Explicit request authorizes the same attempt to continue.
                    receipt.message = "command requested retry".into();
                    write(&path, &receipt)?;
                    publish(context, completion.result)
                }
                updated_contracts::reconciler::MutationResolution::NeedsAttention(message) => {
                    attention(context, &path, &definition, &message)
                }
            }
        }
        outcome => {
            receipt.phase = Phase::Failed;
            receipt.exit_code = outcome.as_ref().ok().copied().flatten();
            receipt.message = match &outcome {
                Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                    "command deadline exceeded"
                }
                _ => "command failed",
            }
            .into();
            write(&path, &receipt)?;
            if context.operation == Operation::Rollback {
                attention(
                    context,
                    &path,
                    &definition,
                    "recovery command failed; operator attention required",
                )
            } else {
                Err(io::Error::other(format!(
                    "deployment {} (exit {:?})",
                    receipt.message, receipt.exit_code
                )))
            }
        }
    }
}

// A routine repair must not erase the transaction still protected by its confirmation window.
fn transaction_identity(prior: Option<&Receipt>, attempt_id: &str) -> Option<String> {
    if attempt::is_reserved(attempt_id) {
        prior.and_then(|receipt| receipt.transaction.clone())
    } else {
        Some(attempt_id.trim_end_matches('r').into())
    }
}

fn attention(context: &Context, path: &Path, definition: &str, message: &str) -> io::Result<()> {
    let previous = read::<Receipt>(path)?;
    let exit_code = previous.as_ref().and_then(|r| r.exit_code);
    let transaction = transaction_identity(previous.as_ref(), &context.attempt_id);
    let inputs_sha256 = match previous {
        Some(receipt) => receipt.inputs_sha256,
        None => inputs_digest(context)?,
    };
    write(
        path,
        &Receipt {
            transaction,
            definition: definition.into(),
            inputs_sha256,
            attempt: context.attempt_id.clone(),
            phase: Phase::NeedsAttention,
            message: message.into(),
            exit_code,
            completion: None,
        },
    )?;
    publish(
        context,
        ResultDocument::needs_attention(message.into()).map_err(invalid)?,
    )
}
fn success(context: &Context, changed: bool) -> io::Result<()> {
    publish(
        context,
        ResultDocument::succeeded(
            changed,
            updated_contracts::reconciler::HostAction::None,
            None,
        )
        .map_err(invalid)?,
    )
}
fn publish(context: &Context, result: ResultDocument) -> io::Result<()> {
    foundation::durable::atomic_write(
        &context.result_file,
        ".command-result-",
        &result.to_bounded_json().map_err(invalid)?,
    )
}

fn observe_command(
    context: &Context,
    procedure: &Procedure,
    operation: Operation,
) -> io::Result<Option<i32>> {
    let observation = context.observing(
        operation
            .observation()
            .ok_or_else(|| invalid("expected observation"))?,
    );
    let outcome = launch(&observation, procedure)?;
    crate::reconciler::take_result(&context.result_file, operation)?;
    if !crate::reconciler::snapshot_directory(&context.output_dir)?.is_empty() {
        return Err(invalid("observation must not publish outputs"));
    }
    Ok(outcome)
}

fn launch(context: &Context, procedure: &Procedure) -> io::Result<Option<i32>> {
    let executable = Path::new(&procedure.argv[0]);
    let executable = if executable.is_relative() && executable.components().count() > 1 {
        context.payload_root.join(executable)
    } else {
        executable.to_path_buf()
    };
    let mut command = Command::new(executable);
    command
        .args(&procedure.argv[1..])
        .current_dir(&context.payload_root)
        .stdin(Stdio::null())
        .stdout(if context.operation == Operation::Inspect {
            Stdio::inherit()
        } else {
            Stdio::from(io::stderr())
        })
        .stderr(Stdio::inherit())
        .env("UPDATED_INSTALL_ROOT", &context.install_root)
        .env("UPDATED_RESULT_FILE", &context.result_file)
        .env("UPDATED_OUTPUT_DIR", &context.output_dir)
        .env("UPDATED_REASON", context.reason.as_str())
        .env("UPDATED_PAYLOAD_ROOT", &context.payload_root)
        .env("UPDATED_PAYLOAD_VERSION", &context.payload_version)
        .env("UPDATED_INPUT_DIR", &context.input_dir)
        .env("UPDATED_STATE_DIR", &context.state_dir)
        .env("UPDATED_ATTEMPT_ID", &context.attempt_id)
        .env("UPDATED_OPERATION", context.operation.as_str())
        .env(
            updated_contracts::helper::CONTEXT_ENV,
            serde_json::to_string(context).map_err(io::Error::other)?,
        );
    let deadline = Instant::now() + Duration::from_secs(procedure.timeout_seconds);
    foundation::process::run_to_exit(command, deadline)
}
