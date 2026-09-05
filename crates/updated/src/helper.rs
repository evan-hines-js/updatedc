//! Native helper embedded in the agent and publisher. One request on stdin, one JSON response.
//! No runtime, enrollment, or network initialization is needed to enter this subcommand.
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    path::{Path, PathBuf},
    process::{Command, ExitCode, Stdio},
    time::{Duration, Instant},
};
use updated_contracts::{
    helper as contract,
    reconciler::{Arguments, MutationResolution, Operation, Reason, ResultDocument},
};

const LIMIT: usize = 1024 * 1024;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Context {
    pub(crate) protocol: String,
    pub(crate) operation: Operation,
    pub(crate) attempt_id: String,
    pub(crate) reason: Reason,
    pub(crate) install_root: PathBuf,
    pub(crate) state_dir: PathBuf,
    pub(crate) payload_root: PathBuf,
    pub(crate) payload_version: String,
    pub(crate) input_dir: PathBuf,
    pub(crate) output_dir: PathBuf,
    pub(crate) result_file: PathBuf,
}

impl Context {
    pub(crate) fn validate(&self) -> io::Result<()> {
        if self.protocol != updated_contracts::reconciler::PROTOCOL {
            return Err(invalid("unsupported reconciler protocol"));
        }
        self.operation
            .validate_invocation(self.reason, &self.attempt_id)
            .map_err(invalid)
    }
    pub(crate) fn observing(
        &self,
        operation: updated_contracts::reconciler::ObservationOperation,
    ) -> Self {
        let mut context = self.clone();
        context.operation = operation.operation();
        if self.operation == Operation::Inspect && context.operation == Operation::Healthcheck {
            context.attempt_id = updated_contracts::reconciler::attempt::PERIODIC.into();
        }
        context
    }
    fn mutation(&self) -> io::Result<()> {
        self.validate()?;
        if self.operation.mutation().is_none() {
            return Err(invalid("observations cannot use mutation helpers"));
        }
        Ok(())
    }
}

/// Copy once at agent startup, while its enrollment lock is held. This private, fixed-size cache
/// retains the executing helper through atomic replacement of the distributed agent binary.
/// Never called by a health probe or an individual invocation.
pub fn pin(source: &Path, directory: &Path) -> io::Result<PathBuf> {
    match foundation::durable::create_private_directory(directory) {
        Ok(()) => (),
        Err(e)
            if e.kind() == io::ErrorKind::AlreadyExists
                && std::fs::symlink_metadata(directory)?.is_dir() => {}
        Err(e) => return Err(e),
    }
    let target = directory.join(if cfg!(windows) {
        "updated-helper.exe"
    } else {
        "updated-helper"
    });
    crate::native_runtime::install(source, &target)?;
    Ok(target)
}

/// Called after the shared environment scrub. Application input values stay in files.
pub fn configure(
    command: &mut Command,
    executable: &Path,
    operation: Operation,
    args: &Arguments<'_>,
) -> io::Result<()> {
    let string = |value: &std::ffi::OsStr| {
        value
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| invalid("helper context needs UTF-8 protocol values"))
    };
    let context = Context {
        protocol: string(args.protocol)?,
        operation,
        attempt_id: string(args.attempt_id)?,
        reason: args.reason,
        install_root: args.install_root.into(),
        state_dir: args.state_dir.into(),
        payload_root: args.payload_root.into(),
        payload_version: string(args.payload_version)?,
        input_dir: args.input_dir.into(),
        output_dir: args.output_dir.into(),
        result_file: args.result_file.into(),
    };
    // Unknown protocol/operation probes are owned by the conformance harness. Normal invocations
    // are validated by the caller and again by every helper request before it touches state.
    let json = serde_json::to_string(&context).map_err(io::Error::other)?;
    command
        .env(contract::EXECUTABLE_ENV, executable)
        .env(contract::CONTEXT_ENV, json);
    Ok(())
}

#[derive(Deserialize)]
struct Request {
    api: u32,
    #[serde(flatten)]
    action: Action,
}

#[derive(Deserialize)]
#[serde(
    tag = "command",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
enum Action {
    Capabilities {},
    Context {},
    BootId {},
    Succeed {
        #[serde(default)]
        changed: bool,
        #[serde(default)]
        reboot: bool,
        #[serde(default)]
        message: Option<String>,
        #[serde(default)]
        outputs: BTreeMap<String, String>,
    },
    Retry {
        after_seconds: u64,
        #[serde(default)]
        message: Option<String>,
    },
    Result {
        result: ResultDocument,
        #[serde(default)]
        outputs: BTreeMap<String, String>,
    },
    Output {
        name: String,
        content: String,
    },
    File {
        path: PathBuf,
        content: String,
    },
    Sequence {
        resource: String,
        steps: Vec<Step>,
        timeout_seconds: u64,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Step {
    id: String,
    definition_sha256: String,
    check: Vec<String>,
    apply: Vec<String>,
    timeout_seconds: u64,
}

impl Step {
    fn validate(&self) -> io::Result<()> {
        if !updated_contracts::identity::is_segment(&self.id)
            || !updated_contracts::is_canonical_sha256(&self.definition_sha256)
            || contract::validate_command(&self.check, self.timeout_seconds).is_err()
            || contract::validate_command(&self.apply, self.timeout_seconds).is_err()
        {
            return Err(invalid(
                "invalid migration step identity, commands, or timeout",
            ));
        }
        Ok(())
    }

    fn path(&self, directory: &Path) -> PathBuf {
        directory.join(format!("{}.json", self.id))
    }

    fn validate_progress(&self, directory: &Path) -> io::Result<()> {
        match foundation::file::read_bounded_regular(
            &self.path(directory),
            1024,
            foundation::file::FinalSymlink::Refuse,
        ) {
            Ok(bytes) => {
                let progress: Progress = serde_json::from_slice(&bytes)
                    .map_err(|_| invalid("invalid migration progress"))?;
                if progress.definition_sha256 != self.definition_sha256 {
                    return Err(invalid(
                        "migration identity was reused with a different definition",
                    ));
                }
                Ok(())
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// Return `None` for an ordinary agent/publisher invocation. Helper dispatch precedes all other
/// initialization, including argument parsing and the async runtime.
pub fn dispatch() -> Option<ExitCode> {
    let mut args = std::env::args_os().skip(1);
    if args.next().as_deref() != Some(std::ffi::OsStr::new(contract::SUBCOMMAND)) {
        return None;
    }
    let result = if args.next().is_some() {
        Err(invalid(
            "helper accepts a JSON request on stdin, no additional arguments",
        ))
    } else {
        let mut body = Vec::new();
        io::stdin()
            .take((LIMIT + 1) as u64)
            .read_to_end(&mut body)
            .and_then(|_| handle(&body))
    };
    let (response, exit) = match result {
        Ok(value) => (
            serde_json::json!({"api":contract::API,"ok":true,"value":value}),
            ExitCode::SUCCESS,
        ),
        Err(error) => {
            let code = match error.kind() {
                io::ErrorKind::WouldBlock => "busy",
                io::ErrorKind::TimedOut => "timeout",
                io::ErrorKind::Unsupported => "unsupported",
                _ => "failed",
            };
            (
                serde_json::json!({"api":contract::API,"ok":false,"error":{"code":code,"message":error.to_string()}}),
                ExitCode::FAILURE,
            )
        }
    };
    let mut stdout = io::stdout().lock();
    if serde_json::to_writer(&mut stdout, &response)
        .and_then(|_| stdout.write_all(b"\n").map_err(serde_json::Error::io))
        .is_err()
    {
        return Some(ExitCode::FAILURE);
    }
    Some(exit)
}

fn handle(body: &[u8]) -> io::Result<serde_json::Value> {
    if body.len() > LIMIT {
        return Err(invalid("helper request exceeds 1 MiB"));
    }
    // Do not echo malformed input: requests may contain credentials.
    let request: Request =
        serde_json::from_slice(body).map_err(|_| invalid("invalid helper request"))?;
    if request.api != contract::API {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "unsupported helper API; upgrade the agent",
        ));
    }
    if matches!(request.action, Action::Capabilities {}) {
        return serde_json::to_value(contract::Support::current()).map_err(io::Error::other);
    }
    let context: Context = serde_json::from_str(
        &std::env::var(contract::CONTEXT_ENV)
            .map_err(|_| invalid("helper must run inside a reconciler invocation"))?,
    )
    .map_err(|_| invalid("invalid helper invocation context"))?;
    execute(&context, request.action)
}

fn execute(context: &Context, action: Action) -> io::Result<serde_json::Value> {
    context.validate()?;
    let action = match action {
        Action::Succeed {
            changed,
            reboot,
            message,
            outputs,
        } => Action::Result {
            result: ResultDocument::succeeded(
                changed,
                if reboot {
                    updated_contracts::reconciler::HostAction::Reboot
                } else {
                    updated_contracts::reconciler::HostAction::None
                },
                message,
            )
            .map_err(invalid)?,
            outputs,
        },
        Action::Retry {
            after_seconds,
            message,
        } => Action::Result {
            result: ResultDocument::retry(after_seconds, message).map_err(invalid)?,
            outputs: BTreeMap::new(),
        },
        action => action,
    };
    if matches!(action, Action::Context {}) {
        return serde_json::to_value(context).map_err(io::Error::other);
    }
    if matches!(action, Action::BootId {}) {
        return Ok(serde_json::json!({"bootId":boot_identity()?}));
    }
    context.mutation()?;
    match action {
        Action::Result { result, outputs } => {
            let encoded = result.to_bounded_json().map_err(invalid)?;
            if matches!(result.into_resolution(), MutationResolution::Succeeded(_)) {
                // Validate the whole declaration before writing any file. Each successful replay
                // publishes its complete outputs, regardless of the `changed` result.
                let mut snapshot = updated_contracts::dataflow::FileSnapshot::default();
                for (name, content) in &outputs {
                    snapshot.files.insert(
                        name.clone(),
                        updated_contracts::dataflow::FileValue::from_bytes(content.as_bytes())
                            .map_err(invalid)?,
                    );
                }
                snapshot.validate().map_err(invalid)?;
                for (name, content) in outputs {
                    output(context, &name, &content)?;
                }
                crate::reconciler::snapshot_directory(&context.output_dir)?;
            } else if !outputs.is_empty() {
                return Err(invalid("an incomplete result cannot publish outputs"));
            }
            foundation::durable::atomic_write(&context.result_file, ".helper-result-", &encoded)?;
            Ok(serde_json::json!({}))
        }
        Action::Output { name, content } => {
            output(context, &name, &content)?;
            Ok(serde_json::json!({}))
        }
        Action::File { path, content } => {
            Ok(serde_json::json!({"changed": converge_file(&path, content.as_bytes())?}))
        }
        Action::Sequence {
            resource,
            steps,
            timeout_seconds,
        } => sequence(context, &resource, &steps, timeout_seconds),
        _ => Err(invalid("invalid mutation helper command")),
    }
}

fn output(context: &Context, name: &str, content: &str) -> io::Result<()> {
    if !updated_contracts::dataflow::FileSnapshot::valid_name(name) {
        return Err(invalid("invalid output name"));
    }
    updated_contracts::dataflow::FileValue::from_bytes(content.as_bytes()).map_err(invalid)?;
    foundation::durable::atomic_write(
        &context.output_dir.join(name),
        ".helper-output-",
        content.as_bytes(),
    )
}

fn converge_file(path: &Path, content: &[u8]) -> io::Result<bool> {
    match foundation::file::read_bounded_regular(
        path,
        LIMIT,
        foundation::file::FinalSymlink::Refuse,
    ) {
        Ok(existing) if existing == content => return Ok(false),
        Ok(_) => (),
        Err(e) if e.kind() == io::ErrorKind::NotFound => (),
        Err(e) => return Err(e),
    }
    std::fs::create_dir_all(foundation::durable::parent_dir(path))?;
    foundation::durable::atomic_write(path, ".helper-file-", content)?;
    Ok(true)
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Progress {
    definition_sha256: String,
    complete: bool,
}

fn sequence(
    context: &Context,
    resource: &str,
    steps: &[Step],
    timeout: u64,
) -> io::Result<serde_json::Value> {
    if !updated_contracts::identity::is_segment(resource)
        || steps.is_empty()
        || steps.len() > contract::MAX_SEQUENCE_STEPS
        || !(1..=contract::MAX_COMMAND_SECONDS).contains(&timeout)
    {
        return Err(invalid(
            "invalid migration sequence resource, length, or timeout",
        ));
    }
    // Reject the complete declaration before any child runs, including a bad later step.
    let mut identities = std::collections::BTreeSet::new();
    for step in steps {
        step.validate()?;
        if !identities.insert(&step.id) {
            return Err(invalid("duplicate migration step identity"));
        }
    }
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let directory = context.state_dir.join("helper-steps").join(resource);
    // One lock spans the entire sequence. Another cooperating local invocation cannot interleave
    // transitions between steps. This is not a distributed application lock.
    std::fs::create_dir_all(&directory)?;
    let _lock = crate::lock::InstanceLock::acquire(&directory.join(".lock"))?;
    for step in steps {
        step.validate_progress(&directory)?;
    }
    let mut changed = false;
    for (index, step) in steps.iter().enumerate() {
        eprintln!("migration step {}/{}: {}", index + 1, steps.len(), step.id);
        changed |= run_step(context, &directory, step, deadline).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "migration step {} ({}/{}): {error}",
                    step.id,
                    index + 1,
                    steps.len()
                ),
            )
        })?;
    }
    Ok(serde_json::json!({"changed":changed,"completed":steps.len()}))
}

/// The only checked-effect implementation, used for both a single step and a longer sequence.
/// The caller holds the resource lock and has validated every declaration and prior identity.
fn run_step(
    context: &Context,
    directory: &Path,
    step: &Step,
    sequence_deadline: Instant,
) -> io::Result<bool> {
    let path = step.path(directory);
    let persist = |complete| {
        foundation::durable::atomic_write(
            &path,
            ".helper-step-",
            &serde_json::to_vec(&Progress {
                definition_sha256: step.definition_sha256.clone(),
                complete,
            })
            .map_err(io::Error::other)?,
        )
    };
    let deadline =
        sequence_deadline.min(Instant::now() + Duration::from_secs(step.timeout_seconds));
    // A marker is never proof that an arbitrary effect completed. Inspect the destination on
    // EVERY invocation, including after a previous completion and after an interrupted apply.
    let observation =
        context.observing(updated_contracts::reconciler::ObservationOperation::Healthcheck);
    let changed = match run_child(&observation, &step.check, deadline)? {
        Some(0) => false,
        Some(10) => {
            persist(false)?; // bind identity before the external effect
            if run_child(context, &step.apply, deadline)? != Some(0) {
                return Err(io::Error::other("migration apply failed"));
            }
            if run_child(&observation, &step.check, deadline)? != Some(0) {
                return Err(io::Error::other("migration postcondition was not verified"));
            }
            true
        }
        _ => {
            return Err(io::Error::other(
                "migration observation failed; no apply was attempted",
            ))
        }
    };
    persist(true)?;
    Ok(changed)
}

fn run_child(context: &Context, argv: &[String], deadline: Instant) -> io::Result<Option<i32>> {
    let mut command = Command::new(&argv[0]);
    command
        .args(&argv[1..])
        .env(
            contract::CONTEXT_ENV,
            serde_json::to_string(context).map_err(io::Error::other)?,
        )
        .env("UPDATED_OPERATION", context.operation.as_str())
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    // Child output is diagnostic; reserve the helper's stdout for its one JSON response.
    command.stdout(Stdio::from(io::stderr()));
    foundation::process::run_to_exit(command, deadline)
}

/// Stable across service restarts; changes only when the OS reports a new boot session.
pub fn boot_identity() -> io::Result<String> {
    foundation::boot::identity().map(|bytes| updated_contracts::digest::sha256_bytes(&bytes))
}
