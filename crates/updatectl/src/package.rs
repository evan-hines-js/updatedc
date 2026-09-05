//! The customer surface is a package and an entrypoint. Runtime metadata is generated privately.
use crate::*;

#[derive(Clone, Copy, Debug, ValueEnum)]
pub(crate) enum ReplayPolicy {
    Manual,
    Safe,
}
impl ReplayPolicy {
    fn name(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Safe => "safe",
        }
    }
}

#[derive(Args, Debug)]
pub(crate) struct ProcedureArgs {
    /// Program or script inside the package to execute. No reconciler protocol is required.
    #[arg(long)]
    pub(crate) entrypoint: Option<String>,
    /// Interpreter executable, such as python3 or pwsh. Omit for a native executable or shebang script.
    #[arg(long, requires = "entrypoint")]
    interpreter: Option<String>,
    /// Literal argument for the entrypoint (repeatable). Assigned secrets belong in input files.
    #[arg(long = "arg", requires = "entrypoint", allow_hyphen_values = true)]
    arguments: Vec<String>,
    /// Optional package script for ongoing health checks, using the same interpreter.
    #[arg(long, requires = "entrypoint")]
    healthcheck: Option<String>,
    /// Optional package program that emits measured state for fleet fingerprints.
    #[arg(long, requires = "entrypoint")]
    inspect: Option<String>,
    /// Deadline for deployment and recovery commands in seconds.
    #[arg(long, default_value_t = 300, requires = "entrypoint", value_parser = clap::value_parser!(u64).range(1..=3600))]
    timeout_seconds: u64,
    /// Permission to repeat after interruption. Manual pauses for a decision; safe authorizes replay.
    #[arg(long, value_enum, default_value_t = ReplayPolicy::Manual, requires = "entrypoint")]
    replay: ReplayPolicy,
    /// Optional package script that restores application state after a failed deployment.
    #[arg(long, requires = "entrypoint")]
    recover: Option<String>,
    /// Permission to repeat an interrupted recovery command.
    #[arg(long, value_enum, default_value_t = ReplayPolicy::Manual, requires = "recover")]
    recovery_replay: ReplayPolicy,
}

#[derive(Args, Debug)]
pub(crate) struct CheckArgs {
    /// Package directory. Without --against this validates without executing customer code.
    source: PathBuf,
    #[command(flatten)]
    procedure: ProcedureArgs,
    /// Execute conformance checks using this predecessor fixture. Commands run on the test host.
    #[arg(long)]
    against: Option<PathBuf>,
}

pub(crate) struct PreparedPackage {
    pub(crate) source: PathBuf,
    pub(crate) info: updated::command_adapter::PackageInfo,
    _scratch: Option<tempfile::TempDir>,
}

pub(crate) fn prepare(source: &Path, procedure: &ProcedureArgs) -> Result<PreparedPackage, Error> {
    let source = std::fs::canonicalize(source)?;
    let scratch = tempfile::tempdir()?;
    let staged = scratch.path().join("payload");
    std::fs::create_dir(&staged)?;
    if staged.starts_with(&source) {
        return Err("package source must not contain the temporary staging directory".into());
    }
    crate::package_check::copy_fixture(&source, &staged)?;
    let Some(entrypoint) = &procedure.entrypoint else {
        if !staged.join(updated::command_adapter::CONFIG).exists() {
            return Err(
                "specify --entrypoint with the program or script inside your package".into(),
            );
        }
        let info = updated::command_adapter::inspect_package(&staged)?;
        return Ok(PreparedPackage {
            source: staged,
            info,
            _scratch: Some(scratch),
        });
    };
    if staged.join(updated::command_adapter::CONFIG).exists() {
        return Err("--entrypoint generates execution metadata; remove .updated-execution.json or omit --entrypoint to use its explicit configuration".into());
    }
    let command =
        |path: &str, arguments: &[String], timeout: u64| -> Result<serde_json::Value, Error> {
            let path = path.replace('\\', "/");
            let path = path.strip_prefix("./").unwrap_or(&path);
            if !updated_contracts::path::is_confined_relative(path) {
                return Err("entrypoints must name a file inside the package".into());
            }
            let metadata = std::fs::symlink_metadata(staged.join(path))?;
            if !metadata.is_file() {
                return Err(format!("entrypoint {path:?} is not a regular file").into());
            }
            let mut argv = Vec::new();
            if let Some(interpreter) = &procedure.interpreter {
                argv.push(interpreter.clone());
            }
            argv.push(format!("./{path}"));
            argv.extend_from_slice(arguments);
            Ok(serde_json::json!({"argv":argv,"timeoutSeconds":timeout}))
        };
    let mut config = serde_json::json!({"schema":updated::command_adapter::API,
        "deploy":command(entrypoint, &procedure.arguments, procedure.timeout_seconds)?,
        "replay":{"policy":procedure.replay.name()},
        "recovery":{"policy":"manual"}});
    if let Some(health) = &procedure.healthcheck {
        config["health"] = command(health, &[], 5)?;
    }
    if let Some(inspect) = &procedure.inspect {
        config["inspect"] = command(inspect, &[], procedure.timeout_seconds)?;
    }
    if let Some(recover) = &procedure.recover {
        config["recovery"] = serde_json::json!({"policy":"command",
            "command":command(recover, &[], procedure.timeout_seconds)?,
            "replay":{"policy":procedure.recovery_replay.name()}});
    }
    foundation::durable::atomic_write(
        &staged.join(updated::command_adapter::CONFIG),
        ".execution-",
        &serde_json::to_vec(&config)?,
    )?;
    let info = updated::command_adapter::inspect_package(&staged)?;
    Ok(PreparedPackage {
        source: staged,
        info,
        _scratch: Some(scratch),
    })
}

pub(crate) fn check(args: CheckArgs) -> Result<(), Error> {
    let package = prepare(&args.source, &args.procedure)?;
    println!(
        "Execution validated: success from {}; automatic recovery {}; invocation budget {}s.",
        if package.info.health_check {
            "exit status and a health check"
        } else {
            "exit status"
        },
        if package.info.manual_recovery {
            "disabled"
        } else {
            "configured"
        },
        package.info.timeout_millis / 1000
    );
    if let Some(previous) = args.against {
        let previous = prepare(&previous, &args.procedure)?;
        crate::package_check::check_package(
            &package.source,
            &previous.source,
            package.info.manual_recovery,
        )?;
    } else {
        println!("No customer code executed. Use --against with isolated fixtures to run conformance checks.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn procedure(entrypoint: &str) -> ProcedureArgs {
        let Command::Check(args) =
            Cli::try_parse_from(["updatectl", "check", ".", "--entrypoint", entrypoint])
                .unwrap()
                .command
        else {
            unreachable!()
        };
        args.procedure
    }
    #[test]
    fn metadata_is_generated_privately_and_excludes_host_runner_paths() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("run.py"), b"print('hello')").unwrap();
        std::fs::write(root.path().join("deployment.json"), b"application data").unwrap();
        let mut arguments = procedure("run.py");
        arguments.interpreter = Some("python3".into());
        let package = prepare(root.path(), &arguments).unwrap();
        assert!(!root.path().join(".updated-execution.json").exists());
        let config: serde_json::Value = serde_json::from_slice(
            &std::fs::read(package.source.join(".updated-execution.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            config["deploy"]["argv"],
            serde_json::json!(["python3", "./run.py"])
        );
        assert!(config.get("health").is_none());
        assert_eq!(
            std::fs::read(package.source.join("deployment.json")).unwrap(),
            b"application data"
        );
        assert_eq!(config["replay"]["policy"], "manual");
        assert_eq!(package.info.timeout_millis, 305_000);
    }
    #[test]
    fn invalid_entrypoints_and_conflicting_configurations_fail_before_publication() {
        let root = tempfile::tempdir().unwrap();
        assert!(prepare(root.path(), &procedure("../escape")).is_err());
        assert!(prepare(root.path(), &procedure("missing")).is_err());
        std::fs::write(root.path().join("run"), b"code").unwrap();
        std::fs::write(root.path().join(".updated-execution.json"), b"{}").unwrap();
        assert!(prepare(root.path(), &procedure("run")).is_err());
        assert_eq!(
            std::fs::read(root.path().join(".updated-execution.json")).unwrap(),
            b"{}"
        );
    }
    #[test]
    fn every_cli_command_has_a_consistent_argument_graph() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
        // Default policy values must not require entrypoint flags in advanced config mode.
        assert!(Cli::try_parse_from(["updatectl", "check", "."]).is_ok());
    }
}
