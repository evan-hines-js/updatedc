use super::*;
use updated::config::{config_path, Config};

/// Build the supervisor's runtime options from its one argument, `--config <path>`.
/// Everything else lives in the TOML config (see [`updated::config`]); the guardian
/// launches the supervisor with the same file, and supplies the control channel and
/// state directory in the environment (see [`control`]).
pub(crate) fn parse_args() -> Result<Options, String> {
    let cfg = Config::load(&config_path("supervisor")?)?;
    // One shared resolver derives every on-disk path (binary, state, datastore, and the
    // staging/journal/rejected/app-token siblings) so the supervisor and the
    // one-shot updater never re-derive them by hand and drift apart.
    let paths = cfg.resolve_paths()?;

    let restart = match &cfg.application.reload_command {
        Some(command) => Restart::Reload {
            command: command.clone(),
        },
        None => Restart::StopStart,
    };

    let supervisor_update = build_supervisor_update(&cfg)?;
    Ok(Options {
        repository: cfg.repository,
        application: cfg.application,
        timeouts: cfg.timeouts,
        paths,
        restart,
        supervisor_update,
    })
}

/// Supervisor replacement requires the guardian's state directory, where verified
/// content-addressed candidates are staged.
fn build_supervisor_update(cfg: &Config) -> Result<SupervisorUpdate, String> {
    let Ok(state_dir) = std::env::var(control::STATE_DIR_ENV) else {
        return Err(
            "the supervisor was not launched by the guardian (no state directory); \
             run `bootstrap --state-dir <dir> --supervisor-config <path>`"
                .into(),
        );
    };
    let state_dir = PathBuf::from(state_dir);
    Ok(SupervisorUpdate {
        channel: cfg.application.channel.clone(),
        state_dir,
        check_interval: cfg.timeouts.supervisor_check_interval,
    })
}
