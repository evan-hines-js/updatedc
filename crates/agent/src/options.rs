use super::*;
use updated::enrollment::config_path;

/// Build the agent's runtime options from its one argument, `--config <path>`.
/// Everything else lives in the TOML config (see [`updated::config`]); the launcher
/// launches the agent with the same file, and supplies the control channel and
/// state directory in the environment (see [`control`]).
pub(crate) async fn parse_args() -> Result<Options, String> {
    let config = config_path("updated-agent")?;
    let state_dir = agent_state_dir()?;
    let cfg = updated_tuf::resolve_managed_config(&config, &state_dir)
        .await
        .map_err(|error| format!("resolving signed managed configuration: {error}"))?;
    // One shared resolver derives every on-disk path (binary, state, datastore, and the
    // staging/journal/rejected siblings) so the agent and the
    // one-shot updater never re-derive them by hand and drift apart.
    let paths = cfg.resolve_paths();

    let timeouts = BoundedTimeouts::new(cfg.timeouts);
    let agent_update = AgentUpdate {
        channel: cfg.application.channel.clone(),
        state_dir: state_dir.clone(),
        check_interval: timeouts.agent_check_interval,
    };
    // Only the client is built here. The bundle itself is fetched from `run`, behind the launcher
    // readiness signal, because that fetch waits out a control-plane outage and nothing that waits
    // may sit in front of a candidate agent's readiness deadline.
    let secrets = secrets::SecretManager::new(&cfg.routing, &cfg.application.secrets)?;
    Ok(Options {
        deployment: cfg.deployment,
        routing: cfg.routing,
        application: cfg.application,
        timeouts,
        storage: cfg.storage,
        paths,
        agent_update,
        secrets,
        identity_renewal: IdentityRenewal { config, state_dir },
    })
}

/// Agent replacement requires the launcher's state directory, where verified
/// content-addressed candidates are staged.
fn agent_state_dir() -> Result<PathBuf, String> {
    let Ok(state_dir) = std::env::var(control::STATE_DIR_ENV) else {
        return Err(
            "the agent was not launched by the launcher (no state directory); \
             run `launcher --state-dir <dir> --config <path>`"
                .into(),
        );
    };
    Ok(PathBuf::from(state_dir))
}
