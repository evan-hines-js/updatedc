use super::*;
use updated::enrollment::bootstrap_path;

/// Build the supervisor's runtime options from its one argument, `--config <path>`.
/// Everything else lives in the TOML config (see [`updated::config`]); the guardian
/// launches the supervisor with the same file, and supplies the control channel and
/// state directory in the environment (see [`control`]).
pub(crate) async fn parse_args() -> Result<Options, String> {
    let bootstrap = bootstrap_path("supervisor")?;
    let state_dir = supervisor_state_dir()?;
    let cfg = updated_tuf::resolve_managed_config(&bootstrap, &state_dir)
        .await
        .map_err(|error| format!("resolving signed managed configuration: {error}"))?;
    // One shared resolver derives every on-disk path (binary, state, datastore, and the
    // staging/journal/rejected siblings) so the supervisor and the
    // one-shot updater never re-derive them by hand and drift apart.
    let paths = cfg.resolve_paths();

    let timeouts = BoundedTimeouts::new(cfg.timeouts);
    let supervisor_update = SupervisorUpdate {
        channel: cfg.application.channel.clone(),
        state_dir: state_dir.clone(),
        check_interval: timeouts.supervisor_check_interval,
    };
    let secrets =
        secrets::SecretManager::initialize(&cfg.routing, &cfg.deployment, &cfg.application.secrets)
            .await?;
    Ok(Options {
        deployment: cfg.deployment,
        routing: cfg.routing,
        repository: cfg.repository,
        application: cfg.application,
        timeouts,
        storage: cfg.storage,
        paths,
        supervisor_update,
        secrets,
        identity_renewal: IdentityRenewal {
            bootstrap,
            state_dir,
        },
    })
}

/// Supervisor replacement requires the guardian's state directory, where verified
/// content-addressed candidates are staged.
fn supervisor_state_dir() -> Result<PathBuf, String> {
    let Ok(state_dir) = std::env::var(control::STATE_DIR_ENV) else {
        return Err(
            "the supervisor was not launched by the guardian (no state directory); \
             run `bootstrap --state-dir <dir> --supervisor-config <path>`"
                .into(),
        );
    };
    Ok(PathBuf::from(state_dir))
}
