use super::*;
use updated::enrollment::config_path;

/// Build the agent's runtime options from its one argument, `--config <path>`.
/// Everything else lives in the TOML config (see [`updated::config`]); the platform service
/// definition supplies the persistent state directory in `UPDATED_STATE_DIR`.
pub(crate) async fn parse_args() -> Result<(Options, updated::lock::InstanceLock), String> {
    let config = config_path("updated-agent")?;
    let state_dir = agent_state_dir()?;
    // Resolution writes enrollment identity, routing metadata, and the cached assignment. Own
    // those paths before resolution, and keep the lock throughout the process lifetime.
    let enrollment_lock = lock_enrollment(&state_dir)?;
    let helper_executable = updated::helper::pin(
        &std::env::current_exe().map_err(|error| error.to_string())?,
        &state_dir.join("helper-runtime"),
    )
    .map_err(|error| format!("retaining the running helper executable: {error}"))?;
    let cfg = updated_tuf::resolve_managed_config(&config, &state_dir)
        .await
        .map_err(|error| format!("resolving signed managed configuration: {error}"))?;
    // One shared resolver derives every on-disk path (binary, state, datastore, and the
    // staging/journal/rejected siblings) so the agent and the
    // one-shot updater never re-derive them by hand and drift apart.
    let paths = cfg.resolve_paths();

    let timeouts = BoundedTimeouts::new(cfg.timeouts);
    let runtime_data = runtime_data::RuntimeDataManager::new(
        &cfg.routing,
        &cfg.application.input_selection,
        &paths.runtime_inputs,
    )?;
    Ok((
        Options {
            helper_executable,
            deployment: cfg.deployment,
            assignment_sha256: cfg.assignment_sha256,
            routing: cfg.routing,
            application: cfg.application,
            inputs: updated_contracts::dataflow::FileSnapshot::default(),
            timeouts,
            storage: cfg.storage,
            paths,
            runtime_data,
            runtime_converge_pending: false,
            identity_renewal: IdentityRenewal { config, state_dir },
        },
        enrollment_lock,
    ))
}

fn lock_enrollment(state_dir: &Path) -> Result<updated::lock::InstanceLock, String> {
    updated::lock::InstanceLock::acquire(&state_dir.join("agent.lock")).map_err(|error| {
        format!("another agent already owns this install's enrollment state: {error}")
    })
}

/// Resolve the persistent state directory supplied by the platform service definition.
fn agent_state_dir() -> Result<PathBuf, String> {
    let Ok(state_dir) = std::env::var(updated::env::STATE_DIR) else {
        return Err("the agent has no persistent state directory; set UPDATED_STATE_DIR".into());
    };
    Ok(PathBuf::from(state_dir))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn competing_startup_fails_without_waiting_and_other_nodes_are_independent() {
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("first");
        let held = lock_enrollment(&first).unwrap();
        let (send, receive) = std::sync::mpsc::channel();
        let contender = first.clone();
        let thread = std::thread::spawn(move || {
            send.send(lock_enrollment(&contender).is_err()).unwrap();
        });
        assert!(receive.recv_timeout(Duration::from_secs(2)).unwrap());
        let independent = lock_enrollment(&root.path().join("second")).unwrap();
        thread.join().unwrap();
        drop(held);
        let restarted = lock_enrollment(&first).unwrap();
        drop((independent, restarted));
    }
}
