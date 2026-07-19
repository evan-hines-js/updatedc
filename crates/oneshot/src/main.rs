//! One-shot bundle updater: reconcile, select, activate, then execute the active release.

use foundation::log::{error, info, warn};
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use updated::bundle::{read_active, write_active};
use updated::config::{Config, Paths};
use updated::lock::InstanceLock;
use updated::provider::BundleStore;
use updated::reject::Rejections;
use updated::state::{read_installed, Installed, InstalledState};
use updated_tuf::TrustedRepository;

fn main() -> ExitCode {
    updated::tls::install_crypto_provider();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            error("oneshot", &message);
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let (bootstrap, enrollment_state) = parse_args()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("creating runtime: {error}"))?;
    let config = runtime
        .block_on(updated_tuf::resolve_managed_config(
            &bootstrap,
            &enrollment_state,
        ))
        .map_err(|error| format!("resolving signed managed configuration: {error}"))?;
    let paths = config.resolve_paths()?;
    let _lock = InstanceLock::acquire(&paths.install_root.join("state/instance.lock"))
        .map_err(|error| format!("another updater owns this install: {error}"))?;
    updated::on_launch::reconcile(&paths)
        .map_err(|error| format!("recovering bundle transaction: {error}"))?;
    let installed = match read_installed(&paths.state) {
        Installed::Present(state) => state,
        Installed::Missing => {
            return Err("installed bundle state is missing; reseed the install".into())
        }
        Installed::Invalid => return Err("installed bundle state is corrupt".into()),
    };
    if !matches!(
        updated::state::read_enrollment(&paths.state),
        updated::state::EnrollmentState::Present
    ) {
        return Err("installed bundle has no valid enrollment record".into());
    }
    verify_active(&paths, &installed)
        .map_err(|error| format!("verifying active bundle: {error}"))?;

    if let Err(message) = runtime.block_on(update(&config, &paths, &installed)) {
        warn("oneshot", &format!("update skipped: {message}"));
    }
    execute_active(&config, &paths)
}

fn parse_args() -> Result<(PathBuf, PathBuf), String> {
    let usage = "usage: updated-oneshot --config <bootstrap.toml> --state-dir <dir>";
    let mut args = std::env::args_os().skip(1);
    let mut config = None;
    let mut state = None;
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--config") if config.is_none() => {
                config = Some(PathBuf::from(args.next().ok_or("--config needs a path")?));
            }
            Some("--state-dir") if state.is_none() => {
                state = Some(PathBuf::from(
                    args.next().ok_or("--state-dir needs a path")?,
                ));
            }
            Some("-h" | "--help") => {
                println!("{usage}");
                std::process::exit(0);
            }
            _ => return Err(usage.into()),
        }
    }
    Ok((
        config.ok_or_else(|| usage.to_string())?,
        state.ok_or_else(|| usage.to_string())?,
    ))
}

async fn update(config: &Config, paths: &Paths, installed: &InstalledState) -> Result<(), String> {
    let mut rejected = Rejections::load(&paths.rejected)
        .map_err(|error| format!("loading rejections: {error}"))?;
    let repository =
        TrustedRepository::assigned(&config.routing, &config.repository, &config.storage, paths)
            .await
            .map_err(|error| format!("loading repository: {error}"))?;
    let assignment = repository
        .assignment()
        .ok_or_else(|| "release repository has no desired deployment".to_string())?;
    let lineage = updated::state::RepositoryLineage::from_metadata_url(&assignment.metadata_url);
    let prepared = match update_client::prepare_assigned_application(
        update_client::ApplicationRequest {
            repository: &repository,
            application: &config.application,
            repository_config: &config.repository,
            paths,
            current_version: installed.version_floor_for(&lineage),
        },
        |sha256| rejected.is_rejected(&lineage.rejection_key(sha256)),
    )
    .await
    {
        Ok(Some(prepared)) => prepared,
        Ok(None) => return Ok(()),
        Err(error) => {
            if let Some((version, archive_sha256)) = error.rejected_archive() {
                rejected.reject(&lineage.rejection_key(archive_sha256)).map_err(|reject_error| {
                    format!(
                        "{error}; rejecting malformed application bundle {version} also failed: {reject_error}"
                    )
                })?;
            }
            return Err(error.to_string());
        }
    };
    if let Some(rebound) = installed.rebind_if_same_artifact(
        lineage.clone(),
        &prepared.release,
        &prepared.archive_sha256,
    ) {
        updated::state::write_installed(&paths.state, &rebound)
            .map_err(|error| format!("committing repository lineage: {error}"))?;
        info(
            "oneshot",
            &format!(
                "adopted repository lineage for already-installed {}",
                installed.release.version
            ),
        );
        return Ok(());
    }
    updated::on_launch::activate(
        paths,
        installed,
        prepared.release,
        prepared.archive_sha256.clone(),
        lineage.clone(),
    )
    .map_err(|error| error.to_string())?;
    if let Err(error) = rejected.clear(&lineage.rejection_key(&prepared.archive_sha256)) {
        warn(
            "oneshot",
            &format!("could not clear stale rejection: {error}"),
        );
    }
    info(
        "oneshot",
        &format!(
            "updated {} -> {}",
            installed.release.version, prepared.version
        ),
    );
    Ok(())
}

fn verify_active(paths: &Paths, installed: &InstalledState) -> io::Result<()> {
    let provider = BundleStore::for_app(paths);
    if read_active(&paths.active_release)?.as_ref() != Some(&installed.release) {
        provider.resolve(&installed.release)?;
        write_active(&paths.active_release, &installed.release)?;
    }
    provider.resolve(&installed.release).map(|_| ())
}

fn execute_active(config: &Config, paths: &Paths) -> Result<(), String> {
    let release = read_active(&paths.active_release)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "active-release is missing".to_string())?;
    let launch = BundleStore::for_app(paths)
        .resolve(&release)
        .map_err(|error| error.to_string())?;
    execute(
        &launch.program,
        &config.application.args,
        &launch.cwd,
        &paths.install_root,
    )
}

#[cfg(unix)]
fn execute(program: &Path, args: &[String], cwd: &Path, install_root: &Path) -> Result<(), String> {
    use std::os::unix::process::CommandExt;
    let error = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .env(updated::env::INSTALL_ROOT, install_root)
        .exec();
    Err(format!("executing active bundle: {error}"))
}

#[cfg(not(unix))]
fn execute(program: &Path, args: &[String], cwd: &Path, install_root: &Path) -> Result<(), String> {
    let status = Command::new(program)
        .args(args)
        .current_dir(cwd)
        .env(updated::env::INSTALL_ROOT, install_root)
        .status()
        .map_err(|error| format!("executing active bundle: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("application exited with {status}"))
    }
}
