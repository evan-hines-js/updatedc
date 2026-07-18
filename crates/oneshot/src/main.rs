//! One-shot bundle updater: reconcile, select, activate, then execute the active release.

use foundation::log::{error, info, warn};
use std::io;
use std::path::Path;
use std::process::{Command, ExitCode};
use updated::bundle::{read_active, write_active, ExpectedBundle};
use updated::config::{config_path, Config, Paths};
use updated::lock::InstanceLock;
use updated::provider::BundleStore;
use updated::reject::Rejections;
use updated::state::{read_installed, Installed, InstalledState};
use updated_tuf::{DefaultPolicy, TrustedRepository};

fn main() -> ExitCode {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            error("oneshot", &message);
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let config = Config::load(&config_path("updated-oneshot")?)?;
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
    verify_active(&paths, &installed)
        .map_err(|error| format!("verifying active bundle: {error}"))?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("creating runtime: {error}"))?;
    if let Err(message) = runtime.block_on(update(&config, &paths, &installed)) {
        warn("oneshot", &format!("update skipped: {message}"));
    }
    execute_active(&config, &paths)
}

async fn update(config: &Config, paths: &Paths, installed: &InstalledState) -> Result<(), String> {
    let mut rejected = Rejections::load(&paths.rejected, config.timeouts.retry_after)
        .map_err(|error| format!("loading rejections: {error}"))?;
    let repository =
        TrustedRepository::assigned(&config.routing, &config.repository, &config.storage, paths)
            .await
            .map_err(|error| format!("loading repository: {error}"))?;
    let policy = DefaultPolicy::current(&config.application.product, &config.application.channel);
    let Some(selected) = repository
        .assigned_application(&policy, Some(&installed.release.version))
        .map_err(|error| format!("selecting desired application: {error}"))?
    else {
        return Ok(());
    };
    if rejected.is_rejected(&selected.sha256) {
        return Ok(());
    }
    repository
        .stage_release(&selected, &paths.download)
        .await
        .map_err(|error| format!("downloading bundle {}: {error}", selected.version))?;
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let provider = BundleStore::for_app(paths).with_target_limit(config.repository.target_limit);
    let staged = provider
        .install(
            &paths.download,
            &ExpectedBundle {
                product: &config.application.product,
                version: &selected.version,
                platform: &platform,
            },
        )
        .map_err(|error| format!("staging bundle {}: {error}", selected.version))?;
    updated::on_launch::activate(paths, installed, staged.id, selected.sha256.clone())
        .map_err(|error| error.to_string())?;
    if let Err(error) = rejected.clear(&selected.sha256) {
        warn(
            "oneshot",
            &format!("could not clear stale rejection: {error}"),
        );
    }
    info(
        "oneshot",
        &format!(
            "updated {} -> {}",
            installed.release.version, selected.version
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
