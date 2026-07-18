//! One-shot bundle updater: reconcile, select, activate, then execute the active release.

use foundation::log::{error, info, warn};
use std::io;
use std::path::Path;
use std::process::{Command, ExitCode};
use updated::bundle::{
    read_active, read_release, stage_bundle, write_active, BundleLimits, ExpectedBundle,
};
use updated::config::{config_path, Config, Paths};
use updated::lock::InstanceLock;
use updated::reject::Rejections;
use updated::state::{read_installed, write_installed, Installed, InstalledState};
use updated::transaction::{self, Recovery};
use updated_tuf::select::target_sha;
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
    reconcile(&paths).map_err(|error| format!("recovering bundle transaction: {error}"))?;
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
    let repository = TrustedRepository::assigned(&config.routing, &config.repository, paths)
        .await
        .map_err(|error| format!("loading repository: {error}"))?;
    let policy = DefaultPolicy::current(&config.application.product, &config.application.channel);
    let Some(selected) = repository.select_release(
        &policy,
        Some(&installed.release.version),
        |message| info("oneshot", message),
        |target, _| rejected.is_rejected(&target_sha(target)),
    ) else {
        return Ok(());
    };
    repository
        .stage_release(&selected, &paths.download)
        .await
        .map_err(|error| format!("downloading bundle {}: {error}", selected.version))?;
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let staged = stage_bundle(
        &paths.download,
        &paths.staging,
        &paths.versions,
        &ExpectedBundle {
            product: &config.application.product,
            version: &selected.version,
            platform: &platform,
        },
        &BundleLimits {
            archive_bytes: config.repository.target_limit,
            ..Default::default()
        },
    )
    .map_err(|error| format!("staging bundle {}: {error}", selected.version))?;
    let mut tx = updated::transaction::Transaction {
        id: updated::rand::token().map_err(|error| error.to_string())?,
        kind: updated::transaction::Kind::OnLaunch,
        previous_release: installed.release.clone(),
        previous_archive_sha256: installed.archive_sha256.clone(),
        candidate_release: staged.id.clone(),
        candidate_archive_sha256: selected.sha256.clone(),
        candidate_rejection_required: false,
        transition_required: false,
        phase: updated::transaction::Phase::Started,
    };
    transaction::write(&paths.journal, &tx).map_err(|error| error.to_string())?;
    write_active(&paths.active_release, &staged.id).map_err(|error| error.to_string())?;
    tx.advance(updated::transaction::Phase::CandidateActivated)
        .map_err(|error| error.to_string())?;
    transaction::write(&paths.journal, &tx).map_err(|error| error.to_string())?;
    read_release(&paths.versions, &staged.id).map_err(|error| error.to_string())?;
    tx.advance(updated::transaction::Phase::CandidateVerified)
        .map_err(|error| error.to_string())?;
    transaction::write(&paths.journal, &tx).map_err(|error| error.to_string())?;
    write_installed(
        &paths.state,
        &InstalledState::confirmed(staged.id, selected.sha256.clone()),
    )
    .map_err(|error| error.to_string())?;
    tx.advance(updated::transaction::Phase::Committed)
        .map_err(|error| error.to_string())?;
    transaction::write(&paths.journal, &tx).map_err(|error| error.to_string())?;
    transaction::clear(&paths.journal).map_err(|error| error.to_string())?;
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

fn reconcile(paths: &Paths) -> io::Result<()> {
    let Some(tx) = transaction::read(&paths.journal)? else {
        return Ok(());
    };
    let active = read_active(&paths.active_release)?;
    let committed = match read_installed(&paths.state) {
        Installed::Present(state) => Some(state.release),
        Installed::Missing | Installed::Invalid => None,
    };
    match transaction::classify_recovery(&tx, active.as_ref(), committed.as_ref()) {
        Recovery::Committed | Recovery::NeverSwapped => {}
        Recovery::RestorePredecessor => {
            read_release(&paths.versions, &tx.previous_release)?;
            write_active(&paths.active_release, &tx.previous_release)?;
        }
    }
    transaction::clear(&paths.journal)
}

fn verify_active(paths: &Paths, installed: &InstalledState) -> io::Result<()> {
    if read_active(&paths.active_release)?.as_ref() != Some(&installed.release) {
        read_release(&paths.versions, &installed.release)?;
        write_active(&paths.active_release, &installed.release)?;
    }
    read_release(&paths.versions, &installed.release).map(|_| ())
}

fn execute_active(config: &Config, paths: &Paths) -> Result<(), String> {
    let release = read_active(&paths.active_release)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| "active-release is missing".to_string())?;
    let (_, entrypoint) =
        read_release(&paths.versions, &release).map_err(|error| error.to_string())?;
    let cwd = paths.versions.join(release.directory_name());
    execute(
        &entrypoint,
        &config.application.args,
        &cwd,
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
