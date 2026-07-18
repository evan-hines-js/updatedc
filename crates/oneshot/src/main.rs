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
    let repository =
        TrustedRepository::assigned(&config.routing, &config.repository, &config.storage, paths)
            .await
            .map_err(|error| format!("loading repository: {error}"))?;
    let policy = DefaultPolicy::current(&config.application.product, &config.application.channel);
    let assignment = repository
        .assignment()
        .ok_or("release repository has no desired deployment")?;
    let target = repository
        .exact_target(&assignment.application)
        .map_err(|error| format!("resolving desired application: {error}"))?;
    let version = target
        .custom
        .get("version")
        .and_then(serde_json::Value::as_str)
        .ok_or("desired application metadata has no version")?
        .to_string();
    if version == installed.release.version {
        return Ok(());
    }
    policy
        .authorize(Some(&installed.release.version), &target)
        .map_err(|error| error.to_string())?;
    let sha = target_sha(&target);
    if rejected.is_rejected(&sha) {
        return Ok(());
    }
    repository
        .download_target(&target, &paths.download)
        .await
        .map_err(|error| format!("downloading bundle {version}: {error}"))?;
    let platform = format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH);
    let provider = BundleStore::for_app(paths).with_target_limit(config.repository.target_limit);
    let staged = provider
        .install(
            &paths.download,
            &ExpectedBundle {
                product: &config.application.product,
                version: &version,
                platform: &platform,
            },
        )
        .map_err(|error| format!("staging bundle {version}: {error}"))?;
    let mut tx = updated::transaction::Transaction {
        id: updated::rand::token().map_err(|error| error.to_string())?,
        kind: updated::transaction::Kind::OnLaunch,
        previous_release: installed.release.clone(),
        previous_archive_sha256: installed.archive_sha256.clone(),
        candidate_release: staged.id.clone(),
        candidate_archive_sha256: sha.clone(),
        candidate_rejection_required: false,
        lifecycle: None,
        phase: updated::transaction::Phase::Started,
    };
    transaction::write(&paths.journal, &tx).map_err(|error| error.to_string())?;
    write_active(&paths.active_release, &staged.id).map_err(|error| error.to_string())?;
    tx.advance(updated::transaction::Phase::CandidateActivated)
        .map_err(|error| error.to_string())?;
    transaction::write(&paths.journal, &tx).map_err(|error| error.to_string())?;
    provider
        .resolve(&staged.id)
        .map_err(|error| error.to_string())?;
    tx.advance(updated::transaction::Phase::CandidateVerified)
        .map_err(|error| error.to_string())?;
    transaction::write(&paths.journal, &tx).map_err(|error| error.to_string())?;
    write_installed(
        &paths.state,
        &InstalledState::confirmed(staged.id, sha.clone()),
    )
    .map_err(|error| error.to_string())?;
    tx.advance(updated::transaction::Phase::Committed)
        .map_err(|error| error.to_string())?;
    transaction::write(&paths.journal, &tx).map_err(|error| error.to_string())?;
    transaction::clear(&paths.journal).map_err(|error| error.to_string())?;
    if let Err(error) = rejected.clear(&sha) {
        warn(
            "oneshot",
            &format!("could not clear stale rejection: {error}"),
        );
    }
    info(
        "oneshot",
        &format!("updated {} -> {}", installed.release.version, version),
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
            BundleStore::for_app(paths).resolve(&tx.previous_release)?;
            write_active(&paths.active_release, &tx.previous_release)?;
        }
    }
    transaction::clear(&paths.journal)
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
