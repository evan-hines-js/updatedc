//! Update-on-launch wrapper for CLIs, batch jobs, and on-demand tools. It reconciles
//! an interrupted update, checks once, atomically installs a verified release, and
//! then execs the program. Unlike the supervisor, it commits without a health window.

use std::io;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};

use foundation::log::{error, info, warn};
use updated::config::{config_path, with_suffix, Config};
use updated::lock::InstanceLock;
use updated::reject::Rejections;
use updated::state::{
    provision_baseline, read_installed, write_installed, Installed, InstalledState,
};
use updated::transaction::{self, BinaryAction, Recovery, Transaction};
use updated::{apply, hash};
use updated_tuf::select::target_sha;
use updated_tuf::{DefaultPolicy, TrustedRepository};

const COMPONENT: &str = "oneshot";

fn main() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cfg_path = config_path("updated-oneshot").unwrap_or_else(|e| {
        eprintln!("updated-oneshot: {e}");
        std::process::exit(2);
    });
    let cfg = Config::load(&cfg_path).unwrap_or_else(|e| {
        error(COMPONENT, &e);
        std::process::exit(1);
    });
    let paths = cfg.resolve_paths().unwrap_or_else(|e| {
        error(COMPONENT, &e);
        std::process::exit(1);
    });

    // Serialize updaters on this install so two launches never swap the binary at
    // once. The guard is scoped to this block and dropped before we exec, so the
    // launched program never inherits (and never blocks the next launch on) the lock.
    // Whichever branch runs, the binary is verified before we exec it below — a
    // contending updater must never let us launch unverified or mid-swap bytes.
    let ready = {
        match acquire_lock(&with_suffix(&paths.state, ".lock")) {
            Some(_guard) => ensure_provisioned(&cfg, &paths).and_then(|()| {
                let rt = tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .build()
                    .expect("tokio runtime");
                rt.block_on(try_update(&cfg, &paths))
            }),
            None => {
                warn(
                    COMPONENT,
                    "another updater holds the lock; launching the current version without updating",
                );
                verify_committed(&paths)
            }
        }
    };
    if let Err(e) = ready {
        error(COMPONENT, &e);
        std::process::exit(1);
    }

    run_program(&cfg.application.command)
}

/// Turn the installer's immutable version/digest pair into durable installed state
/// before repository access or execution. Missing both is not an implicit trust-on-
/// first-use mode: the updater has no authenticated fact with which to identify the
/// bytes, so it fails closed.
fn ensure_provisioned(cfg: &Config, paths: &updated::config::Paths) -> Result<(), String> {
    match read_installed(&paths.state) {
        Installed::Present(_) => Ok(()),
        Installed::Invalid => corrupt_state(),
        Installed::Missing => {
            let version = cfg.application.current_version.as_deref().ok_or_else(|| {
                "installed state is missing and no installer-provisioned application.current_version/application.current_sha256 baseline is configured; refusing to run".to_string()
            })?;
            let sha = cfg.application.current_sha256.as_deref().ok_or_else(|| {
                "installed state is missing and no installer-provisioned application.current_version/application.current_sha256 baseline is configured; refusing to run".to_string()
            })?;
            provision_baseline(&paths.binary, &paths.state, version, sha)
                .map(|_| info(COMPONENT, &format!("provisioned installer baseline {version}")))
                .map_err(|e| format!("installer baseline does not match the application binary ({e}); refusing to run"))
        }
    }
}

/// How long a contending launch waits for the active updater to finish before giving
/// up and launching the current version (verified, without updating).
const LOCK_WAIT: Duration = Duration::from_secs(30);

/// Acquire the updater lock, waiting up to [`LOCK_WAIT`] for a contending updater to
/// finish — so we launch its freshly-updated version instead of racing its swap.
/// Returns `None` if it stays contended (or the lock errors); the caller then
/// verifies the committed binary without updating.
fn acquire_lock(path: &Path) -> Option<InstanceLock> {
    let deadline = Instant::now() + LOCK_WAIT;
    loop {
        match InstanceLock::acquire(path) {
            Ok(lock) => return Some(lock),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => {
                warn(
                    COMPONENT,
                    &format!("could not acquire the updater lock: {e}"),
                );
                return None;
            }
        }
    }
}

/// Verify the on-disk binary against committed state without updating (the path taken
/// when another updater holds the lock). Fails closed on drift or corrupt state,
/// exactly as the update path's final check does, so a contending updater can never
/// cause unverified bytes to run.
///
/// This path holds no lock, so it is strictly read-only: a binary that disagrees with
/// committed state is far more likely to be the lock holder's in-flight swap than real
/// drift, and repairing it here would clobber that swap. Refuse to run instead and let
/// the holder finish; the next launch takes the lock and repairs any genuine drift.
fn verify_committed(paths: &updated::config::Paths) -> Result<(), String> {
    match read_installed(&paths.state) {
        Installed::Present(s) => hash::file_matches(&paths.binary, &s.sha256)
            .then_some(())
            .ok_or_else(|| {
                "on-disk binary does not match committed state while another updater holds the \
                 lock; refusing to run (the contending updater is mid-swap, or the binary drifted \
                 — the next launch repairs it under the lock)"
                    .to_string()
            }),
        Installed::Missing => Err(
            "installed state is missing; another updater did not finish provisioning the installer baseline — refusing to run".into(),
        ),
        Installed::Invalid => corrupt_state(),
    }
}

/// The shared fail-closed decision for a corrupt installed-state record: never update
/// or attest the bytes.
fn corrupt_state() -> Result<(), String> {
    error(
        COMPONENT,
        "installed-state record is corrupt; refusing to update",
    );
    Err("installed-state record is corrupt and cannot be verified; repair or remove it only through a trusted installer — refusing to update or run".into())
}

/// Reconcile a prior update, best-effort update to the newest verified release, and
/// verify the bytes we are about to run. Returns `Err` only when the binary cannot
/// be trusted and must not be executed (fail closed); every "no update happened"
/// reason is logged and treated as "launch the current version".
async fn try_update(cfg: &Config, paths: &updated::config::Paths) -> Result<(), String> {
    let (current, committed_sha) = match read_installed(&paths.state) {
        Installed::Present(s) => (Some(s.version), Some(s.sha256)),
        Installed::Missing => {
            return Err(
                "installed state is missing after baseline provisioning; refusing to run".into(),
            )
        }
        Installed::Invalid => return corrupt_state(),
    };

    // Crash-safety: fix a swap the previous run left half-done before touching it. A
    // failed reconciliation means the binary / rollback-image / committed-state
    // relationship is unresolved — proceeding could overwrite recovery evidence or
    // eventually run an indeterminate version — so fail closed rather than continue.
    recover_transaction(paths).map_err(|e| {
        format!("could not reconcile a prior interrupted update ({e}); refusing to proceed")
    })?;

    let applied = match update_to_newest(cfg, paths, current.as_deref()).await {
        Ok(sha) => sha,
        Err(e) => {
            warn(
                COMPONENT,
                &format!("update skipped: {e}; launching the current version"),
            );
            None
        }
    };

    // Fail closed on whatever we are about to run. A freshly installed binary was
    // already verified during the swap; otherwise it must match the committed digest.
    let expected = applied.or(committed_sha).ok_or_else(|| {
        "no committed digest is available for the application binary; refusing to run".to_string()
    })?;
    ensure_runnable(&paths.binary, &expected)
}

/// Reconcile the shared durable transaction before selection or execution.
fn recover_transaction(paths: &updated::config::Paths) -> io::Result<()> {
    let Some(tx) = transaction::read(&paths.journal)? else {
        return Ok(());
    };
    let committed_version = match read_installed(&paths.state) {
        Installed::Present(state) => Some(state.version),
        Installed::Missing | Installed::Invalid => None,
    };
    let disk_sha = hash::sha256_file(&paths.binary).unwrap_or_default();
    match transaction::classify_recovery(&tx, &disk_sha, committed_version.as_deref()) {
        Recovery::Committed | Recovery::NeverSwapped => apply::cleanup_previous(&paths.binary)?,
        Recovery::RestorePredecessor => {
            apply::rollback(&paths.binary)?;
            hash::verify_file(&paths.binary, &tx.old_sha256)?;
            apply::cleanup_previous(&paths.binary)?;
        }
    }
    transaction::clear(&paths.journal)?;
    Ok(())
}

/// Select, download, verify, install, and record the newest eligible release.
/// Returns its digest on a committed update, `None` when already up to date. Errors
/// are non-fatal (the caller launches the current version).
async fn update_to_newest(
    cfg: &Config,
    paths: &updated::config::Paths,
    current: Option<&str>,
) -> Result<Option<String>, String> {
    let repo = TrustedRepository::from_config(cfg, paths)
        .await
        .map_err(|e| format!("repository unavailable: {e}"))?;

    let mut rejected = Rejections::load(&paths.rejected, cfg.timeouts.retry_after)
        .map_err(|e| format!("reading rejection state: {e}"))?;
    let policy = DefaultPolicy::current(
        cfg.application.product.clone(),
        cfg.application.channel.clone(),
    );
    let Some(staged) = repo
        .stage_update(
            &policy,
            current,
            &paths.download,
            |m| info(COMPONENT, &format!("update: {m}")),
            |t, _| rejected.is_rejected(&target_sha(t)),
        )
        .await
        .map_err(|e| format!("acquiring release: {e}"))?
    else {
        info(
            COMPONENT,
            &format!("up to date ({})", current.unwrap_or("no baseline")),
        );
        return Ok(None);
    };
    let version = staged.version;
    let sha = staged.sha256;

    let tx = Transaction {
        old_sha256: hash::sha256_file(&paths.binary)
            .map_err(|e| format!("hashing installed binary before {version}: {e}"))?,
        new_sha256: sha.clone(),
        to_version: version.clone(),
        from_version: current.map(str::to_string),
    };
    transaction::write(&paths.journal, &tx)
        .map_err(|e| format!("recording transaction for {version}: {e}"))?;

    // The program is not running, so replacing its binary is a plain atomic swap that
    // keeps the previous image at <binary>.old for rollback. Every failure after the
    // journal lands is reconciled through the same recovery state machine before launch.
    if let Err(e) = apply::atomic_swap_file(&paths.binary, &paths.download) {
        let _ = std::fs::remove_file(&paths.download);
        recover_transaction(paths).map_err(|recovery| {
            format!("swapping in {version}: {e}; recovery failed: {recovery}")
        })?;
        return Err(format!("swapping in {version}: {e}"));
    }
    let _ = std::fs::remove_file(&paths.download);

    // Re-verify the installed bytes against the signed digest before recording or
    // running them; a mismatch rolls back and rejects exactly these bytes.
    if !hash::file_matches(&paths.binary, &sha) {
        recover_transaction(paths).map_err(|e| {
            format!("installed {version} failed signed-hash verification; recovery failed: {e}")
        })?;
        rejected.reject(&sha).map_err(|persist| {
            format!(
                "installed {version} failed signed-hash verification and was rolled back, but recording its rejection failed: {persist}"
            )
        })?;
        return Err(format!(
            "installed {version} failed signed-hash verification; rolled back"
        ));
    }

    if let Err(e) = write_installed(
        &paths.state,
        &InstalledState::confirmed(version.clone(), sha.clone()),
    ) {
        recover_transaction(paths)
            .map_err(|recovery| format!("recording {version}: {e}; recovery failed: {recovery}"))?;
        return Err(format!("recording {version}: {e}"));
    }
    if let Err(e) = transaction::clear(&paths.journal) {
        warn(
            COMPONENT,
            &format!("{version} committed but clearing its journal failed ({e}); next launch will finish cleanup"),
        );
    }
    if let Err(e) = apply::cleanup_previous(&paths.binary) {
        warn(
            COMPONENT,
            &format!("{version} committed but rollback cleanup failed: {e}"),
        );
    }
    if let Err(e) = rejected.clear(&sha) {
        warn(
            COMPONENT,
            &format!("{version} committed but clearing its stale rejection failed: {e}"),
        );
    }
    info(
        COMPONENT,
        &format!("updated {} -> {version}", current.unwrap_or("baseline")),
    );
    Ok(Some(sha))
}

/// Fail closed on bytes that do not match the committed digest — tamper or drift.
/// Mirrors the supervisor's drift check using the shared hash
/// and rollback primitives: restore the committed image from `<binary>.old` if it is
/// available and matches, else refuse to run.
fn ensure_runnable(binary: &Path, committed_sha: &str) -> Result<(), String> {
    let sha = committed_sha;
    let old = apply::old_path(binary);
    let live_sha = hash::sha256_file(binary).ok();
    let rollback_sha = hash::sha256_file(&old).ok();
    match transaction::classify_binary(live_sha.as_deref(), rollback_sha.as_deref(), sha) {
        BinaryAction::Ready => Ok(()),
        BinaryAction::RestoreRollback => {
            warn(
                COMPONENT,
                "on-disk binary drifted from committed state; restoring the committed image",
            );
            apply::rollback(binary).map_err(|e| format!("restoring committed binary: {e}"))?;
            hash::verify_file(binary, sha)
                .map_err(|e| format!("verifying restored committed binary: {e}"))?;
            apply::cleanup_previous(binary)
                .map_err(|e| format!("cleaning restored rollback image: {e}"))?;
            Ok(())
        }
        BinaryAction::FailClosed => Err(
            "on-disk binary does not match committed state and no verified rollback image is \
             available; refusing to run drifted bytes"
                .into(),
        ),
    }
}

/// Launch the program, replacing this process. On Unix `exec` never returns on
/// success (so the updater leaves no lingering parent); on Windows it waits and
/// propagates the exit code.
fn run_program(command: &[String]) -> ! {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = Command::new(&command[0]).args(&command[1..]).exec();
        error(COMPONENT, &format!("failed to exec {}: {err}", command[0]));
        std::process::exit(126);
    }
    #[cfg(windows)]
    {
        match Command::new(&command[0]).args(&command[1..]).status() {
            Ok(status) => std::process::exit(status.code().unwrap_or(1)),
            Err(e) => {
                error(COMPONENT, &format!("failed to launch {}: {e}", command[0]));
                std::process::exit(126);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("oneshot-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn sha(path: &Path) -> String {
        hash::sha256_file(path).unwrap()
    }

    fn paths(name: &str) -> updated::config::Paths {
        let d = dir(name);
        let binary = d.join("app");
        let state = d.join("app.installed");
        updated::config::Paths {
            datastore: d.join("tuf"),
            download: d.join("app.download"),
            journal: d.join("app.transaction"),
            rejected: d.join("app.rejected"),
            app_token: d.join("app.apptoken"),
            binary,
            state,
        }
    }

    // --- reconcile: crash-safety of an interrupted prior swap via <binary>.old ---

    #[test]
    fn reconcile_is_a_noop_without_a_journal() {
        let p = paths("reconcile-noop");
        std::fs::write(&p.binary, b"CURRENT").unwrap();
        recover_transaction(&p).unwrap();
        assert_eq!(std::fs::read(&p.binary).unwrap(), b"CURRENT", "untouched");
    }

    #[test]
    fn reconcile_drops_stale_image_when_binary_is_already_committed() {
        // Swap + state-write both landed; only the .old cleanup didn't. The on-disk
        // binary already matches committed state, so just drop the rollback image.
        let p = paths("reconcile-committed");
        std::fs::write(&p.binary, b"NEW").unwrap();
        std::fs::write(apply::old_path(&p.binary), b"OLD").unwrap();
        let new_sha = sha(&p.binary);
        write_installed(
            &p.state,
            &InstalledState::confirmed("2.0.0".into(), new_sha.clone()),
        )
        .unwrap();
        transaction::write(
            &p.journal,
            &Transaction {
                old_sha256: sha(&apply::old_path(&p.binary)),
                new_sha256: new_sha,
                to_version: "2.0.0".into(),
                from_version: Some("1.0.0".into()),
            },
        )
        .unwrap();
        recover_transaction(&p).unwrap();
        assert_eq!(
            std::fs::read(&p.binary).unwrap(),
            b"NEW",
            "committed binary kept"
        );
        assert!(
            !apply::old_path(&p.binary).exists(),
            "stale rollback image dropped"
        );
        assert!(!p.journal.exists());
    }

    #[test]
    fn reconcile_restores_committed_when_swap_was_interrupted() {
        // The swap happened (binary == NEW) but the commit didn't (state still records
        // OLD): restore the committed bytes from the rollback image, don't run NEW.
        let p = paths("reconcile-interrupted");
        std::fs::write(&p.binary, b"NEW").unwrap();
        let old = apply::old_path(&p.binary);
        std::fs::write(&old, b"OLD").unwrap();
        let committed_old = sha(&old);
        write_installed(
            &p.state,
            &InstalledState::confirmed("1.0.0".into(), committed_old.clone()),
        )
        .unwrap();
        transaction::write(
            &p.journal,
            &Transaction {
                old_sha256: committed_old,
                new_sha256: sha(&p.binary),
                to_version: "2.0.0".into(),
                from_version: Some("1.0.0".into()),
            },
        )
        .unwrap();
        recover_transaction(&p).unwrap();
        assert_eq!(
            std::fs::read(&p.binary).unwrap(),
            b"OLD",
            "restored committed bytes"
        );
        assert!(!apply::old_path(&p.binary).exists());
        assert!(!p.journal.exists());
    }

    // --- ensure_runnable: fail closed on drift or corruption ---

    #[test]
    fn ensure_runnable_ok_when_binary_matches_committed_digest() {
        let bin = dir("run-match").join("app");
        std::fs::write(&bin, b"GOOD").unwrap();
        assert!(ensure_runnable(&bin, &sha(&bin)).is_ok());
    }

    #[test]
    fn ensure_runnable_fails_closed_on_drift() {
        let d = dir("run-drift");
        let bin = d.join("app");
        std::fs::write(&bin, b"TAMPERED").unwrap();
        let good = d.join("good");
        std::fs::write(&good, b"GOOD").unwrap();
        let committed = sha(&good); // binary differs, no rollback image available
        assert!(
            ensure_runnable(&bin, &committed).is_err(),
            "drifted bytes must be refused"
        );
    }

    #[test]
    fn ensure_runnable_restores_committed_from_rollback_on_drift() {
        let bin = dir("run-restore").join("app");
        std::fs::write(&bin, b"TAMPERED").unwrap();
        std::fs::write(apply::old_path(&bin), b"GOOD").unwrap();
        let committed = sha(&apply::old_path(&bin));
        assert!(ensure_runnable(&bin, &committed).is_ok());
        assert_eq!(
            std::fs::read(&bin).unwrap(),
            b"GOOD",
            "restored the committed image from the rollback copy"
        );
    }

    // --- verify_committed: the unlocked path never writes ---

    #[test]
    fn verify_committed_is_read_only_while_a_contender_holds_the_lock() {
        // The exact mid-swap window of a lock holder: it has swapped NEW in and kept OLD
        // at <binary>.old, but has not yet recorded NEW as installed. Repairing here would
        // overwrite the holder's freshly-swapped binary and delete its rollback image,
        // making the holder's own re-verification fail and reject a valid signed release.
        let d = dir("verify-contended");
        let paths = updated::config::Paths {
            binary: d.join("app"),
            download: d.join("app.download"),
            state: d.join("app.installed"),
            datastore: d.join("app.installed.tuf"),
            journal: d.join("app.transaction"),
            rejected: d.join("app.rejected"),
            app_token: d.join("app.installed.apptoken"),
        };
        std::fs::write(&paths.binary, b"NEW").unwrap();
        std::fs::write(apply::old_path(&paths.binary), b"OLD").unwrap();
        let old_sha = sha(&apply::old_path(&paths.binary));
        write_installed(
            &paths.state,
            &InstalledState::confirmed("1.0.0".into(), old_sha),
        )
        .unwrap();

        assert!(
            verify_committed(&paths).is_err(),
            "a binary that disagrees with committed state must be refused, not repaired"
        );
        assert_eq!(
            std::fs::read(&paths.binary).unwrap(),
            b"NEW",
            "the contender's swapped-in binary is left untouched"
        );
        assert_eq!(
            std::fs::read(apply::old_path(&paths.binary)).unwrap(),
            b"OLD",
            "the contender's rollback image is left untouched"
        );
    }
}
