use super::*;

pub(crate) enum Outcome {
    Committed,
    RolledBack,
    RejectedBeforeActivation,
}

/// Crashes at a configured transaction boundary, for the e2e's crash-recovery scenarios.
/// Compiled in only under the `chaos` feature (which the e2e enables); a production build
/// has no injection points, so a stray `UPDATED_CHAOS_POINT` can never crash it. One-shot:
/// after it fires it drops a sentinel, so the relaunched supervisor recovers instead of
/// crashing again at the same boundary forever.
struct Chaos {
    #[cfg(feature = "chaos")]
    point: Option<String>,
    #[cfg(feature = "chaos")]
    sentinel: Option<PathBuf>,
}

impl Chaos {
    #[cfg(feature = "chaos")]
    fn from_env() -> Self {
        Chaos {
            point: std::env::var(env::CHAOS_POINT).ok(),
            sentinel: std::env::var(control::STATE_DIR_ENV)
                .ok()
                .map(|d| PathBuf::from(d).join("chaos-fired")),
        }
    }
    #[cfg(not(feature = "chaos"))]
    fn from_env() -> Self {
        Chaos {}
    }

    #[cfg(feature = "chaos")]
    fn crossing(&self, phase: &str) {
        if self.point.as_deref() != Some(phase) {
            return;
        }
        if let Some(sentinel) = &self.sentinel {
            if sentinel.exists() {
                return; // already crashed here once; let recovery proceed.
            }
            let _ = std::fs::write(sentinel, phase);
        }
        eprintln!("[supervisor] CHAOS: exiting at boundary {phase:?}");
        std::process::exit(137);
    }

    #[cfg(not(feature = "chaos"))]
    #[inline]
    fn crossing(&self, _phase: &str) {}
}

/// The transaction boundaries chaos can crash at, as named constants. The crossing points
/// in [`apply_update`] and the [`BOUNDARIES`] list the e2e enumerates both reference these,
/// so the two cannot drift — a crossing and its list entry are the *same* string.
mod boundary {
    pub const JOURNAL_WRITTEN: &str = "journal-written";
    pub const APP_STOPPED: &str = "app-stopped";
    pub const RELEASE_ACTIVATED: &str = "release-activated";
    pub const NEW_APP_STARTED: &str = "new-app-started";
    pub const HEALTH_PASSED: &str = "health-passed";
    pub const STATE_COMMITTED: &str = "state-committed";
    pub const JOURNAL_REMOVED: &str = "journal-removed";
}

/// The ordered boundary list, emitted by `supervisor --list-chaos-boundaries` so the e2e
/// drives exactly these — one source of truth across the crate boundary (the e2e runs the
/// supervisor as a subprocess and cannot share a `const`).
#[cfg(feature = "chaos")]
pub(crate) const BOUNDARIES: &[&str] = &[
    boundary::JOURNAL_WRITTEN,
    boundary::APP_STOPPED,
    boundary::RELEASE_ACTIVATED,
    boundary::NEW_APP_STARTED,
    boundary::HEALTH_PASSED,
    boundary::STATE_COMMITTED,
    boundary::JOURNAL_REMOVED,
];

// ============================ the live-application port ============================
//
// What the transaction drives on the *live* side — the running application and its
// readiness — behind a port, exactly as [`Store`] ports the durable side. The production
// [`LiveTower`] performs the configured [`Restart`] mode over the guardian-owned [`App`]; a
// test fake scripts control outcomes and health, so every fault path of [`apply_update`] is
// provable without a guardian, an HTTP server, or a real process.

/// Bring a staged release into (or back out of) service — the two hand-off moments plus the
/// quiesce a failed rollback needs. The port the transaction drives; the sole restart
/// abstraction (the [`Restart`] mode is data the [`LiveTower`] adapter acts on).
pub(crate) trait Control {
    /// Validate a candidate before durable transaction state or live state changes.
    fn preflight(
        &mut self,
        candidate: &updated::bundle::ReleaseId,
        predecessor: &updated::bundle::ReleaseId,
    ) -> io::Result<()>;
    /// Quiesce before activation: StopStart stops the app; reload keeps it serving.
    fn before_activation(&mut self);
    /// Put the active release into service: launch fresh, or signal a same-PID re-exec.
    fn activate(
        &mut self,
        candidate: &updated::bundle::ReleaseId,
        predecessor: &updated::bundle::ReleaseId,
    ) -> io::Result<()>;
    /// Stop the app — used when a rollback itself fails its health check.
    fn quiesce(&mut self);
    /// A same-PID reload keeps the launch token, so readiness must additionally prove the
    /// running image's version; a fresh launch's per-launch token already identifies it.
    fn requires_version_proof(&self) -> bool;
}

/// Probe the application to readiness. `expected_version` is required only for a reload.
/// The future is not `Send`-bound: the update loop is driven by `block_on` on one thread,
/// never spawned, so the transaction never crosses threads (as before this port existed).
pub(crate) trait Health {
    fn became_healthy(
        &self,
        expected_version: Option<&str>,
    ) -> impl std::future::Future<Output = bool>;
}

/// The production adapter: `Control` performs the configured [`Restart`] mode over the
/// guardian-owned [`App`]; `Health` is the real HTTP readiness probe.
pub(crate) struct LiveTower<'a> {
    app: &'a mut App,
    opts: &'a Options,
}

impl<'a> LiveTower<'a> {
    pub(crate) fn new(app: &'a mut App, opts: &'a Options) -> Self {
        LiveTower { app, opts }
    }
}

impl Control for LiveTower<'_> {
    fn preflight(
        &mut self,
        candidate: &updated::bundle::ReleaseId,
        predecessor: &updated::bundle::ReleaseId,
    ) -> io::Result<()> {
        match &self.opts.application.activation {
            Activation::StopStart => Ok(()),
            Activation::Reexec {
                preflight_command: Some(command),
                ..
            } => run_activation_command(
                "preflight",
                command,
                self.opts,
                self.app.pid(),
                candidate,
                predecessor,
            ),
            Activation::Reexec {
                preflight_command: None,
                ..
            } => Ok(()),
        }
    }
    fn before_activation(&mut self) {
        match &self.opts.application.activation {
            // StopStart quiesces the app before activation; a reload keeps serving.
            Activation::StopStart => stop(self.app, &self.opts.paths.app_token),
            Activation::Reexec { .. } => {}
        }
    }
    fn activate(
        &mut self,
        candidate: &updated::bundle::ReleaseId,
        predecessor: &updated::bundle::ReleaseId,
    ) -> io::Result<()> {
        match &self.opts.application.activation {
            Activation::StopStart => self.app.launch(self.opts),
            Activation::Reexec { command, .. } => run_activation_command(
                "activation",
                command,
                self.opts,
                self.app.pid(),
                candidate,
                predecessor,
            ),
        }
    }
    fn quiesce(&mut self) {
        stop(self.app, &self.opts.paths.app_token);
    }
    fn requires_version_proof(&self) -> bool {
        matches!(self.opts.application.activation, Activation::Reexec { .. })
    }
}

impl Health for LiveTower<'_> {
    async fn became_healthy(&self, expected_version: Option<&str>) -> bool {
        // A probe-infrastructure error (a client that will not even build) is a health
        // failure like any other: fail closed to a rollback rather than propagate.
        became_healthy(
            self.app,
            self.opts.timeouts.health_grace,
            self.opts.application.health_url.as_deref(),
            expected_version,
            self.opts.timeouts.health_successes,
            self.opts.timeouts.health_interval,
        )
        .await
        .unwrap_or(false)
    }
}

// ================================ the transaction ================================

/// Drive one application update through the durable transaction, over the [`Store`] and
/// live-application ([`Control`] + [`Health`]) ports.
pub(crate) async fn apply_update<T: Control + Health>(
    tower: &mut T,
    store: &mut dyn Store,
    candidate: &updated::bundle::ReleaseId,
    candidate_archive_sha256: &str,
) -> io::Result<Outcome> {
    // Recovery belongs to the boot state machine. A live supervisor must never mutate
    // recovery evidence or restore an executable underneath a guardian-owned process.
    // Any transaction error terminates this disposable supervisor; bootstrap keeps the
    // application alive and relaunches us through the one recovery path.
    if store.journal()?.is_some() {
        return Err(io::Error::other(
            "an unreconciled update journal requires supervisor restart",
        ));
    }

    let installed = match store.installed() {
        Installed::Present(state) => state,
        _ => return Err(io::Error::other("a verified installed release is required")),
    };
    if let Err(error) = store.verify_release(candidate) {
        warn(&format!(
            "candidate {} failed manifest verification before preflight ({error})",
            candidate.version
        ));
        return Ok(Outcome::RejectedBeforeActivation);
    }
    if let Err(error) = tower.preflight(candidate, &installed.release) {
        warn(&format!(
            "candidate {} failed preflight ({error}); the running release was not touched",
            candidate.version
        ));
        return Ok(Outcome::RejectedBeforeActivation);
    }
    if let Err(error) = store.verify_release(candidate) {
        warn(&format!(
            "candidate {} changed during preflight ({error}); the running release was not touched",
            candidate.version
        ));
        return Ok(Outcome::RejectedBeforeActivation);
    }
    let chaos = Chaos::from_env();
    let tx = Transaction {
        previous_release: installed.release.clone(),
        candidate_release: candidate.clone(),
        candidate_archive_sha256: candidate_archive_sha256.to_string(),
    };
    store.write_journal(&tx)?;
    chaos.crossing(boundary::JOURNAL_WRITTEN);

    // Hand-off part 1: stop the application (StopStart) or nothing (a reload strategy).
    tower.before_activation();
    chaos.crossing(boundary::APP_STOPPED);

    if let Err(e) = store.activate(candidate) {
        warn(&format!("release activation failed before commit ({e})"));
        roll_back(tower, store, &tx).await?;
        return Ok(Outcome::RolledBack);
    }
    chaos.crossing(boundary::RELEASE_ACTIVATED);

    // Re-verify the installed bytes against the signed digest before executing.
    if let Err(e) = store.verify_release(candidate) {
        warn(&format!(
            "active release failed manifest verification ({e})"
        ));
        roll_back(tower, store, &tx).await?;
        return Ok(Outcome::RolledBack);
    }

    // Hand-off part 2: start a fresh application, or trigger the server's own reload.
    if let Err(e) = tower.activate(candidate, &tx.previous_release) {
        warn(&format!("activating the new version failed ({e})"));
        roll_back(tower, store, &tx).await?;
        return Ok(Outcome::RolledBack);
    }
    chaos.crossing(boundary::NEW_APP_STARTED);

    let version_proof = tower
        .requires_version_proof()
        .then_some(candidate.version.as_str());
    if !tower.became_healthy(version_proof).await {
        roll_back(tower, store, &tx).await?;
        return Ok(Outcome::RolledBack);
    }
    chaos.crossing(boundary::HEALTH_PASSED);

    // Commit atomically WITH the pending rollback intent: the update is unconfirmed until
    // it survives its window. Folding the rollback intent into one write means there is no
    // separate "arm" step to be interrupted — if a crash lands after this, the pending
    // record is already durable; if before, the journal reactivates the predecessor.
    let pending = Some(Pending {
        previous_release: installed.release,
        previous_archive_sha256: installed.archive_sha256,
        committed_at: now_unix(),
    });
    store.commit_installed(&InstalledState {
        release: candidate.clone(),
        archive_sha256: candidate_archive_sha256.to_string(),
        pending,
    })?;
    chaos.crossing(boundary::STATE_COMMITTED);
    // The update is durable now: the active pointer and installed state (with its
    // pending intent) is committed. Failing to delete the spent journal must NOT report the
    // transaction as failed — that would leave the loop's in-memory state stale (still the
    // old version, not pending) while disk records the new one, letting a second update
    // start over this unconfirmed one. Return Committed and let recovery remove the journal
    // (it resolves as already-committed).
    if let Err(e) = store.clear_journal() {
        warn(&format!(
            "update committed but clearing its journal failed ({e}); recovery will remove it"
        ));
    }
    chaos.crossing(boundary::JOURNAL_REMOVED);
    Ok(Outcome::Committed)
}

/// Reactivate the previous release and get it running again through the same strategy (so a
/// reload strategy rolls back with zero downtime too). This is the only in-process
/// rollback — for an update whose new version stayed *alive* but never became healthy; a
/// crash instead tears the tower down and recovery rolls back on the next boot.
pub(crate) async fn roll_back<T: Control + Health>(
    tower: &mut T,
    store: &mut dyn Store,
    tx: &Transaction,
) -> io::Result<()> {
    tower.before_activation();
    store.activate(&tx.previous_release)?;
    tower.activate(&tx.previous_release, &tx.candidate_release)?;
    // Prove the rollback landed with the same evidence the forward path demands. A reload
    // keeps the PID and the launch token, so under that strategy the token proves nothing
    // about *which* image is answering: without the predecessor's version, an app that
    // never re-execed would have the just-rejected new version answer this probe and pass
    // it — leaving the release recorded as rolled back and rejected while it is still the
    // one running. A stop/start relaunch mints a fresh token, which already identifies it.
    let version_proof = if tower.requires_version_proof() {
        Some(tx.previous_release.version.as_str())
    } else {
        None
    };
    if !tower.became_healthy(version_proof).await {
        tower.quiesce();
        return Err(io::Error::other(
            "restored application failed its rollback health check",
        ));
    }
    store.clear_journal()?;
    Ok(())
}

/// Run one configured reexec command directly. Placeholders expand inside individual argv
/// elements without changing argument boundaries or invoking a shell.
pub(crate) fn run_activation_command(
    phase: &str,
    command: &[String],
    opts: &Options,
    pid: u32,
    candidate: &updated::bundle::ReleaseId,
    predecessor: &updated::bundle::ReleaseId,
) -> io::Result<()> {
    let (program, args) = command.split_first().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{phase} command is empty"),
        )
    })?;
    let pid = pid.to_string();
    let candidate_dir = opts.paths.versions.join(candidate.directory_name());
    let predecessor_dir = opts.paths.versions.join(predecessor.directory_name());
    let expand = |arg: &str| {
        arg.replace("{install_root}", &opts.paths.install_root.to_string_lossy())
            .replace("{candidate}", &candidate_dir.to_string_lossy())
            .replace("{predecessor}", &predecessor_dir.to_string_lossy())
            .replace("{candidate_version}", &candidate.version)
            .replace("{predecessor_version}", &predecessor.version)
            .replace("{version}", &candidate.version)
            .replace("{pid}", &pid)
    };
    let mut cmd = Command::new(expand(program));
    for arg in args {
        cmd.arg(expand(arg));
    }
    // The reload command is operator code, not a party to the guardian contract: strip the
    // same control-plane environment the managed application is launched without.
    for key in crate::app::CONTROL_PLANE_ENV {
        cmd.env_remove(key);
    }
    let status = cmd
        .env(env::CHILD_PID, &pid)
        .env(env::INSTALL_ROOT, &opts.paths.install_root)
        .env(env::CANDIDATE, &candidate_dir)
        .env(env::PREDECESSOR, &predecessor_dir)
        .env(env::CANDIDATE_VERSION, &candidate.version)
        .env(env::PREDECESSOR_VERSION, &predecessor.version)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "{phase} command exited with {status}"
        )))
    }
}
