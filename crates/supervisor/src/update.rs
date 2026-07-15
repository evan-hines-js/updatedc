use super::*;

pub(crate) enum Outcome {
    Committed,
    RolledBack,
    /// The swap never happened (it failed to write); the binary is untouched.
    Aborted,
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
    pub const BINARY_SWAPPED: &str = "binary-swapped";
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
    boundary::BINARY_SWAPPED,
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

/// Bring a staged binary into (or back out of) service — the two hand-off moments plus the
/// quiesce a failed rollback needs. The port the transaction drives; the sole restart
/// abstraction (the [`Restart`] mode is data the [`LiveTower`] adapter acts on).
pub(crate) trait Control {
    /// Quiesce before the swap: StopStart stops the app; a reload keeps it serving.
    fn before_swap(&mut self);
    /// Put the new binary into service: launch a fresh app, or run the reload command.
    fn activate(&mut self) -> io::Result<()>;
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
    fn before_swap(&mut self) {
        match &self.opts.restart {
            // StopStart quiesces the app before its binary is swapped; a reload keeps serving.
            Restart::StopStart => stop(self.app, &self.opts.paths.app_token),
            Restart::Reload { .. } => {}
        }
    }
    fn activate(&mut self) -> io::Result<()> {
        match &self.opts.restart {
            Restart::StopStart => self.app.launch(self.opts),
            Restart::Reload { command } => {
                run_reload(command, &self.opts.paths.binary, self.app.pid())
            }
        }
    }
    fn quiesce(&mut self) {
        stop(self.app, &self.opts.paths.app_token);
    }
    fn requires_version_proof(&self) -> bool {
        matches!(self.opts.restart, Restart::Reload { .. })
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
    new_sha256: &str,
    to_version: &str,
    from_version: Option<&str>,
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

    let chaos = Chaos::from_env();
    let tx = Transaction {
        old_sha256: store.binary_sha().unwrap_or_default(),
        new_sha256: new_sha256.to_string(),
        to_version: to_version.to_string(),
        from_version: from_version.map(str::to_string),
    };
    store.write_journal(&tx)?;
    chaos.crossing(boundary::JOURNAL_WRITTEN);

    // Hand-off part 1: stop the application (StopStart) or nothing (a reload strategy).
    tower.before_swap();
    chaos.crossing(boundary::APP_STOPPED);

    if let Err(e) = store.swap_in_staged() {
        warn(&format!(
            "swap failed before commit ({e}); keeping current version"
        ));
        roll_back(tower, store, &tx).await?;
        return Ok(Outcome::Aborted);
    }
    chaos.crossing(boundary::BINARY_SWAPPED);

    // Re-verify the installed bytes against the signed digest before executing.
    if let Err(e) = store.verify_binary(&tx.new_sha256) {
        warn(&format!(
            "installed update failed signed hash verification ({e})"
        ));
        roll_back(tower, store, &tx).await?;
        return Ok(Outcome::RolledBack);
    }

    // Hand-off part 2: start a fresh application, or trigger the server's own reload.
    if let Err(e) = tower.activate() {
        warn(&format!("activating the new version failed ({e})"));
        roll_back(tower, store, &tx).await?;
        return Ok(Outcome::RolledBack);
    }
    chaos.crossing(boundary::NEW_APP_STARTED);

    let version_proof = tower.requires_version_proof().then_some(to_version);
    if !tower.became_healthy(version_proof).await {
        roll_back(tower, store, &tx).await?;
        return Ok(Outcome::RolledBack);
    }
    chaos.crossing(boundary::HEALTH_PASSED);

    // Commit atomically WITH the pending rollback intent: the update is unconfirmed until
    // it survives its window. Folding the rollback intent into one write means there is no
    // separate "arm" step to be interrupted — if a crash lands after this, the pending
    // record is already durable; if before, the journal rolls the swap back. The rollback
    // image is simply the retained `<binary>.old`; updates are skipped while pending, so it
    // stays intact until the update is confirmed or reverted.
    let pending = tx.from_version.as_deref().map(|previous| Pending {
        previous_version: previous.to_string(),
        previous_sha256: tx.old_sha256.clone(),
        committed_at: now_unix(),
    });
    let first_install = pending.is_none();
    store.commit_installed(&InstalledState {
        version: to_version.to_string(),
        sha256: tx.new_sha256.clone(),
        pending,
    })?;
    chaos.crossing(boundary::STATE_COMMITTED);
    // A first install has no predecessor to revert to; drop the rollback copy.
    if first_install {
        store.drop_rollback();
    }
    // The update is durable now: the binary is swapped and the installed state (with its
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

/// Restore the previous binary and get it running again, through the same strategy (so a
/// reload strategy rolls back with zero downtime too). This is the only in-process
/// rollback — for an update whose new version stayed *alive* but never became healthy; a
/// crash instead tears the tower down and recovery rolls back on the next boot.
pub(crate) async fn roll_back<T: Control + Health>(
    tower: &mut T,
    store: &mut dyn Store,
    tx: &Transaction,
) -> io::Result<()> {
    tower.before_swap();
    ensure_old_binary(store, &tx.old_sha256)?;
    tower.activate()?;
    // The restored binary is the previous version, so we require liveness + the
    // launch token but not a version match (we are going backward). This must
    // hold for every restart mode: an unhealthy rollback is not a completed one.
    if !tower.became_healthy(None).await {
        tower.quiesce();
        return Err(io::Error::other(
            "restored application failed its rollback health check",
        ));
    }
    store.clear_journal()?;
    Ok(())
}

/// Ensure the live binary is the committed/old one, restoring from the rollback image
/// only if the current bytes differ (i.e. a swap happened).
pub(crate) fn ensure_old_binary(store: &mut dyn Store, old_sha256: &str) -> io::Result<()> {
    if store
        .binary_sha()
        .is_some_and(|s| s.eq_ignore_ascii_case(old_sha256))
    {
        return Ok(());
    }
    store.restore_committed(old_sha256)
}

// ============================== the restart mode ==============================

/// How a verified, staged binary becomes the running service — a closed set of exactly two,
/// so an enum, not a trait object. The transaction ([`apply_update`]) owns journaling,
/// health, commit, and rollback; the restart mode owns only the two hand-off moments, which
/// the [`LiveTower`] adapter performs against the guardian-owned [`App`].
pub(crate) enum Restart {
    /// Stop the app, swap, start a fresh one. Brief downtime; every OS.
    StopStart,
    /// Zero-downtime: swap in place while the server keeps serving, then run an operator
    /// command that signals it to re-exec into the new binary (same PID).
    Reload { command: String },
}

impl Restart {
    pub(crate) fn name(&self) -> &'static str {
        match self {
            Restart::StopStart => "stop-start",
            Restart::Reload { .. } => "reload-command",
        }
    }
}

/// Run the operator's reload command, exposing the application PID and binary path.
pub(crate) fn run_reload(command: &str, binary: &Path, pid: u32) -> io::Result<()> {
    #[cfg(unix)]
    let mut cmd = {
        let mut c = Command::new("sh");
        c.arg("-c").arg(command);
        c
    };
    #[cfg(windows)]
    let mut cmd = {
        let mut c = Command::new("cmd");
        c.arg("/C").arg(command);
        c
    };
    let status = cmd
        .env(env::CHILD_PID, pid.to_string())
        .env(env::BINARY, binary)
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "reload command exited with {status}"
        )))
    }
}
