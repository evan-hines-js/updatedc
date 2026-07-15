use super::*;
use updated::reject::Rejections;

/// When to next check for a supervisor self-update, and which candidate hashes have
/// been rejected (so a bad release is never re-staged).
pub(crate) struct SelfUpdateState {
    next_check: Instant,
    rejected: Rejections,
}

impl SelfUpdateState {
    pub(crate) fn load(opts: &Options) -> Self {
        let path = opts.supervisor_update.state_dir.join("supervisor-rejected");
        // Effectively-permanent suppression: the remedy for a bad supervisor release is
        // a corrected republish (new bytes ⇒ new hash), not the passage of time.
        SelfUpdateState {
            next_check: Instant::now(),
            rejected: Rejections::load(&path, updated::reject::REJECT_TTL),
        }
    }

    pub(crate) fn due(&self, now: Instant) -> bool {
        now >= self.next_check
    }

    pub(crate) fn due_in(&self, now: Instant) -> Duration {
        self.next_check.saturating_duration_since(now)
    }

    pub(crate) fn defer(&mut self, until: Instant) {
        self.next_check = until;
    }

    /// Reject the candidate supervisor at `path` (which the guardian just rolled back).
    /// The path is content-addressed — `supervisors/<hash>/supervisor` — so its parent
    /// directory names the hash to suppress, terminating a bad-release loop.
    pub(crate) fn reject_candidate(&mut self, path: &Path) {
        if let Some(hash) = path
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|h| h.to_str())
        {
            if let Err(e) = self.rejected.reject(hash) {
                warn(&format!("could not record rejected supervisor {hash}: {e}"));
            } else {
                log(&format!("recorded rejected supervisor candidate {hash}"));
            }
        }
    }

    /// Select the newest signed, non-rejected supervisor release. If its bytes differ
    /// from the running supervisor, stage them and hand the path to the guardian; on
    /// acceptance this process exits so the guardian can activate the candidate under a
    /// readiness gate. The supervisor's identity is its content hash, not a version, so
    /// selection is "newest trusted release whose bytes differ from mine".
    pub(crate) async fn check(
        &mut self,
        su: &SupervisorUpdate,
        repo: &TrustedRepository,
        guardian: &mut Guardian,
    ) {
        self.next_check = Instant::now() + su.check_interval;
        let policy = DefaultPolicy::current("supervisor", su.channel.clone());
        let Some(selected) = repo.select_release(
            &policy,
            None, // no "current version": the running supervisor is identified by hash
            |m| log(&format!("self-update: {m}")),
            |t, _| self.rejected.is_rejected(&target_sha(t)),
        ) else {
            return;
        };
        if running_supervisor_is(&selected.sha256) {
            return; // already running these exact bytes
        }
        if let Err(e) = self.stage_and_handoff(su, repo, &selected, guardian).await {
            warn(&format!(
                "staging supervisor self-update {} failed: {e}",
                selected.version
            ));
        }
    }

    async fn stage_and_handoff(
        &mut self,
        su: &SupervisorUpdate,
        repo: &TrustedRepository,
        selected: &SelectedRelease,
        guardian: &mut Guardian,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Content-addressed staging: never overwrite a running supervisor binary, so
        // Windows executable locks do not apply: each candidate has a fresh path.
        let dir = su.state_dir.join("supervisors").join(&selected.sha256);
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(supervisor_filename());
        let download = with_suffix(&path, ".download");
        repo.stage_release(selected, &download).await?;
        verify_file(&download, &selected.sha256)?;
        apply::install_executable(&path, &download)?;
        let _ = std::fs::remove_file(&download);
        log(&format!(
            "supervisor self-update {} staged at {}; handing off to the guardian",
            selected.version,
            path.display()
        ));
        match guardian.replace_supervisor(&path) {
            Ok(()) => {
                log(
                    "guardian accepted the replacement; exiting for it to activate the \
                     candidate under a readiness gate (the application keeps running)",
                );
                std::process::exit(0);
            }
            Err(msg) => {
                // The handoff itself failed — a control-channel error, or a guardian too
                // old to advertise CAP_REPLACE_SUPERVISOR_V1. The guardian never judged
                // these bytes (its ReplaceSupervisor dispatch always accepts and only
                // rejects later, at the readiness gate), so do NOT reject them: that would
                // permanently block a good release. Keep the current version and retry next
                // cycle — this self-heals once the guardian is upgraded or the blip clears.
                warn(&format!(
                    "handing supervisor candidate {} off to the guardian failed ({msg}); \
                     keeping the current version and retrying later",
                    selected.version
                ));
                Ok(())
            }
        }
    }
}

/// Whether the running supervisor's own executable already has content hash `sha`.
fn running_supervisor_is(sha: &str) -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|p| sha256_file(&p).ok())
        .is_some_and(|h| h.eq_ignore_ascii_case(sha))
}

/// The supervisor binary's file name inside a content-addressed staging directory.
fn supervisor_filename() -> &'static str {
    if cfg!(windows) {
        "supervisor.exe"
    } else {
        "supervisor"
    }
}
