use super::*;
use std::collections::HashSet;
use std::ffi::OsString;
use updated::reject::Rejections;

/// When to next check for a supervisor self-update, and which candidate hashes have
/// been rejected (so a bad release is never re-staged).
pub(crate) struct SelfUpdateState {
    next_check: Instant,
    rejected: Rejections,
}

impl SelfUpdateState {
    pub(crate) fn load(opts: &Options) -> io::Result<Self> {
        let path = opts.supervisor_update.state_dir.join("supervisor-rejected");
        // Effectively-permanent suppression: the remedy for a bad supervisor release is
        // a corrected republish (new bytes ⇒ new hash), not the passage of time.
        prune_supervisor_cache(opts);
        Ok(SelfUpdateState {
            next_check: Instant::now(),
            rejected: Rejections::load(&path)?,
        })
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

    /// Suppress the candidate supervisor with content hash `hash` (which the guardian just rolled
    /// back), terminating a bad-release loop. The caller extracts the hash from the marker's
    /// content-addressed `supervisors/<hash>/<binary>` path — once, up front, so that "the marker
    /// is not evidence" and "the rejection did not reach disk" are never the same test.
    ///
    /// Every way of failing is an error, never a warning: the caller clears the guardian's marker
    /// on the strength of this returning `Ok`, and the marker is the only other record that the
    /// candidate was ever rejected. A swallowed failure — an unwritable rejections file — would
    /// lose the hash and let `check` re-select, re-stage and re-trial the identical bad release on
    /// the next cycle, forever.
    pub(crate) fn reject_candidate(&mut self, hash: &str) -> io::Result<()> {
        self.rejected.reject(hash).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("could not record rejected supervisor {hash}: {e}"),
            )
        })?;
        log(&format!("recorded rejected supervisor candidate {hash}"));
        Ok(())
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
        // The download is the verification: `download_target` streams through the TUF target
        // reader, which enforces this target's declared length and sha256 byte by byte and
        // errors out rather than yield unverified data. Re-hashing the staged file here proved
        // the same digest a second time, and the application/provider path never did.
        repo.download_target(&selected.target, &download).await?;
        foundation::durable::install_executable(&path, &download)?;
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
                // old to know the REPLACE_SUPERVISOR tag. The guardian never judged
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

fn prune_supervisor_cache(opts: &Options) {
    let state_dir = &opts.supervisor_update.state_dir;
    let root = state_dir.join("supervisors");
    // Two entries are never candidates for collection: the running supervisor's own directory, and
    // the one the guardian has COMMITTED. This process may itself be an unconfirmed candidate the
    // guardian is trialling, in which case the committed entry is the rollback target — older than
    // everything else and therefore exactly what an age-ordered GC removes first. Deleting it
    // leaves the guardian with a pointer to a missing binary and no way back.
    let staged_dir_name =
        |path: PathBuf| path.parent().and_then(Path::file_name).map(OsString::from);
    let committed =
        match control::read_supervisor_pointer(&state_dir.join(control::DESIRED_SUPERVISOR_FILE)) {
            Ok(committed) => committed,
            Err(error) => {
                // Unreadable pointer: skip this pass rather than prune blind. A GC deferred to the
                // next boot costs disk; one that eats the rollback target costs the node.
                warn(&format!(
                "could not read the guardian's committed supervisor ({error}); skipping cache prune"
            ));
                return;
            }
        };
    let protected: HashSet<OsString> = std::env::current_exe()
        .ok()
        .into_iter()
        .chain(committed)
        .filter_map(staged_dir_name)
        .collect();
    match updated::gc::prune_directories(
        &root,
        &protected,
        opts.storage.inactive_supervisors,
        opts.storage.inactive_bytes,
    ) {
        Ok(0) => {}
        Ok(count) => log(&format!("removed {count} inactive supervisor candidate(s)")),
        Err(error) => warn(&format!("could not prune supervisor candidates: {error}")),
    }
}

/// Whether the running supervisor's own executable already has content hash `sha`.
fn running_supervisor_is(sha: &str) -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|p| sha256_file(&p).ok())
        .is_some_and(|h| h.eq_ignore_ascii_case(sha))
}

/// The supervisor binary's file name inside a content-addressed staging directory. The
/// guardian validates against the same name via [`foundation::platform`], so the two
/// cannot drift.
fn supervisor_filename() -> &'static str {
    foundation::platform::supervisor_binary_name()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let guard = tempfile::tempdir().unwrap();
        let path = guard.path().join(name);
        std::fs::create_dir_all(&path).unwrap();
        (guard, path)
    }

    fn state(dir: &Path) -> SelfUpdateState {
        SelfUpdateState {
            next_check: Instant::now(),
            rejected: Rejections::load(&dir.join("supervisor-rejected")).unwrap(),
        }
    }

    const HASH: &str = "aa11bb22cc33dd44ee55ff6677889900aa11bb22cc33dd44ee55ff6677889900";

    #[test]
    fn a_recorded_rejection_suppresses_the_candidate() {
        let (_guard, d) = dir("recorded");
        let mut state = state(&d);
        state.reject_candidate(HASH).unwrap();
        assert!(state.rejected.is_rejected(HASH));
        assert!(
            Rejections::load(&d.join("supervisor-rejected"))
                .unwrap()
                .is_rejected(HASH),
            "the rejection is durable, not just in memory"
        );
    }

    #[test]
    fn a_rejection_that_cannot_be_recorded_is_an_error_not_a_warning() {
        // The caller clears the guardian's marker on the strength of `Ok`. A swallowed failure
        // would lose the only two records of the bad candidate at once, and `check` would
        // re-select, re-stage and re-trial the identical release forever.
        let (_guard, d) = dir("unrecordable");
        let mut state = state(&d);
        // The rejections file can no longer be written.
        std::fs::remove_dir_all(&d).unwrap();
        assert!(state.reject_candidate(HASH).is_err());
    }
}
