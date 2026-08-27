use super::*;
use std::collections::HashSet;
use std::ffi::OsString;
use updated::reject::Rejections;

/// When to next check for an agent self-update, and which candidate hashes have
/// been rejected (so a bad release is never re-staged).
pub(crate) struct SelfUpdateState {
    next_check: Instant,
    rejected: Rejections,
}

impl SelfUpdateState {
    pub(crate) fn load(opts: &Options) -> io::Result<Self> {
        let path = opts.agent_update.state_dir.join("agent-rejected");
        // Effectively-permanent suppression: the remedy for a bad agent release is
        // a corrected republish (new bytes ⇒ new hash), not the passage of time.
        prune_agent_cache(opts);
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

    /// Suppress the candidate agent with content hash `hash` (which the launcher just rolled
    /// back), terminating a bad-release loop. The caller extracts the hash from the marker's
    /// content-addressed `agents/<hash>/<binary>` path — once, up front, so that "the marker
    /// is not evidence" and "the rejection did not reach disk" are never the same test.
    ///
    /// Every way of failing is an error, never a warning: the caller clears the launcher's marker
    /// on the strength of this returning `Ok`, and the marker is the only other record that the
    /// candidate was ever rejected. A swallowed failure — an unwritable rejections file — would
    /// lose the hash and let `check` re-select, re-stage and re-trial the identical bad release on
    /// the next cycle, forever.
    pub(crate) fn reject_candidate(&mut self, hash: &str) -> io::Result<()> {
        self.rejected.reject(hash).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("could not record rejected agent {hash}: {e}"),
            )
        })?;
        log(&format!("recorded rejected agent candidate {hash}"));
        Ok(())
    }

    /// Select the newest signed, non-rejected agent release. If its bytes differ
    /// from the running agent, stage them and hand the path to the launcher; on
    /// acceptance this process exits so the launcher can activate the candidate under a
    /// readiness gate. The agent's identity is its content hash, not a version, so
    /// selection is "newest trusted release whose bytes differ from mine".
    pub(crate) async fn check(
        &mut self,
        su: &AgentUpdate,
        repo: &TrustedRepository,
        launcher: &mut Launcher,
    ) {
        self.next_check = Instant::now() + su.check_interval;
        let policy = DefaultPolicy::current("agent", su.channel.clone());
        let Some(selected) = repo.select_release(
            &policy,
            // The running agent is identified by its content hash, not a version, so there is no
            // installed version to floor against or to short-circuit on.
            updated_tuf::select::Stance::Nothing,
            |m| log(&format!("self-update: {m}")),
            |t, _| self.rejected.is_rejected(&target_sha(t)),
        ) else {
            return;
        };
        if running_agent_is(&selected.sha256) {
            return; // already running these exact bytes
        }
        if let Err(e) = self.stage_and_handoff(su, repo, &selected, launcher).await {
            warn(&format!(
                "staging agent self-update {} failed: {e}",
                selected.version
            ));
        }
    }

    async fn stage_and_handoff(
        &mut self,
        su: &AgentUpdate,
        repo: &TrustedRepository,
        selected: &SelectedRelease,
        launcher: &mut Launcher,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Content-addressed staging: never overwrite a running agent binary, so
        // Windows executable locks do not apply: each candidate has a fresh path.
        // Built by the shared rule the LAUNCHER admits binaries with, so a change to the layout
        // cannot leave the permanent component refusing every self-update.
        let path = control::staged_agent_binary(&su.state_dir, &selected.sha256);
        std::fs::create_dir_all(
            path.parent()
                .expect("a staged agent path has a digest directory"),
        )?;
        let download = with_suffix(&path, ".download");
        // The download is the verification: `download_target` streams through the TUF target
        // reader, which enforces this target's declared length and sha256 byte by byte and
        // errors out rather than yield unverified data. Re-hashing the staged file here proved
        // the same digest a second time, and the application/provider path never did.
        let mut downloaded = repo.download_target(&selected.target, &download).await?;
        downloaded.install_executable(&path)?;
        let _ = std::fs::remove_file(&download);
        log(&format!(
            "agent self-update {} staged at {}; handing off to the launcher",
            selected.version,
            path.display()
        ));
        match launcher.replace_agent(&path) {
            Ok(()) => {
                log(
                    "launcher accepted the replacement; exiting for it to activate the \
                     candidate under a readiness gate (the application keeps running)",
                );
                std::process::exit(0);
            }
            Err(msg) => {
                // The handoff itself failed — a control-channel error, or a launcher too
                // old to know the REPLACE_AGENT tag. The launcher never judged
                // these bytes (its ReplaceAgent dispatch always accepts and only
                // rejects later, at the readiness gate), so do NOT reject them: that would
                // permanently block a good release. Keep the current version and retry next
                // cycle — this self-heals once the launcher is upgraded or the blip clears.
                warn(&format!(
                    "handing agent candidate {} off to the launcher failed ({msg}); \
                     keeping the current version and retrying later",
                    selected.version
                ));
                Ok(())
            }
        }
    }
}

fn prune_agent_cache(opts: &Options) {
    let state_dir = &opts.agent_update.state_dir;
    let root = control::agent_staging_root(state_dir);
    // Two entries are never candidates for collection: the running agent's own directory, and
    // the one the launcher has COMMITTED. This process may itself be an unconfirmed candidate the
    // launcher is trialling, in which case the committed entry is the rollback target — older than
    // everything else and therefore exactly what an age-ordered GC removes first. Deleting it
    // leaves the launcher with a pointer to a missing binary and no way back.
    let staged_dir_name =
        |path: PathBuf| path.parent().and_then(Path::file_name).map(OsString::from);
    let committed = match control::read_agent_pointer(&state_dir.join(control::DESIRED_AGENT_FILE))
    {
        Ok(committed) => committed,
        Err(error) => {
            // Unreadable pointer: skip this pass rather than prune blind. A GC deferred to the
            // next boot costs disk; one that eats the rollback target costs the node.
            warn(&format!(
                "could not read the launcher's committed agent ({error}); skipping cache prune"
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
        opts.storage.inactive_agents,
        opts.storage.inactive_bytes,
    ) {
        Ok(0) => {}
        Ok(count) => log(&format!("removed {count} inactive agent candidate(s)")),
        Err(error) => warn(&format!("could not prune agent candidates: {error}")),
    }
}

/// Whether the running agent's own executable already has content hash `sha`.
fn running_agent_is(sha: &str) -> bool {
    std::env::current_exe()
        .ok()
        .and_then(|p| sha256_file(&p).ok())
        .is_some_and(|hash| updated_contracts::digest::digests_match(&hash, sha))
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
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
            rejected: Rejections::load(&dir.join("agent-rejected")).unwrap(),
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
            Rejections::load(&d.join("agent-rejected"))
                .unwrap()
                .is_rejected(HASH),
            "the rejection is durable, not just in memory"
        );
    }

    #[test]
    fn a_rejection_that_cannot_be_recorded_is_an_error_not_a_warning() {
        // The caller clears the launcher's marker on the strength of `Ok`. A swallowed failure
        // would lose the only two records of the bad candidate at once, and `check` would
        // re-select, re-stage and re-trial the identical release forever.
        let (_guard, d) = dir("unrecordable");
        let mut state = state(&d);
        // The rejections file can no longer be written.
        std::fs::remove_dir_all(&d).unwrap();
        assert!(state.reject_candidate(HASH).is_err());
    }
}
